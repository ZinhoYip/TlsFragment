#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <algorithm>

// 第三方头文件名保持不变
#include "log.h"
#include "remote.h"
#include "fake_desync.h"
#include "fragment.h"
#include "utils.h"
#include "config.h"
#include "pac.h"

namespace fs = std::filesystem;
using std::string;

// 保留全局变量原始命名风格
fs::path datapath;
string pacfile = "function genshin(){}";

std::atomic<bool> ThreadtoWork(false);
std::thread proxy_thread;

class ThreadedServer {
public:
    ThreadedServer(const string& host, int port) : host_(host), port_(port) {
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        if(host_.empty())
            addr.sin_addr.s_addr = INADDR_ANY;
        else
            inet_pton(AF_INET, host_.c_str(), &addr.sin_addr);
        if(bind(sock_, (sockaddr*)&addr, sizeof(addr)) < 0){
            throw std::runtime_error("bind失败");
        }
    }
    ~ThreadedServer(){
        close(sock_);
    }

    void listen(bool block = true){
        ::listen(sock_, 128);
        ThreadtoWork = true;
        proxy_thread = std::thread([this](){ accept_connections(); });
        if(block){
            try{
                while(true){
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }catch(...){ // 对应KeyboardInterrupt，捕获任意中断
                logger.warning("\nServer shutting down.");
            }
            ThreadtoWork = false;
            close(sock_);
        }
    }

private:
    string host_;
    int port_;
    int sock_;

    void accept_connections(){
        try{
            while(ThreadtoWork){
                sockaddr_in client_addr{};
                socklen_t len = sizeof(client_addr);
                int client_sock = accept(sock_, (sockaddr*)&client_addr, &len);
                setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO,
                           &(timeval){config["my_socket_timeout"]}, sizeof(timeval));
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                std::thread([&](int cs){ my_upstream(cs); }, client_sock).detach();
            }
            close(sock_);
        }catch(const std::exception& e){
            logger.warning(string("Server error: ") + e.what());
        }
    }

    remote::Remote* handle_client_request(int client_socket){
        try{
            char buf[5] = {0};
            ssize_t r = recv(client_socket, buf, sizeof(buf), MSG_PEEK);
            if(r<=0){
                close(client_socket);
                return nullptr;
            }
            if(static_cast<unsigned char>(buf[0]) == 0x05){
                return _handle_socks5(client_socket);
            }else{
                return _handle_http_protocol(client_socket);
            }
        }catch(const std::exception& e){
            logger.error(string("协议检测异常: ") + e.what());
            close(client_socket);
            return nullptr;
        }
    }

    remote::Remote* _handle_socks5(int client_socket){
        try{
            recv(client_socket, nullptr, 2, 0); // skip 版本+nmethods
            char nmethods;
            recv(client_socket, &nmethods, 1, 0);
            recv(client_socket, nullptr, nmethods, 0);
            string resp = "\x05\x00";
            send(client_socket, resp.c_str(), resp.size(), 0);

            char header[3];
            recv(client_socket, header, 3, 0);
            while(header[0] != 0x05){
                logger.debug("right 1, "+string(header,3));
                memmove(header, header+1, 2);
                recv(client_socket, &header[2], 1, 0);
            }
            if(header[0]!=0x05){
                throw std::runtime_error("Invalid SOCKS5 header");
            }
            uint8_t cmd = header[1];
            if(cmd!=0x01 && cmd!=0x05){
                string resp2 = "\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00";
                send(client_socket, resp2.c_str(), resp2.size(), 0);
                close(client_socket);
                throw std::runtime_error("Not supported socks command");
            }

            auto [server_name, server_port] = utils::parse_socks5_address(client_socket);
            logger.info(server_name+":"+std::to_string(server_port));
            try{
                auto* rem = new remote::Remote(server_name, server_port, cmd==0x01?6:17);
                string ok = "\x05\x00\x00\x01" + string("\x00\x00\x00\x00",4) + string("\x00\x00",2);
                send(client_socket, ok.c_str(), ok.size(), 0);
                return rem;
            }catch(const std::exception& e){
                logger.info(string("连接失败: ")+e.what());
                string fail = "\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00";
                send(client_socket, fail.c_str(), fail.size(), 0);
                close(client_socket);
                return utils::is_ip_address(server_name) ? new remote::Remote(server_name, server_port, 6) : nullptr;
            }
        }catch(const std::exception& e){
            logger.info(string("SOCKS5处理错误: ")+e.what());
            close(client_socket);
            return nullptr;
        }
    }

    remote::Remote* _handle_http_protocol(int client_socket){
        char buf[16384] = {0};
        ssize_t n = recv(client_socket, buf, sizeof(buf), 0);
        string data(buf, n);

        if(data.rfind("CONNECT ",0)==0){
            auto [host, port] = extract_servername_and_port(data);
            logger.info("CONNECT "+host+":"+std::to_string(port));
            try{
                auto* rem = new remote::Remote(host, port);
                string resp = "HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n";
                send(client_socket, resp.c_str(), resp.size(), 0);
                return rem;
            }catch(const std::exception& e){
                logger.info(string("连接失败: ")+e.what());
                string resp = "HTTP/1.1 502 Bad Gateway\r\nProxy-agent: MyProxy/1.0\r\n\r\n";
                send(client_socket, resp.c_str(), resp.size(), 0);
                close(client_socket);
                return utils::is_ip_address(host) ? new remote::Remote(host, port, 6) : nullptr;
            }
        }else if(data.find("/proxy.pac")!=string::npos){
            string resp = load_pac();
            send(client_socket, resp.c_str(), resp.size(), 0);
            close(client_socket);
            return nullptr;
        }else if(data.rfind("GET ",0)==0 || 
                 data.rfind("PUT ",0)==0 || 
                 data.rfind("DELETE ",0)==0 || 
                 data.rfind("POST ",0)==0 || 
                 data.rfind("HEAD ",0)==0 || 
                 data.rfind("OPTIONS ",0)==0){
            vector<string> line_list;
            size_t pos = 0, last=0;
            for(;(pos=data.find("\r\n", last))!=string::npos;last=pos+2){
                line_list.push_back(data.substr(last, pos-last));
            }
            string first_line = line_list.empty()? "" : line_list[0];
            vector<string> split_v;
            string method, url;
            {
                stringstream ss(first_line);
                ss >> method >> url;
            }
            string https_url = url;
            size_t http_pos = https_url.find("http://");
            if(http_pos!=string::npos){
                https_url.replace(http_pos, 7, "https://");
            }
            logger.info("重定向 "+method+" 到 HTTPS: "+https_url);
            string resp = "HTTP/1.1 302 Found\r\nLocation: "+https_url+"\r\nProxy-agent: MyProxy/1.0\r\n\r\n";
            send(client_socket, resp.c_str(), resp.size(), 0);
            close(client_socket);
            return nullptr;
        }else{
            string resp = "HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n";
            send(client_socket, resp.c_str(), resp.size(), 0);
            close(client_socket);
            return nullptr;
        }
    }

    void my_upstream(int client_sock){
        bool first_flag = true;
        remote::Remote* backend_sock = handle_client_request(client_sock);
        if(backend_sock==nullptr){
            close(client_sock);
            return;
        }

        while(ThreadtoWork){
            try{
                if(first_flag){
                    first_flag=false;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    char buf[16384];
                    ssize_t n = recv(client_sock, buf, sizeof(buf), 0);
                    string data(buf, n);

                    string extractedsni;
                    try{
                        extractedsni = utils::extract_sni(data);
                        if(backend_sock->domain=="127.0.0.114" || backend_sock->domain=="::114" 
                           || (config["BySNIfirst"] && extractedsni!=backend_sock->domain)){
                            logger.info("replace backendsock: "+extractedsni+" "+std::to_string(backend_sock->port)+" "+std::to_string(backend_sock->protocol));
                            delete backend_sock;
                            backend_sock = new remote::Remote(extractedsni, backend_sock->port, backend_sock->protocol);
                        }
                    }catch(...){}

                    backend_sock->client_sock = client_sock;
                    try{
                        backend_sock->connect();
                    }catch(...){
                        throw std::runtime_error("backend connect fail");
                    }

                    if(backend_sock->policy["safety_check"] && data.rfind("GET ",0)==0){
                        logger.warning("HTTP protocol detected, will redirect to https");
                        vector<string> line_list;
                        stringstream ss(data);
                        string method, url;
                        ss >> method >> url;
                        string https_url = url;
                        size_t pos = https_url.find("http://");
                        if(pos!=string::npos){
                            https_url.replace(pos,7,"https://");
                        }
                        string resp = "HTTP/1.1 302 Found\r\nLocation: "+https_url+"\r\nProxy-agent: MyProxy/1.0\r\n\r\n";
                        send(client_sock, resp.c_str(), resp.size(), 0);
                        close(client_sock);
                        backend_sock->close();
                        delete backend_sock;
                        return;
                    }

                    if(!data.empty()){
                        std::thread([=](){
                            my_downstream(backend_sock, client_sock);
                        }).detach();
                    }

                    try{
                        backend_sock->sni = extractedsni;
                        if(backend_sock->sni!=backend_sock->domain){
                            backend_sock->policy.update(match_domain(backend_sock->sni));
                        }
                    }catch(...){
                        try{
                            backend_sock->send(data);
                        }catch(...){
                            continue;
                        }
                    }

                    if(backend_sock->policy["safety_check"]){
                        try{
                            if(utils.detect_tls_version_by_keyshare(data)!=1){
                                logger.warning("Not a TLS 1.3 connection and will close");
                                backend_sock->close();
                                close(client_sock);
                                delete backend_sock;
                                throw std::runtime_error("Not a TLS 1.3 connection");
                            }
                        }catch(...){}
                    }

                    if(!data.empty()){
                        string mode = backend_sock->policy["mode"];
                        if(mode=="TLSfrag"){
                            fragment::send_fraggmed_tls_data(backend_sock, data);
                        }else if(mode=="FAKEdesync"){
                            fake_desync::send_data_with_fake(backend_sock,data);
                        }else if(mode=="DIRECT"){
                            backend_sock->send(data);
                        }else if(mode=="GFWlike"){
                            backend_sock->close();
                            close(client_sock);
                            delete backend_sock;
                            return;
                        }
                    }else{
                        throw std::runtime_error("cli syn close");
                    }
                }else{
                    char buf[16384];
                    ssize_t n = recv(client_sock, buf, sizeof(buf), 0);
                    if(n>0){
                        backend_sock->send(string(buf,n));
                    }else{
                        throw std::runtime_error("cli pipe close");
                    }
                }
            }catch(const std::exception& e){
                logger.info(string("upstream : ")+e.what()+" from "+backend_sock->domain);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                close(client_sock);
                backend_sock->close();
                delete backend_sock;
                return;
            }
        }
    }

    void my_downstream(remote::Remote* backend_sock, int client_sock){
        bool first_flag = true;
        while(ThreadtoWork){
            try{
                if(first_flag){
                    first_flag=false;
                    string data = backend_sock->recv(16384);
                    if(!data.empty()){
                        send(client_sock, data.c_str(), data.size(), 0);
                    }else{
                        throw std::runtime_error("backend pipe close at first");
                    }
                }else{
                    string data = backend_sock->recv(16384);
                    if(!data.empty()){
                        send(client_sock, data.c_str(), data.size(), 0);
                    }else{
                        throw std::runtime_error("backend pipe close");
                    }
                }
            }catch(const std::exception& e){
                logger.info(string("downstream : ")+e.what()+" from "+backend_sock->domain);
                std::this_thread::sleep_for(std::chrono::seconds(2));
                backend_sock->close();
                close(client_sock);
                delete backend_sock;
                return;
            }
        }
    }

    std::pair<std::string,int> extract_servername_and_port(const std::string& data){
        vector<string> parts;
        stringstream ss(data);
        string line;
        std::getline(ss, line);
        vector<string> line_parts;
        string tmp;
        stringstream ls(line);
        while(ls>>tmp) line_parts.push_back(tmp);
        string host_and_port = line_parts[1];
        size_t colon_pos = host_and_port.rfind(':');
        string host, port_str;
        if(colon_pos==string::npos){
            // 尝试解析IPv6
            size_t open_br = host_and_port.find('[');
            if(open_br!=string::npos){
                host = host_and_port.substr(open_br+1, host_and_port.find(']')-open_br-1);
                port_str = host_and_port.substr(host_and_port.find(']')+2);
            }else{
                // 纯IPv6无[]，手工找第六个冒号
                int cnt = 0;
                size_t idx = 0;
                while(cnt < 6){
                    idx = host_and_port.find(':', idx+1);
                    cnt++;
                }
                host = host_and_port.substr(0, idx);
                port_str = host_and_port.substr(idx+1);
            }
        }else{
            host = host_and_port.substr(0, colon_pos);
            port_str = host_and_port.substr(colon_pos+1);
        }
        return {host, std::stoi(port_str)};
    }
};

ThreadedServer* serverHandle = nullptr;

void start_server(bool block = true){
    generate_pac();
    serverHandle = new ThreadedServer("", config["port"]);
    logger.info("Now listening at: 127.0.0.1:"+std::to_string(config["port"]));
    serverHandle->listen(block);
}

void stop_server(bool wait_for_stop = true){
    ThreadtoWork = false;
    int sock = socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config["port"]);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connect(sock, (sockaddr*)&addr, sizeof(addr));
    close(sock);
    if(wait_for_stop){
        while(proxy_thread.joinable()){
            proxy_thread.join();
        }
        logger.info("Server stopped");
    }
}

fs::path dataPath = fs::current_path();
std::atomic<bool> ThreadtoWork(true);

int main(){
    start_server();
    return 0;
}