#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include "app/application.hpp"
#include "server/http_server.hpp"
#include "dns/dns_service.hpp"
#include <filesystem>
#include <iostream>
#include <thread>

static std::stop_source shutdown_source;
static BOOL WINAPI console_handler(DWORD event) {
    if(event==CTRL_C_EVENT || event==CTRL_BREAK_EVENT || event==CTRL_CLOSE_EVENT){shutdown_source.request_stop();return TRUE;}return FALSE;
}
int main(int argc,char** argv) {
    int port=8787;std::filesystem::path web="src/web";int duration=0;
    try {
        for(int i=1;i<argc;++i) {
            std::string arg=argv[i];
            if(arg=="--help"){std::cout<<"Home network prototype: --port 8787 --web src/web --duration SECONDS\n";return 0;}
            if(i+1>=argc)throw std::invalid_argument("Missing option value");
            if(arg=="--port")port=std::stoi(argv[++i]);else if(arg=="--web")web=argv[++i];else if(arg=="--duration")duration=std::stoi(argv[++i]);else throw std::invalid_argument("Unknown option");
        }
        if(port<1024 || port>65535 || duration<0)throw std::invalid_argument("Invalid port or duration");
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
    WSADATA data{};if(WSAStartup(MAKEWORD(2,2),&data))return 1;
    SetConsoleCtrlHandler(console_handler,TRUE);int result=0;
    {
        home::Application app;auto stop=shutdown_source.get_token();
        std::jthread collector([&]{app.collect(stop);});
        std::jthread health([&]{app.check_health(stop);});
        std::jthread dns([&]{home::serve_dns(stop,[&]{return app.dns_settings();},[&](bool ready){app.dns_status(ready);});});
        std::jthread timer([&](std::stop_token own){auto end=std::chrono::steady_clock::now()+std::chrono::seconds(duration);while(!own.stop_requested() && !stop.stop_requested()){if(duration && std::chrono::steady_clock::now()>=end){shutdown_source.request_stop();break;}std::this_thread::sleep_for(std::chrono::milliseconds(100));}});
        std::cout<<"Home network prototype\nDashboard: http://127.0.0.1:"<<port<<"\nTest DNS: 127.0.0.1:1053 (UDP/TCP)\nLive readings stay in memory. Network controls are simulated. Ctrl+C stops.\n";
        try {home::serve_http(app,port,web,stop);}catch(const std::exception& error){std::cerr<<error.what()<<'\n';result=1;}
        shutdown_source.request_stop();
    }
    WSACleanup();return result;
}
