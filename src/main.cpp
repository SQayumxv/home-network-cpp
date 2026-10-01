#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "platform/network_platform.hpp"
#include "monitoring/traffic_history.hpp"
#include <chrono>
#include <iostream>
#include <map>
#include <thread>

int main(int argc, char** argv) {
    WSADATA data{}; if (WSAStartup(MAKEWORD(2,2), &data)) return 1;
    std::map<std::string,home::CounterSample> previous;
    try {
        for (int sample=0;sample<5;++sample) {
            double now=std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
            for (const auto& item : home::interfaces()) {
                home::CounterSample current{item.received,item.sent,now,item.up};
                auto rate=home::calculate_rate(previous[item.id],current); previous[item.id]=current;
                if(item.up) std::cout<<item.name<<" | down "<<rate.down<<" B/s | up "<<rate.up<<" B/s\n";
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; WSACleanup(); return 1; }
    WSACleanup();
}
