#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace home {
struct Interface {
    std::string id, name, type;
    bool up{};
    uint64_t received{}, sent{}, link_bps{};
    std::vector<std::string> addresses;
};
struct Resources { uint64_t memory_bytes{}; double cpu_percent{}; };
std::vector<Interface> interfaces();
Resources resources();
bool tcp_check(const char* address, unsigned short port, int timeout_ms);
std::vector<std::string> dns_servers();
}
