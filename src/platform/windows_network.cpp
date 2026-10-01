#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include "network_platform.hpp"
#include <chrono>
#include <memory>
#include <stdexcept>

namespace home {
static std::string utf8(const wchar_t* value) {
    if (!value) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), size, nullptr, nullptr);
    out.pop_back(); return out;
}
std::vector<Interface> interfaces() {
    MIB_IF_TABLE2* raw{};
    if (GetIfTable2(&raw) != NO_ERROR) throw std::runtime_error("Interface enumeration failed");
    std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table(raw, FreeMibTable);
    ULONG size = 16000;
    std::vector<unsigned char> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size); adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    }
    std::vector<Interface> output;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        Interface item;
        item.id = std::to_string(row.InterfaceLuid.Value);
        item.name = utf8(row.Alias);
        item.type = row.Type == IF_TYPE_IEEE80211 ? "Wi-Fi" : row.Type == IF_TYPE_ETHERNET_CSMACD ? "Ethernet" : row.Type == IF_TYPE_SOFTWARE_LOOPBACK ? "Loopback" : "Virtual / other";
        item.up = row.OperStatus == IfOperStatusUp;
        item.received = row.InOctets; item.sent = row.OutOctets; item.link_bps = row.ReceiveLinkSpeed;
        if (result == NO_ERROR) for (auto* a = adapters; a; a = a->Next) {
            if (a->Luid.Value != row.InterfaceLuid.Value) continue;
            for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
                char text[INET6_ADDRSTRLEN]{};
                auto* sa = u->Address.lpSockaddr;
                const void* address = sa->sa_family == AF_INET ? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(sa)->sin_addr) : sa->sa_family == AF_INET6 ? static_cast<void*>(&reinterpret_cast<sockaddr_in6*>(sa)->sin6_addr) : nullptr;
                if (address && inet_ntop(sa->sa_family, address, text, sizeof(text))) item.addresses.emplace_back(text);
            }
        }
        output.push_back(std::move(item));
    }
    return output;
}
static uint64_t ticks(FILETIME value) { return (uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
Resources resources() {
    PROCESS_MEMORY_COUNTERS memory{}; memory.cb = sizeof(memory);
    GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory));
    FILETIME create{}, exit{}, kernel{}, user{};
    GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
    static uint64_t previous = ticks(kernel) + ticks(user);
    static auto previous_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now(); auto current = ticks(kernel) + ticks(user);
    double seconds = std::chrono::duration<double>(now - previous_time).count();
    double cpu = seconds > 0 ? (current - previous) / 1e7 / seconds * 100.0 : 0;
    previous = current; previous_time = now;
    return {memory.WorkingSetSize, cpu};
}
bool tcp_check(const char* address, unsigned short port, int timeout_ms) {
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) return false;
    sockaddr_in endpoint{}; endpoint.sin_family = AF_INET; endpoint.sin_port = htons(port);
    inet_pton(AF_INET, address, &endpoint.sin_addr);
    u_long nonblocking = 1; ioctlsocket(socket, FIONBIO, &nonblocking);
    int connected = connect(socket, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
    bool success = connected == 0;
    if (!success && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set write{}, errors{}; FD_ZERO(&write); FD_ZERO(&errors); FD_SET(socket, &write); FD_SET(socket, &errors);
        timeval timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        if (select(0, nullptr, &write, &errors, &timeout) > 0 && FD_ISSET(socket, &write)) {
            int error{}; int length = sizeof(error);
            success = getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0;
        }
    }
    closesocket(socket); return success;
}
std::vector<std::string> dns_servers() {
    ULONG size{}; GetNetworkParams(nullptr, &size);
    std::vector<unsigned char> data(size);
    auto* info = reinterpret_cast<FIXED_INFO*>(data.data());
    std::vector<std::string> result;
    if (GetNetworkParams(info, &size) == NO_ERROR) for (auto* d = &info->DnsServerList; d; d = d->Next) {
        in_addr address{};
        if (inet_pton(AF_INET, d->IpAddress.String, &address) == 1 && address.s_addr != 0) result.emplace_back(d->IpAddress.String);
    }
    return result;
}
}
