#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "policy_engine.hpp"
#include <set>

namespace home {
Json initial_config() {
    Json networks = Json::array();
    const char* names[] = {"household", "guests", "cameras", "experiments", "services", "management"};
    int vlan = 10;
    for (auto name : names) { networks.push_back({{"id", name}, {"name", name}, {"vlan", vlan}, {"subnet", "10.77." + std::to_string(vlan) + ".0/24"}, {"default_action", "block"}}); vlan += 10; }
    return {{"networks", networks}, {"devices", Json::array({
        {{"id", "demo-laptop"}, {"name", "Example laptop"}, {"network", "household"}},
        {{"id", "demo-guest"}, {"name", "Example guest"}, {"network", "guests"}},
        {{"id", "demo-camera"}, {"name", "Example camera"}, {"network", "cameras"}},
        {{"id", "demo-server"}, {"name", "Example server"}, {"network", "services"}},
        {{"id", "demo-admin"}, {"name", "Example admin"}, {"network", "management"}}})},
        {"rules", Json::array({
            {{"id", "household-web"}, {"source", "household"}, {"destination", "services"}, {"protocol", "tcp"}, {"port", 443}, {"action", "allow"}, {"enabled", true}},
            {{"id", "admin-access"}, {"source", "management"}, {"destination", "*"}, {"protocol", "any"}, {"port", 0}, {"action", "allow"}, {"enabled", true}},
            {{"id", "guest-internet"}, {"source", "guests"}, {"destination", "internet"}, {"protocol", "any"}, {"port", 0}, {"action", "allow"}, {"enabled", true}}})},
        {"vpn_peers", Json::array({{{"id", "example-phone"}, {"enabled", true}, {"allowed_networks", Json::array({"services"})}}})},
        {"dns", {{"records", {{"nas.home.arpa", "10.77.50.10"}, {"monitor.home.arpa", "10.77.50.11"}}}, {"blocked", Json::array({"ads.example", "blocked.example"})}, {"allowed", Json::array()}}}};
}
static bool subnet(const std::string& text, uint32_t& low, uint32_t& high) {
    auto slash = text.find('/'); if (slash == std::string::npos) return false;
    auto bits_text = text.substr(slash + 1);
    if (bits_text.empty() || bits_text.size() > 2 || bits_text.find_first_not_of("0123456789") != std::string::npos) return false;
    int bits = std::stoi(bits_text); if (bits < 1 || bits > 30) return false;
    in_addr value{}; if (inet_pton(AF_INET, text.substr(0, slash).c_str(), &value) != 1) return false;
    uint32_t mask = 0xffffffffu << (32 - bits); low = ntohl(value.s_addr) & mask; high = low | ~mask;
    return ntohl(value.s_addr) == low;
}
std::string validate_config(const Json& config) {
    try {
        for (auto key : {"networks", "devices", "rules", "vpn_peers"}) if (!config.at(key).is_array() || config.at(key).size() > 256) return "Lists must contain at most 256 entries";
        std::set<std::string> networks, devices, rules, peers; std::set<int> vlans;
        std::vector<std::pair<uint32_t,uint32_t>> ranges;
        for (const auto& n : config.at("networks")) {
            auto id = n.at("id").get<std::string>(); int vlan = n.at("vlan").get<int>();
            if (id.empty() || id.size() > 64 || id == "*" || id == "internet" || !networks.insert(id).second || vlan < 1 || vlan > 4094 || !vlans.insert(vlan).second) return "Invalid or duplicate network ID/VLAN";
            if (n.at("name").get<std::string>().size() > 128) return "Network name too long";
            if (n.at("default_action") != "allow" && n.at("default_action") != "block") return "Invalid default action";
            uint32_t low{}, high{}; if (!subnet(n.at("subnet").get<std::string>(), low, high)) return "Use a canonical IPv4 subnet with prefix 1–30";
            for (auto [a,b] : ranges) if (low <= b && a <= high) return "Subnets overlap";
            ranges.push_back({low,high});
        }
        if (networks.empty()) return "At least one network is required";
        for (const auto& d : config.at("devices")) {
            auto id = d.at("id").get<std::string>();
            if (id.empty() || id.size() > 64 || !devices.insert(id).second || !networks.contains(d.at("network").get<std::string>())) return "Invalid device or network reference";
            if (d.at("name").get<std::string>().size() > 128) return "Device name too long";
        }
        for (const auto& r : config.at("rules")) {
            auto id = r.at("id").get<std::string>();
            auto source = r.at("source").get<std::string>(), destination = r.at("destination").get<std::string>();
            if (id.empty() || id.size() > 64 || !rules.insert(id).second || (source != "*" && !networks.contains(source)) || (destination != "*" && destination != "internet" && !networks.contains(destination))) return "Invalid rule or network reference";
            auto protocol = r.at("protocol").get<std::string>(); int port = r.at("port").get<int>();
            if (protocol != "tcp" && protocol != "udp" && protocol != "icmp" && protocol != "any") return "Invalid protocol";
            if (port < 0 || port > 65535 || ((protocol == "icmp" || protocol == "any") && port != 0)) return "Invalid port; any/icmp must use 0";
            if (r.at("action") != "allow" && r.at("action") != "block") return "Invalid rule action";
            r.at("enabled").get<bool>();
        }
        for (const auto& p : config.at("vpn_peers")) {
            auto id = p.at("id").get<std::string>(); if (id.empty() || id.size() > 64 || !peers.insert(id).second) return "Invalid VPN peer ID";
            p.at("enabled").get<bool>();
            if (!p.at("allowed_networks").is_array() || p.at("allowed_networks").size() > 256) return "Invalid VPN permissions";
            for (const auto& n : p.at("allowed_networks")) if (!networks.contains(n.get<std::string>())) return "Unknown VPN destination";
        }
        const auto& dns = config.at("dns");
        if (!dns.at("records").is_object() || dns.at("records").size() > 256) return "Too many DNS records";
        auto valid_name = [](const std::string& s) { if (s.empty() || s.size() > 253 || s.front() == '.' || s.back() == '.') return false; size_t label = 0; for (char ch : s) { if (ch == '.') { if (!label || label > 63) return false; label = 0; } else { if (!(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-') return false; ++label; } } return label > 0 && label <= 63; };
        for (auto it = dns.at("records").begin(); it != dns.at("records").end(); ++it) { in_addr address{}; if (!valid_name(it.key()) || inet_pton(AF_INET, it.value().get<std::string>().c_str(), &address) != 1) return "Invalid lowercase DNS name or IPv4 record"; }
        for (auto key : {"blocked", "allowed"}) { if (!dns.at(key).is_array() || dns.at(key).size() > 4096) return "Invalid DNS list"; for (const auto& name : dns.at(key)) if (!valid_name(name.get<std::string>())) return "Invalid lowercase DNS list name"; }
        return {};
    } catch (...) { return "Configuration is missing fields or contains incorrect types"; }
}
Json evaluate(const Json& config, const Json& connection) {
    auto source = connection.at("source").get<std::string>();
    auto destination = connection.at("destination").get<std::string>();
    auto protocol = connection.at("protocol").get<std::string>(); int port = connection.at("port").get<int>();
    if (port < 0 || port > 65535 || (protocol != "tcp" && protocol != "udp" && protocol != "icmp")) throw std::invalid_argument("Invalid protocol or port");
    std::set<std::string> networks; for (const auto& n : config.at("networks")) networks.insert(n.at("id").get<std::string>());
    if (!networks.contains(source) || (destination != "internet" && !networks.contains(destination))) throw std::invalid_argument("Unknown network");
    for (const auto& rule : config.at("rules")) {
        if (!rule.at("enabled").get<bool>()) continue;
        if (rule.at("source") != "*" && rule.at("source") != source) continue;
        if (rule.at("destination") != "*" && rule.at("destination") != destination) continue;
        if (rule.at("protocol") != "any" && rule.at("protocol") != protocol) continue;
        if (rule.at("port") != 0 && rule.at("port") != port) continue;
        return {{"action", rule.at("action")}, {"rule", rule.at("id")}, {"reason", "First matching enabled rule"}, {"origin", "simulated"}};
    }
    for (const auto& network : config.at("networks")) if (network.at("id") == source) return {{"action", network.at("default_action")}, {"rule", nullptr}, {"reason", "Source network default policy"}, {"origin", "simulated"}};
    throw std::invalid_argument("Unknown source");
}
}
