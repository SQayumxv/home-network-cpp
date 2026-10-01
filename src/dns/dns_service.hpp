#pragma once
#include "../model/policy_engine.hpp"
#include <functional>
#include <stop_token>
#include <string>
#include <vector>

namespace home {
using DnsPacket = std::vector<unsigned char>;
DnsPacket dns_query(const std::string& name);
DnsPacket dns_response(const DnsPacket& query, const Json& settings, const std::vector<std::string>& upstreams);
Json dns_result(const DnsPacket& response);
void serve_dns(std::stop_token stop, std::function<Json()> settings, std::function<void(bool)> status);
}
