#pragma once
#include "json.hpp"
#include <string>

namespace home {
using Json = nlohmann::json;
Json initial_config();
std::string validate_config(const Json& config);
Json evaluate(const Json& config, const Json& connection);
}
