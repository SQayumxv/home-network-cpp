#pragma once
#include "../app/application.hpp"
#include <filesystem>
#include <stop_token>
namespace home { void serve_http(Application& app,int port,const std::filesystem::path& web,std::stop_token stop); }
