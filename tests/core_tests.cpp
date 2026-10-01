#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include "../src/model/configuration_session.hpp"
#include "../src/monitoring/traffic_history.hpp"
#include <iostream>
#include <stdexcept>

static void require(bool condition, const char* description) { if (!condition) throw std::runtime_error(description); }
int main() {
    WSADATA data{}; WSAStartup(MAKEWORD(2,2), &data);
    try {
        using namespace home;
        auto rate = calculate_rate({100,200,1,true}, {2100,1200,3,true});
        require(rate.valid && rate.down == 1000 && rate.up == 500, "Rate calculation");
        require(!calculate_rate({100,100,1,true}, {0,0,2,true}).valid, "Counter reset");
        require(!calculate_rate({100,100,1,true}, {200,200,20,true}).valid, "Sleep gap");
        require(!calculate_rate({0,0,1,false}, {100,100,2,true}).valid, "Reconnect");
        TrafficHistory history(3); for (int i=0;i<20;++i) history.push({i,{}});
        require(history.points().size() == 3 && history.points().front().timestamp == 17, "Bounded history");
        auto config = initial_config(); require(validate_config(config).empty(), "Default config validates");
        require(evaluate(config, {{"source","guests"},{"destination","services"},{"protocol","tcp"},{"port",443}}).at("action") == "block", "Guest isolation");
        require(evaluate(config, {{"source","household"},{"destination","services"},{"protocol","tcp"},{"port",443}}).at("action") == "allow", "Explicit service access");
        auto broken = config; broken["networks"][1]["subnet"] = broken["networks"][0]["subnet"];
        require(!validate_config(broken).empty(), "Overlapping subnet rejected");
        auto priority = config; priority["rules"].insert(priority["rules"].begin(), Json{{"id","deny-first"},{"source","*"},{"destination","*"},{"protocol","any"},{"port",0},{"action","block"},{"enabled",true}});
        require(evaluate(priority, {{"source","household"},{"destination","services"},{"protocol","tcp"},{"port",443}}).at("action") == "block", "First rule wins");
        ConfigurationSession session; auto now = ConfigurationSession::Clock::now(); auto changed=config; changed["networks"][0]["name"]="Changed";
        require(session.apply(changed,now).empty() && session.pending(), "Temporary apply");
        require(!session.apply(changed,now).empty(), "Pending change cannot be replaced");
        require(session.tick(now+std::chrono::seconds(61)) && session.current()==config, "Automatic rollback");
        require(session.apply(changed).empty() && session.confirm() && session.current()==changed, "Confirmed config");
        std::cout << "All 14 core checks passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; WSACleanup(); return 1; }
    WSACleanup();
}
