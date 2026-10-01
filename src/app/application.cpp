#include "application.hpp"
#include "../platform/network_platform.hpp"
#include "../dns/dns_service.hpp"
#include <set>
#include <thread>

namespace home {
static int64_t walltime() {return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void Application::event_locked(const std::string& text,const std::string& origin) {
    if(events_.size()>=256)events_.erase(events_.begin());events_.push_back({{"timestamp",walltime()},{"message",text},{"origin",origin}});
}
void Application::collect(std::stop_token stop) {
    while(!stop.stop_requested()) {
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(1);
        try {
            auto items=interfaces();auto usage=resources();double mono=std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();int64_t wall=walltime();
            std::lock_guard lock(mutex_);Json state=Json::array();std::set<std::string> seen;
            if(config_.tick())event_locked("Unconfirmed configuration rolled back automatically","simulated");
            for(const auto& item:items) {
                if(seen.size()>=64)break;seen.insert(item.id);
                CounterSample sample{item.received,item.sent,mono,item.up};auto found=previous_.find(item.id);Rate rate{};
                if(found!=previous_.end()) {rate=calculate_rate(found->second,sample);if(found->second.up!=sample.up)event_locked(item.name+(sample.up?" connected":" disconnected"),"live");}
                previous_[item.id]=sample;
                histories_.try_emplace(item.id,900);histories_.at(item.id).push({wall,rate});
                auto& bucket=buckets_[item.id];auto minute=wall/60000;
                if(bucket.count && minute!=bucket.minute) {
                    aggregates_.try_emplace(item.id,1440);aggregates_.at(item.id).push({bucket.minute*60000,{bucket.down/bucket.count,bucket.up/bucket.count,true}});bucket={};
                }
                bucket.minute=minute;if(rate.valid){bucket.down+=rate.down;bucket.up+=rate.up;++bucket.count;}
                state.push_back({{"id",item.id},{"name",item.name},{"type",item.type},{"up",item.up},{"addresses",item.addresses},{"received_bytes",item.received},{"sent_bytes",item.sent},{"link_bps",item.link_bps},{"download_bps",rate.down},{"upload_bps",rate.up},{"rate_valid",rate.valid},{"origin","live"}});
            }
            std::erase_if(previous_,[&](const auto& p){return !seen.contains(p.first);});std::erase_if(histories_,[&](const auto& p){return !seen.contains(p.first);});std::erase_if(aggregates_,[&](const auto& p){return !seen.contains(p.first);});std::erase_if(buckets_,[&](const auto& p){return !seen.contains(p.first);});
            interface_state_=std::move(state);resource_state_={{"memory_bytes",usage.memory_bytes},{"cpu_one_core_percent",usage.cpu_percent},{"origin","live"}};
        }catch(...) {std::lock_guard lock(mutex_);event_locked("Interface collection failed","live");}
        while(!stop.stop_requested() && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}
void Application::check_health(std::stop_token stop) {
    int failures=0,successes=0;auto servers=dns_servers();if(servers.size()>2)servers.resize(2);
    while(!stop.stop_requested()) {
        bool a=tcp_check("1.1.1.1",443,1200), b=tcp_check("8.8.8.8",443,1200);
        auto start=std::chrono::steady_clock::now();auto dns=dns_result(dns_response(dns_query("example.com"),{{"records",Json::object()},{"allowed",Json::array()},{"blocked",Json::array()}},servers));
        double millis=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();bool good=a||b;
        failures=good?0:failures+1;successes=good?successes+1:0;
        {std::lock_guard lock(mutex_);auto old=health_.value("status",std::string("unknown"));std::string next=old;
        if(failures>=3)next="unreachable";else if(successes>=2)next="reachable";
        if(next!=old)event_locked("Internet checks: "+next,"live");
        health_={{"status",next},{"external_tcp_a",a},{"external_tcp_b",b},{"dns_ok",dns.at("status")=="resolved"},{"dns_query_ms",millis},{"consecutive_failures",failures},{"timestamp",walltime()},{"origin","live"}};}
        for(int i=0;i<300 && !stop.stop_requested();++i)std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
Json Application::snapshot() {
    std::lock_guard lock(mutex_);Json sensors=scenario_;sensors["temperature_state"]=scenario_.at("temperature_c").get<int>()>=35?"critical":"normal";sensors["fan_state"]=scenario_.at("fan_rpm")==0?"failed":"running";sensors["certificate_state"]=scenario_.at("certificate_days").get<int>()<=14?"renewal due":"valid";
    return {{"interfaces",interface_state_},{"resources",resource_state_},{"health",health_},{"events",events_},{"simulation",sensors},{"configuration",{{"pending",config_.pending()},{"seconds_left",config_.seconds_left()},{"origin","simulated"}}},{"dns",{{"ready",dns_ready_},{"endpoint","127.0.0.1:1053"},{"origin",dns_ready_?"live":"unavailable"}}}};
}
Json Application::traffic(const std::string& id,bool hourly) {
    std::lock_guard lock(mutex_);Json result=Json::array();const auto& map=hourly?aggregates_:histories_;auto found=map.find(id);
    if(found!=map.end())for(const auto& p:found->second.points())result.push_back({{"timestamp",p.timestamp},{"download_bps",p.rate.down},{"upload_bps",p.rate.up},{"valid",p.rate.valid}});return result;
}
Json Application::config(){std::lock_guard lock(mutex_);return config_.current();}
Json Application::dns_settings(){std::lock_guard lock(mutex_);return config_.current().at("dns");}
void Application::dns_status(bool ready){std::lock_guard lock(mutex_);dns_ready_=ready;}
Json Application::change(const std::string& operation,const Json& input) {
    std::lock_guard lock(mutex_);config_.tick();
    if(operation=="preview") {auto error=validate_config(input);Json result={{"valid",error.empty()},{"error",error},{"origin","simulated"}};if(error.empty())result["diff"]=Json::diff(config_.current(),input);return result;}
    if(operation=="apply"){auto error=config_.apply(input);if(!error.empty())throw std::invalid_argument(error);event_locked("Configuration applied temporarily; confirm within 60 seconds","simulated");}
    else if(operation=="confirm"){if(!config_.confirm())throw std::invalid_argument("No pending configuration");event_locked("Configuration confirmed","simulated");}
    else if(operation=="rollback"){if(!config_.rollback())throw std::invalid_argument("No pending configuration");event_locked("Configuration rolled back","simulated");}
    else throw std::invalid_argument("Unknown operation");return {{"ok",true},{"origin","simulated"}};
}
Json Application::connection(const Json& input) {
    std::lock_guard lock(mutex_);
    if(input.contains("peer")) {
        const auto& peers=config_.current().at("vpn_peers");for(const auto& p:peers)if(p.at("id")==input.at("peer")) {
            bool allowed=false;for(const auto& n:p.at("allowed_networks"))if(n==input.at("destination"))allowed=true;
            allowed=allowed && p.at("enabled").get<bool>();return {{"action",allowed?"allow":"block"},{"reason",allowed?"Peer destination permission":"Peer disabled or destination not permitted"},{"origin","simulated"}};
        }
        throw std::invalid_argument("Unknown VPN peer");
    }
    return evaluate(config_.current(),input);
}
Json Application::scenario(const Json& input) {
    std::lock_guard lock(mutex_);auto action=input.at("action").get<std::string>();
    if(action=="primary-down"){scenario_["primary_up"]=false;scenario_["active_wan"]=scenario_.at("backup_available").get<bool>()?"backup":"offline";}
    else if(action=="primary-up"){scenario_["primary_up"]=true;scenario_["active_wan"]="primary";}
    else if(action=="backup-toggle"){bool available=!scenario_.at("backup_available").get<bool>();scenario_["backup_available"]=available;if(!scenario_.at("primary_up").get<bool>())scenario_["active_wan"]=available?"backup":"offline";}
    else if(action=="overheat")scenario_["temperature_c"]=42;
    else if(action=="fan-failed")scenario_["fan_rpm"]=0;
    else if(action=="power-failed")scenario_["ups_on_battery"]=true;
    else if(action=="certificate-expiring")scenario_["certificate_days"]=7;
    else if(action=="reset"){scenario_["primary_up"]=true;scenario_["backup_available"]=true;scenario_["active_wan"]="primary";scenario_["temperature_c"]=24;scenario_["fan_rpm"]=1200;scenario_["ups_on_battery"]=false;scenario_["certificate_days"]=60;}
    else throw std::invalid_argument("Unknown scenario");event_locked("Scenario: "+action,"simulated");return scenario_;
}
}
