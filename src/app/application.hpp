#pragma once
#include "../model/configuration_session.hpp"
#include "../monitoring/traffic_history.hpp"
#include <deque>
#include <map>
#include <mutex>
#include <stop_token>

namespace home {
class Application {
    std::mutex mutex_;
    ConfigurationSession config_;
    Json interface_state_=Json::array(), health_={{"status","unknown"},{"origin","live"}}, events_=Json::array();
    Json scenario_={{"primary_up",true},{"backup_available",true},{"active_wan","primary"},{"temperature_c",24},{"fan_rpm",1200},{"power_w",80},{"ups_on_battery",false},{"ups_minutes",20},{"certificate_days",60},{"origin","simulated"}};
    std::map<std::string,CounterSample> previous_;
    std::map<std::string,TrafficHistory> histories_, aggregates_;
    struct Bucket { double down{},up{};int count{};int64_t minute{}; };
    std::map<std::string,Bucket> buckets_;
    Json resource_state_;
    bool dns_ready_{};
    void event_locked(const std::string& text,const std::string& origin);
public:
    void collect(std::stop_token stop);
    void check_health(std::stop_token stop);
    Json snapshot();
    Json traffic(const std::string& id,bool hourly);
    Json config();
    Json dns_settings();
    void dns_status(bool ready);
    Json change(const std::string& operation,const Json& input);
    Json connection(const Json& input);
    Json scenario(const Json& input);
};
}
