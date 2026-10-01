#pragma once
#include "policy_engine.hpp"
#include <chrono>
#include <optional>

namespace home {
class ConfigurationSession {
public:
    using Clock = std::chrono::steady_clock;
private:
    Json current_ = initial_config();
    std::optional<Json> previous_;
    Clock::time_point deadline_{};
public:
    const Json& current() const { return current_; }
    bool pending() const { return previous_.has_value(); }
    bool tick(Clock::time_point now = Clock::now()) { if (pending() && now >= deadline_) { rollback(); return true; } return false; }
    std::string apply(const Json& proposed, Clock::time_point now = Clock::now()) {
        if (pending()) return "Confirm or roll back the pending change first";
        auto error = validate_config(proposed); if (!error.empty()) return error;
        previous_ = current_; current_ = proposed; deadline_ = now + std::chrono::seconds(60); return {};
    }
    bool confirm() { if (!pending()) return false; previous_.reset(); return true; }
    bool rollback() { if (!pending()) return false; current_ = *previous_; previous_.reset(); return true; }
    int seconds_left() const { return pending() ? (std::max)(0, int(std::chrono::duration_cast<std::chrono::seconds>(deadline_ - Clock::now()).count())) : 0; }
};
}
