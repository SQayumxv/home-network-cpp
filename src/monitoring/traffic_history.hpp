#pragma once
#include <algorithm>
#include <cstdint>
#include <deque>
#include <optional>

namespace home {
struct CounterSample { uint64_t received{}, sent{}; double monotonic{}; bool up{}; };
struct Rate { double down{}, up{}; bool valid{}; };
inline Rate calculate_rate(CounterSample previous, CounterSample current) {
    double elapsed = current.monotonic - previous.monotonic;
    if (!previous.up || !current.up || elapsed <= 0 || elapsed > 5 || current.received < previous.received || current.sent < previous.sent) return {};
    return {(current.received - previous.received) / elapsed, (current.sent - previous.sent) / elapsed, true};
}
struct TrafficPoint { int64_t timestamp{}; Rate rate; };
class TrafficHistory {
    size_t capacity_;
    std::deque<TrafficPoint> points_;
public:
    explicit TrafficHistory(size_t capacity = 900) : capacity_(capacity) {}
    void push(TrafficPoint point) { if (!capacity_) return; if (points_.size() >= capacity_) points_.pop_front(); points_.push_back(point); }
    const std::deque<TrafficPoint>& points() const { return points_; }
};
}
