// The ETW session. krabsetw stays behind this interface because its headers
// define INITGUID, so including them from a second .cpp risks duplicate-symbol
// link errors. Only etw_session.cpp may include krabs.hpp.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include "agent_event.h"
#include "event_mapper.h"

namespace tp {

inline constexpr wchar_t kSessionName[] = L"ThreatPulse-Agent";

// Stops the session with exactly this name and no other. Returns true if a
// session was running and has been stopped. Also safe from a crash handler.
bool stop_session_by_name();

struct SessionStats {
    uint64_t events_handled = 0;
    uint64_t events_lost = 0;
    uint64_t buffers_lost = 0;
};

class EtwSession {
public:
    EtwSession(EventMapper& mapper, Counters& counters);
    ~EtwSession();

    void run();   // blocks until stop(); throws if the session cannot start
    void stop();  // safe to call from another thread, and more than once
    std::optional<SessionStats> query_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tp
