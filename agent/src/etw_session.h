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

struct SessionOptions {
    // Close events need the broad FILEIO keyword, narrowed by an event-ID filter.
    // Turn this off if that causes ETW losses.
    bool close_events = true;

    // Experiment: asks the file and registry providers to report what is already
    // open. Off by default, because a refused request stops the agent from starting.
    bool rundown = false;
};

class EtwSession {
public:
    EtwSession(EventMapper& mapper, Counters& counters, const SessionOptions& options);
    ~EtwSession();

    void run();   // blocks until stop(); throws if the session cannot start
    void stop();  // safe to call from another thread, and more than once
    std::optional<SessionStats> query_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tp
