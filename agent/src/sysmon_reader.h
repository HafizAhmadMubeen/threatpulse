// Reads Sysmon Event IDs 3, 10, 12 and 13 from the Windows Event Log and maps them to
// Event records with source "sysmon". It runs on its own thread, so a slow event log
// can never delay the ETW callback.
//
// The Sysmon config already decides what is logged, so these events pass through no
// noise filter. A dropped event here could be a missed zone signal.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "agent_event.h"
#include "process_table.h"

namespace tp {

struct SysmonError {
    std::string message;
    uint64_t count = 0;
};

class SysmonReader {
public:
    using Sink = std::function<void(PendingEvent&&)>;

    // Subscribes straight away and throws if it can't, for example when Sysmon is not
    // installed. `processes` must outlive the reader.
    SysmonReader(uint32_t own_pid, const ProcessTable& processes, Counters& counters, Sink sink);
    ~SysmonReader();

    void start();
    void stop();  // reads what has arrived and hands over held events; safe to call twice

    // The first few different errors and how often each happened. Call after stop().
    const std::vector<SysmonError>& errors() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tp
