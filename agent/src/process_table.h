// pid -> image, parent, command line and user.
//
// File and registry events carry only a pid, so the Event's process{} block
// comes from this table. Kernel-Process start events carry no command line or
// user, so those are read from the live process. ETW delivers events with a
// delay, so a short-lived process may already be gone: cmdline is then null.
// Only the ETW thread touches this class, so it needs no locks.
#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "path_utils.h"

namespace tp {

struct ResolvedUser {
    std::wstring sid;
    std::wstring account;  // DOMAIN\name, or the SID string if the lookup fails
};

// Cached because SID lookups are slow and the same few SIDs repeat constantly.
class UserResolver {
public:
    const ResolvedUser* resolve(const void* sid, size_t size);

private:
    std::unordered_map<std::string, ResolvedUser> cache_;
};

struct ProcessInfo {
    std::wstring image;
    uint32_t ppid = 0;  // 0 means unknown
    std::optional<std::wstring> cmdline;
    std::optional<std::wstring> user;
    std::optional<std::wstring> sid;
    ULONGLONG exited_tick = 0;  // 0 while running
    bool started_before_agent = true;  // false only if we saw its process_start event
};

class ProcessTable {
public:
    explicit ProcessTable(const PathMapper& paths);

    // Adds processes that were already running when the agent started.
    void seed_from_snapshot();

    // `creator` is the user of the thread that emitted the start event, so it is
    // only a fallback for when the new process's own token cannot be read.
    const ProcessInfo& on_start(uint32_t pid, uint32_t ppid, std::wstring image,
                                uint64_t create_time, const ResolvedUser* creator);

    // Marks the process as exited. The entry stays briefly because late file or
    // registry events for this pid can still arrive.
    const ProcessInfo& on_stop(uint32_t pid);

    // `event_user` is the user attached to the event, used if the table has none.
    const ProcessInfo& lookup(uint32_t pid, const ResolvedUser* event_user);

    UserResolver& users() { return users_; }

private:
    ProcessInfo& entry(uint32_t pid, const ResolvedUser* event_user);
    ProcessInfo read_live(uint32_t pid);
    void read_identity(HANDLE process, ProcessInfo& info);
    void sweep();

    const PathMapper& paths_;
    UserResolver users_;
    std::unordered_map<uint32_t, ProcessInfo> processes_;
    ULONGLONG last_sweep_tick_ = 0;
};

}  // namespace tp
