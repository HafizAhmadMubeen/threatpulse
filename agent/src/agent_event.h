// Types shared between the ETW thread and the writer thread.
#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tp {

// An event after mapping, before hashing and signature checks. `source` and
// `event_type` always point at string literals.
struct PendingEvent {
    uint64_t filetime_utc = 0;
    const char* source = "etw";
    const char* event_type = "";
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::wstring image;
    std::optional<std::wstring> cmdline;
    std::optional<std::wstring> user;
    std::optional<std::wstring> path;
    std::optional<std::wstring> old_path;
    std::optional<std::wstring> registry_key;
    std::optional<uint32_t> target_pid;
    std::optional<std::string> access_mask;  // raw hex, for example "0x1010"
    std::optional<std::vector<std::string>> access_rights;
    std::optional<std::wstring> dest_ip;
    std::optional<uint16_t> dest_port;
    bool recheck_image = false;  // true on process_start: the file may have changed
    bool allow_process_filter = false;  // true only for ETW file and registry events
};

// Printed at shutdown, so data quality is measured rather than assumed.
struct Counters {
    std::atomic<uint64_t> written{0};
    std::atomic<uint64_t> own_dropped{0};
    std::atomic<uint64_t> filtered{0};
    std::atomic<uint64_t> queue_dropped{0};
    std::atomic<uint64_t> callback_errors{0};
    std::atomic<uint64_t> cmdline_missing{0};
    std::atomic<uint64_t> unresolved_file_paths{0};
    std::atomic<uint64_t> unresolved_registry_keys{0};
    std::atomic<uint64_t> rename_new_path_unknown{0};

    std::atomic<uint64_t> sysmon_read{0};
    std::atomic<uint64_t> sysmon_skipped{0};  // inbound connections, CreateKey
    std::atomic<uint64_t> sysmon_no_process_details{0};
    std::atomic<uint64_t> sysmon_errors{0};

    // Path coverage, split by whether the process started before the agent. ETW can
    // only name a handle if it saw the open, so the two groups mean different things.
    std::atomic<uint64_t> writes_before{0};
    std::atomic<uint64_t> writes_with_path_before{0};
    std::atomic<uint64_t> writes_after{0};
    std::atomic<uint64_t> writes_with_path_after{0};
    std::atomic<uint64_t> registry_before{0};
    std::atomic<uint64_t> registry_resolved_before{0};
    std::atomic<uint64_t> registry_after{0};
    std::atomic<uint64_t> registry_resolved_after{0};
};

}  // namespace tp
