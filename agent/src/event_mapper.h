// Turns parsed ETW fields into PendingEvents: applies the own-process, path and
// registry filters, and fills in process details and names. It runs on the ETW
// thread, so it does no file I/O. Hashing, signature checks and the process filter,
// which depends on the signature, happen on the writer thread.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "agent_event.h"
#include "filters.h"
#include "name_tracker.h"
#include "path_utils.h"
#include "process_table.h"

namespace tp {

// Header fields shared by every ETW event.
struct EventContext {
    uint64_t filetime_utc = 0;
    uint32_t header_pid = 0;
    const void* sid = nullptr;  // from the EVENT_ENABLE_PROPERTY_SID extended data
    size_t sid_size = 0;
};

class EventMapper {
public:
    using Sink = std::function<void(PendingEvent&&)>;

    // `close_events` says whether Kernel-File Close (event 14) is being delivered.
    EventMapper(uint32_t own_pid, const PathMapper& paths, const Filters& filters,
                ProcessTable& processes, Counters& counters, bool close_events, Sink sink);

    // Kernel-Process
    void on_process_start(const EventContext& context, uint32_t pid, uint32_t ppid,
                          std::wstring_view nt_image, uint64_t create_time);
    void on_process_stop(const EventContext& context, uint32_t pid);

    // Kernel-File
    void on_file_name(uint64_t file_key, std::wstring_view nt_path);
    void on_file_name_deleted(uint64_t file_key);
    void on_file_open(const EventContext& context, uint64_t file_object,
                      std::wstring_view nt_path, uint32_t create_options);
    void on_file_close(const EventContext& context, uint64_t file_object, uint64_t file_key);
    void on_file_create(const EventContext& context, std::wstring_view nt_path);
    void on_file_write(const EventContext& context, uint64_t file_key, uint64_t file_object);
    void on_file_rename(const EventContext& context, uint64_t file_key, uint64_t file_object,
                        std::wstring_view nt_file_path);
    void on_file_delete(const EventContext& context, uint64_t file_key, uint64_t file_object,
                        std::wstring_view nt_file_path);

    // Kernel-Registry
    void on_registry_open(uint64_t base_object, uint64_t key_object, uint32_t status,
                          std::wstring_view base_name, std::wstring_view relative_name);
    void on_registry_close(uint64_t key_object);
    void on_registry_query(uint64_t key_object, std::wstring_view key_name);
    void on_registry_set(const EventContext& context, uint64_t key_object, uint32_t status,
                         std::wstring_view key_name, std::wstring_view value_name);

    // Kernel-Network. `pid` comes from the event data, because the event header can
    // name a different process, such as System.
    void on_network_connect(const EventContext& context, uint32_t pid, std::wstring dest_ip,
                            uint16_t dest_port);

private:
    bool is_own(const EventContext& context) const { return context.header_pid == own_pid_; }
    PendingEvent make_event(const EventContext& context, const char* type, uint32_t pid,
                            const ProcessInfo& info) const;
    void emit_file_event(const EventContext& context, const char* type,
                         std::optional<std::wstring> path, std::optional<std::wstring> old_path);

    uint32_t own_pid_;
    const PathMapper& paths_;
    const Filters& filters_;
    ProcessTable& processes_;
    Counters& counters_;
    Sink sink_;
    FileNameTracker files_;
    RegistryKeyTracker registry_;
};

}  // namespace tp
