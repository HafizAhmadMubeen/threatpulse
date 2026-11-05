#include "event_mapper.h"

#include <utility>

#include "text.h"

namespace tp {

namespace {

// Kernel-File CreateOptions flags. The disposition is stored in the top byte.
constexpr uint32_t kFileDirectoryFile = 0x00000001;
constexpr uint32_t kFileDeleteOnClose = 0x00001000;

// Pipes, the console and similar devices are not files on disk, so they are left
// out of the path coverage figures.
bool is_device_path(const std::optional<std::wstring>& path) {
    return path && istarts_with(*path, L"\\Device\\");
}

}  // namespace

EventMapper::EventMapper(uint32_t own_pid, const PathMapper& paths, const Filters& filters,
                         ProcessTable& processes, Counters& counters, bool close_events, Sink sink)
    : own_pid_(own_pid),
      paths_(paths),
      filters_(filters),
      processes_(processes),
      counters_(counters),
      sink_(std::move(sink)),
      files_(close_events) {}

PendingEvent EventMapper::make_event(const EventContext& context, const char* type, uint32_t pid,
                                     const ProcessInfo& info) const {
    PendingEvent event;
    event.filetime_utc = context.filetime_utc;
    event.event_type = type;
    event.pid = pid;
    event.ppid = info.ppid;
    event.image = info.image;
    event.cmdline = info.cmdline;
    event.user = info.user;
    return event;
}

void EventMapper::on_process_start(const EventContext& context, uint32_t pid, uint32_t ppid,
                                   std::wstring_view nt_image, uint64_t create_time) {
    if (pid == own_pid_) {
        ++counters_.own_dropped;
        return;
    }
    const ResolvedUser* creator = processes_.users().resolve(context.sid, context.sid_size);
    const ProcessInfo& info =
        processes_.on_start(pid, ppid, paths_.to_dos(nt_image), create_time, creator);
    if (!info.cmdline) ++counters_.cmdline_missing;

    PendingEvent event = make_event(context, "process_start", pid, info);
    event.recheck_image = true;
    sink_(std::move(event));
}

void EventMapper::on_process_stop(const EventContext& context, uint32_t pid) {
    if (pid == own_pid_) {
        ++counters_.own_dropped;
        return;
    }
    const ProcessInfo& info = processes_.on_stop(pid);
    sink_(make_event(context, "process_stop", pid, info));
}

// Name, open and close events update the maps even for the agent's own activity.
// Another process may use the same file later, and it needs the name.
void EventMapper::on_file_name(uint64_t file_key, std::wstring_view nt_path) {
    files_.remember(file_key, paths_.to_dos(nt_path));
}

void EventMapper::on_file_name_deleted(uint64_t file_key) {
    files_.forget(file_key);
}

void EventMapper::on_file_open(const EventContext& context, uint64_t file_object,
                               std::wstring_view nt_path, uint32_t create_options) {
    OpenFile file;
    file.path = paths_.to_dos(nt_path);
    file.opener_pid = context.header_pid;
    file.is_directory = (create_options & kFileDirectoryFile) != 0;
    file.delete_on_close = (create_options & kFileDeleteOnClose) != 0;
    files_.on_open(file_object, std::move(file));
}

void EventMapper::on_file_close(const EventContext& context, uint64_t file_object,
                                uint64_t file_key) {
    const std::optional<OpenFile> closed = files_.on_close(file_object, file_key);

    // A file opened with FILE_DELETE_ON_CLOSE is deleted here, with no event 26. The
    // close can run in another process, so the event is credited to the opener.
    if (closed && closed->delete_on_close && !closed->is_directory) {
        EventContext opener = context;
        opener.header_pid = closed->opener_pid;
        opener.sid = nullptr;
        opener.sid_size = 0;
        emit_file_event(opener, "file_delete", closed->path, std::nullopt);
    }
}

void EventMapper::emit_file_event(const EventContext& context, const char* type,
                                  std::optional<std::wstring> path,
                                  std::optional<std::wstring> old_path) {
    if (is_own(context)) {
        ++counters_.own_dropped;
        return;
    }
    // Drop only when every known path is noise: a file renamed out of a noisy
    // folder into a protected one must still be reported.
    const bool has_path = path.has_value() || old_path.has_value();
    const bool path_is_noise = (!path || filters_.ignores_path(*path)) &&
                               (!old_path || filters_.ignores_path(*old_path));
    if (has_path && path_is_noise) {
        ++counters_.filtered;
        return;
    }

    const ResolvedUser* user = processes_.users().resolve(context.sid, context.sid_size);
    const ProcessInfo& info = processes_.lookup(context.header_pid, user);

    PendingEvent event = make_event(context, type, context.header_pid, info);
    event.path = std::move(path);
    event.old_path = std::move(old_path);
    event.allow_process_filter = true;
    sink_(std::move(event));
}

void EventMapper::on_file_create(const EventContext& context, std::wstring_view nt_path) {
    emit_file_event(context, "file_create", paths_.to_dos(nt_path), std::nullopt);
}

void EventMapper::on_file_write(const EventContext& context, uint64_t file_key,
                                uint64_t file_object) {
    // Resolve first, even for the agent's own writes: this binds events.jsonl to its
    // FileKey, so System's flushes of the log can be filtered out by path.
    std::optional<std::wstring> path = files_.resolve(file_key, file_object, context.header_pid);

    if (!is_own(context) && !is_device_path(path)) {
        const ResolvedUser* user = processes_.users().resolve(context.sid, context.sid_size);
        const bool before = processes_.lookup(context.header_pid, user).started_before_agent;
        ++(before ? counters_.writes_before : counters_.writes_after);
        if (path) {
            ++(before ? counters_.writes_with_path_before : counters_.writes_with_path_after);
        } else {
            ++counters_.unresolved_file_paths;  // still emitted: write rates matter
        }
    }
    emit_file_event(context, "file_write", std::move(path), std::nullopt);
}

void EventMapper::on_file_rename(const EventContext& context, uint64_t file_key,
                                 uint64_t file_object, std::wstring_view nt_file_path) {
    const std::optional<std::wstring> known =
        files_.resolve(file_key, file_object, context.header_pid);
    std::optional<std::wstring> reported;
    if (!nt_file_path.empty()) reported = paths_.to_dos(nt_file_path);

    // FilePath is the new name (confirmed in the VM). If it ever equals the tracked
    // name, the rename changed nothing we can see, so report no new path and count it.
    if (known && reported && iequals(*known, *reported)) {
        ++counters_.rename_new_path_unknown;
        emit_file_event(context, "file_rename", std::nullopt, known);
        return;
    }
    if (reported) files_.on_rename(file_key, file_object, *reported);
    emit_file_event(context, "file_rename", std::move(reported), known);
}

void EventMapper::on_file_delete(const EventContext& context, uint64_t file_key,
                                 uint64_t file_object, std::wstring_view nt_file_path) {
    // Event 26 also fires for folders. Only the open event can tell them apart, so a
    // folder opened before the agent started is still reported.
    const OpenFile* open = files_.find_open(file_object, context.header_pid);
    if (open && open->is_directory) return;

    std::optional<std::wstring> path;
    if (!nt_file_path.empty()) {
        path = paths_.to_dos(nt_file_path);
    } else {
        path = files_.resolve(file_key, file_object, context.header_pid);
    }
    emit_file_event(context, "file_delete", std::move(path), std::nullopt);
}

void EventMapper::on_registry_open(uint64_t base_object, uint64_t key_object, uint32_t status,
                                   std::wstring_view base_name,
                                   std::wstring_view relative_name) {
    if (status != 0) return;  // a failed open leaves no valid key object
    registry_.on_open(base_object, key_object, base_name, relative_name);
}

void EventMapper::on_registry_close(uint64_t key_object) {
    registry_.on_close(key_object);
}

void EventMapper::on_registry_query(uint64_t key_object, std::wstring_view key_name) {
    registry_.learn(key_object, key_name);
}

void EventMapper::on_registry_set(const EventContext& context, uint64_t key_object, uint32_t status,
                                  std::wstring_view key_name, std::wstring_view value_name) {
    if (status != 0) return;  // a failed write changed nothing
    if (is_own(context)) {
        ++counters_.own_dropped;
        return;
    }

    const ResolvedUser* user = processes_.users().resolve(context.sid, context.sid_size);
    const ProcessInfo& info = processes_.lookup(context.header_pid, user);

    std::optional<std::wstring> sid = info.sid;
    if (user) sid = user->sid;

    // Anything less than a complete path is marked <unresolved>, so a partial tail
    // can never be mistaken for a full key.
    std::wstring key = L"<unresolved>";
    bool complete = false;
    if (const auto resolved = registry_.resolve(key_object, key_name)) {
        if (resolved->complete) {
            key = normalize_registry_key(resolved->path, sid);
            complete = true;
        } else {
            key += L"\\" + resolved->path;
        }
    } else if (!key_name.empty()) {
        key += L"\\" + std::wstring(key_name);
    }

    const bool before = info.started_before_agent;
    ++(before ? counters_.registry_before : counters_.registry_after);
    if (complete) {
        ++(before ? counters_.registry_resolved_before : counters_.registry_resolved_after);
    } else {
        ++counters_.unresolved_registry_keys;
    }

    if (filters_.ignores_registry(key)) {
        ++counters_.filtered;
        return;
    }

    // Same layout as the 5.2 sample: key\value. An empty name is the default value.
    key += L"\\";
    key += value_name.empty() ? std::wstring_view(L"(Default)") : value_name;

    PendingEvent event = make_event(context, "registry_set", context.header_pid, info);
    event.registry_key = std::move(key);
    event.allow_process_filter = true;
    sink_(std::move(event));
}

}  // namespace tp
