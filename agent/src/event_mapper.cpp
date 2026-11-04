#include "event_mapper.h"

#include "text.h"

namespace tp {

EventMapper::EventMapper(uint32_t own_pid, const PathMapper& paths, const Filters& filters,
                         ProcessTable& processes, Counters& counters, Sink sink)
    : own_pid_(own_pid),
      paths_(paths),
      filters_(filters),
      processes_(processes),
      counters_(counters),
      sink_(std::move(sink)) {}

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

// Name events update the map even for the agent's own activity. Another process
// may use the same file later, and it needs the name.
void EventMapper::on_file_name(uint64_t file_key, std::wstring_view nt_path) {
    files_.remember(file_key, paths_.to_dos(nt_path));
}

void EventMapper::on_file_name_deleted(uint64_t file_key) {
    files_.forget(file_key);
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

void EventMapper::on_file_write(const EventContext& context, uint64_t file_key) {
    std::optional<std::wstring> path = files_.find(file_key);
    // Still emitted without a path: write rates matter for the ransomware detector.
    if (!path && !is_own(context)) ++counters_.unresolved_file_paths;
    emit_file_event(context, "file_write", std::move(path), std::nullopt);
}

void EventMapper::on_file_rename(const EventContext& context, uint64_t file_key,
                                 std::wstring_view nt_file_path) {
    const std::optional<std::wstring> known = files_.find(file_key);
    std::optional<std::wstring> reported;
    if (!nt_file_path.empty()) reported = paths_.to_dos(nt_file_path);

    // Open question for the VM: the manifest does not say whether FilePath is the
    // old or new name. If it equals the name already tracked, it must be the old
    // one. Report the new path as null rather than a wrong value, and count it.
    if (known && reported && iequals(*known, *reported)) {
        ++counters_.rename_new_path_unknown;
        emit_file_event(context, "file_rename", std::nullopt, known);
        return;
    }
    if (reported) files_.remember(file_key, *reported);
    emit_file_event(context, "file_rename", std::move(reported), known);
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

    std::wstring key;
    if (const auto resolved = registry_.resolve(key_object, key_name)) {
        key = normalize_registry_key(*resolved, sid);
    } else {
        ++counters_.unresolved_registry_keys;
        key = key_name.empty() ? L"<unresolved>" : L"<unresolved>\\" + std::wstring(key_name);
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
