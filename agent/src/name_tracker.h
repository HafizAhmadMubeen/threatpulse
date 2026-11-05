// Rebuilds names that ETW leaves out of the events we need.
//
// Kernel-File Write events carry a FileKey and a FileObject, not a path, and
// Kernel-Registry SetValueKey events carry a KeyObject with an empty KeyName. The
// names appear in earlier events, so these maps remember them.
//
// Priority: never a wrong path, then coverage. A null path is an honest gap, while
// a wrong path could put an event in the wrong protected zone. Only the ETW thread
// touches these classes, so they need no locks.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace tp {

struct OpenFile {
    std::wstring path;
    uint32_t opener_pid = 0;
    bool is_directory = false;
    bool delete_on_close = false;
};

class FileNameTracker {
public:
    // Key binding needs Close events to clear old bindings, so it is off without them.
    explicit FileNameTracker(bool allow_key_binding);

    // FileKey -> name, from NameCreate and NameDelete.
    void remember(uint64_t file_key, std::wstring dos_path);
    void forget(uint64_t file_key);

    // FileObject -> name, from event 12 (every open) and event 14 (last close).
    void on_open(uint64_t file_object, OpenFile file);
    std::optional<OpenFile> on_close(uint64_t file_object, uint64_t file_key);

    // Looks up the FileKey, then the FileObject. A FileObject match counts only for
    // the process that opened it: pointers get reused, and System's stream file
    // objects never appear in an open event, so anything else could be a stale entry.
    // A match also binds the FileKey to the path, so System's later flushes of the
    // same file resolve too.
    std::optional<std::wstring> resolve(uint64_t file_key, uint64_t file_object, uint32_t pid);

    void on_rename(uint64_t file_key, uint64_t file_object, const std::wstring& dos_path);

    // The open entry for this FileObject, if `pid` is the process that opened it.
    const OpenFile* find_open(uint64_t file_object, uint32_t pid) const;

private:
    struct NamedFile {
        std::wstring path;
        uint64_t bound_object = 0;  // 0 means the name came from a NameCreate event
    };

    bool allow_key_binding_;
    std::unordered_map<uint64_t, NamedFile> names_;
    std::unordered_map<uint64_t, OpenFile> open_files_;
};

struct KeyPath {
    std::wstring path;
    bool complete = false;  // false: only the tail is known, the parent was never seen
};

class RegistryKeyTracker {
public:
    // From CreateKey/OpenKey events. Paths stay in kernel form (\REGISTRY\...).
    void on_open(uint64_t base_object, uint64_t key_object, std::wstring_view base_name,
                 std::wstring_view relative_name);
    void on_close(uint64_t key_object);

    // From any event with a KeyName. Only a complete \REGISTRY\... name is accepted.
    void learn(uint64_t key_object, std::wstring_view key_name);

    std::optional<KeyPath> resolve(uint64_t key_object, std::wstring_view event_key_name) const;

private:
    std::unordered_map<uint64_t, KeyPath> keys_;
};

}  // namespace tp
