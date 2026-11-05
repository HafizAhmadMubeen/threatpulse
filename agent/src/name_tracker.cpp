#include "name_tracker.h"

#include <utility>

#include "text.h"

namespace tp {

namespace {

// Safety cap on memory. Close and delete events normally keep the maps small. If
// the cap is reached, names are lost and later events count as unresolved.
constexpr size_t kMaxEntries = 500000;
constexpr std::wstring_view kRegistryRoot = L"\\REGISTRY\\";

template <typename Map>
void enforce_cap(Map& map) {
    if (map.size() >= kMaxEntries) map.clear();
}

std::wstring join(std::wstring_view base, std::wstring_view child) {
    if (child.empty()) return std::wstring(base);
    if (base.empty()) return std::wstring(child);
    return std::wstring(base) + L"\\" + std::wstring(child);
}

}  // namespace

FileNameTracker::FileNameTracker(bool allow_key_binding) : allow_key_binding_(allow_key_binding) {}

void FileNameTracker::remember(uint64_t file_key, std::wstring dos_path) {
    enforce_cap(names_);
    names_[file_key] = NamedFile{std::move(dos_path), 0};
}

void FileNameTracker::forget(uint64_t file_key) {
    names_.erase(file_key);
}

void FileNameTracker::on_open(uint64_t file_object, OpenFile file) {
    enforce_cap(open_files_);
    open_files_[file_object] = std::move(file);
}

std::optional<OpenFile> FileNameTracker::on_close(uint64_t file_object, uint64_t file_key) {
    // A binding is only as trustworthy as the FileObject that made it.
    const auto named = names_.find(file_key);
    if (named != names_.end() && named->second.bound_object == file_object) {
        names_.erase(named);
    }

    const auto open = open_files_.find(file_object);
    if (open == open_files_.end()) return std::nullopt;
    std::optional<OpenFile> closed = std::move(open->second);
    open_files_.erase(open);
    return closed;
}

std::optional<std::wstring> FileNameTracker::resolve(uint64_t file_key, uint64_t file_object,
                                                     uint32_t pid) {
    const auto named = names_.find(file_key);
    if (named != names_.end()) return named->second.path;

    const OpenFile* open = find_open(file_object, pid);
    if (!open) return std::nullopt;

    if (allow_key_binding_ && file_key != 0) {
        enforce_cap(names_);
        names_[file_key] = NamedFile{open->path, file_object};
    }
    return open->path;
}

void FileNameTracker::on_rename(uint64_t file_key, uint64_t file_object,
                                const std::wstring& dos_path) {
    // Update both maps, or a later write through this handle would report the old name.
    const auto open = open_files_.find(file_object);
    if (open != open_files_.end()) open->second.path = dos_path;

    const auto named = names_.find(file_key);
    if (named != names_.end()) {
        named->second.path = dos_path;
    } else if (allow_key_binding_ && file_key != 0) {
        enforce_cap(names_);
        names_[file_key] = NamedFile{dos_path, file_object};
    }
}

const OpenFile* FileNameTracker::find_open(uint64_t file_object, uint32_t pid) const {
    const auto open = open_files_.find(file_object);
    if (open == open_files_.end() || open->second.opener_pid != pid) return nullptr;
    return &open->second;
}

void RegistryKeyTracker::on_open(uint64_t base_object, uint64_t key_object,
                                 std::wstring_view base_name,
                                 std::wstring_view relative_name) {
    enforce_cap(keys_);

    if (istarts_with(relative_name, kRegistryRoot)) {
        keys_[key_object] = KeyPath{std::wstring(relative_name), true};
        return;
    }
    if (istarts_with(base_name, kRegistryRoot)) {
        keys_[key_object] = KeyPath{join(base_name, relative_name), true};
        return;
    }
    const auto base = keys_.find(base_object);
    if (base != keys_.end()) {
        KeyPath path{join(base->second.path, relative_name), base->second.complete};
        keys_[key_object] = std::move(path);
        return;
    }
    // The parent was opened before the trace started. Keep what is known, marked
    // incomplete, because the tail can still show that a key looks like a Run key.
    if (!relative_name.empty()) {
        keys_[key_object] = KeyPath{std::wstring(relative_name), false};
        return;
    }
    // Nothing is known. Remove any stale entry left by a reused KeyObject, so it
    // cannot give this key the wrong path.
    keys_.erase(key_object);
}

void RegistryKeyTracker::on_close(uint64_t key_object) {
    keys_.erase(key_object);
}

void RegistryKeyTracker::learn(uint64_t key_object, std::wstring_view key_name) {
    if (!istarts_with(key_name, kRegistryRoot)) return;
    enforce_cap(keys_);
    keys_[key_object] = KeyPath{std::wstring(key_name), true};
}

std::optional<KeyPath> RegistryKeyTracker::resolve(uint64_t key_object,
                                                   std::wstring_view event_key_name) const {
    if (istarts_with(event_key_name, kRegistryRoot)) {
        return KeyPath{std::wstring(event_key_name), true};
    }
    const auto found = keys_.find(key_object);
    if (found != keys_.end()) return found->second;
    return std::nullopt;
}

}  // namespace tp
