#include "name_tracker.h"

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

void FileNameTracker::remember(uint64_t file_key, std::wstring dos_path) {
    enforce_cap(names_);
    names_[file_key] = std::move(dos_path);
}

void FileNameTracker::forget(uint64_t file_key) {
    names_.erase(file_key);
}

std::optional<std::wstring> FileNameTracker::find(uint64_t file_key) const {
    const auto found = names_.find(file_key);
    if (found == names_.end()) return std::nullopt;
    return found->second;
}

void RegistryKeyTracker::on_open(uint64_t base_object, uint64_t key_object,
                                 std::wstring_view base_name,
                                 std::wstring_view relative_name) {
    enforce_cap(keys_);

    if (istarts_with(relative_name, kRegistryRoot)) {
        keys_[key_object] = std::wstring(relative_name);
        return;
    }
    if (istarts_with(base_name, kRegistryRoot)) {
        keys_[key_object] = join(base_name, relative_name);
        return;
    }
    const auto base = keys_.find(base_object);
    if (base != keys_.end()) {
        keys_[key_object] = join(base->second, relative_name);
        return;
    }
    // The parent key was opened before the trace started. Remove any stale entry
    // left by a reused KeyObject, so it cannot give this key the wrong path.
    keys_.erase(key_object);
}

void RegistryKeyTracker::on_close(uint64_t key_object) {
    keys_.erase(key_object);
}

std::optional<std::wstring> RegistryKeyTracker::resolve(uint64_t key_object,
                                                        std::wstring_view event_key_name) const {
    const auto found = keys_.find(key_object);
    if (found != keys_.end()) return found->second;
    if (istarts_with(event_key_name, kRegistryRoot)) return std::wstring(event_key_name);
    return std::nullopt;
}

}  // namespace tp
