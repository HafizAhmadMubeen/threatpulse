// Rebuilds names that ETW leaves out of the events we need.
//
// Kernel-File Write events carry a FileKey, not a path. Kernel-Registry
// SetValueKey events carry a KeyObject, and their KeyName is often incomplete.
// Both names appear in earlier events, so these maps remember them. An object
// opened before the agent started was never seen, so it stays unresolved.
// Only the ETW thread touches these classes, so they need no locks.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace tp {

class FileNameTracker {
public:
    void remember(uint64_t file_key, std::wstring dos_path);
    void forget(uint64_t file_key);
    std::optional<std::wstring> find(uint64_t file_key) const;

private:
    std::unordered_map<uint64_t, std::wstring> names_;
};

class RegistryKeyTracker {
public:
    // From CreateKey/OpenKey events. Paths stay in kernel form (\REGISTRY\...).
    void on_open(uint64_t base_object, uint64_t key_object, std::wstring_view base_name,
                 std::wstring_view relative_name);
    void on_close(uint64_t key_object);

    // Full \REGISTRY\... path, or nullopt when the key cannot be resolved.
    std::optional<std::wstring> resolve(uint64_t key_object, std::wstring_view event_key_name) const;

private:
    std::unordered_map<uint64_t, std::wstring> keys_;
};

}  // namespace tp
