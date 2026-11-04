// Noise filters loaded from config/filters.json.
//
// Process events are never filtered: dropping a process_start would break the
// process trees used for labelling (PHASES.md step 2.4). Process filters only
// remove that process's file and registry events, and ignores_process() is only
// half of that rule: JsonlWriter also requires a verified Microsoft signature.
#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace tp {

class Filters {
public:
    // Throws std::runtime_error when the file is missing or invalid.
    static Filters load(const std::filesystem::path& path);

    bool ignores_path(std::wstring_view path) const;
    bool ignores_process(std::wstring_view image) const;
    bool ignores_registry(std::wstring_view key) const;

private:
    std::vector<std::wstring> path_prefixes_;
    std::vector<std::wstring> process_prefixes_;
    std::vector<std::wstring> registry_prefixes_;
};

}  // namespace tp
