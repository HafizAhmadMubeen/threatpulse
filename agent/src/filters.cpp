#include "filters.h"

#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "text.h"

namespace tp {

namespace {

std::vector<std::wstring> read_prefixes(const nlohmann::json& config, const char* key) {
    std::vector<std::wstring> prefixes;
    for (const auto& item : config.at(key)) {
        const std::string value = item.get<std::string>();
        // An empty prefix would match everything and silently blind the agent.
        if (value.empty()) {
            throw std::runtime_error(std::string("empty entry in ") + key);
        }
        prefixes.push_back(to_wide(value));
    }
    return prefixes;
}

bool matches_any(std::wstring_view text, const std::vector<std::wstring>& prefixes) {
    for (const auto& prefix : prefixes) {
        if (istarts_with(text, prefix)) return true;
    }
    return false;
}

}  // namespace

Filters Filters::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) throw std::runtime_error("cannot open filter config: " + path.string());

    try {
        const nlohmann::json config = nlohmann::json::parse(file);
        Filters filters;
        filters.path_prefixes_ = read_prefixes(config, "ignore_path_prefixes");
        filters.process_prefixes_ = read_prefixes(config, "ignore_process_prefixes");
        filters.registry_prefixes_ = read_prefixes(config, "ignore_registry_prefixes");
        return filters;
    } catch (const nlohmann::json::exception& error) {
        throw std::runtime_error("invalid filter config: " + std::string(error.what()));
    }
}

bool Filters::ignores_path(std::wstring_view path) const {
    return matches_any(path, path_prefixes_);
}

bool Filters::ignores_process(std::wstring_view image) const {
    return matches_any(image, process_prefixes_);
}

bool Filters::ignores_registry(std::wstring_view key) const {
    return matches_any(key, registry_prefixes_);
}

}  // namespace tp
