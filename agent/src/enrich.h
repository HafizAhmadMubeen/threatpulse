// SHA-256 and signature status per process image, with a per-image cache.
// Hashing is slow, so this runs on the writer thread, never in an ETW callback.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace tp {

struct ImageInfo {
    std::optional<std::wstring> sha256;  // lowercase hex; null if the file can't be read
    bool is_signed = false;              // true only for a verified signature
    std::optional<std::wstring> signer;  // certificate display name, null unless verified
    bool microsoft_root = false;         // verified, and the chain ends at a Microsoft root
    uint64_t file_size = 0;
    uint64_t last_write = 0;
};

class Enricher {
public:
    // With `recheck`, a cached entry is recomputed if the file's size or timestamp
    // changed, so a replaced binary cannot keep the old file's result.
    const ImageInfo& get(const std::wstring& image, bool recheck);

private:
    std::unordered_map<std::wstring, ImageInfo> cache_;
};

}  // namespace tp
