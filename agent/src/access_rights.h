// Decodes a process access mask (Sysmon GrantedAccess) into named rights. The policy
// engine matches on these names, for example `access_includes: vm_read` (PLANNING.md 5.6).
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace tp {

inline std::vector<std::string> decode_process_access(uint32_t mask) {
    struct Right {
        uint32_t bit;
        const char* name;
    };
    // Process-specific rights, then the standard rights every object type shares.
    static constexpr Right kRights[] = {
        {0x00000001, "terminate"},
        {0x00000002, "create_thread"},
        {0x00000004, "set_session_id"},
        {0x00000008, "vm_operation"},
        {0x00000010, "vm_read"},
        {0x00000020, "vm_write"},
        {0x00000040, "dup_handle"},
        {0x00000080, "create_process"},
        {0x00000100, "set_quota"},
        {0x00000200, "set_information"},
        {0x00000400, "query_information"},
        {0x00000800, "suspend_resume"},
        {0x00001000, "query_limited_information"},
        {0x00002000, "set_limited_information"},
        {0x00010000, "delete"},
        {0x00020000, "read_control"},
        {0x00040000, "write_dac"},
        {0x00080000, "write_owner"},
        {0x00100000, "synchronize"},
    };

    std::vector<std::string> rights;
    uint32_t remaining = mask;
    for (const Right& right : kRights) {
        if ((mask & right.bit) != 0) {
            rights.emplace_back(right.name);
            remaining &= ~right.bit;
        }
    }
    // Reported rather than dropped, so an unexpected bit stays visible.
    if (remaining != 0) {
        char text[32];
        std::snprintf(text, sizeof(text), "unknown_0x%x", static_cast<unsigned int>(remaining));
        rights.emplace_back(text);
    }
    return rights;
}

}  // namespace tp
