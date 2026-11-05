// Converts kernel-style names from ETW into the forms used by the Event contract.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tp {

// \Device\HarddiskVolume3\Windows\... -> C:\Windows\...
class PathMapper {
public:
    PathMapper();  // reads the drive-letter table once at startup
    std::wstring to_dos(std::wstring_view nt_path) const;

private:
    std::vector<std::pair<std::wstring, std::wstring>> devices_;  // device -> drive
    std::wstring windows_dir_;
};

// \REGISTRY\MACHINE\X -> HKLM\X
// \REGISTRY\USER\<sid>\X -> HKCU\X when <sid> is the writer's own SID, else HKU\<sid>\X
std::wstring normalize_registry_key(std::wstring_view kernel_key,
                                    const std::optional<std::wstring>& user_sid);

// Sysmon already shortens root keys. This applies the same HKCU rule to HKU\<sid>\X.
std::wstring normalize_sysmon_registry_key(std::wstring_view sysmon_key,
                                           const std::optional<std::wstring>& user_sid);

}  // namespace tp
