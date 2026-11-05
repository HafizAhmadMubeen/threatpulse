#include "path_utils.h"

#include <windows.h>

#include <algorithm>

#include "text.h"

namespace tp {

namespace {

constexpr std::wstring_view kNtPrefix = L"\\??\\";
constexpr std::wstring_view kWin32Prefix = L"\\\\?\\";
constexpr std::wstring_view kSystemRoot = L"\\SystemRoot\\";
constexpr std::wstring_view kMup = L"\\Device\\Mup\\";
constexpr std::wstring_view kMachine = L"\\REGISTRY\\MACHINE";
constexpr std::wstring_view kUsers = L"\\REGISTRY\\USER";

// True when `text` is `prefix` exactly, or `prefix` followed by a backslash.
// This stops HarddiskVolume1 from matching HarddiskVolume10.
bool is_path_prefix(std::wstring_view text, std::wstring_view prefix) {
    return istarts_with(text, prefix) &&
           (text.size() == prefix.size() || text[prefix.size()] == L'\\');
}

}  // namespace

PathMapper::PathMapper() {
    wchar_t letter[] = L"A:";
    wchar_t target[1024];
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        letter[0] = drive;
        if (QueryDosDeviceW(letter, target, ARRAYSIZE(target)) == 0) continue;
        const std::wstring device(target);
        // SUBST drives point at \??\ paths, not devices. Skip them.
        if (istarts_with(device, L"\\Device\\")) devices_.emplace_back(device, letter);
    }

    wchar_t windows_dir[MAX_PATH];
    const UINT length = GetWindowsDirectoryW(windows_dir, ARRAYSIZE(windows_dir));
    windows_dir_.assign(windows_dir, length);
}

std::wstring PathMapper::to_dos(std::wstring_view nt_path) const {
    if (istarts_with(nt_path, kNtPrefix)) return std::wstring(nt_path.substr(kNtPrefix.size()));
    if (istarts_with(nt_path, kWin32Prefix)) return std::wstring(nt_path.substr(kWin32Prefix.size()));

    if (istarts_with(nt_path, kSystemRoot)) {
        return windows_dir_ + L"\\" + std::wstring(nt_path.substr(kSystemRoot.size()));
    }
    if (istarts_with(nt_path, kMup)) {
        return L"\\\\" + std::wstring(nt_path.substr(kMup.size()));
    }
    for (const auto& [device, drive] : devices_) {
        if (is_path_prefix(nt_path, device)) {
            return drive + std::wstring(nt_path.substr(device.size()));
        }
    }
    return std::wstring(nt_path);  // unknown device: keep the raw name, never guess
}

std::wstring normalize_registry_key(std::wstring_view kernel_key,
                                    const std::optional<std::wstring>& user_sid) {
    if (is_path_prefix(kernel_key, kMachine)) {
        return L"HKLM" + std::wstring(kernel_key.substr(kMachine.size()));
    }
    if (!is_path_prefix(kernel_key, kUsers) || kernel_key.size() <= kUsers.size() + 1) {
        return std::wstring(kernel_key);
    }

    const std::wstring_view after_root = kernel_key.substr(kUsers.size() + 1);
    const size_t slash = after_root.find(L'\\');
    const std::wstring_view sid = after_root.substr(0, slash);
    const std::wstring_view rest =
        slash == std::wstring_view::npos ? std::wstring_view{} : after_root.substr(slash);

    if (user_sid && iequals(sid, *user_sid)) return L"HKCU" + std::wstring(rest);
    return L"HKU\\" + std::wstring(sid) + std::wstring(rest);
}

}  // namespace tp
