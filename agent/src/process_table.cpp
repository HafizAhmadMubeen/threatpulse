#include "process_table.h"

// clang-format off
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <sddl.h>
// clang-format on

#include <memory>
#include <utility>
#include <vector>

namespace tp {

namespace {

constexpr ULONGLONG kKeepExitedMs = 60 * 1000;
constexpr ULONGLONG kSweepEveryMs = 30 * 1000;
constexpr ULONG kMaxCommandLineBytes = 1024 * 1024;
constexpr uint64_t kCreateTimeTolerance = 100000;  // 10 ms in FILETIME units

struct HandleCloser {
    void operator()(HANDLE handle) const {
        if (handle) CloseHandle(handle);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

// PROCESS_QUERY_LIMITED_INFORMATION is the smallest right that allows these
// reads. The agent never opens a process with rights that could change it.
UniqueHandle open_for_query(uint32_t pid) {
    return UniqueHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
}

std::optional<std::wstring> query_image(HANDLE process) {
    wchar_t buffer[32768];
    DWORD size = ARRAYSIZE(buffer);
    if (!QueryFullProcessImageNameW(process, 0, buffer, &size)) return std::nullopt;
    return std::wstring(buffer, size);
}

std::optional<std::wstring> query_cmdline(HANDLE process) {
    // ProcessCommandLineInformation is missing from the public enum in winternl.h.
    const auto info_class = static_cast<PROCESSINFOCLASS>(60);

    ULONG needed = 0;
    NtQueryInformationProcess(process, info_class, nullptr, 0, &needed);
    if (needed == 0 || needed > kMaxCommandLineBytes) return std::nullopt;

    std::vector<BYTE> buffer(needed);
    if (NtQueryInformationProcess(process, info_class, buffer.data(), needed, &needed) < 0) {
        return std::nullopt;
    }
    const auto* text = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
    if (!text->Buffer || text->Length == 0) return std::nullopt;
    return std::wstring(text->Buffer, text->Length / sizeof(wchar_t));
}

uint64_t to_u64(const FILETIME& time) {
    return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

// Windows reuses pids. Reading another process's command line would be worse
// than reporting null, so check that this is the process from the event.
bool is_same_process(HANDLE process, uint64_t create_time) {
    if (create_time == 0) return true;  // the event had no usable CreateTime
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return false;
    const uint64_t actual = to_u64(created);
    const uint64_t difference = actual > create_time ? actual - create_time : create_time - actual;
    return difference <= kCreateTimeTolerance;
}

}  // namespace

const ResolvedUser* UserResolver::resolve(const void* sid, size_t size) {
    if (!sid || size == 0) return nullptr;

    std::string key(static_cast<const char*>(sid), size);
    const auto found = cache_.find(key);
    if (found != cache_.end()) return &found->second;

    PSID mutable_sid = const_cast<void*>(sid);
    if (!IsValidSid(mutable_sid)) return nullptr;

    LPWSTR sid_text = nullptr;
    if (!ConvertSidToStringSidW(mutable_sid, &sid_text)) return nullptr;
    ResolvedUser user;
    user.sid = sid_text;
    LocalFree(sid_text);

    wchar_t name[256];
    wchar_t domain[256];
    DWORD name_size = ARRAYSIZE(name);
    DWORD domain_size = ARRAYSIZE(domain);
    SID_NAME_USE use{};
    if (LookupAccountSidW(nullptr, mutable_sid, name, &name_size, domain, &domain_size, &use)) {
        user.account = std::wstring(domain) + L"\\" + name;
    } else {
        user.account = user.sid;
    }

    return &cache_.emplace(std::move(key), std::move(user)).first->second;
}

ProcessTable::ProcessTable(const PathMapper& paths) : paths_(paths) {}

void ProcessTable::read_identity(HANDLE process, ProcessInfo& info) {
    if (auto cmdline = query_cmdline(process)) info.cmdline = std::move(cmdline);

    HANDLE token_handle = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token_handle)) return;
    const UniqueHandle token(token_handle);

    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
    if (needed == 0) return;
    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), needed, &needed)) return;

    const auto* token_user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    const ResolvedUser* user =
        users_.resolve(token_user->User.Sid, GetLengthSid(token_user->User.Sid));
    if (user) {
        info.user = user->account;
        info.sid = user->sid;
    }
}

void ProcessTable::seed_from_snapshot() {
    // This API reports failure with INVALID_HANDLE_VALUE, which must not be closed.
    const HANDLE raw_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (raw_snapshot == INVALID_HANDLE_VALUE) return;
    const UniqueHandle snapshot(raw_snapshot);

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Process32FirstW(snapshot.get(), &entry); more;
         more = Process32NextW(snapshot.get(), &entry)) {
        if (entry.th32ProcessID == 0) continue;  // System Idle Process

        ProcessInfo info;
        info.image = entry.szExeFile;  // fallback when the process cannot be opened
        info.ppid = entry.th32ParentProcessID;
        if (const UniqueHandle process = open_for_query(entry.th32ProcessID)) {
            if (auto image = query_image(process.get())) info.image = std::move(*image);
            read_identity(process.get(), info);
        }
        processes_[entry.th32ProcessID] = std::move(info);
    }
}

const ProcessInfo& ProcessTable::on_start(uint32_t pid, uint32_t ppid, std::wstring image,
                                          uint64_t create_time, const ResolvedUser* creator) {
    sweep();

    ProcessInfo info;
    info.image = std::move(image);
    info.ppid = ppid;
    info.started_before_agent = false;
    if (const UniqueHandle process = open_for_query(pid)) {
        if (is_same_process(process.get(), create_time)) read_identity(process.get(), info);
    }
    if (!info.user && creator) {
        info.user = creator->account;
        info.sid = creator->sid;
    }
    return processes_[pid] = std::move(info);  // overwrites any entry from a reused pid
}

const ProcessInfo& ProcessTable::on_stop(uint32_t pid) {
    ProcessInfo& info = entry(pid, nullptr);
    info.exited_tick = GetTickCount64();
    return info;
}

const ProcessInfo& ProcessTable::lookup(uint32_t pid, const ResolvedUser* event_user) {
    return entry(pid, event_user);
}

ProcessInfo& ProcessTable::entry(uint32_t pid, const ResolvedUser* event_user) {
    auto found = processes_.find(pid);
    if (found == processes_.end()) {
        found = processes_.emplace(pid, read_live(pid)).first;
    }
    ProcessInfo& info = found->second;
    if (!info.user && event_user) {
        info.user = event_user->account;
        info.sid = event_user->sid;
    }
    return info;
}

ProcessInfo ProcessTable::read_live(uint32_t pid) {
    ProcessInfo info;
    info.image = pid == 4 ? L"System" : L"unknown";
    if (const UniqueHandle process = open_for_query(pid)) {
        if (auto image = query_image(process.get())) info.image = std::move(*image);
        read_identity(process.get(), info);
    }
    return info;
}

void ProcessTable::sweep() {
    const ULONGLONG now = GetTickCount64();
    if (now - last_sweep_tick_ < kSweepEveryMs) return;
    last_sweep_tick_ = now;

    for (auto it = processes_.begin(); it != processes_.end();) {
        const ULONGLONG exited = it->second.exited_tick;
        if (exited != 0 && now - exited > kKeepExitedMs) {
            it = processes_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace tp
