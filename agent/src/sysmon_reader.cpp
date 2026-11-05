#include "sysmon_reader.h"

// clang-format off
#include <windows.h>
#include <sddl.h>
#include <winevt.h>
// clang-format on

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <exception>
#include <iostream>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "access_rights.h"
#include "path_utils.h"
#include "text.h"

namespace tp {

namespace {

constexpr wchar_t kChannel[] = L"Microsoft-Windows-Sysmon/Operational";
constexpr wchar_t kQuery[] = L"*[System[(EventID=3 or EventID=10 or EventID=12 or EventID=13)]]";

constexpr uint64_t kNetworkConnect = 3;
constexpr uint64_t kProcessAccess = 10;
constexpr uint64_t kRegistryCreateDelete = 12;
constexpr uint64_t kRegistryValueSet = 13;

constexpr DWORD kBatchSize = 64;
constexpr DWORD kNextTimeoutMs = 100;
constexpr DWORD kPollMs = 200;

// ETW start events arrive about a second late, so a process can be missing from the
// table when its Sysmon event is read. Longer than the ETW flush timer.
constexpr ULONGLONG kHoldMs = 2000;
constexpr size_t kMaxHeld = 10000;

constexpr size_t kMaxErrorsKept = 5;

// One render context covers every event. A field an event doesn't have comes back as
// EvtVarTypeNull, so the positions don't depend on the Sysmon schema version.
enum Field {
    kEventId,
    kSystemTime,
    kUtcTime,
    kProcessId,
    kImage,
    kUser,
    kRegistryOperation,
    kTargetObject,
    kInitiated,
    kDestinationIp,
    kDestinationPort,
    kSourceProcessId,
    kSourceImage,
    kSourceUser,
    kTargetProcessId,
    kTargetImage,
    kGrantedAccess,
    kFieldCount
};

const wchar_t* const kFieldPaths[kFieldCount] = {
    L"Event/System/EventID",
    L"Event/System/TimeCreated/@SystemTime",
    L"Event/EventData/Data[@Name='UtcTime']",
    L"Event/EventData/Data[@Name='ProcessId']",
    L"Event/EventData/Data[@Name='Image']",
    L"Event/EventData/Data[@Name='User']",
    L"Event/EventData/Data[@Name='EventType']",
    L"Event/EventData/Data[@Name='TargetObject']",
    L"Event/EventData/Data[@Name='Initiated']",
    L"Event/EventData/Data[@Name='DestinationIp']",
    L"Event/EventData/Data[@Name='DestinationPort']",
    L"Event/EventData/Data[@Name='SourceProcessId']",
    L"Event/EventData/Data[@Name='SourceImage']",
    L"Event/EventData/Data[@Name='SourceUser']",
    L"Event/EventData/Data[@Name='TargetProcessId']",
    L"Event/EventData/Data[@Name='TargetImage']",
    L"Event/EventData/Data[@Name='GrantedAccess']",
};

struct EvtCloser {
    void operator()(void* handle) const {
        if (handle) EvtClose(handle);
    }
};
using EvtPtr = std::unique_ptr<void, EvtCloser>;

// "EvtNext failed, error 5: Access is denied."
std::string describe_error(const char* action, DWORD code) {
    std::string message = std::string(action) + " failed, error " + std::to_string(code);

    char system_text[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
                   system_text, sizeof(system_text), nullptr);
    std::string detail = system_text;
    while (!detail.empty() && (detail.back() == '\r' || detail.back() == '\n')) detail.pop_back();
    if (!detail.empty()) message += ": " + detail;
    return message;
}

std::wstring text_of(const EVT_VARIANT& value) {
    if (value.Type == EvtVarTypeString && value.StringVal) return value.StringVal;
    if (value.Type == EvtVarTypeAnsiString && value.AnsiStringVal) {
        return to_wide(value.AnsiStringVal);
    }
    return {};
}

std::optional<std::wstring> optional_text(const EVT_VARIANT& value) {
    std::wstring text = text_of(value);
    if (text.empty()) return std::nullopt;
    return text;
}

// The event log may render these as numbers or as text, depending on the manifest.
std::optional<uint64_t> number_of(const EVT_VARIANT& value) {
    switch (value.Type) {
        case EvtVarTypeByte:
            return value.ByteVal;
        case EvtVarTypeUInt16:
            return value.UInt16Val;
        case EvtVarTypeUInt32:
        case EvtVarTypeHexInt32:
            return value.UInt32Val;
        case EvtVarTypeUInt64:
        case EvtVarTypeHexInt64:
            return value.UInt64Val;
        default:
            break;
    }
    const std::wstring text = text_of(value);
    if (text.empty()) return std::nullopt;
    wchar_t* end = nullptr;
    const uint64_t parsed = std::wcstoull(text.c_str(), &end, 0);  // base 0 accepts "0x1010"
    if (end == text.c_str() || *end != L'\0') return std::nullopt;
    return parsed;
}

bool is_true(const EVT_VARIANT& value) {
    if (value.Type == EvtVarTypeBoolean) return value.BooleanVal != FALSE;
    return iequals(text_of(value), L"true");
}

// Sysmon's UtcTime, "2026-11-05 10:15:00.123", is when the action happened. The log's
// own timestamp is when Sysmon wrote the event.
uint64_t parse_utc_time(const std::wstring& text) {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, millisecond = 0;
    if (swscanf_s(text.c_str(), L"%d-%d-%d %d:%d:%d.%d", &year, &month, &day, &hour, &minute,
                  &second, &millisecond) != 7) {
        return 0;
    }
    SYSTEMTIME utc{};
    utc.wYear = static_cast<WORD>(year);
    utc.wMonth = static_cast<WORD>(month);
    utc.wDay = static_cast<WORD>(day);
    utc.wHour = static_cast<WORD>(hour);
    utc.wMinute = static_cast<WORD>(minute);
    utc.wSecond = static_cast<WORD>(second);
    utc.wMilliseconds = static_cast<WORD>(millisecond);

    FILETIME time{};
    if (!SystemTimeToFileTime(&utc, &time)) return 0;
    return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

uint64_t timestamp_of(const EVT_VARIANT* values) {
    if (const uint64_t parsed = parse_utc_time(text_of(values[kUtcTime]))) return parsed;
    if (values[kSystemTime].Type == EvtVarTypeFileTime) return values[kSystemTime].FileTimeVal;

    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    return (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
}

std::wstring image_or_unknown(const EVT_VARIANT& value) {
    std::wstring image = text_of(value);
    return image.empty() ? L"unknown" : image;
}

// The table's details are used only if its image matches Sysmon's, so a reused pid
// can't give an event another process's parent or command line.
bool same_image(std::wstring_view table_image, std::wstring_view sysmon_image) {
    if (iequals(table_image, sysmon_image)) return true;
    // A protected process can't be opened, so the snapshot holds only its file name.
    if (table_image.find(L'\\') != std::wstring_view::npos) return false;
    const size_t slash = sysmon_image.rfind(L'\\');
    return slash != std::wstring_view::npos && iequals(table_image, sysmon_image.substr(slash + 1));
}

}  // namespace

struct SysmonReader::Impl {
    struct Held {
        PendingEvent event;
        std::optional<std::wstring> table_sid;
        ULONGLONG deadline = 0;
    };

    Impl(uint32_t own, const ProcessTable& table, Counters& event_counters, Sink event_sink)
        : own_pid(own), processes(table), counters(event_counters), sink(std::move(event_sink)) {
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        // Manual reset, and starts signalled so the first pass reads what is waiting.
        signal_event = CreateEventW(nullptr, TRUE, TRUE, nullptr);
        if (!stop_event || !signal_event) throw std::runtime_error("cannot create Sysmon events");

        render_context.reset(EvtCreateRenderContext(kFieldCount,
                                                    const_cast<LPCWSTR*>(kFieldPaths),
                                                    EvtRenderContextValues));
        if (!render_context) {
            throw std::runtime_error("cannot create the event render context, error " +
                                     std::to_string(GetLastError()));
        }

        subscribe();
        if (!subscription) {
            throw std::runtime_error("cannot subscribe to the Sysmon log, error " +
                                     std::to_string(GetLastError()));
        }
    }

    ~Impl() {
        stop();
        subscription.reset();  // before the signal event it uses
        if (stop_event) CloseHandle(stop_event);
        if (signal_event) CloseHandle(signal_event);
    }

    void subscribe() {
        subscription.reset(EvtSubscribe(nullptr, signal_event, kChannel, kQuery, nullptr, nullptr,
                                        nullptr, EvtSubscribeToFutureEvents));
    }

    void stop() {
        if (stop_event) SetEvent(stop_event);
        if (thread.joinable()) thread.join();
    }

    void run() {
        const HANDLE handles[] = {stop_event, signal_event};
        for (;;) {
            const DWORD wait = WaitForMultipleObjects(2, handles, FALSE, kPollMs);
            if (wait != WAIT_TIMEOUT && wait != WAIT_OBJECT_0 + 1) break;
            // A timeout only releases held events, unless a lost subscription needs replacing.
            if (wait == WAIT_OBJECT_0 + 1 || !subscription) {
                // Reset before reading: an event arriving during the read signals again.
                ResetEvent(signal_event);
                read_available();
            }
            release_held(false);
        }
        read_available();
        release_held(true);
    }

    void record_error(const std::string& message) {
        ++counters.sysmon_errors;
        for (SysmonError& known : errors) {
            if (known.message == message) {
                ++known.count;
                return;
            }
        }
        if (errors.size() < kMaxErrorsKept) {
            errors.push_back({message, 1});
            std::cerr << "Sysmon error: " << message << "\n";
        }
    }

    void read_available() {
        if (!subscription) {
            subscribe();
            if (!subscription) record_error(describe_error("EvtSubscribe", GetLastError()));
            return;
        }
        for (;;) {
            EVT_HANDLE events[kBatchSize];
            DWORD returned = 0;
            if (!EvtNext(subscription.get(), kBatchSize, events, kNextTimeoutMs, 0, &returned)) {
                const DWORD error = GetLastError();
                // An empty subscription can answer ERROR_INVALID_OPERATION as well as
                // ERROR_NO_MORE_ITEMS. Neither means anything went wrong.
                if (error != ERROR_NO_MORE_ITEMS && error != ERROR_TIMEOUT &&
                    error != ERROR_INVALID_OPERATION) {
                    // The subscription fell behind or the service restarted. Anything
                    // missed is gone, so this is counted and shown in the summary.
                    record_error(describe_error("EvtNext", error));
                    subscribe();
                }
                return;
            }
            for (DWORD i = 0; i < returned; ++i) {
                const EvtPtr event(events[i]);
                try {
                    handle_event(event.get());  // one bad event costs one event
                } catch (const std::exception& error) {
                    record_error(error.what());
                } catch (...) {
                    record_error("unknown error while reading an event");
                }
            }
        }
    }

    const EVT_VARIANT* render(EVT_HANDLE event) {
        DWORD used = 0;
        DWORD property_count = 0;
        const DWORD size = static_cast<DWORD>(render_buffer.size());
        if (!EvtRender(render_context.get(), event, EvtRenderEventValues, size,
                       render_buffer.data(), &used, &property_count)) {
            const DWORD error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER) {
                throw std::runtime_error(describe_error("EvtRender", error));
            }
            render_buffer.resize(used);
            if (!EvtRender(render_context.get(), event, EvtRenderEventValues, used,
                           render_buffer.data(), &used, &property_count)) {
                throw std::runtime_error(describe_error("EvtRender", GetLastError()));
            }
        }
        if (property_count != kFieldCount) throw std::runtime_error("unexpected field count");
        return reinterpret_cast<const EVT_VARIANT*>(render_buffer.data());
    }

    void handle_event(EVT_HANDLE raw_event) {
        const EVT_VARIANT* values = render(raw_event);
        ++counters.sysmon_read;

        const std::optional<uint64_t> event_id = number_of(values[kEventId]);
        if (!event_id) throw std::runtime_error("event without an ID");

        Held held;
        held.event.source = "sysmon";
        held.event.filetime_utc = timestamp_of(values);

        bool mapped = false;
        switch (*event_id) {
            case kNetworkConnect:
                mapped = map_network(values, held.event);
                break;
            case kProcessAccess:
                mapped = map_process_access(values, held.event);
                break;
            case kRegistryCreateDelete:
            case kRegistryValueSet:
                mapped = map_registry(*event_id, values, held.event);
                break;
            default:
                break;
        }
        if (!mapped) {
            ++counters.sysmon_skipped;
            return;
        }
        if (held.event.pid == own_pid) {
            ++counters.own_dropped;
            return;
        }

        if (fill_from_table(held)) {
            emit(held);
        } else if (held_events.size() >= kMaxHeld) {
            ++counters.sysmon_no_process_details;
            emit(held);
        } else {
            held.deadline = GetTickCount64() + kHoldMs;
            held_events.push_back(std::move(held));
        }
    }

    // Initiated=false is an inbound connection, where Sysmon's destination is this
    // machine. The network zone is about what a process connects out to.
    static bool map_network(const EVT_VARIANT* values, PendingEvent& event) {
        const auto pid = number_of(values[kProcessId]);
        const auto port = number_of(values[kDestinationPort]);
        std::optional<std::wstring> ip = optional_text(values[kDestinationIp]);
        if (!is_true(values[kInitiated]) || !pid || !port || !ip) return false;

        event.event_type = "network_connect";
        event.pid = static_cast<uint32_t>(*pid);
        event.image = image_or_unknown(values[kImage]);
        event.user = optional_text(values[kUser]);
        event.dest_ip = std::move(ip);
        event.dest_port = static_cast<uint16_t>(*port);
        return true;
    }

    // `pid` and `process` are the process doing the access, `target` the one accessed.
    static bool map_process_access(const EVT_VARIANT* values, PendingEvent& event) {
        const auto pid = number_of(values[kSourceProcessId]);
        const auto target_pid = number_of(values[kTargetProcessId]);
        const auto mask = number_of(values[kGrantedAccess]);
        if (!pid || !target_pid || !mask) return false;

        event.event_type = "process_access";
        event.pid = static_cast<uint32_t>(*pid);
        event.image = image_or_unknown(values[kSourceImage]);
        event.user = optional_text(values[kSourceUser]);
        event.target_pid = static_cast<uint32_t>(*target_pid);
        event.path = optional_text(values[kTargetImage]);

        char hex[16];
        std::snprintf(hex, sizeof(hex), "0x%x", static_cast<unsigned int>(*mask));
        event.access_mask = hex;
        event.access_rights = decode_process_access(static_cast<uint32_t>(*mask));
        return true;
    }

    // ID 12 covers create and delete. A created key has no value yet, so it isn't a
    // write, and sysmon-modular excludes CreateKey anyway.
    static bool map_registry(uint64_t event_id, const EVT_VARIANT* values, PendingEvent& event) {
        const auto pid = number_of(values[kProcessId]);
        std::optional<std::wstring> key = optional_text(values[kTargetObject]);
        if (!pid || !key) return false;

        if (event_id == kRegistryValueSet) {
            event.event_type = "registry_set";
        } else if (istarts_with(text_of(values[kRegistryOperation]), L"Delete")) {
            event.event_type = "registry_delete";
        } else {
            return false;
        }
        event.pid = static_cast<uint32_t>(*pid);
        event.image = image_or_unknown(values[kImage]);
        event.user = optional_text(values[kUser]);
        event.registry_key = std::move(key);
        return true;
    }

    bool fill_from_table(Held& held) const {
        const std::optional<ProcessInfo> info = processes.snapshot(held.event.pid);
        if (!info || !same_image(info->image, held.event.image)) return false;
        held.event.ppid = info->ppid;
        held.event.cmdline = info->cmdline;
        if (!held.event.user) held.event.user = info->user;
        held.table_sid = info->sid;
        return true;
    }

    void release_held(bool everything) {
        const ULONGLONG now = GetTickCount64();
        for (auto it = held_events.begin(); it != held_events.end();) {
            const bool filled = fill_from_table(*it);
            if (filled || everything || now >= it->deadline) {
                // After the wait, Sysmon's own image and user stand: ppid is 0 and
                // cmdline is null, which the contract allows.
                if (!filled) ++counters.sysmon_no_process_details;
                emit(*it);
                it = held_events.erase(it);
            } else {
                ++it;
            }
        }
    }

    void emit(Held& held) {
        PendingEvent& event = held.event;
        if (event.registry_key) {
            // The event's own user is checked first, because the process has often
            // exited by now, and an HKCU write must not depend on the table.
            std::optional<std::wstring> sid = sid_for_account(event.user);
            if (!sid) sid = held.table_sid;
            event.registry_key = normalize_sysmon_registry_key(*event.registry_key, sid);
        }
        sink(std::move(event));
    }

    // Cached because account lookups are slow and the same few accounts repeat.
    std::optional<std::wstring> sid_for_account(const std::optional<std::wstring>& account) {
        if (!account) return std::nullopt;
        const auto found = sid_cache.find(*account);
        if (found != sid_cache.end()) return found->second;

        BYTE sid[SECURITY_MAX_SID_SIZE];
        DWORD sid_size = sizeof(sid);
        wchar_t domain[256];
        DWORD domain_size = ARRAYSIZE(domain);
        SID_NAME_USE use{};
        std::optional<std::wstring> result;
        if (LookupAccountNameW(nullptr, account->c_str(), sid, &sid_size, domain, &domain_size,
                               &use)) {
            LPWSTR sid_text = nullptr;
            if (ConvertSidToStringSidW(sid, &sid_text)) {
                result = sid_text;
                LocalFree(sid_text);
            }
        }
        sid_cache.emplace(*account, result);
        return result;
    }

    const uint32_t own_pid;
    const ProcessTable& processes;
    Counters& counters;
    Sink sink;

    HANDLE stop_event = nullptr;
    HANDLE signal_event = nullptr;
    EvtPtr render_context;
    EvtPtr subscription;
    std::vector<BYTE> render_buffer = std::vector<BYTE>(64 * 1024);
    std::list<Held> held_events;
    std::unordered_map<std::wstring, std::optional<std::wstring>> sid_cache;
    std::vector<SysmonError> errors;
    std::thread thread;
};

SysmonReader::SysmonReader(uint32_t own_pid, const ProcessTable& processes, Counters& counters,
                           Sink sink)
    : impl_(std::make_unique<Impl>(own_pid, processes, counters, std::move(sink))) {}

SysmonReader::~SysmonReader() = default;

void SysmonReader::start() {
    impl_->thread = std::thread([impl = impl_.get()] { impl->run(); });
}

void SysmonReader::stop() {
    impl_->stop();
}

const std::vector<SysmonError>& SysmonReader::errors() const {
    return impl_->errors;
}

}  // namespace tp
