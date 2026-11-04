// ThreatPulse endpoint agent: observes process, file and registry activity through
// ETW and writes Event records (PLANNING.md 5.1) to a JSONL file.
//
// The agent only observes. It changes no system setting, and the only ETW session
// it ever stops is its own, "ThreatPulse-Agent".
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "agent_event.h"
#include "etw_session.h"
#include "event_mapper.h"
#include "filters.h"
#include "jsonl_writer.h"
#include "path_utils.h"
#include "process_table.h"
#include "text.h"

namespace {

constexpr wchar_t kLabMarker[] = L"C:\\ThreatPulseLab\\LAB_VM";
constexpr wchar_t kDefaultOut[] = L"C:\\ThreatPulseLab\\logs\\events.jsonl";

// Exit codes
constexpr int kExitOk = 0;
constexpr int kExitBadArguments = 1;
constexpr int kExitNotLabVm = 2;
constexpr int kExitNotAdmin = 3;
constexpr int kExitStartupFailed = 4;
constexpr int kExitRuntimeFailed = 5;

HANDLE g_stop_requested = nullptr;
HANDLE g_shutdown_done = nullptr;

BOOL WINAPI on_console_event(DWORD type) {
    if (g_stop_requested) SetEvent(g_stop_requested);
    // Ctrl+C returns at once. For window close, logoff and shutdown, Windows ends
    // the process when this handler returns, so wait for main() to clean up.
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT && g_shutdown_done) {
        WaitForSingleObject(g_shutdown_done, 4000);
    }
    return TRUE;
}

// Best effort on a crash. The next start also clears a leftover session.
LONG WINAPI on_crash(EXCEPTION_POINTERS*) {
    tp::stop_session_by_name();
    return EXCEPTION_CONTINUE_SEARCH;
}

bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool is_lab_vm() {
    return GetFileAttributesW(kLabMarker) != INVALID_FILE_ATTRIBUTES;
}

std::filesystem::path default_config_path() {
    wchar_t exe[32768];
    const DWORD length = GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
    return std::filesystem::path(std::wstring(exe, length)).parent_path() / L"filters.json";
}

std::string make_run_id() {
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char text[32];
    std::snprintf(text, sizeof(text), "%04u%02u%02uT%02u%02u%02u", utc.wYear, utc.wMonth, utc.wDay,
                  utc.wHour, utc.wMinute, utc.wSecond);
    return text;
}

void print_usage() {
    std::wcout << L"Usage: threatpulse_agent [--out <file>] [--config <filters.json>]\n"
               << L"  --out     output file (default " << kDefaultOut << L")\n"
               << L"  --config  filter file (default: filters.json next to the program)\n"
               << L"Stop with Ctrl+C.\n";
}

void print_summary(const tp::Counters& counters, const std::optional<tp::SessionStats>& stats) {
    std::wcout << L"\nEvents written:            " << counters.written.load()
               << L"\nDropped, own process:      " << counters.own_dropped.load()
               << L"\nDropped, noise filters:    " << counters.filtered.load()
               << L"\nLost, queue full:          " << counters.queue_dropped.load()
               << L"\nHandler errors:            " << counters.callback_errors.load()
               << L"\nStarts without cmdline:    " << counters.cmdline_missing.load()
               << L"\nFile writes without path:  " << counters.unresolved_file_paths.load()
               << L"\nUnresolved registry keys:  " << counters.unresolved_registry_keys.load()
               << L"\nRenames, new path unknown: " << counters.rename_new_path_unknown.load();
    if (stats) {
        std::wcout << L"\nLost by ETW, events:       " << stats->events_lost
                   << L"\nLost by ETW, buffers:      " << stats->buffers_lost;
    } else {
        std::wcout << L"\nLost by ETW:               could not be read";
    }
    std::wcout << std::endl;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::filesystem::path out_path = kDefaultOut;
    std::filesystem::path config_path = default_config_path();

    for (int i = 1; i < argc; ++i) {
        const std::wstring argument = argv[i];
        if (argument == L"--help" || argument == L"-h") {
            print_usage();
            return kExitOk;
        }
        if ((argument == L"--out" || argument == L"--config") && i + 1 < argc) {
            (argument == L"--out" ? out_path : config_path) = argv[++i];
            continue;
        }
        std::wcerr << L"Unknown or incomplete argument: " << argument << L"\n";
        print_usage();
        return kExitBadArguments;
    }

    if (!is_lab_vm()) {
        std::wcerr << L"Refusing to start: " << kLabMarker << L" was not found.\n"
                   << L"The agent runs only inside the ThreatPulse lab VM.\n";
        return kExitNotLabVm;
    }
    if (!is_elevated()) {
        std::wcerr << L"Refusing to start: administrator rights are required for ETW.\n"
                   << L"Open PowerShell with \"Run as administrator\" and try again.\n";
        return kExitNotAdmin;
    }

    g_stop_requested = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_shutdown_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_requested || !g_shutdown_done) {
        std::wcerr << L"Could not create the stop events.\n";
        return kExitStartupFailed;
    }

    tp::Counters counters;
    std::optional<tp::Filters> filters;  // declared first: the writer holds a reference
    std::unique_ptr<tp::JsonlWriter> writer;

    try {
        filters = tp::Filters::load(config_path);
        writer = std::make_unique<tp::JsonlWriter>(make_run_id(), *filters, counters, [] {
            std::wcerr << L"Cannot write to the output file. Stopping.\n";
            SetEvent(g_stop_requested);
        });
        writer->open(out_path);
    } catch (const std::exception& error) {
        std::cerr << "Startup failed: " << error.what() << "\n";
        return kExitStartupFailed;
    }

    SetConsoleCtrlHandler(on_console_event, TRUE);
    SetUnhandledExceptionFilter(on_crash);

    // A crashed run can leave the session alive in the kernel, because ETW sessions
    // outlive the process that started them.
    if (tp::stop_session_by_name()) {
        std::wcout << L"Stopped a leftover " << tp::kSessionName << L" session.\n";
    }

    const tp::PathMapper paths;
    tp::ProcessTable processes(paths);
    processes.seed_from_snapshot();

    tp::EventMapper mapper(GetCurrentProcessId(), paths, *filters, processes, counters,
                           [&writer](tp::PendingEvent&& event) { writer->push(std::move(event)); });

    std::optional<tp::EtwSession> session;
    try {
        session.emplace(mapper, counters);
    } catch (const std::exception& error) {
        std::cerr << "Could not set up ETW: " << error.what() << "\n";
        return kExitStartupFailed;
    }

    writer->start();

    std::atomic<bool> etw_finished{false};
    std::string etw_error;
    std::thread etw_thread([&] {
        try {
            session->run();
        } catch (const std::exception& error) {
            etw_error = error.what();
        } catch (...) {
            etw_error = "unknown ETW error";
        }
        etw_finished = true;
        SetEvent(g_stop_requested);  // also covers the session ending by itself
    });

    std::wcout << L"ThreatPulse agent running. Writing to " << out_path.wstring()
               << L"\nPress Ctrl+C to stop.\n";

    WaitForSingleObject(g_stop_requested, INFINITE);
    std::wcout << L"Stopping...\n";

    const std::optional<tp::SessionStats> stats = session->query_stats();

    // stop() has no effect if Ctrl+C arrives before run() has registered the
    // session, so keep calling it until the ETW thread has really finished.
    while (!etw_finished) {
        session->stop();
        tp::stop_session_by_name();
        Sleep(100);
    }
    etw_thread.join();

    // If the session ended by itself the loop above never ran. Close it here, where
    // errors are caught, because ~trace() cannot safely throw.
    session->stop();

    writer->stop();

    // Last check, so the session can never outlive this process.
    tp::stop_session_by_name();

    print_summary(counters, stats);
    SetEvent(g_shutdown_done);

    if (!etw_error.empty()) {
        std::cerr << "ETW session failed: " << etw_error << "\n";
        return kExitRuntimeFailed;
    }
    return kExitOk;
}
