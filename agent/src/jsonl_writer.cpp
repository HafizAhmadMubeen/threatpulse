#include "jsonl_writer.h"

#include <chrono>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <utility>

#include <nlohmann/json.hpp>

#include "text.h"

namespace tp {

namespace {

using Json = nlohmann::ordered_json;  // keeps the PLANNING.md 5.1 field order

constexpr size_t kMaxQueued = 200000;
constexpr size_t kFlushBytes = 64 * 1024;
constexpr auto kFlushInterval = std::chrono::seconds(1);

std::string read_host_name() {
    wchar_t name[256];
    DWORD size = ARRAYSIZE(name);
    if (!GetComputerNameExW(ComputerNameDnsHostname, name, &size)) return "unknown";
    return to_utf8(lowercase(std::wstring(name, size)));
}

std::string format_timestamp(uint64_t filetime) {
    FILETIME time{};
    time.dwLowDateTime = static_cast<DWORD>(filetime & 0xFFFFFFFF);
    time.dwHighDateTime = static_cast<DWORD>(filetime >> 32);

    SYSTEMTIME utc{};
    FileTimeToSystemTime(&time, &utc);

    char text[32];
    std::snprintf(text, sizeof(text), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", utc.wYear, utc.wMonth,
                  utc.wDay, utc.wHour, utc.wMinute, utc.wSecond, utc.wMilliseconds);
    return text;
}

Json nullable(const std::optional<std::wstring>& value) {
    return value ? Json(to_utf8(*value)) : Json(nullptr);
}

std::string timestamp_for_filename() {
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char text[32];
    std::snprintf(text, sizeof(text), "%04u%02u%02uT%02u%02u%02u", utc.wYear, utc.wMonth, utc.wDay,
                  utc.wHour, utc.wMinute, utc.wSecond);
    return text;
}

// events.jsonl -> events-20261105T101500.jsonl, with -1, -2... if that name is taken.
void rotate_existing(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return;

    const std::wstring stem = path.stem().wstring() + L"-" + to_wide(timestamp_for_filename());
    for (int attempt = 0; attempt < 1000; ++attempt) {
        const std::wstring suffix = attempt == 0 ? L"" : L"-" + std::to_wstring(attempt);
        const std::filesystem::path rotated =
            path.parent_path() / (stem + suffix + path.extension().wstring());
        if (MoveFileExW(path.c_str(), rotated.c_str(), 0)) return;
        if (GetLastError() != ERROR_ALREADY_EXISTS) break;
    }
    throw std::runtime_error("cannot rename the existing output file: " + path.string());
}

}  // namespace

JsonlWriter::JsonlWriter(std::string run_id, const Filters& filters, Counters& counters,
                         std::function<void()> on_fatal_error)
    : run_id_(std::move(run_id)),
      host_(read_host_name()),
      filters_(filters),
      counters_(counters),
      on_fatal_error_(std::move(on_fatal_error)) {}

JsonlWriter::~JsonlWriter() {
    stop();
}

void JsonlWriter::prepare(const std::filesystem::path& path) {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    rotate_existing(path);

    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot create output file: " + path.string());
    }
    CloseHandle(file);
    path_ = path;
}

// Opened only once events are arriving. The session must already be live, or it never
// sees this open, System's flushes of the log have no path, and the path filter for
// the log folder cannot drop them. Those flushes would then feed the log itself.
bool JsonlWriter::open_output() {
    // FILE_SHARE_READ lets other tools read the file while the agent is running.
    file_ = CreateFileW(path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    return file_ != INVALID_HANDLE_VALUE;
}

void JsonlWriter::start() {
    thread_ = std::thread([this] { worker(); });
}

void JsonlWriter::push(PendingEvent&& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= kMaxQueued) {
            ++counters_.queue_dropped;
            return;
        }
        queue_.push_back(std::move(event));
    }
    wake_.notify_one();
}

void JsonlWriter::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
    }
    wake_.notify_one();
    if (thread_.joinable()) thread_.join();

    if (file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
}

// Same principle as the never-suspend list: path AND signature, never the path
// alone. A file placed at a filtered path, or a signature that failed or could not
// be checked, keeps the event. This runs here, not on the ETW thread, because the
// signature is only known after enrichment.
bool JsonlWriter::is_filtered(const PendingEvent& event, const ImageInfo& image) const {
    return event.allow_process_filter && image.is_signed && image.microsoft_root &&
           filters_.ignores_process(event.image);
}

std::string JsonlWriter::format(const PendingEvent& event, const ImageInfo& image) {
    char event_id[64];
    std::snprintf(event_id, sizeof(event_id), "e-%s-%06llu", run_id_.c_str(),
                  static_cast<unsigned long long>(next_sequence_++));

    Json json;
    json["event_id"] = event_id;
    json["ts"] = format_timestamp(event.filetime_utc);
    json["host"] = host_;
    json["source"] = event.source;
    json["event_type"] = event.event_type;
    json["pid"] = event.pid;
    json["ppid"] = event.ppid;
    json["process"] = {
        {"image", to_utf8(event.image)},
        {"cmdline", nullable(event.cmdline)},
        {"user", nullable(event.user)},
        {"sha256", nullable(image.sha256)},
        {"signed", image.is_signed},
        {"signer", nullable(image.signer)},
        // Optional in the schema. True only for a verified signature whose chain ends at
        // a Microsoft root, so a display name alone ("Microsoft") never makes it true.
        {"microsoft_root", image.is_signed && image.microsoft_root},
    };
    json["target"] = {
        {"path", nullable(event.path)},
        {"old_path", nullable(event.old_path)},
        {"registry_key", nullable(event.registry_key)},
        {"pid", event.target_pid ? Json(*event.target_pid) : Json(nullptr)},
        {"access_mask", event.access_mask ? Json(*event.access_mask) : Json(nullptr)},
        {"access_rights", event.access_rights ? Json(*event.access_rights) : Json(nullptr)},
        {"dest_ip", nullable(event.dest_ip)},
        {"dest_port", event.dest_port ? Json(*event.dest_port) : Json(nullptr)},
    };
    // Paths can hold invalid Unicode, which must never crash the writer thread.
    return json.dump(-1, ' ', false, Json::error_handler_t::replace);
}

bool JsonlWriter::flush() {
    if (buffer_.empty()) return true;
    DWORD written = 0;
    const DWORD size = static_cast<DWORD>(buffer_.size());
    const bool ok = WriteFile(file_, buffer_.data(), size, &written, nullptr) && written == size;
    buffer_.clear();
    return ok;
}

void JsonlWriter::worker() {
    auto last_flush = std::chrono::steady_clock::now();
    bool file_ok = true;

    for (;;) {
        std::deque<PendingEvent> batch;
        bool stopping = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait_for(lock, kFlushInterval, [this] { return stopping_ || !queue_.empty(); });
            batch.swap(queue_);
            stopping = stopping_;
        }

        if (file_ok && !batch.empty() && file_ == INVALID_HANDLE_VALUE) {
            file_ok = open_output();
        }

        for (const PendingEvent& event : batch) {
            if (!file_ok) break;
            try {
                const ImageInfo& image = enricher_.get(event.image, event.recheck_image);
                if (is_filtered(event, image)) {
                    ++counters_.filtered;
                    continue;
                }
                buffer_ += format(event, image);
                buffer_ += '\n';
                ++counters_.written;
            } catch (...) {
                ++counters_.callback_errors;
            }
            if (buffer_.size() >= kFlushBytes) {
                file_ok = flush();
                last_flush = std::chrono::steady_clock::now();
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (file_ok && (stopping || now - last_flush >= kFlushInterval)) {
            file_ok = flush();
            last_flush = now;
        }

        if (!file_ok) {
            // A disk problem must end the run, not silently lose data. Keep looping
            // so stop() can still join this thread.
            if (on_fatal_error_) {
                on_fatal_error_();
                on_fatal_error_ = nullptr;
            }
        }
        if (stopping) return;
    }
}

}  // namespace tp
