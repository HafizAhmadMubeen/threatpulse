// Bounded queue plus writer thread: ETW callback -> queue -> enrich -> events.jsonl.
//
// ETW drops events if its callback is slow, so the callback only queues work.
// Hashing, JSON formatting and disk writes all happen on this thread.
#pragma once

#include <windows.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "agent_event.h"
#include "enrich.h"
#include "filters.h"

namespace tp {

class JsonlWriter {
public:
    // `filters` must outlive the writer.
    JsonlWriter(std::string run_id, const Filters& filters, Counters& counters,
                std::function<void()> on_fatal_error);
    ~JsonlWriter();

    // Renames any existing `path` so nothing is lost, then opens it. Throws on failure.
    void open(const std::filesystem::path& path);

    void start();
    void push(PendingEvent&& event);  // never blocks: a full queue drops and counts
    void stop();                      // writes everything queued, then closes the file

private:
    void worker();
    bool is_filtered(const PendingEvent& event, const ImageInfo& image) const;
    std::string format(const PendingEvent& event, const ImageInfo& image);
    bool flush();

    const std::string run_id_;
    const std::string host_;
    const Filters& filters_;
    Counters& counters_;
    std::function<void()> on_fatal_error_;

    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<PendingEvent> queue_;
    bool stopping_ = false;

    std::thread thread_;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    std::string buffer_;
    uint64_t next_sequence_ = 1;
    Enricher enricher_;
};

}  // namespace tp
