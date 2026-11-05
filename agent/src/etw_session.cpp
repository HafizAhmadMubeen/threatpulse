// krabs.hpp must come first and be included from this file only (see etw_session.h).
#include <krabs.hpp>

#include "etw_session.h"

#include <cstddef>
#include <string>
#include <vector>

namespace tp {

namespace {

// Provider GUIDs and keywords come from the provider manifests. GUIDs are used
// rather than names so that no manifest name lookup can fail at startup.
constexpr wchar_t kProcessProvider[] = L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
constexpr wchar_t kFileProvider[] = L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}";
constexpr wchar_t kRegistryProvider[] = L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}";

constexpr ULONGLONG kProcessKeywords = 0x10;  // WINEVENT_KEYWORD_PROCESS

// FILENAME 0x10 | CREATE 0x80 | WRITE 0x200 | DELETE_PATH 0x400 |
// RENAME_SETLINK_PATH 0x800 | CREATE_NEW_FILE 0x1000.
constexpr ULONGLONG kFileKeywords = 0x1E90;

// FILEIO 0x20 is the only keyword that delivers Close (event 14), but it also turns
// on reads and most other file operations. The event-ID filter below removes those.
constexpr ULONGLONG kFileIoKeyword = 0x20;

// CloseKey 0x1 | SetValueKey 0x100 | CreateKey 0x1000 | OpenKey 0x2000 | QueryKey 0x8000
constexpr ULONGLONG kRegistryKeywords = 0xB101;

// Kernel-Process event IDs
constexpr int kProcessStart = 1;
constexpr int kProcessStop = 2;

// Kernel-File event IDs
constexpr int kNameCreate = 10;
constexpr int kNameDelete = 11;
constexpr int kFileOpen = 12;
constexpr int kFileClose = 14;
constexpr int kFileWrite = 16;
constexpr int kDeletePath = 26;
constexpr int kRenamePath = 27;
constexpr int kCreateNewFile = 30;

// Kernel-Registry event IDs
constexpr int kRegCreateKey = 1;
constexpr int kRegOpenKey = 2;
constexpr int kRegQueryKey = 4;
constexpr int kRegSetValue = 5;
constexpr int kRegCloseKey = 13;

constexpr uint32_t kFileDirectoryFile = 0x00000001;  // CreateOptions: it is a directory

EventContext make_context(const EVENT_RECORD& record) {
    EventContext context;
    context.filetime_utc = static_cast<uint64_t>(record.EventHeader.TimeStamp.QuadPart);
    context.header_pid = record.EventHeader.ProcessId;
    for (USHORT i = 0; i < record.ExtendedDataCount; ++i) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record.ExtendedData[i];
        if (item.ExtType == EVENT_HEADER_EXT_TYPE_SID) {
            context.sid = reinterpret_cast<const void*>(item.DataPtr);
            context.sid_size = item.DataSize;
            break;
        }
    }
    return context;
}

// Optional string fields: a field missing on this Windows build reads as empty.
std::wstring read_string(krabs::parser& parser, const wchar_t* name) {
    std::wstring value;
    parser.try_parse(name, value);
    return value;
}

// Optional pointer fields: a field missing on this Windows build reads as 0.
uint64_t read_pointer(krabs::parser& parser, const wchar_t* name) {
    krabs::pointer value{};
    parser.try_parse(name, value);
    return value.address;
}

uint64_t filetime_field(krabs::parser& parser, const wchar_t* name) {
    FILETIME value{};
    if (!parser.try_parse(name, value)) return 0;
    return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

}  // namespace

struct EtwSession::Impl {
    Impl(EventMapper& event_mapper, Counters& event_counters, const SessionOptions& options)
        : mapper(event_mapper),
          counters(event_counters),
          process_provider(krabs::guid(kProcessProvider)),
          file_provider(krabs::guid(kFileProvider)),
          registry_provider(krabs::guid(kRegistryProvider)),
          trace(kSessionName) {
        configure(process_provider, kProcessKeywords);
        process_provider.add_on_event_callback(make_callback(&Impl::handle_process));

        configure(registry_provider, kRegistryKeywords);
        registry_provider.add_on_event_callback(make_callback(&Impl::handle_registry));

        if (options.close_events) {
            // The ID list runs in the kernel, so unwanted events never reach the
            // session. If this Windows build ignores it, handle_file() skips them
            // instead, and any cost shows up as "Lost by ETW" in the summary.
            configure(file_provider, kFileKeywords | kFileIoKeyword);
            krabs::event_filter file_filter(std::vector<unsigned short>{
                kNameCreate, kNameDelete, kFileOpen, kFileClose, kFileWrite, kDeletePath,
                kRenamePath, kCreateNewFile});
            file_filter.add_on_event_callback(make_callback(&Impl::handle_file));
            file_provider.add_filter(file_filter);
        } else {
            // The fallback uses no ID filter either, so it also works if Windows
            // refuses that filter.
            configure(file_provider, kFileKeywords);
            file_provider.add_on_event_callback(make_callback(&Impl::handle_file));
        }

        if (options.rundown) {
            file_provider.enable_rundown_events();
            registry_provider.enable_rundown_events();
        }

        // Larger buffers reduce event loss during bursts. The flush timer also sets
        // how old an event can be when it arrives, which is why short-lived
        // processes may be gone before their command line can be read.
        EVENT_TRACE_PROPERTIES properties{};
        properties.BufferSize = 256;  // KB
        properties.MinimumBuffers = 32;
        properties.MaximumBuffers = 256;
        properties.FlushTimer = 1;  // seconds
        trace.set_trace_properties(&properties);

        // trace keeps references to these providers, so they are declared first
        // and destroyed last.
        trace.enable(process_provider);
        trace.enable(file_provider);
        trace.enable(registry_provider);
    }

    using Handler = void (Impl::*)(krabs::schema&, krabs::parser&, const EVENT_RECORD&);

    static void configure(krabs::provider<>& provider, ULONGLONG keywords) {
        provider.any(keywords);
        provider.trace_flags(EVENT_ENABLE_PROPERTY_SID);
    }

    // Returned as a temporary on purpose: krabs copies temporaries, but keeps only a
    // reference to a named non-const callback, which would dangle here.
    krabs::provider_callback make_callback(Handler handler) {
        return [this, handler](const EVENT_RECORD& record, const krabs::trace_context& context) {
            // krabs only catches could_not_find_schema, so any other exception leaving
            // this callback would stop all event processing. One bad event must cost
            // one event, never the whole session.
            try {
                krabs::schema schema(record, context.schema_locator);
                krabs::parser parser(schema);
                (this->*handler)(schema, parser, record);
            } catch (...) {
                ++counters.callback_errors;
            }
        };
    }

    void handle_process(krabs::schema& schema, krabs::parser& parser, const EVENT_RECORD& record) {
        switch (schema.event_id()) {
            case kProcessStart:
                mapper.on_process_start(make_context(record), parser.parse<uint32_t>(L"ProcessID"),
                                        parser.parse<uint32_t>(L"ParentProcessID"),
                                        parser.parse<std::wstring>(L"ImageName"),
                                        filetime_field(parser, L"CreateTime"));
                break;
            case kProcessStop:
                mapper.on_process_stop(make_context(record), parser.parse<uint32_t>(L"ProcessID"));
                break;
            default:
                break;
        }
    }

    void handle_file(krabs::schema& schema, krabs::parser& parser, const EVENT_RECORD& record) {
        switch (schema.event_id()) {
            case kNameCreate:
                mapper.on_file_name(parser.parse<krabs::pointer>(L"FileKey").address,
                                    parser.parse<std::wstring>(L"FileName"));
                break;
            case kNameDelete:
                mapper.on_file_name_deleted(parser.parse<krabs::pointer>(L"FileKey").address);
                break;
            case kFileOpen: {
                uint32_t options = 0;
                parser.try_parse(L"CreateOptions", options);
                mapper.on_file_open(make_context(record),
                                    parser.parse<krabs::pointer>(L"FileObject").address,
                                    parser.parse<std::wstring>(L"FileName"), options);
                break;
            }
            case kFileClose:
                mapper.on_file_close(make_context(record), read_pointer(parser, L"FileObject"),
                                     read_pointer(parser, L"FileKey"));
                break;
            case kFileWrite:
                mapper.on_file_write(make_context(record),
                                     parser.parse<krabs::pointer>(L"FileKey").address,
                                     parser.parse<krabs::pointer>(L"FileObject").address);
                break;
            case kRenamePath:
                mapper.on_file_rename(make_context(record),
                                      parser.parse<krabs::pointer>(L"FileKey").address,
                                      parser.parse<krabs::pointer>(L"FileObject").address,
                                      read_string(parser, L"FilePath"));
                break;
            case kDeletePath:
                mapper.on_file_delete(make_context(record),
                                      parser.parse<krabs::pointer>(L"FileKey").address,
                                      parser.parse<krabs::pointer>(L"FileObject").address,
                                      read_string(parser, L"FilePath"));
                break;
            case kCreateNewFile: {
                uint32_t options = 0;
                parser.try_parse(L"CreateOptions", options);
                if ((options & kFileDirectoryFile) == 0) {
                    mapper.on_file_create(make_context(record),
                                          parser.parse<std::wstring>(L"FileName"));
                }
                break;
            }
            default:
                break;
        }
    }

    void handle_registry(krabs::schema& schema, krabs::parser& parser, const EVENT_RECORD& record) {
        switch (schema.event_id()) {
            case kRegCreateKey:
            case kRegOpenKey:
                mapper.on_registry_open(parser.parse<krabs::pointer>(L"BaseObject").address,
                                        parser.parse<krabs::pointer>(L"KeyObject").address,
                                        parser.parse<uint32_t>(L"Status"),
                                        read_string(parser, L"BaseName"),
                                        read_string(parser, L"RelativeName"));
                break;
            case kRegCloseKey:
                mapper.on_registry_close(parser.parse<krabs::pointer>(L"KeyObject").address);
                break;
            case kRegQueryKey:
                mapper.on_registry_query(parser.parse<krabs::pointer>(L"KeyObject").address,
                                         read_string(parser, L"KeyName"));
                break;
            case kRegSetValue:
                mapper.on_registry_set(make_context(record),
                                       parser.parse<krabs::pointer>(L"KeyObject").address,
                                       parser.parse<uint32_t>(L"Status"),
                                       read_string(parser, L"KeyName"),
                                       read_string(parser, L"ValueName"));
                break;
            default:
                break;
        }
    }

    EventMapper& mapper;
    Counters& counters;
    krabs::provider<> process_provider;
    krabs::provider<> file_provider;
    krabs::provider<> registry_provider;
    krabs::user_trace trace;  // declared after the providers it references
};

bool stop_session_by_name() {
    // Fixed-size stack storage, because this can run from the crash handler.
    struct {
        EVENT_TRACE_PROPERTIES properties;
        wchar_t logger_name[512];
        wchar_t log_file_name[512];
    } buffer{};
    buffer.properties.Wnode.BufferSize = sizeof(buffer);
    buffer.properties.LoggerNameOffset = offsetof(decltype(buffer), logger_name);
    buffer.properties.LogFileNameOffset = offsetof(decltype(buffer), log_file_name);

    return ControlTraceW(0, kSessionName, &buffer.properties, EVENT_TRACE_CONTROL_STOP) ==
           ERROR_SUCCESS;
}

EtwSession::EtwSession(EventMapper& mapper, Counters& counters, const SessionOptions& options)
    : impl_(std::make_unique<Impl>(mapper, counters, options)) {}

EtwSession::~EtwSession() = default;

void EtwSession::run() {
    impl_->trace.start();
}

void EtwSession::stop() {
    try {
        impl_->trace.stop();
    } catch (...) {
        // main() follows up with stop_session_by_name(), so a failure here cannot
        // leave the session running.
    }
}

std::optional<SessionStats> EtwSession::query_stats() {
    try {
        const krabs::trace_stats stats = impl_->trace.query_stats();
        SessionStats result;
        result.events_handled = stats.eventsHandled;
        result.events_lost = stats.eventsLost;
        result.buffers_lost = stats.buffersLost;
        return result;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace tp
