# ThreatPulse endpoint agent. Built and run ONLY inside the lab VM (MSVC, x64).
cmake_minimum_required(VERSION 3.24)
project(ThreatPulseAgent LANGUAGES CXX)

if(NOT MSVC)
    message(FATAL_ERROR "The agent is Windows-only: build it with MSVC inside the lab VM.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# krabsetw publishes no Git tags or GitHub releases, so it is pinned to a full
# commit SHA: the "Bump NuGet packages to 4.5.0" commit on master. It has no
# CMakeLists.txt, so FetchContent only downloads it and the target below exposes
# its headers.
FetchContent_Declare(
    krabsetw
    GIT_REPOSITORY https://github.com/microsoft/krabsetw.git
    GIT_TAG        d626e49c41a2a324ad8b433b186703aa551373b3
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.12.0
    GIT_SHALLOW    TRUE
)

set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(krabsetw nlohmann_json)

add_library(krabsetw_headers INTERFACE)
target_include_directories(krabsetw_headers SYSTEM INTERFACE "${krabsetw_SOURCE_DIR}/krabs")
# krabsetw does not compile without UNICODE.
target_compile_definitions(krabsetw_headers INTERFACE UNICODE _UNICODE)

add_executable(threatpulse_agent
    src/main.cpp
    src/etw_session.cpp
    src/event_mapper.cpp
    src/process_table.cpp
    src/name_tracker.cpp
    src/enrich.cpp
    src/filters.cpp
    src/path_utils.cpp
    src/jsonl_writer.cpp
)

target_compile_definitions(threatpulse_agent PRIVATE
    _WIN32_WINNT=0x0A00   # Windows 10+ APIs, e.g. CryptCATAdminAcquireContext2
    WINVER=0x0A00
)

target_compile_options(threatpulse_agent PRIVATE /W4 /utf-8)

target_link_libraries(threatpulse_agent PRIVATE
    krabsetw_headers
    nlohmann_json::nlohmann_json
    advapi32
    bcrypt
    crypt32
    ntdll
    ole32
    rpcrt4
    tdh
    user32
    wintrust
)

# The default --config path is filters.json next to the executable.
add_custom_command(TARGET threatpulse_agent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/config/filters.json"
            "$<TARGET_FILE_DIR:threatpulse_agent>/filters.json"
)
