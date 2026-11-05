// UTF-8/UTF-16 conversion and case-insensitive comparison.
// Windows paths and registry keys are case-insensitive, so every match uses these.
#pragma once

#include <windows.h>

#include <string>
#include <string_view>

namespace tp {

inline std::string to_utf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int size = static_cast<int>(text.size());
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), size, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), size, out.data(), needed, nullptr, nullptr);
    return out;
}

inline std::wstring to_wide(std::string_view text) {
    if (text.empty()) return {};
    const int size = static_cast<int>(text.size());
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(), size, nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), size, out.data(), needed);
    return out;
}

inline bool iequals(std::wstring_view a, std::wstring_view b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    const int size = static_cast<int>(a.size());
    return CompareStringOrdinal(a.data(), size, b.data(), size, TRUE) == CSTR_EQUAL;
}

inline bool istarts_with(std::wstring_view text, std::wstring_view prefix) {
    return text.size() >= prefix.size() && iequals(text.substr(0, prefix.size()), prefix);
}

inline std::wstring lowercase(std::wstring text) {
    if (!text.empty()) CharLowerBuffW(text.data(), static_cast<DWORD>(text.size()));
    return text;
}

}  // namespace tp
