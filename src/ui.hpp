#pragma once
#include <spdlog/fmt/fmt.h>

#include <windows.h>
#include <string>

namespace proctun::ui {

inline bool& colors() { static bool on = false; return on; }

inline void init() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode) &&
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        colors() = true;
}

inline std::string paint(const char* code, const std::string& s) {
    return colors() ? "\x1b[" + std::string(code) + "m" + s + "\x1b[0m" : s;
}
inline std::string bold(const std::string& s)   { return paint("1", s); }
inline std::string dim(const std::string& s)    { return paint("90", s); }
inline std::string green(const std::string& s)  { return paint("32", s); }
inline std::string yellow(const std::string& s) { return paint("33", s); }
inline std::string red(const std::string& s)    { return paint("31", s); }
inline std::string cyan(const std::string& s)   { return paint("36", s); }

// pad to a display width counting UTF-8 code points, not bytes
inline std::string pad(std::string s, size_t width) {
    size_t glyphs = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) ++glyphs;
    if (glyphs < width) s.append(width - glyphs, ' ');
    return s;
}

inline std::string fit(const std::string& s, size_t width) {
    size_t glyphs = 0, cut = std::string::npos;
    for (size_t i = 0; i < s.size(); ++i) {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) == 0x80) continue;
        if (++glyphs == width) cut = i;
    }
    if (glyphs <= width) return pad(s, width);
    return s.substr(0, cut) + "…";
}

inline void ok(const std::string& s)   { fmt::print("  {}  {}\n", green("✔"), s); }
inline void note(const std::string& s) { fmt::print("  {} {}\n", cyan(">>"), s); }
inline void warn(const std::string& s) { fmt::print("  {} {}\n", yellow(">>"), s); }
inline void fail(const std::string& s) { fmt::print(stderr, "  {} {}\n", red("error:"), s); }

inline void header(const std::string& title, const std::string& hint = {}) {
    fmt::print("\n  {}{}\n", bold(title), hint.empty() ? "" : "  " + dim(hint));
}
inline void kv(const std::string& key, const std::string& value) {
    fmt::print("    {} {}\n", dim(pad(key, 16)), value);
}
inline void blank() { fmt::print("\n"); }

}
