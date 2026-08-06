#pragma once
#include "ui.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/pattern_formatter.h>

namespace proctun {

// Console only — the service file logger keeps spdlog's default pattern.
class level_marker_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        std::string m;
        switch (msg.level) {
            case spdlog::level::warn:  m = ui::yellow("▲") + " ";    break;
            case spdlog::level::err:   m = ui::red("error:") + " "; break;
            case spdlog::level::debug: m = ui::dim("·") + " ";      break;
            default: break;
        }
        dest.append(m.data(), m.data() + m.size());
    }
    std::unique_ptr<custom_flag_formatter> clone() const override {
        return spdlog::details::make_unique<level_marker_flag>();
    }
};

inline void init_logging(bool verbose) {
    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<level_marker_flag>('*');
    formatter->set_pattern(verbose ? "  [%H:%M:%S.%e] %*%v" : "  %*%v");
    spdlog::set_formatter(std::move(formatter));
    spdlog::set_level(verbose ? spdlog::level::debug : spdlog::level::info);
}

}
