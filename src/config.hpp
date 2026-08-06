#pragma once
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

namespace proctun {

struct Rule {
    std::string match;
    std::string via = "tun";
    std::optional<std::string> dns;
};

enum class Mode {
    Include,
    Exclude
};

struct Config {
    std::vector<Rule> rules;
    Mode mode = Mode::Include;
    std::string tunnel_remote;

    std::string tun_alias;
    std::string tun_gateway;
    std::string wan_alias;
    bool leakguard = true;
    bool block_ipv6 = true;
    bool tunnel_dns = true;
    std::string dns_server = "1.1.1.1";

    static std::filesystem::path default_path();
    static Config load(const std::filesystem::path& p);
    void save(const std::filesystem::path& p) const;
};

}
