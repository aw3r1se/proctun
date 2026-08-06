#include "config.hpp"
#include "log.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>

using nlohmann::json;

namespace proctun {

void to_json(json& j, const Rule& r) {
    j = json{{"match", r.match}, {"via", r.via}};
    if (r.dns) j["dns"] = *r.dns;
}
void from_json(const json& j, Rule& r) {
    j.at("match").get_to(r.match);
    if (j.contains("via")) j.at("via").get_to(r.via);
    if (j.contains("dns")) r.dns = j.at("dns").get<std::string>();
}

std::filesystem::path Config::default_path() {
    const char* pd = std::getenv("ProgramData");
    std::filesystem::path base = pd ? pd : ".";
    return base / "proctun" / "config.json";
}

Config Config::load(const std::filesystem::path& p) {
    Config c;
    std::ifstream f(p);
    if (!f) {
        spdlog::debug("config: {} not found, using defaults", p.string());
        return c;
    }
    try {
        json j; f >> j;
        if (j.contains("rules"))      for (auto& jr : j["rules"]) c.rules.push_back(jr.get<Rule>());
        if (j.contains("mode"))        c.mode = (j["mode"].get<std::string>() == "exclude")
                                                  ? Mode::Exclude : Mode::Include;
        if (j.contains("tunnel_remote")) j["tunnel_remote"].get_to(c.tunnel_remote);
        if (j.contains("tun_alias"))   j["tun_alias"].get_to(c.tun_alias);
        if (j.contains("tun_gateway")) j["tun_gateway"].get_to(c.tun_gateway);
        if (j.contains("wan_alias"))   j["wan_alias"].get_to(c.wan_alias);
        if (j.contains("leakguard"))   j["leakguard"].get_to(c.leakguard);
        if (j.contains("block_ipv6"))  j["block_ipv6"].get_to(c.block_ipv6);
        if (j.contains("tunnel_dns"))  j["tunnel_dns"].get_to(c.tunnel_dns);
        if (j.contains("dns_server"))  j["dns_server"].get_to(c.dns_server);
    } catch (const std::exception& e) {
        spdlog::error("config: cannot parse {}: {} — using defaults", p.string(), e.what());
        return Config{};
    }
    return c;
}

void Config::save(const std::filesystem::path& p) const {
    std::filesystem::create_directories(p.parent_path());
    json j;
    j["rules"]         = rules;
    j["mode"]          = (mode == Mode::Exclude) ? "exclude" : "include";
    j["tunnel_remote"] = tunnel_remote;
    j["tun_alias"]     = tun_alias;
    j["tun_gateway"] = tun_gateway;
    j["wan_alias"]   = wan_alias;
    j["leakguard"]  = leakguard;
    j["block_ipv6"] = block_ipv6;
    j["tunnel_dns"] = tunnel_dns;
    j["dns_server"] = dns_server;
    std::ofstream f(p);
    f << j.dump(2) << '\n';
}

}
