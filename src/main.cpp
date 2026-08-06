#include "log.hpp"
#include "config.hpp"
#include "driver.hpp"
#include "adapters.hpp"
#include "engine.hpp"
#include "service.hpp"
#include "ui.hpp"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>

using namespace proctun;

namespace {

std::atomic<bool> g_stop{false};
BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop.store(true);
        return TRUE;
    }
    return FALSE;
}

std::string onoff(bool v) { return v ? ui::green("on") : ui::dim("off"); }

void cmd_adapters() {
    auto all = enumerate_adapters();
    const AdapterInfo* wan = pick_wan(all);
    ui::header("ADAPTERS", fmt::format("({})", all.size()));
    fmt::print("      {}\n", ui::dim(fmt::format("{} {} {}",
               ui::pad("NAME", 32), ui::pad("ADDRESS", 18), "GATEWAY")));
    for (const auto& a : all) {
        std::string ip = a.ipv4.empty() ? "—" : a.ipv4;
        if (!a.ipv4.empty() && a.prefix_v4) ip += fmt::format("/{}", a.prefix_v4);
        fmt::print("    {} {} {} {} {}{}\n",
                   a.is_up ? ui::green("●") : ui::dim("○"),
                   ui::fit(a.friendly.empty() ? a.guid : a.friendly, 32),
                   ui::pad(ip, 18),
                   ui::pad(a.gateway_v4, 16),
                   a.is_tunnel ? ui::dim("tunnel ") : "",
                   (wan == &a) ? ui::cyan("◀ wan") : "");
    }
    ui::blank();
}

void cmd_list(const Config& cfg) {
    const bool excl = cfg.mode == Mode::Exclude;
    ui::header(fmt::format("RULES ({})", cfg.rules.size()),
               excl ? "exclude mode — matched processes bypass the tunnel"
                    : "include mode — matched processes go via the tunnel");
    if (cfg.rules.empty()) {
        fmt::print("    {}\n", ui::dim("none — add one: proctun add <exe>"));
        ui::blank();
        return;
    }
    for (const auto& r : cfg.rules)
        fmt::print("    {} {} {}{}\n", ui::pad(r.match, 17), ui::dim("→"),
                   excl ? "direct" : "tunnel",
                   r.dns ? ui::dim("   dns " + *r.dns) : "");
    ui::blank();
}

std::optional<nlohmann::json> read_stats() {
    std::ifstream f(svc::stats_path());
    if (!f) return std::nullopt;
    try { nlohmann::json j; f >> j; return j; } catch (...) { return std::nullopt; }
}

void print_engine_kv(const nlohmann::json& j) {
    ui::kv("engine", j.value("mode", "?"));
    ui::kv("tunnel", j.value("armed", false) ? ui::green("up ✔") : ui::red("DOWN"));
    ui::kv("wan", fmt::format("{}  {}", j.value("wan", "?"), ui::dim(j.value("wan_ip", "?"))));
    ui::kv("tun", fmt::format("{}  {}", j.value("tun", "?"), ui::dim(j.value("tun_ip", "?"))));
}

void cmd_status(const Config& cfg) {
    const bool inst = svc::is_installed();
    const bool run = svc::is_running();
    fmt::print("\n  {} {}\n", ui::bold("proctun"), ui::dim(PROCTUN_VERSION));

    ui::header("SERVICE");
    ui::kv("state", !inst ? ui::yellow("not installed")
                          : run ? ui::green("running") : ui::dim("stopped"));
    if (run) {
        if (auto j = read_stats()) {
            print_engine_kv(*j);
            ui::header("COUNTERS");
            ui::kv("tunneled",   fmt::format("{}", j->value("tunneled", 0ull)));
            ui::kv("dns",        fmt::format("{}", j->value("dns", 0ull)));
            ui::kv("v6-dropped", fmt::format("{}", j->value("v6_dropped", 0ull)));
            ui::kv("killed",     fmt::format("{}", j->value("killed", 0ull)));
            ui::kv("conntrack",  fmt::format("{}", j->value("conntrack", 0ull)));
        } else {
            ui::kv("engine", ui::dim("(stats file not ready yet)"));
        }
    }

    ui::header("CONFIG");
    ui::kv("mode", cfg.mode == Mode::Exclude ? "exclude" : "include");
    ui::kv("leakguard", onoff(cfg.leakguard));
    ui::kv("ipv6-block", onoff(cfg.block_ipv6));
    ui::kv("tunnel-dns", onoff(cfg.tunnel_dns) +
           (cfg.tunnel_dns && !cfg.dns_server.empty()
                ? ui::dim("  → " + cfg.dns_server) : ""));
    ui::kv("tunnel-remote", cfg.tunnel_remote.empty() ? ui::dim("—") : cfg.tunnel_remote);
    ui::kv("tun-gw", cfg.tun_gateway.empty() ? ui::dim("—") : cfg.tun_gateway);

    cmd_list(cfg);
}

int cmd_up_foreground(Config& cfg) {
    if (svc::is_running()) {
        ui::fail("the proctun service is already running — two engines on the same "
                 "adapters conflict. Stop it first: proctun down.");
        return 1;
    }
    AdapterInfo wan, tun;
    std::string err;
    if (!resolve_endpoints(cfg, wan, tun, err)) { ui::fail(err); return 1; }

    Engine engine;
    if (!engine.start(cfg, wan, tun)) { ui::fail("engine failed to start"); return 1; }
    const auto st = engine.stats();

    fmt::print("\n  {} {}\n", ui::bold("proctun"), ui::dim(PROCTUN_VERSION));
    ui::header("ENGINE");
    ui::kv("mode", cfg.mode == Mode::Exclude ? "exclude" : "include");
    ui::kv("strategy", st.full_tunnel
        ? "full-tunnel  " + ui::dim("— direct traffic is pulled out of the tunnel")
        : "classic  " + ui::dim("— tunneled traffic is pushed into the tunnel"));
    ui::kv("wan", fmt::format("{}  {}", wan.friendly, ui::dim(wan.ipv4)));
    ui::kv("tun", fmt::format("{}  {}", tun.friendly, ui::dim(tun.ipv4)));
    ui::kv("rules", fmt::format("{}", cfg.rules.size()));
    ui::kv("leakguard", onoff(cfg.leakguard) + (cfg.leakguard
        ? ui::dim(fmt::format("  (ipv6-block {}, tunnel-dns {}{})",
                              cfg.block_ipv6 ? "on" : "off",
                              cfg.tunnel_dns ? "on" : "off",
                              cfg.tunnel_dns ? " → " + cfg.dns_server : ""))
        : ""));
    if (!cfg.tunnel_remote.empty()) ui::kv("transport-bypass", cfg.tunnel_remote);
    ui::blank();

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    ui::ok(fmt::format("running in the foreground — Ctrl+C to stop {}",
                       ui::dim("(use -d for the background service)")));
    while (!g_stop.load()) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ui::note("stopping...");
    engine.stop();
    ui::blank();
    return 0;
}

bool apply_overrides(Config& cfg, const std::string& mode, const std::string& tungw,
                     const std::string& remote, const std::string& dns,
                     const std::string& tun, const std::string& wan,
                     const std::string& lg, const std::string& v6, const std::string& tdns) {
    bool ch = false;
    auto onoff = [](const std::string& s, bool& dst, bool& changed) {
        if (s == "on")  { dst = true;  changed = true; }
        if (s == "off") { dst = false; changed = true; }
    };
    if (mode == "include") { cfg.mode = Mode::Include; ch = true; }
    if (mode == "exclude") { cfg.mode = Mode::Exclude; ch = true; }
    if (!tungw.empty())  { cfg.tun_gateway = tungw; ch = true; }
    if (!remote.empty()) { cfg.tunnel_remote = remote; ch = true; }
    if (!dns.empty())    { cfg.dns_server = dns; ch = true; }
    if (!tun.empty())    { cfg.tun_alias = tun; ch = true; }
    if (!wan.empty())    { cfg.wan_alias = wan; ch = true; }
    onoff(lg, cfg.leakguard, ch);
    onoff(v6, cfg.block_ipv6, ch);
    onoff(tdns, cfg.tunnel_dns, ch);
    return ch;
}

}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "run-service")
        return svc::run_dispatcher();
    SetConsoleOutputCP(CP_UTF8);

    CLI::App app{"proctun — per-process split tunneling for Windows"};
    app.set_version_flag("--version", std::string(PROCTUN_VERSION));
    app.require_subcommand(1);

    bool verbose = false;
    std::string config_path;
    app.add_flag("-v,--verbose", verbose, "Debug logging");
    app.add_option("--config", config_path, "Path to config.json");

    auto* initc = app.add_subcommand("init", "One-shot setup: `proctun` command alias + WinpkFilter driver install");
    driver::InitOptions init_opt;
    initc->add_flag("--yes", init_opt.yes, "non-interactive: accept the vendor license prompt");
    initc->add_flag("--force", init_opt.force, "reinstall even if the driver is already present");
    initc->add_option("--driver-path", init_opt.msi_path, "install this local MSI instead of downloading the pinned one");

    app.add_subcommand("adapters", "List network adapters");
    app.add_subcommand("ndis",     "List interfaces as seen by the WinpkFilter driver");

    auto* sniff = app.add_subcommand("sniff", "Passive packet sniff (verifies driver binds an adapter)");
    size_t sniff_index = 0; int sniff_seconds = 10;
    sniff->add_option("index", sniff_index, "interface index from `ndis`")->required();
    sniff->add_option("--seconds", sniff_seconds, "capture duration (default 10)");
    app.add_subcommand("status",   "Show adapters, rules and engine state");
    app.add_subcommand("list",     "List routing rules");
    auto* up   = app.add_subcommand("up",   "Start the engine (foreground; -d for the background service)");
    bool detach = false;
    up->add_flag("-d,--detach", detach, "run as the background Windows service (installs it if needed)");
    auto* down = app.add_subcommand("down", "Stop the background service");
    app.add_subcommand("install",   "Register the Windows service");
    app.add_subcommand("uninstall", "Stop and remove the Windows service");
    app.add_subcommand("update",    "Replace the installed proctun.exe with this executable and restart the service");
    auto* set  = app.add_subcommand("set",  "Set configuration values (persisted)");

    struct Overrides { std::string mode, tungw, remote, dns, tun, wan, lg, v6, tdns; } ov;
    auto add_overrides = [&](CLI::App* s) {
        s->add_option("--mode", ov.mode, "routing policy: include|exclude");
        s->add_option("--tun-gw", ov.tungw, "tunnel gateway IP (OpenVPN route-gateway)");
        s->add_option("--tunnel-remote", ov.remote, "VPN server IP (never tunneled; needed for exclude)");
        s->add_option("--dns", ov.dns, "DNS server reached via the tunnel");
        s->add_option("--tun", ov.tun, "tunnel adapter GUID/alias");
        s->add_option("--wan", ov.wan, "WAN adapter GUID/alias");
        s->add_option("--leakguard", ov.lg, "leak protection on|off");
        s->add_option("--ipv6-block", ov.v6, "drop tunneled IPv6 on|off");
        s->add_option("--tunnel-dns", ov.tdns, "tunnel all DNS on|off");
    };
    add_overrides(up);
    add_overrides(set);

    auto* add = app.add_subcommand("add", "Add a rule: route a process via an adapter");
    std::string add_match, add_via = "tun", add_dns;
    add->add_option("match", add_match, "exe path or wildcard mask")->required();
    add->add_option("--via", add_via, "target adapter alias (default: tun)");
    add->add_option("--dns", add_dns, "force DNS server for this rule");

    auto* rem = app.add_subcommand("remove", "Remove a rule by match");
    std::string rem_match;
    rem->add_option("match", rem_match, "exe path or wildcard mask")->required();

    auto* lg = app.add_subcommand("leakguard", "Toggle leak protection only");
    std::string lg_state;
    lg->add_option("state", lg_state, "on|off")->required();

    // let a global flag placed after a subcommand (`proctun up -v`) reach the app
    for (auto* s : app.get_subcommands([](const CLI::App*) { return true; }))
        s->fallthrough();

    ui::init();
    CLI11_PARSE(app, argc, argv);
    init_logging(verbose);

    auto cfg_path = config_path.empty() ? Config::default_path()
                                        : std::filesystem::path(config_path);
    Config cfg = Config::load(cfg_path);

    if (app.got_subcommand(initc)) { return driver::run_init(init_opt); }
    if (app.got_subcommand("adapters")) { cmd_adapters(); return 0; }
    if (app.got_subcommand("ndis")) {
        auto ifaces = ndis_interfaces();
        auto all = enumerate_adapters();
        const bool loaded = ndis_driver_loaded();
        ui::blank();
        if (loaded) ui::ok("WinpkFilter driver loaded");
        else        ui::fail("WinpkFilter driver NOT loaded");
        ui::header(fmt::format("NDIS INTERFACES ({})", ifaces.size()));
        for (size_t i = 0; i < ifaces.size(); ++i) {
            // ndis internal name looks like "\DEVICE\{GUID}" — pull the GUID out.
            const std::string& in = ifaces[i].internal;
            auto lb = in.find('{'), rb = in.find('}');
            std::string guid = (lb != std::string::npos && rb != std::string::npos)
                                   ? in.substr(lb, rb - lb + 1) : "";
            const AdapterInfo* m = nullptr;
            for (const auto& a : all) if (a.guid == guid) { m = &a; break; }
            if (m)
                fmt::print("    {} {} {} {} {}\n",
                           ui::dim(fmt::format("[{:>2}]", i)),
                           m->is_up ? ui::green("●") : ui::dim("○"),
                           ui::fit(m->friendly.empty() ? guid : m->friendly, 32),
                           ui::pad(m->ipv4.empty() ? "—" : m->ipv4, 15),
                           m->is_tunnel ? ui::dim("tunnel") : "");
            else
                fmt::print("    {}   {} {}\n", ui::dim(fmt::format("[{:>2}]", i)),
                           ui::fit(ifaces[i].friendly, 32), ui::dim(guid));
        }
        ui::blank();
        return 0;
    }
    if (app.got_subcommand(sniff)) {
        return ndis_sniff(sniff_index, sniff_seconds) ? 0 : 1;
    }
    if (app.got_subcommand("list"))     { cmd_list(cfg);  return 0; }
    if (app.got_subcommand("status"))   { cmd_status(cfg);return 0; }

    if (app.got_subcommand(add)) {
        Rule r; r.match = add_match; r.via = add_via;
        if (!add_dns.empty()) r.dns = add_dns;
        cfg.rules.push_back(std::move(r));
        cfg.save(cfg_path);
        ui::blank();
        ui::ok(fmt::format("rule added: {} → {}", add_match,
                           cfg.mode == Mode::Exclude ? "direct" : "tunnel"));
        ui::blank();
        return 0;
    }
    if (app.got_subcommand(rem)) {
        auto before = cfg.rules.size();
        std::erase_if(cfg.rules, [&](const Rule& r){ return r.match == rem_match; });
        cfg.save(cfg_path);
        const auto n = before - cfg.rules.size();
        ui::blank();
        if (n) ui::ok(fmt::format("removed {} rule(s) matching '{}'", n, rem_match));
        else   ui::note(fmt::format("no rules match '{}'", rem_match));
        ui::blank();
        return 0;
    }
    if (app.got_subcommand(lg)) {
        cfg.leakguard = (lg_state == "on");
        cfg.save(cfg_path);
        ui::blank();
        ui::ok(fmt::format("leakguard {}", cfg.leakguard ? "on" : "off"));
        ui::blank();
        return 0;
    }
    if (app.got_subcommand("update")) { return driver::run_update(); }
    if (app.got_subcommand("install")) {
        std::string err;
        if (!svc::install(err)) { ui::fail("install: " + err); return 1; }
        ui::blank();
        ui::ok("service installed");
        ui::blank();
        return 0;
    }
    if (app.got_subcommand("uninstall")) {
        std::string err;
        if (!svc::uninstall(err)) { ui::fail("uninstall: " + err); return 1; }
        ui::blank();
        ui::ok("service uninstalled");
        ui::blank();
        return 0;
    }
    if (app.got_subcommand(set)) {
        ui::blank();
        if (apply_overrides(cfg, ov.mode, ov.tungw, ov.remote, ov.dns, ov.tun, ov.wan, ov.lg, ov.v6, ov.tdns)) {
            cfg.save(cfg_path);
            ui::ok("config saved");
        } else {
            ui::note("nothing to set (no options given)");
        }
        cmd_status(cfg);
        return 0;
    }
    if (app.got_subcommand(up)) {
        if (!detach) {
            apply_overrides(cfg, ov.mode, ov.tungw, ov.remote, ov.dns, ov.tun, ov.wan, ov.lg, ov.v6, ov.tdns);
            return cmd_up_foreground(cfg);
        }
        if (apply_overrides(cfg, ov.mode, ov.tungw, ov.remote, ov.dns, ov.tun, ov.wan, ov.lg, ov.v6, ov.tdns))
            cfg.save(cfg_path);
        std::string err;
        if (!svc::is_installed() && !svc::install(err)) { ui::fail("install: " + err); return 1; }
        if (svc::is_running()) {
            ui::blank();
            ui::note("service is running — restarting to apply the config");
            if (!svc::stop(err)) { ui::fail("restart: " + err); return 1; }
        }
        if (!svc::start(err)) { ui::fail("start: " + err); return 1; }
        if (!svc::wait_running(5000)) {
            ui::fail("service exited right after start — engine failed to initialize. "
                     "See %ProgramData%\\proctun\\proctun.log or run `proctun up -v`.");
            return 1;
        }
        std::optional<nlohmann::json> j;
        for (int i = 0; i < 30 && !(j = read_stats()); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ui::header("SERVICE");
        ui::kv("state", ui::green("running"));
        if (j) print_engine_kv(*j);
        ui::blank();
        ui::ok(fmt::format("service started {}",
                           ui::dim("— proctun status for state, proctun down to stop")));
        ui::blank();
        return 0;
    }
    if (app.got_subcommand("down")) {
        std::string err;
        if (!svc::stop(err)) { ui::fail("down: " + err); return 1; }
        ui::blank();
        ui::ok("service stopped");
        ui::blank();
        return 0;
    }

    return 0;
}
