#if PROCTUN_WITH_NDISAPI
#include "ndis_prelude.hpp"
#endif

#include "engine.hpp"
#include "log.hpp"

#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <mutex>

namespace proctun {

#if PROCTUN_WITH_NDISAPI

namespace {
constexpr auto kPass = [](HANDLE, INTERMEDIATE_BUFFER&) {
    return ndisapi::fastio_packet_filter::packet_action::pass;
};
}

bool ndis_driver_loaded() {
    ndisapi::fastio_packet_filter probe(kPass, kPass, false);
    return probe.IsDriverLoaded();
}

std::vector<NdisIface> ndis_interfaces() {
    std::vector<NdisIface> out;
    ndisapi::fastio_packet_filter probe(kPass, kPass, false);
    if (!probe.IsDriverLoaded()) return out;
    for (const auto& a : probe.get_interface_list())
        out.push_back({a->get_internal_name(), a->get_friendly_name()});
    return out;
}

namespace {
std::string summarize(INTERMEDIATE_BUFFER& buf) {
    auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
    if (ntohs(eth->h_proto) != ETH_P_IP) return {};
    auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);

    std::ostringstream os;
    auto* l4 = reinterpret_cast<const uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
    if (ip->ip_p == IPPROTO_TCP) {
        auto* t = reinterpret_cast<const tcphdr*>(l4);
        os << "TCP " << net::ip_address_v4(ip->ip_src) << ':' << ntohs(t->th_sport)
           << " -> " << net::ip_address_v4(ip->ip_dst) << ':' << ntohs(t->th_dport);
    } else if (ip->ip_p == IPPROTO_UDP) {
        auto* u = reinterpret_cast<const udphdr*>(l4);
        os << "UDP " << net::ip_address_v4(ip->ip_src) << ':' << ntohs(u->th_sport)
           << " -> " << net::ip_address_v4(ip->ip_dst) << ':' << ntohs(u->th_dport);
    } else {
        os << "IP proto " << int(ip->ip_p) << ' '
           << net::ip_address_v4(ip->ip_src) << " -> " << net::ip_address_v4(ip->ip_dst);
    }
    return os.str();
}
}

bool ndis_sniff(size_t index, int seconds) {
    std::atomic<uint64_t> total{0};
    std::atomic<uint64_t> logged{0};
    constexpr uint64_t kMaxLogged = 40;

    auto on_packet = [&](const char* dir, INTERMEDIATE_BUFFER& buf) {
        ++total;
        if (logged.load() < kMaxLogged) {
            if (auto s = summarize(buf); !s.empty()) {
                spdlog::info("  [{}] {}", dir, s);
                ++logged;
            }
        }
        return ndisapi::fastio_packet_filter::packet_action::pass;
    };

    ndisapi::fastio_packet_filter filter(
        [&](HANDLE, INTERMEDIATE_BUFFER& b) { return on_packet("in ", b); },
        [&](HANDLE, INTERMEDIATE_BUFFER& b) { return on_packet("out", b); },
        true);

    if (!filter.IsDriverLoaded()) {
        spdlog::error("WinpkFilter driver is not loaded. Install the WinpkFilter "
                      "kernel driver, then run from an elevated shell.");
        return false;
    }

    auto ifaces = filter.get_interface_names_list();
    if (index >= ifaces.size()) {
        spdlog::error("Interface index {} out of range (have {}).", index, ifaces.size());
        return false;
    }

    spdlog::info("Sniffing '{}' for {}s (pass-through)...", ifaces[index], seconds);
    if (!filter.start_filter(index)) {
        spdlog::error("start_filter({}) failed.", index);
        return false;
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    filter.stop_filter();
    spdlog::info("Done. Captured {} packet(s) on '{}'.", total.load(), ifaces[index]);
    return true;
}

namespace {

using packet_action = ndisapi::dual_packet_filter::packet_action;

std::wstring utf8_to_wlower(const std::string& s) {
    std::wstring w;
    if (!s.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        w.resize(n);
        MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    }
    for (auto& c : w) c = (wchar_t)towlower(c);
    return w;
}

bool is_private_v4(const net::ip_address_v4& ip) {
    uint32_t a = ntohl(static_cast<uint32_t>(in_addr(ip).S_un.S_addr));
    uint32_t o1 = a >> 24;
    return o1 == 10 || o1 == 127 || o1 == 0 || o1 >= 224 || // 10/8, loopback, 0/8, multicast+
           (a >> 20) == 0xAC1 ||                            // 172.16.0.0/12
           (a >> 16) == 0xC0A8 ||                           // 192.168.0.0/16
           (a >> 16) == 0xA9FE;                             // 169.254.0.0/16 link-local
}

}

class RouterEngine {
public:
    bool init(const Config& cfg, const AdapterInfo& wan, const AdapterInfo& tun) {
        exclude_mode_ = (cfg.mode == Mode::Exclude);
        full_tunnel_ = redirect_gateway_active();
        for (const auto& r : cfg.rules)
            masks_.push_back(utf8_to_wlower(r.match));
        if (!exclude_mode_ && masks_.empty()) {
            spdlog::error("Include mode with no rules tunnels nothing. Add one: proctun add <exe>");
            return false;
        }
        wan_ip_ = net::ip_address_v4(wan.ipv4);
        tap_ip_ = net::ip_address_v4(tun.ipv4);
        wan_name_ = wan.friendly; tun_name_ = tun.friendly;
        wan_ip_str_ = wan.ipv4;   tun_ip_str_ = tun.ipv4;
        wan_guid_ = wan.guid;     tun_guid_ = tun.guid;

        using cb_t = std::function<packet_action(HANDLE, INTERMEDIATE_BUFFER&)>;
        cb_t wan_in, wan_out, tap_in, tap_out;
        if (full_tunnel_) {
            wan_in  = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_wan_in_m(b); };
            wan_out = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_wan_out_m(b); };
            tap_in  = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_tap_in_m(b); };
            tap_out = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_tap_out_m(b); };
        } else {
            wan_out = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_wan_out(b); };
            tap_in  = [this](HANDLE, INTERMEDIATE_BUFFER& b) { return on_tap_in(b); };
        }
        filter_ = std::make_unique<ndisapi::dual_packet_filter>(wan_in, wan_out, tap_in, tap_out);

        if (!filter_->IsDriverLoaded()) {
            spdlog::error("WinpkFilter driver not loaded.");
            return false;
        }

        for (const auto& a : filter_->get_interface_list()) {
            const auto& name = a->get_internal_name();
            if (name.find(wan.guid) != std::string::npos) {
                wan_h_ = a->get_adapter(); wan_mac_ = a->get_hw_address();
            }
            if (name.find(tun.guid) != std::string::npos) {
                tap_h_ = a->get_adapter(); tap_mac_ = a->get_hw_address();
            }
        }
        if (!wan_h_ || !tap_h_) {
            spdlog::error("Could not bind NDIS handles (wan_h={}, tap_h={}).",
                          (void*)wan_h_, (void*)tap_h_);
            return false;
        }

        block_ipv6_ = cfg.leakguard && cfg.block_ipv6;
        tunnel_dns_ = cfg.leakguard && cfg.tunnel_dns;
        if (tunnel_dns_) {
            if (cfg.dns_server.empty()) { spdlog::error("tunnel_dns on but dns_server is empty."); return false; }
            dns_server_ = net::ip_address_v4(cfg.dns_server);
        }
        if (!cfg.tunnel_remote.empty()) {
            in_addr tmp{};
            if (inet_pton(AF_INET, cfg.tunnel_remote.c_str(), &tmp) == 1) {
                tunnel_remote_ = net::ip_address_v4(cfg.tunnel_remote);
                has_remote_ = true;
            } else {
                spdlog::error("Invalid tunnel_remote '{}'.", cfg.tunnel_remote);
                return false;
            }
        } else if (exclude_mode_ && !full_tunnel_) {
            spdlog::error("Exclude mode requires tunnel_remote (the VPN server IP) — otherwise "
                          "the OpenVPN transport itself would be routed into its own tunnel. "
                          "Set it: proctun set --tunnel-remote <server-ip>.");
            return false;
        }

        // The tunnel gateway MAC is needed to inject into the tunnel: always in
        // classic mode, only for the DNS hijack in full-tunnel mode.
        if (!full_tunnel_ || tunnel_dns_) {
            std::string gw_ip = cfg.tun_gateway.empty() ? tun.gateway_v4 : cfg.tun_gateway;
            if (gw_ip.empty()) {
                spdlog::error("Tunnel gateway IP unknown. Set \"tun_gateway\" in config to "
                              "the OpenVPN route-gateway (see the connect log, e.g. 10.8.0.1).");
                return false;
            }
            in_addr gw_addr{};
            if (inet_pton(AF_INET, gw_ip.c_str(), &gw_addr) != 1) {
                spdlog::error("Invalid tun_gateway '{}'.", gw_ip);
                return false;
            }
            if (in_addr tun_addr{}; tun.prefix_v4 > 0 && tun.prefix_v4 <= 32 &&
                inet_pton(AF_INET, tun.ipv4.c_str(), &tun_addr) == 1) {
                const uint32_t mask = ~0u << (32 - tun.prefix_v4);
                if ((ntohl(gw_addr.S_un.S_addr) & mask) != (ntohl(tun_addr.S_un.S_addr) & mask)) {
                    spdlog::error("tun_gateway {} is outside the tun adapter's subnet {}/{} — it "
                                  "belongs to another tunnel. Use the route-gateway of the session "
                                  "that owns '{}', or pin the right adapter with --tun.",
                                  gw_ip, tun.ipv4, tun.prefix_v4, tun.friendly);
                    return false;
                }
            }
            unsigned char macbuf[8] = {};
            ULONG maclen = 6;
            if (SendARP(static_cast<IPAddr>(gw_addr.S_un.S_addr), 0, macbuf, &maclen) != NO_ERROR ||
                maclen < 6) {
                spdlog::error("Could not resolve MAC of tunnel gateway {}. Ping it once "
                              "(ping {}) so it enters the ARP table, then retry.", gw_ip, gw_ip);
                return false;
            }
            std::memcpy(tap_gw_mac_.data.data(), macbuf, 6);
        }

        if (full_tunnel_) {
            if (wan.gateway_v4.empty()) {
                spdlog::error("full-tunnel mode: WAN adapter '{}' has no default gateway to "
                              "send extracted traffic through.", wan.friendly);
                return false;
            }
            in_addr wgw{};
            if (inet_pton(AF_INET, wan.gateway_v4.c_str(), &wgw) != 1) {
                spdlog::error("Invalid WAN gateway '{}'.", wan.gateway_v4);
                return false;
            }
            unsigned char macbuf[8] = {};
            ULONG maclen = 6;
            if (SendARP(static_cast<IPAddr>(wgw.S_un.S_addr), 0, macbuf, &maclen) != NO_ERROR ||
                maclen < 6) {
                spdlog::error("Could not resolve MAC of WAN gateway {}. Ping it once "
                              "(ping {}) so it enters the ARP table, then retry.",
                              wan.gateway_v4, wan.gateway_v4);
                return false;
            }
            std::memcpy(wan_gw_mac_.data.data(), macbuf, 6);
        }

        if (!filter_->start_filter(wan_h_, 0) || !filter_->start_filter(tap_h_, 1)) {
            spdlog::error("start_filter failed.");
            return false;
        }
        monitor_ = std::thread([this] { monitor_loop(); });
        return true;
    }

    ~RouterEngine() {
        mon_exit_.store(true);
        if (monitor_.joinable()) monitor_.join();
        filter_.reset();
    }

    EngineStats snapshot() const {
        EngineStats s;
        s.running = true;
        s.armed = armed_.load();
        s.mode = exclude_mode_ ? "exclude" : "include";
        if (full_tunnel_) s.mode += "/full-tunnel";
        s.full_tunnel = full_tunnel_;
        s.wan = wan_name_; s.tun = tun_name_;
        s.wan_ip = wan_ip_str_; s.tun_ip = tun_ip_str_;
        s.tunneled = n_tun_.load(); s.dns = n_dns_.load();
        s.v6_dropped = n_v6drop_.load(); s.killed = n_kill_.load();
        { std::lock_guard<std::mutex> lk(dns_mtx_); s.conntrack = dns_map_.size(); }
        { std::lock_guard<std::mutex> lk(nat_mtx_); s.conntrack += nat_map_.size(); }
        return s;
    }

private:
    bool name_matches(const std::wstring& lower_path) const {
        for (const auto& m : masks_)
            if (!m.empty() && lower_path.find(m) != std::wstring::npos) return true;
        return false;
    }

    static uint16_t l4_sport(uint8_t proto, void* l4) {
        return ntohs(proto == IPPROTO_TCP ? static_cast<tcphdr*>(l4)->th_sport
                                          : static_cast<udphdr*>(l4)->th_sport);
    }
    static uint16_t l4_dport(uint8_t proto, void* l4) {
        return ntohs(proto == IPPROTO_TCP ? static_cast<tcphdr*>(l4)->th_dport
                                          : static_cast<udphdr*>(l4)->th_dport);
    }

    static void fix_checksums(INTERMEDIATE_BUFFER& buf, iphdr_ptr ip) {
        if (ip->ip_p == IPPROTO_TCP) CNdisApi::RecalculateTCPChecksum(&buf);
        else                         CNdisApi::RecalculateUDPChecksum(&buf);
        CNdisApi::RecalculateIPChecksum(&buf);
    }

    void snat_to_tun(INTERMEDIATE_BUFFER& buf, ether_header_ptr eth, iphdr_ptr ip) {
        ip->ip_src = tap_ip_;
        std::memcpy(eth->h_source, tap_mac_.data.data(), tap_mac_.data.size());
        std::memcpy(eth->h_dest,   tap_gw_mac_.data.data(), tap_gw_mac_.data.size());
        fix_checksums(buf, ip);
    }

    void snat_to_wan(INTERMEDIATE_BUFFER& buf, ether_header_ptr eth, iphdr_ptr ip) {
        ip->ip_src = wan_ip_;
        std::memcpy(eth->h_source, wan_mac_.data.data(), wan_mac_.data.size());
        std::memcpy(eth->h_dest,   wan_gw_mac_.data.data(), wan_gw_mac_.data.size());
        fix_checksums(buf, ip);
    }

    bool process_tunneled(const std::shared_ptr<iphelper::network_process>& proc) const {
        const bool matched = proc && name_matches(towlower_copy(proc->path_name));
        return exclude_mode_ ? !matched : matched;
    }

    packet_action wan_out_v6(INTERMEDIATE_BUFFER& buf, ether_header_ptr eth) {
        if (!block_ipv6_ && !tunnel_dns_) return packet_action::pass;
        auto* ip6 = reinterpret_cast<ipv6hdr_ptr>(eth + 1);
        auto [l4, proto] = net::ipv6_helper::find_transport_header(
            ip6, buf.m_Length - ETHER_HEADER_LENGTH);
        if (!l4 || (proto != IPPROTO_TCP && proto != IPPROTO_UDP)) return packet_action::pass;
        if (tunnel_dns_ && l4_dport(proto, l4) == 53) { ++n_v6drop_; return packet_action::drop; }
        if (!block_ipv6_) return packet_action::pass;
        auto proc = resolve6(proto, ip6, l4_sport(proto, l4), l4_dport(proto, l4));
        if (process_tunneled(proc)) { ++n_v6drop_; return packet_action::drop; }
        return packet_action::pass;
    }

    packet_action on_wan_out(INTERMEDIATE_BUFFER& buf) {
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        const uint16_t etype = ntohs(eth->h_proto);

        if (etype == ETH_P_IPV6) return wan_out_v6(buf, eth);

        if (etype != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_src) != wan_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        const uint16_t sport = l4_sport(ip->ip_p, l4);
        const uint16_t dport = l4_dport(ip->ip_p, l4);

        if (tunnel_dns_ && dport == 53) {
            if (!armed_.load()) { ++n_kill_; return packet_action::drop; }
            { std::lock_guard<std::mutex> lk(dns_mtx_);
              dns_map_[dns_key(ip->ip_p, sport)] =
                  {net::ip_address_v4(ip->ip_dst), std::chrono::steady_clock::now()}; }
            ip->ip_dst = dns_server_;
            snat_to_tun(buf, eth, ip);
            ++n_dns_;
            return packet_action::route;
        }

        if (is_private_v4(net::ip_address_v4(ip->ip_dst))) return packet_action::pass;
        if (has_remote_ && net::ip_address_v4(ip->ip_dst) == tunnel_remote_) return packet_action::pass;

        auto proc = (ip->ip_p == IPPROTO_TCP) ? resolve_tcp(ip, reinterpret_cast<tcphdr*>(l4))
                                              : resolve_udp(ip, reinterpret_cast<udphdr*>(l4));
        if (!process_tunneled(proc)) return packet_action::pass;
        if (!armed_.load()) { ++n_kill_; return packet_action::drop; }
        snat_to_tun(buf, eth, ip);
        ++n_tun_;
        return packet_action::route;
    }

    void monitor_loop() {
        bool last = armed_.load();
        // full-tunnel guards the escape hatch (WAN); classic guards the tunnel.
        const std::string& guard_guid = full_tunnel_ ? wan_guid_ : tun_guid_;
        const std::string& guard_ip   = full_tunnel_ ? wan_ip_str_ : tun_ip_str_;
        bool strategy_warned = false;
        while (!mon_exit_.load()) {
            bool up = false;
            for (const auto& a : enumerate_adapters())
                if (a.guid == guard_guid) { up = a.is_up && a.ipv4 == guard_ip; break; }
            armed_.store(up);
            if (up != last) {
                spdlog::warn("kill-switch: {} {} — {} traffic {}",
                             full_tunnel_ ? "wan" : "tunnel", up ? "UP" : "DOWN",
                             full_tunnel_ ? "extracted" : "tunneled",
                             up ? "flowing" : "BLOCKED");
                last = up;
            }
            if (const bool rg = redirect_gateway_active(); rg != full_tunnel_) {
                if (!strategy_warned) {
                    spdlog::warn("redirect-gateway {} after start — the {} strategy is stale; "
                                 "restart proctun to switch.",
                                 rg ? "appeared" : "disappeared",
                                 full_tunnel_ ? "FULL-TUNNEL" : "CLASSIC");
                    strategy_warned = true;
                }
            } else strategy_warned = false;
            {
                std::lock_guard<std::mutex> lk(dns_mtx_);
                const auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(2);
                std::erase_if(dns_map_, [&](const auto& kv) { return kv.second.ts < cutoff; });
            }
            {
                std::lock_guard<std::mutex> lk(nat_mtx_);
                const auto now = std::chrono::steady_clock::now();
                std::erase_if(nat_map_, [&](const auto& kv) {
                    const bool tcp = (kv.first >> 16) == IPPROTO_TCP;
                    return kv.second < now - (tcp ? std::chrono::minutes(60)
                                                  : std::chrono::minutes(5));
                });
            }
            for (int i = 0; i < 20 && !mon_exit_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    packet_action on_tap_in(INTERMEDIATE_BUFFER& buf) {
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_dst) != tap_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        if (tunnel_dns_ && l4_sport(ip->ip_p, l4) == 53) {
            const uint16_t dport = l4_dport(ip->ip_p, l4); // = original client source port
            std::lock_guard<std::mutex> lk(dns_mtx_);
            if (auto it = dns_map_.find(dns_key(ip->ip_p, dport)); it != dns_map_.end())
                ip->ip_src = it->second.ip;
        }
        ip->ip_dst = wan_ip_;
        std::memcpy(eth->h_dest, wan_mac_.data.data(), wan_mac_.data.size());
        fix_checksums(buf, ip);
        return packet_action::route;
    }

    // full-tunnel strategy: the OS default route already points into the tunnel,
    // so direct-bound traffic is pulled OUT of it instead of pushed in.

    packet_action on_tap_out_m(INTERMEDIATE_BUFFER& buf) {
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_src) != tap_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        const uint16_t sport = l4_sport(ip->ip_p, l4);
        const uint16_t dport = l4_dport(ip->ip_p, l4);

        if (tunnel_dns_ && dport == 53) {
            { std::lock_guard<std::mutex> lk(dns_mtx_);
              dns_map_[dns_key(ip->ip_p, sport)] =
                  {net::ip_address_v4(ip->ip_dst), std::chrono::steady_clock::now(), false}; }
            ip->ip_dst = dns_server_;
            fix_checksums(buf, ip);
            ++n_dns_;
            return packet_action::pass; // stays in the tunnel, just re-aimed
        }

        if (is_private_v4(net::ip_address_v4(ip->ip_dst))) return packet_action::pass;
        if (has_remote_ && net::ip_address_v4(ip->ip_dst) == tunnel_remote_) return packet_action::pass;

        auto proc = (ip->ip_p == IPPROTO_TCP) ? resolve_tcp(ip, reinterpret_cast<tcphdr*>(l4))
                                              : resolve_udp(ip, reinterpret_cast<udphdr*>(l4));
        if (process_tunneled(proc)) return packet_action::pass;
        if (!armed_.load()) { ++n_kill_; return packet_action::drop; }
        { std::lock_guard<std::mutex> lk(nat_mtx_);
          nat_map_[dns_key(ip->ip_p, sport)] = std::chrono::steady_clock::now(); }
        snat_to_wan(buf, eth, ip);
        ++n_tun_;
        return packet_action::route;
    }

    packet_action on_wan_in_m(INTERMEDIATE_BUFFER& buf) {
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_dst) != wan_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        {
            std::lock_guard<std::mutex> lk(nat_mtx_);
            auto it = nat_map_.find(dns_key(ip->ip_p, l4_dport(ip->ip_p, l4)));
            if (it == nat_map_.end()) return packet_action::pass; // native WAN traffic
            it->second = std::chrono::steady_clock::now();
        }
        ip->ip_dst = tap_ip_;
        std::memcpy(eth->h_dest, tap_mac_.data.data(), tap_mac_.data.size());
        fix_checksums(buf, ip);
        return packet_action::route; // on an incoming packet: up the tun adapter's stack
    }

    packet_action on_wan_out_m(INTERMEDIATE_BUFFER& buf) {
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        const uint16_t etype = ntohs(eth->h_proto);

        if (etype == ETH_P_IPV6) return wan_out_v6(buf, eth);

        if (etype != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_src) != wan_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        // DNS that escaped the tunnel (e.g. a LAN resolver) is still hijacked into it;
        // anything else on WAN is there because the OS routed it there.
        if (tunnel_dns_ && l4_dport(ip->ip_p, l4) == 53) {
            { std::lock_guard<std::mutex> lk(dns_mtx_);
              dns_map_[dns_key(ip->ip_p, l4_sport(ip->ip_p, l4))] =
                  {net::ip_address_v4(ip->ip_dst), std::chrono::steady_clock::now(), true}; }
            ip->ip_dst = dns_server_;
            snat_to_tun(buf, eth, ip);
            ++n_dns_;
            return packet_action::route;
        }
        return packet_action::pass;
    }

    packet_action on_tap_in_m(INTERMEDIATE_BUFFER& buf) {
        if (!tunnel_dns_) return packet_action::pass;
        auto* eth = reinterpret_cast<ether_header_ptr>(buf.m_IBuffer);
        if (ntohs(eth->h_proto) != ETH_P_IP) return packet_action::pass;
        auto* ip = reinterpret_cast<iphdr_ptr>(eth + 1);
        if (net::ip_address_v4(ip->ip_dst) != tap_ip_) return packet_action::pass;
        if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return packet_action::pass;
        if (ntohs(ip->ip_off) & (IP_MF | 0x1FFF)) return packet_action::pass;

        auto* l4 = reinterpret_cast<uint8_t*>(ip) + sizeof(DWORD) * ip->ip_hl;
        if (l4_sport(ip->ip_p, l4) != 53) return packet_action::pass;

        DnsOrigin origin;
        {
            std::lock_guard<std::mutex> lk(dns_mtx_);
            auto it = dns_map_.find(dns_key(ip->ip_p, l4_dport(ip->ip_p, l4)));
            if (it == dns_map_.end()) return packet_action::pass;
            origin = it->second;
        }
        ip->ip_src = origin.ip;
        if (origin.from_wan) {
            ip->ip_dst = wan_ip_;
            std::memcpy(eth->h_dest, wan_mac_.data.data(), wan_mac_.data.size());
            fix_checksums(buf, ip);
            return packet_action::route;
        }
        fix_checksums(buf, ip);
        return packet_action::pass;
    }

    static std::wstring towlower_copy(std::wstring s) {
        for (auto& c : s) c = (wchar_t)towlower(c);
        return s;
    }

    static std::shared_ptr<iphelper::network_process> resolve_tcp(const iphdr* ip, const tcphdr* t) {
        using PL = iphelper::process_lookup<net::ip_address_v4>;
        net::ip_session<net::ip_address_v4> s{ip->ip_src, ip->ip_dst, ntohs(t->th_sport), ntohs(t->th_dport)};
        auto p = PL::get_process_helper().lookup_process_for_tcp<false>(s);
        if (!p) { PL::get_process_helper().actualize(true, false);
                  p = PL::get_process_helper().lookup_process_for_tcp<true>(s); }
        return p;
    }
    static std::shared_ptr<iphelper::network_process> resolve_udp(const iphdr* ip, const udphdr* u) {
        using PL = iphelper::process_lookup<net::ip_address_v4>;
        net::ip_endpoint<net::ip_address_v4> e{ip->ip_src, ntohs(u->th_sport)};
        auto p = PL::get_process_helper().lookup_process_for_udp<false>(e);
        if (!p) { PL::get_process_helper().actualize(false, true);
                  p = PL::get_process_helper().lookup_process_for_udp<true>(e); }
        return p;
    }
    static std::shared_ptr<iphelper::network_process> resolve6(
            unsigned char proto, const ipv6hdr* ip6, uint16_t sport, uint16_t dport) {
        using PL = iphelper::process_lookup<net::ip_address_v6>;
        if (proto == IPPROTO_TCP) {
            net::ip_session<net::ip_address_v6> s{net::ip_address_v6(ip6->ip6_src),
                net::ip_address_v6(ip6->ip6_dst), sport, dport};
            auto p = PL::get_process_helper().lookup_process_for_tcp<false>(s);
            if (!p) { PL::get_process_helper().actualize(true, false);
                      p = PL::get_process_helper().lookup_process_for_tcp<true>(s); }
            return p;
        }
        net::ip_endpoint<net::ip_address_v6> e{net::ip_address_v6(ip6->ip6_src), sport};
        auto p = PL::get_process_helper().lookup_process_for_udp<false>(e);
        if (!p) { PL::get_process_helper().actualize(false, true);
                  p = PL::get_process_helper().lookup_process_for_udp<true>(e); }
        return p;
    }

    std::unique_ptr<ndisapi::dual_packet_filter> filter_;
    HANDLE wan_h_ = nullptr, tap_h_ = nullptr;
    net::ip_address_v4 wan_ip_{}, tap_ip_{}, dns_server_{}, tunnel_remote_{};
    net::mac_address wan_mac_{}, tap_mac_{}, tap_gw_mac_{}, wan_gw_mac_{};
    std::vector<std::wstring> masks_;
    bool block_ipv6_ = false, tunnel_dns_ = false, exclude_mode_ = false, has_remote_ = false;
    bool full_tunnel_ = false;

    struct DnsOrigin { net::ip_address_v4 ip; std::chrono::steady_clock::time_point ts;
                       bool from_wan = true; };
    static uint32_t dns_key(uint8_t proto, uint16_t port) { return (uint32_t(proto) << 16) | port; }
    std::unordered_map<uint32_t, DnsOrigin> dns_map_; // (proto, client port) -> original resolver
    mutable std::mutex dns_mtx_;

    // full-tunnel strategy: (proto, local port) of flows extracted out via WAN
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> nat_map_;
    mutable std::mutex nat_mtx_;

    std::atomic<bool> armed_{true};
    std::atomic<bool> mon_exit_{false};
    std::thread monitor_;
    mutable std::atomic<uint64_t> n_tun_{0}, n_dns_{0}, n_v6drop_{0}, n_kill_{0};
    std::string wan_name_, tun_name_, wan_ip_str_, tun_ip_str_, wan_guid_, tun_guid_;
};

bool Engine::start(const Config& cfg, const AdapterInfo& wan, const AdapterInfo& tun) {
    if (running_) { spdlog::error("engine.start: already running"); return false; }
    auto* router = new RouterEngine();
    if (!router->init(cfg, wan, tun)) { delete router; return false; }
    impl_ = router;
    running_ = true;
    return true;
}

EngineStats Engine::stats() const {
    if (impl_) return static_cast<RouterEngine*>(impl_)->snapshot();
    EngineStats s; s.running = running_; return s;
}

#else

bool ndis_driver_loaded() { return false; }
std::vector<NdisIface> ndis_interfaces() {
    spdlog::error("Built without WinpkFilter. Reconfigure with the "
                  "'win-amd64-release-vs2026-ndis' preset after cloning vendor/ndisapi.");
    return {};
}
bool ndis_sniff(size_t, int) {
    spdlog::error("Built without WinpkFilter (see ndis_interfaces error).");
    return false;
}
bool Engine::start(const Config&, const AdapterInfo& wan, const AdapterInfo& tun) {
    spdlog::error("engine.start: built without WinpkFilter. wan={}, tun={}",
                  wan.friendly, tun.friendly);
    return false;
}
EngineStats Engine::stats() const { EngineStats s; s.running = running_; return s; }

#endif

bool resolve_endpoints(const Config& cfg, AdapterInfo& wan, AdapterInfo& tun, std::string& err) {
    auto all = enumerate_adapters();
    const AdapterInfo* w = nullptr;
    const AdapterInfo* t = nullptr;
    for (const auto& a : all) {
        if (!cfg.wan_alias.empty() && (a.friendly == cfg.wan_alias || a.guid == cfg.wan_alias)) w = &a;
        if (!cfg.tun_alias.empty() && (a.friendly == cfg.tun_alias || a.guid == cfg.tun_alias)) t = &a;
        if (!t && cfg.tun_alias.empty() && a.is_up && !a.ipv4.empty() && a.is_tunnel) t = &a;
    }
    if (!w) w = pick_wan(all);
    if (!w || !t) {
        err = "could not resolve adapters — bring up OpenVPN (dev tap) or set wan_alias/tun_alias (GUID)";
        return false;
    }
    if (w->guid == t->guid) {
        err = "WAN resolved to the tunnel adapter — pin the physical one: proctun set --wan <GUID>";
        return false;
    }
    wan = *w;
    tun = *t;
    return true;
}

void Engine::stop() {
    if (running_) spdlog::debug("engine.stop");
#if PROCTUN_WITH_NDISAPI
    delete static_cast<RouterEngine*>(impl_);
#endif
    impl_ = nullptr;
    running_ = false;
}

Engine::~Engine() { stop(); }

}
