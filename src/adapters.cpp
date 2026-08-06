#include "adapters.hpp"
#include "log.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>

namespace proctun {

namespace {
std::string sockaddr_to_str(const SOCKADDR* sa) {
    if (!sa || sa->sa_family != AF_INET) return {};
    char buf[INET_ADDRSTRLEN] = {};
    auto* in = reinterpret_cast<const sockaddr_in*>(sa);
    inet_ntop(AF_INET, &in->sin_addr, buf, sizeof buf);
    return buf;
}

std::string wide_to_utf8(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}
}

std::vector<AdapterInfo> enumerate_adapters() {
    std::vector<AdapterInfo> out;
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    DWORD rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc != NO_ERROR) {
        spdlog::error("GetAdaptersAddresses failed: {}", rc);
        return out;
    }

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        AdapterInfo info;
        info.guid        = a->AdapterName ? a->AdapterName : "";
        info.friendly    = wide_to_utf8(a->FriendlyName);
        info.description = wide_to_utf8(a->Description);
        info.if_index    = a->IfIndex;
        info.is_up       = (a->OperStatus == IfOperStatusUp);
        info.is_tunnel   = (a->IfType == IF_TYPE_TUNNEL) ||
                           info.description.find("TAP") != std::string::npos ||
                           info.description.find("OpenVPN") != std::string::npos;

        if (a->FirstUnicastAddress) {
            info.ipv4 = sockaddr_to_str(a->FirstUnicastAddress->Address.lpSockaddr);
            info.prefix_v4 = a->FirstUnicastAddress->OnLinkPrefixLength;
        }
        if (a->FirstGatewayAddress)
            info.gateway_v4 = sockaddr_to_str(a->FirstGatewayAddress->Address.lpSockaddr);

        out.push_back(std::move(info));
    }
    return out;
}

namespace {
std::vector<unsigned char> ip_forward_table() {
    ULONG size = 0;
    if (GetIpForwardTable(nullptr, &size, FALSE) != ERROR_INSUFFICIENT_BUFFER) return {};
    std::vector<unsigned char> buf(size);
    if (GetIpForwardTable(reinterpret_cast<MIB_IPFORWARDTABLE*>(buf.data()), &size, FALSE) != NO_ERROR)
        return {};
    return buf;
}
}

const AdapterInfo* pick_wan(const std::vector<AdapterInfo>& all) {
    // Lowest-metric true default route (0.0.0.0/0) on a non-tunnel adapter. The /1
    // pair installed by redirect-gateway never matches mask 0, so it cannot hijack
    // the pick.
    const AdapterInfo* best = nullptr;
    DWORD best_metric = ~0ul;
    if (auto buf = ip_forward_table(); !buf.empty()) {
        auto* tbl = reinterpret_cast<const MIB_IPFORWARDTABLE*>(buf.data());
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& r = tbl->table[i];
            if (r.dwForwardMask != 0 || r.dwForwardMetric1 >= best_metric) continue;
            for (const auto& a : all)
                if (a.if_index == r.dwForwardIfIndex && a.is_up && !a.is_tunnel && !a.ipv4.empty()) {
                    best = &a;
                    best_metric = r.dwForwardMetric1;
                    break;
                }
        }
    }
    if (best) return best;

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    DWORD best_if = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&dst), &best_if) == NO_ERROR) {
        for (const auto& a : all)
            if (a.if_index == best_if && !a.ipv4.empty() && !a.is_tunnel) return &a;
    }
    for (const auto& a : all)
        if (a.is_up && !a.is_tunnel && !a.ipv4.empty() && !a.gateway_v4.empty())
            return &a;
    return nullptr;
}

bool redirect_gateway_active() {
    auto buf = ip_forward_table();
    if (buf.empty()) return false;
    auto* tbl = reinterpret_cast<const MIB_IPFORWARDTABLE*>(buf.data());
    for (DWORD i = 0; i < tbl->dwNumEntries; ++i)
        if (tbl->table[i].dwForwardMask == htonl(0x80000000u)) return true;
    return false;
}

}
