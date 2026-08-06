#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace proctun {

struct AdapterInfo {
    std::string guid;
    std::string friendly;
    std::string description;
    std::string ipv4;
    std::string gateway_v4;
    uint32_t    if_index = 0;
    uint8_t     prefix_v4 = 0;
    bool        is_up = false;
    bool        is_tunnel = false;
};

std::vector<AdapterInfo> enumerate_adapters();

const AdapterInfo* pick_wan(const std::vector<AdapterInfo>& all);

bool redirect_gateway_active();

}
