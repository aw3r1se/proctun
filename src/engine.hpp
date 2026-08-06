#pragma once
#include "config.hpp"
#include "adapters.hpp"

#include <string>
#include <vector>

namespace proctun {

struct EngineStats {
    bool running = false;
    bool armed = false;
    bool full_tunnel = false;
    std::string mode;
    std::string wan, tun;
    std::string wan_ip, tun_ip;
    unsigned long long tunneled = 0;
    unsigned long long dns = 0;
    unsigned long long v6_dropped = 0;
    unsigned long long killed = 0;
    unsigned long long conntrack = 0;
};

bool resolve_endpoints(const Config& cfg, AdapterInfo& wan, AdapterInfo& tun, std::string& err);

bool ndis_driver_loaded();

struct NdisIface { std::string internal; std::string friendly; };
std::vector<NdisIface> ndis_interfaces();

bool ndis_sniff(size_t index, int seconds);

class Engine {
public:
    ~Engine();
    bool start(const Config& cfg, const AdapterInfo& wan, const AdapterInfo& tun);
    void stop();
    bool running() const { return running_; }
    EngineStats stats() const;

private:
    bool running_ = false;
    void* impl_ = nullptr;
};

}
