#pragma once
#include <string>

namespace proctun::driver {

struct InitOptions {
    bool yes = false;
    bool force = false;
    std::string msi_path;
};

int run_init(const InitOptions& opt);

int run_update();

}
