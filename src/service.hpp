#pragma once
#include <string>
#include <filesystem>

namespace proctun::svc {

constexpr const wchar_t* kServiceName = L"proctun";

bool install(std::string& err, const std::filesystem::path& exe = {});
bool uninstall(std::string& err);
bool start(std::string& err);
bool stop(std::string& err);
bool wait_running(int timeout_ms);
bool is_installed();
bool is_running();

int run_dispatcher();

std::string stats_path();

}
