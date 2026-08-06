#include "service.hpp"
#include "config.hpp"
#include "engine.hpp"
#include "log.hpp"

#include <windows.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <vector>

namespace proctun::svc {

namespace {

std::filesystem::path data_dir() {
    const char* pd = std::getenv("ProgramData");
    return std::filesystem::path(pd ? pd : ".") / "proctun";
}

struct ScmHandle {
    SC_HANDLE h = nullptr;
    ScmHandle(SC_HANDLE x) : h(x) {}
    ~ScmHandle() { if (h) CloseServiceHandle(h); }
    explicit operator bool() const { return h != nullptr; }
};

std::string last_error(const char* what) {
    return std::string(what) + " failed (err " + std::to_string(GetLastError()) + ")";
}

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
HANDLE g_stop_event = nullptr;
SERVICE_STATUS g_status = {};

void report(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint = wait_hint;
    static DWORD checkpoint = 0;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : ++checkpoint;
    SetServiceStatus(g_status_handle, &g_status);
}

void write_stats(const EngineStats& s) {
    nlohmann::json j{
        {"running", s.running}, {"armed", s.armed}, {"mode", s.mode},
        {"wan", s.wan}, {"wan_ip", s.wan_ip}, {"tun", s.tun}, {"tun_ip", s.tun_ip},
        {"tunneled", s.tunneled}, {"dns", s.dns}, {"v6_dropped", s.v6_dropped},
        {"killed", s.killed}, {"conntrack", s.conntrack},
    };
    std::error_code ec;
    std::filesystem::create_directories(data_dir(), ec);
    std::ofstream f(stats_path());
    if (f) f << j.dump(2);
}

void WINAPI service_ctrl(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_stop_event) SetEvent(g_stop_event);
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerW(kServiceName, service_ctrl);
    if (!g_status_handle) return;
    report(SERVICE_START_PENDING, NO_ERROR, 3000);

    try {
        std::error_code ec; std::filesystem::create_directories(data_dir(), ec);
        auto logger = spdlog::basic_logger_mt("svc", (data_dir() / "proctun.log").string(), true);
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::info);
        spdlog::flush_on(spdlog::level::info);
    } catch (...) {}

    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    Config cfg = Config::load(Config::default_path());
    AdapterInfo wan, tun;
    std::string err;
    if (!resolve_endpoints(cfg, wan, tun, err)) {
        spdlog::error("service: {}", err);
        report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    Engine engine;
    if (!engine.start(cfg, wan, tun)) {
        spdlog::error("service: engine failed to start");
        report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    report(SERVICE_RUNNING);
    {
        const auto st = engine.stats();
        spdlog::info("service running: {} mode, {} strategy, wan {} ({}) <-> tun {} ({}), "
                     "{} rule(s), leakguard={}",
                     cfg.mode == Mode::Exclude ? "EXCLUDE" : "INCLUDE",
                     st.full_tunnel ? "FULL-TUNNEL" : "CLASSIC",
                     st.wan, st.wan_ip, st.tun, st.tun_ip, cfg.rules.size(), cfg.leakguard);
    }
    while (WaitForSingleObject(g_stop_event, 1000) != WAIT_OBJECT_0)
        write_stats(engine.stats());

    spdlog::info("service stopping");
    engine.stop();
    std::error_code ec;
    std::filesystem::remove(stats_path(), ec);
    report(SERVICE_STOPPED);
}

}

std::string stats_path() { return (data_dir() / "stats.json").string(); }

bool install(std::string& err, const std::filesystem::path& exe) {
    std::wstring target = exe.wstring();
    if (target.empty()) {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) { err = last_error("GetModuleFileName"); return false; }
        target = path;
    }
    std::wstring bin = L"\"" + target + L"\" run-service";

    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm) { err = last_error("OpenSCManager"); return false; }
    ScmHandle svc(CreateServiceW(scm.h, kServiceName, L"proctun split tunneling",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
    if (svc) return true;
    if (GetLastError() != ERROR_SERVICE_EXISTS) { err = last_error("CreateService"); return false; }

    ScmHandle old(OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG));
    if (!old) { err = last_error("OpenService"); return false; }
    DWORD cb = 0;
    QueryServiceConfigW(old.h, nullptr, 0, &cb);
    std::vector<BYTE> buf(cb ? cb : 1);
    auto* qc = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
    if (QueryServiceConfigW(old.h, qc, static_cast<DWORD>(buf.size()), &cb) &&
        qc->lpBinaryPathName && bin == qc->lpBinaryPathName)
        return true;
    if (!ChangeServiceConfigW(old.h, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                              bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                              L"proctun split tunneling")) {
        err = last_error("ChangeServiceConfig");
        return false;
    }
    spdlog::info("Service binary path updated to the current executable.");
    return true;
}

bool uninstall(std::string& err) {
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm) { err = last_error("OpenSCManager"); return false; }
    ScmHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_ALL_ACCESS));
    if (!svc) { if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return true; err = last_error("OpenService"); return false; }
    SERVICE_STATUS st{};
    ControlService(svc.h, SERVICE_CONTROL_STOP, &st); // best-effort
    if (!DeleteService(svc.h)) { err = last_error("DeleteService"); return false; }
    return true;
}

bool start(std::string& err) {
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { err = last_error("OpenSCManager"); return false; }
    ScmHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc) { err = last_error("OpenService (install first?)"); return false; }
    if (!StartServiceW(svc.h, 0, nullptr)) {
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) return true;
        err = last_error("StartService");
        return false;
    }
    return true;
}

bool stop(std::string& err) {
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) { err = last_error("OpenSCManager"); return false; }
    ScmHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc) { err = last_error("OpenService"); return false; }
    SERVICE_STATUS st{};
    if (!ControlService(svc.h, SERVICE_CONTROL_STOP, &st)) {
        if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) return true;
        err = last_error("ControlService(STOP)");
        return false;
    }
    for (int i = 0; i < 100; ++i) {
        if (!QueryServiceStatus(svc.h, &st) || st.dwCurrentState == SERVICE_STOPPED)
            return true;
        Sleep(100);
    }
    err = "service did not stop within 10s";
    return false;
}

namespace {
DWORD current_state() {
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return 0;
    ScmHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_STATUS));
    if (!svc) return 0;
    SERVICE_STATUS st{};
    if (!QueryServiceStatus(svc.h, &st)) return 0;
    return st.dwCurrentState;
}
}

bool is_installed() {
    ScmHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return false;
    ScmHandle svc(OpenServiceW(scm.h, kServiceName, SERVICE_QUERY_STATUS));
    return static_cast<bool>(svc);
}

bool is_running() { return current_state() == SERVICE_RUNNING; }

bool wait_running(int timeout_ms) {
    for (int waited = 0;; waited += 100) {
        const DWORD s = current_state();
        if (s == SERVICE_RUNNING) return true;
        if (s == SERVICE_STOPPED || s == 0 || waited >= timeout_ms) return false;
        Sleep(100);
    }
}

int run_dispatcher() {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), service_main},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(table)) return 1;
    return 0;
}

}
