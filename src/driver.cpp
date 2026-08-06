#include "driver.hpp"
#include "engine.hpp"
#include "log.hpp"
#include "service.hpp"
#include "ui.hpp"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace proctun::driver {

namespace {

constexpr wchar_t kMsiUrl[] =
    L"https://github.com/wiresock/ndisapi/releases/download/v3.6.2/"
    L"Windows.Packet.Filter.3.6.2.1.x64.msi";
constexpr char kMsiSha256[] = "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c";
constexpr char kVersion[] = "3.6.2.1";
constexpr char kLicenseUrl[] = "https://www.ntkernel.com/windows-packet-filter/";
constexpr wchar_t kDriverService[] = L"ndisrd";

std::string last_error(const char* what, DWORD e = GetLastError()) {
    return std::string(what) + " failed (err " + std::to_string(e) + ")";
}

bool driver_service_present() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, kDriverService, SERVICE_QUERY_STATUS);
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return svc != nullptr;
}

std::string installed_version() {
    wchar_t sysdir[MAX_PATH];
    if (!GetSystemDirectoryW(sysdir, MAX_PATH)) return {};
    std::wstring sys = std::wstring(sysdir) + L"\\drivers\\ndisrd.sys";
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(sys.c_str(), &dummy);
    if (!sz) return {};
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(sys.c_str(), 0, sz, buf.data())) return {};
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&ffi), &len) || !ffi)
        return {};
    return std::to_string(HIWORD(ffi->dwFileVersionMS)) + "." +
           std::to_string(LOWORD(ffi->dwFileVersionMS)) + "." +
           std::to_string(HIWORD(ffi->dwFileVersionLS)) + "." +
           std::to_string(LOWORD(ffi->dwFileVersionLS));
}

struct HInternet {
    HINTERNET h = nullptr;
    HInternet(HINTERNET x) : h(x) {}
    ~HInternet() { if (h) WinHttpCloseHandle(h); }
    explicit operator bool() const { return h != nullptr; }
};

bool download(const std::wstring& url, const std::filesystem::path& dst, std::string& err) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}, path[1024]{};
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;  uc.dwUrlPathLength = 1023;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) { err = last_error("WinHttpCrackUrl"); return false; }

    HInternet ses(WinHttpOpen(L"proctun-init", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!ses) { err = last_error("WinHttpOpen"); return false; }
    HInternet con(WinHttpConnect(ses.h, host, uc.nPort, 0));
    if (!con) { err = last_error("WinHttpConnect"); return false; }
    HInternet req(WinHttpOpenRequest(con.h, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0));
    if (!req) { err = last_error("WinHttpOpenRequest"); return false; }

    if (!WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req.h, nullptr)) {
        err = last_error("HTTP request");
        return false;
    }

    DWORD status = 0, len = sizeof(status);
    if (!WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                             WINHTTP_NO_HEADER_INDEX)) {
        err = last_error("WinHttpQueryHeaders");
        return false;
    }
    if (status != 200) {
        err = "HTTP status " + std::to_string(status);
        return false;
    }

    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) { err = "cannot write " + dst.string(); return false; }
    std::vector<char> buf(64 * 1024);
    DWORD got = 0;
    do {
        if (!WinHttpReadData(req.h, buf.data(), static_cast<DWORD>(buf.size()), &got)) {
            err = last_error("WinHttpReadData");
            return false;
        }
        out.write(buf.data(), got);
    } while (got > 0);
    out.close();
    return out.good();
}

bool sha256_file(const std::filesystem::path& p, std::string& hex, std::string& err) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { err = "cannot read " + p.string(); return false; }

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        err = "BCryptOpenAlgorithmProvider failed";
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        err = "BCryptCreateHash failed";
        return false;
    }

    bool ok = true;
    std::vector<char> buf(64 * 1024);
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        auto n = f.gcount();
        if (n > 0 && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()),
                                    static_cast<ULONG>(n), 0) != 0) {
            ok = false;
            break;
        }
    }
    UCHAR digest[32]{};
    if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) { err = "SHA-256 computation failed"; return false; }

    static const char* d = "0123456789abcdef";
    hex.clear();
    for (UCHAR b : digest) { hex += d[b >> 4]; hex += d[b & 0xF]; }
    return true;
}

bool authenticode_valid(const std::filesystem::path& p, std::string& err) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    std::wstring wpath = p.wstring();
    fi.pcwszFilePath = wpath.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(nullptr, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
    if (st != ERROR_SUCCESS) {
        char code[16];
        std::snprintf(code, sizeof code, "0x%08lX", static_cast<unsigned long>(st));
        err = std::string("Authenticode verification failed (") + code + ")";
        return false;
    }
    return true;
}

bool msi_install(const std::filesystem::path& msi, bool& reboot_required, std::string& err) {
    wchar_t sysdir[MAX_PATH];
    if (!GetSystemDirectoryW(sysdir, MAX_PATH)) { err = last_error("GetSystemDirectory"); return false; }
    std::wstring cmd = L"\"" + std::wstring(sysdir) + L"\\msiexec.exe\" /i \"" +
                       msi.wstring() + L"\" /qn /norestart";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        err = last_error("CreateProcess(msiexec)");
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    reboot_required = (code == ERROR_SUCCESS_REBOOT_REQUIRED);
    if (code != ERROR_SUCCESS && code != ERROR_SUCCESS_REBOOT_REQUIRED) {
        err = "msiexec exited with code " + std::to_string(code);
        return false;
    }
    return true;
}

bool user_consents() {
    ui::note(fmt::format("about to install Windows Packet Filter {} (NDIS kernel driver)", kVersion));
    ui::note(fmt::format("continuing accepts the vendor's license: {}", kLicenseUrl));
    ui::warn("network adapters may briefly lose connectivity while the filter binds");
    std::cout << "  Proceed? [y/N]: " << std::flush;
    std::string line;
    std::getline(std::cin, line);
    return line == "y" || line == "Y" || line == "yes";
}

bool install_alias(std::filesystem::path& dst, bool& path_added, std::string& err) {
    path_added = false;

    wchar_t self[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) { err = last_error("GetModuleFileName"); return false; }
    wchar_t pf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH);
    if (!n || n >= MAX_PATH) { err = "%ProgramFiles% is not set"; return false; }

    std::filesystem::path dir = std::filesystem::path(pf) / L"proctun";
    dst = dir / L"proctun.exe";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    bool same = std::filesystem::exists(dst, ec) && std::filesystem::equivalent(self, dst, ec);
    if (!same && !CopyFileW(self, dst.c_str(), FALSE)) {
        DWORD e = GetLastError();
        err = (e == ERROR_SHARING_VIOLATION)
                  ? dst.string() + " is in use — stop the service first (`proctun down`)"
                  : last_error("CopyFile", e);
        return false;
    }

    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                      0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) {
        err = "cannot open the machine Environment registry key";
        return false;
    }
    std::wstring cur;
    DWORD type = REG_EXPAND_SZ, cb = 0;
    if (RegQueryValueExW(key, L"Path", nullptr, &type, nullptr, &cb) == ERROR_SUCCESS && cb) {
        cur.resize(cb / sizeof(wchar_t));
        if (RegQueryValueExW(key, L"Path", nullptr, &type,
                             reinterpret_cast<LPBYTE>(cur.data()), &cb) != ERROR_SUCCESS)
            cur.clear();
        while (!cur.empty() && cur.back() == L'\0') cur.pop_back();
    }

    const std::wstring want = dir.wstring();
    bool present = false;
    for (size_t p = 0; p <= cur.size() && !present;) {
        size_t q = cur.find(L';', p);
        if (q == std::wstring::npos) q = cur.size();
        std::wstring seg = cur.substr(p, q - p);
        while (!seg.empty() && seg.back() == L'\\') seg.pop_back();
        present = _wcsicmp(seg.c_str(), want.c_str()) == 0;
        p = q + 1;
    }
    if (!present) {
        std::wstring next = cur;
        if (!next.empty() && next.back() != L';') next += L';';
        next += want;
        if (RegSetValueExW(key, L"Path", 0, type,
                           reinterpret_cast<const BYTE*>(next.c_str()),
                           static_cast<DWORD>((next.size() + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) {
            RegCloseKey(key);
            err = "cannot update the machine PATH";
            return false;
        }
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                            reinterpret_cast<LPARAM>(L"Environment"),
                            SMTO_ABORTIFHUNG, 3000, nullptr);
        path_added = true;
    }
    RegCloseKey(key);
    return true;
}

}

int run_update() {
    ui::blank();
    wchar_t self[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) {
        ui::fail("update: " + last_error("GetModuleFileName"));
        return 1;
    }

    std::string err;
    const bool was_running = svc::is_running();
    if (was_running) {
        ui::note("stopping the service...");
        if (!svc::stop(err)) { ui::fail("update: " + err); return 1; }
    }

    std::filesystem::path dst;
    bool path_added = false;
    if (!install_alias(dst, path_added, err)) { ui::fail("update: " + err); return 1; }

    std::error_code ec;
    if (std::filesystem::equivalent(std::filesystem::path(self), dst, ec))
        ui::note("already running the installed copy — nothing to replace");
    else
        ui::ok(fmt::format("installed {} → {}", std::filesystem::path(self).string(), dst.string()));

    if (svc::is_installed() && !svc::install(err, dst)) { ui::fail("update: " + err); return 1; }

    if (was_running) {
        if (!svc::start(err)) { ui::fail("update: " + err); return 1; }
        if (!svc::wait_running(5000)) {
            ui::fail("service did not come back up after the update. "
                     "See %ProgramData%\\proctun\\proctun.log or run `proctun up -v`.");
            return 1;
        }
        ui::ok("service restarted on the new binary");
    }

    ui::ok(fmt::format("proctun {} is now the installed version", PROCTUN_VERSION));
    ui::blank();
    return 0;
}

int run_init(const InitOptions& opt) {
    ui::blank();
    std::filesystem::path alias_dst;
    bool path_added = false;
    std::string alias_err;
    if (install_alias(alias_dst, path_added, alias_err)) {
        if (path_added)
            ui::ok(fmt::format("installed {} and added it to the system PATH — new shells can "
                               "run `proctun`", alias_dst.string()));
        else
            ui::ok(fmt::format("command alias up to date: {} (already on PATH)", alias_dst.string()));
    } else {
        ui::warn("could not set up the `proctun` command alias: " + alias_err);
    }

    if (driver_service_present() && !opt.force) {
        auto v = installed_version();
        ui::ok(fmt::format("WinpkFilter driver is already installed{}",
                           v.empty() ? "" : " (ndisrd.sys " + v + ")"));
#if PROCTUN_WITH_NDISAPI
        if (!ndis_driver_loaded())
            ui::warn("driver is installed but not reachable — a reboot may be pending");
#endif
        ui::note(fmt::format("nothing to do — `proctun init --force` reinstalls version {}", kVersion));
        ui::blank();
        return 0;
    }

    std::filesystem::path msi;
    bool downloaded = false;
    std::string err;

    if (!opt.msi_path.empty()) {
        msi = opt.msi_path;
        if (!std::filesystem::exists(msi)) {
            ui::fail("--driver-path: file not found: " + msi.string());
            return 1;
        }
        std::string hex;
        if (!sha256_file(msi, hex, err)) { ui::fail(err); return 1; }
        if (hex == kMsiSha256) {
            ui::ok(fmt::format("local MSI matches the pinned {} build", kVersion));
        } else {
            ui::warn(fmt::format("local MSI is not the pinned {} build; checking its "
                                 "Authenticode signature", kVersion));
            if (!authenticode_valid(msi, err)) {
                ui::fail(err + " — refusing to install an unverified driver package");
                return 1;
            }
            ui::ok("Authenticode signature is valid");
        }
    } else {
        msi = std::filesystem::temp_directory_path() / "Windows.Packet.Filter.3.6.2.1.x64.msi";
        ui::note(fmt::format("downloading Windows Packet Filter {}...", kVersion));
        if (!download(kMsiUrl, msi, err)) {
            ui::fail("download failed: " + err + ". If this machine is offline, pass a local "
                     "installer via --driver-path.");
            return 1;
        }
        std::string hex;
        if (!sha256_file(msi, hex, err)) { ui::fail(err); return 1; }
        if (hex != kMsiSha256) {
            std::error_code ec;
            std::filesystem::remove(msi, ec);
            ui::fail(fmt::format("SHA-256 mismatch (got {}, expected {}) — aborting", hex, kMsiSha256));
            return 1;
        }
        if (!authenticode_valid(msi, err)) { ui::fail(err); return 1; }
        ui::ok("verified: SHA-256 pin + Authenticode signature OK");
        downloaded = true;
    }

    if (!opt.yes && !user_consents()) {
        ui::note("aborted by user");
        return 1;
    }

    ui::note("installing (msiexec /qn /norestart)...");
    bool reboot = false;
    if (!msi_install(msi, reboot, err)) { ui::fail(err); return 1; }
    if (downloaded) {
        std::error_code ec;
        std::filesystem::remove(msi, ec);
    }

    if (!driver_service_present())
        ui::warn("installer succeeded but the 'ndisrd' driver service is not visible yet");
#if PROCTUN_WITH_NDISAPI
    if (!ndis_driver_loaded())
        ui::warn("driver is not reachable yet — a reboot may be pending");
#endif
    if (reboot)
        ui::warn("Windows requests a reboot to finish the driver installation");
    auto v = installed_version();
    ui::ok(fmt::format("WinpkFilter installed{}", v.empty() ? "" : " (ndisrd.sys " + v + ")"));
    ui::blank();
    return 0;
}

}
