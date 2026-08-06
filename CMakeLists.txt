cmake_minimum_required(VERSION 3.21)
project(proctun VERSION 0.3.7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Match the x64-windows-static vcpkg triplet (static CRT /MT, /MTd for debug).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# WinpkFilter (ndisapi) is vendored, not in vcpkg. The packet engine that depends
# on it is gated behind this option so the rest of the project builds without it.
option(PROCTUN_WITH_NDISAPI "Build the WinpkFilter packet engine (needs vendor/ndisapi)" OFF)

find_package(CLI11 CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(proctun
    src/main.cpp
    src/config.cpp
    src/driver.cpp
    src/adapters.cpp
    src/engine.cpp
    src/service.cpp
)

target_include_directories(proctun PRIVATE src)
target_compile_definitions(proctun PRIVATE PROCTUN_VERSION="${PROJECT_VERSION}")

target_link_libraries(proctun PRIVATE
    CLI11::CLI11
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    iphlpapi   # GetAdaptersAddresses / GetBestInterfaceEx / SendARP
    advapi32   # Service Control Manager
    ws2_32
    winhttp    # `init`: driver MSI download
    bcrypt     # `init`: SHA-256 pin check
    wintrust   # `init`: Authenticode verification
    version    # `init`: installed driver version (ndisrd.sys)
)

# Require administrator privileges (WinpkFilter driver access).
if (MSVC)
    target_link_options(proctun PRIVATE "/MANIFESTUAC:level='requireAdministrator'")
    target_compile_definitions(proctun PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if (PROCTUN_WITH_NDISAPI)
    set(NDISAPI_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/vendor/ndisapi")
    if (NOT EXISTS "${NDISAPI_ROOT}/ndisapi/ndisapi.cpp")
        message(FATAL_ERROR
            "PROCTUN_WITH_NDISAPI=ON but vendor/ndisapi not found. "
            "Run: git submodule update --init")
    endif()
    find_package(Microsoft.GSL CONFIG REQUIRED)
    target_sources(proctun PRIVATE "${NDISAPI_ROOT}/ndisapi/ndisapi.cpp")
    # include/ holds common.h + ndisapi.h; examples/cpp/common holds the header-only
    # helpers (fastio/dual filters, iphelper, net, ...). See src/ndis_prelude.hpp.
    target_include_directories(proctun PRIVATE
        "${NDISAPI_ROOT}/include"
        "${NDISAPI_ROOT}/examples/cpp/common")
    target_link_libraries(proctun PRIVATE Microsoft.GSL::GSL)
    # _LIB: link ndisapi statically (drops dllimport/export on CNdisApi).
    # _ENABLE_EXTENDED_ALIGNED_STORAGE: ndisapi uses over-aligned types.
    target_compile_definitions(proctun PRIVATE
        PROCTUN_WITH_NDISAPI=1 _LIB _ENABLE_EXTENDED_ALIGNED_STORAGE)
endif()
