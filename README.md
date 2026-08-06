# proctun

**Per-process split tunneling for Windows.** Selected applications are routed
through an OpenVPN tunnel while the rest keep using the normal connection —
or the inverse: everything goes through the tunnel except the applications
listed in the rules.

proctun runs on top of any OpenVPN TAP tunnel, entirely in user mode, via the
signed [WinpkFilter](https://github.com/wiresock/ndisapi) NDIS driver. A
single executable serves as both the CLI and the Windows service.

[Русская версия](README.ru.md)

```console
$ proctun status

  proctun 0.3.7

  SERVICE
    state            running
    engine           exclude/full-tunnel
    tunnel           up ✔
    wan              Wi-Fi  192.168.1.10
    tun              OpenVPN TAP  10.8.0.6

  COUNTERS
    tunneled         48210
    dns              377
    killed           0

  CONFIG
    mode             exclude
    leakguard        on
    ...

  RULES (1)  exclude mode — matched processes bypass the tunnel
    chrome.exe        → direct
```

## Features

- **Per-process routing** — a rule matches an executable name or any part of
  its full path.
- **Two policies** — `include` (only the listed applications use the tunnel)
  and `exclude` (every application uses the tunnel except the listed ones).
- **Compatibility with an existing VPN configuration** — proctun adapts to the
  way the tunnel is already set up (see
  [Routing strategies](#routing-strategies)) and never modifies the route
  table itself.
- **Leak protection** — DNS is directed through the tunnel, IPv6 of tunneled
  applications is blocked, and a fail-closed kill switch drops traffic instead
  of leaking it when the tunnel goes down.
- **No kernel code of its own** — everything runs in user mode on top of a
  third-party signed driver.

## Requirements

- Windows 10/11 x64 and administrator rights (driver and service access).
- OpenVPN on an L2 TAP adapter: `dev tap` and `disable-dco`. Wintun and DCO
  operate at L3 and are not supported — WinpkFilter requires Ethernet frames.
- WinpkFilter driver 3.6.2 or newer, installed by `proctun init`.

## Installation

From an elevated PowerShell:

```powershell
.\proctun.exe init
```

The command copies the executable to `%ProgramFiles%\proctun`, adds that
directory to the machine PATH (so that `proctun` is available in any new
console) and installs the WinpkFilter kernel driver. The MSI is downloaded
from the vendor's GitHub release and verified against a SHA-256 pin and its
Authenticode signature; proceeding past the prompt constitutes acceptance of
the [vendor license](https://www.ntkernel.com/windows-packet-filter/). On a
machine without internet access a local installer can be supplied via
`--driver-path <msi>`.

Verification:

```powershell
proctun ndis      # ✔ WinpkFilter driver loaded
```

## Quick start

The VPN must be connected first — proctun binds to the adapters in the state
they are in at engine start. The following is then run in an elevated console:

```powershell
# only these applications use the tunnel
proctun set --mode include --tun-gw 10.8.0.1
proctun add chrome.exe

proctun up -d      # start as a background service
proctun status     # tunnel ✔ and rising counters indicate normal operation
proctun down       # stop
```

The inverse scenario — everything through the tunnel except one application:

```powershell
proctun set --mode exclude --tun-gw 10.8.0.1 --tunnel-remote 203.0.113.10
proctun add SomeApp.exe
proctun up -d
```

Two values are taken from the VPN session:

| Value | Source | Option |
|---|---|---|
| Tunnel gateway | `route-gateway 10.8.0.1` in the OpenVPN log | `--tun-gw` |
| VPN server IP | `remote <ip> <port>` in the `.ovpn` file | `--tunnel-remote` |

The result can be verified by opening a "what is my IP" page in the routed
application: it reports the VPN address, while any other application reports
the real one.

`proctun up` **without** `-d` keeps the engine in the foreground with live
logs and Ctrl+C to stop, which is the convenient way to debug a setup.

## Routing strategies

proctun reads the route table at start and adapts to the way the VPN is
configured. The strategy is not selected manually; the active one is reported
by `status`.

| VPN configuration | Strategy | Engine behaviour |
|---|---|---|
| The default route stays on the physical link (`route-nopull`, no `redirect-gateway`) | **classic** | Matched traffic is pushed *into* the tunnel |
| `redirect-gateway def1` — the OS already sends everything into the tunnel | **full-tunnel** | Direct-bound traffic is pulled *out* of the tunnel |

The strategy is fixed at engine start. After a VPN reconnect with different
options proctun has to be restarted (`down`, then `up`); a warning is written
to the log when the engine notices that the routing world has changed.

## Commands

`proctun [-v] [--config <path>] <command> [arguments]` — one command per
invocation, always with administrator rights.

| Command | Description |
|---|---|
| `init [--yes] [--force] [--driver-path <msi>]` | One-time machine setup: PATH alias and driver installation. Idempotent |
| `up [-d] [options]` | Starts the engine, in the foreground or, with `-d`, as the background service |
| `down` | Stops the service and removes all interception |
| `status` | Service state, live counters, configuration and rules |
| `add <match> [--via] [--dns]` | Adds a rule. `--via` and `--dns` are reserved and currently have no effect |
| `remove <match>` | Removes rules whose match equals the given string exactly |
| `list` | Prints the current rules |
| `set [options]` | Changes and persists settings, then prints `status` |
| `leakguard <on\|off>` | Shorthand for `set --leakguard` |
| `adapters` | Lists adapters and marks the one selected as WAN |
| `ndis` | Driver state and the interfaces as the driver sees them (GUIDs, indexes) |
| `sniff <index> [--seconds N]` | Passive capture on a single interface; modifies nothing |
| `install` / `uninstall` | Registers or removes the Windows service |
| `update` | Deploys the running executable over the installed copy and restarts the service |

### Options

Accepted by `set` and `up`. `set` and `up -d` persist the values into the
configuration, whereas a foreground `up` applies them to that run only.
Options that are not passed leave the stored values unchanged.

| Option | Default | Meaning |
|---|---|---|
| `--mode <include\|exclude>` | `include` | Which side of the rules uses the tunnel |
| `--tun-gw <ip>` | — | Tunnel gateway (OpenVPN `route-gateway`) |
| `--tunnel-remote <ip>` | — | VPN server IP, never tunneled. Required for `exclude` under the classic strategy |
| `--dns <ip>` | `1.1.1.1` | Resolver that all DNS is redirected to; must be reachable through the tunnel |
| `--tun <guid\|name>` | auto | Pins the TAP adapter |
| `--wan <guid\|name>` | auto | Pins the physical adapter |
| `--leakguard <on\|off>` | `on` | Master switch for the two settings below |
| `--ipv6-block <on\|off>` | `on` | Drops IPv6 of tunneled processes |
| `--tunnel-dns <on\|off>` | `on` | Sends all DNS through the tunnel |

### Adapter selection

Both adapters are detected automatically: **WAN** by the true `0.0.0.0/0`
route (an active redirect-gateway does not mislead the detection), **TUN** as
the first TAP adapter that is up and holds an IPv4 address. The output of
`proctun adapters` should show `◀ wan` on the physical adapter
(Ethernet/Wi-Fi), with only the intended tunnel up.

If another VPN keeps a second TAP adapter alive, both adapters can be pinned
by GUID:

```powershell
proctun ndis                              # lists the GUIDs
proctun set --wan "{...}" --tun "{...}"
```

`--tun-gw` must belong to the subnet of the TUN adapter itself: a gateway
from a different tunnel produces frames that go nowhere, and proctun refuses
to start in that case.

## Configuration

`%ProgramData%\proctun\config.json` is shared by the CLI and the service.
Editing through `set`/`add`/`remove` is preferable to editing by hand — a
malformed file is reported and ignored, and the defaults are used instead.
Changes take effect at the next engine start.

```jsonc
{
  "mode": "include",                  // "include" | "exclude"
  "rules": [
    { "match": "chrome.exe", "via": "tun" }
  ],
  "tun_gateway": "10.8.0.1",        // tunnel gateway (route-gateway)
  "tunnel_remote": "203.0.113.10",  // VPN server IP
  "tun_alias": "",                  // TAP adapter GUID/name ("" = autodetect)
  "wan_alias": "",                  // WAN adapter GUID/name ("" = autodetect)
  "leakguard": true,
  "block_ipv6": true,               // drop IPv6 of tunneled processes
  "tunnel_dns": true,               // redirect all DNS into the tunnel
  "dns_server": "1.1.1.1"
}
```

| Path | Purpose |
|---|---|
| `%ProgramData%\proctun\config.json` | Configuration |
| `%ProgramData%\proctun\stats.json` | Live statistics, rewritten about once a second |
| `%ProgramData%\proctun\proctun.log` | Service log |
| `%ProgramFiles%\proctun\proctun.exe` | Installed copy (`init`) |

Windows service: `proctun`, LocalSystem, demand start.

## Scripting

proctun deliberately does not manage OpenVPN. It is intended to be started
from an external script once the TAP adapter has received an IP address, and
stopped when the VPN goes down:

```powershell
proctun up -d      # the VPN is up
proctun down       # the VPN is going down
```

`stats.json` is machine-readable and refreshed about once a second:

```powershell
Get-Content "$env:ProgramData\proctun\stats.json" | ConvertFrom-Json
# .armed, .mode, .tunneled, .dns, .killed, .conntrack, .tun_ip, ...
```

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `WinpkFilter driver NOT loaded` | Run `proctun init` |
| `could not resolve adapters` | The tunnel is down or there is no TAP adapter — bring the VPN up, or pin `--tun`/`--wan` by GUID |
| `WAN resolved to the tunnel adapter` | Autodetection or a stale alias selected the wrong adapter — set `--wan` to the physical adapter's GUID |
| `could not resolve MAC of tunnel gateway` | No ARP entry yet: `ping <tun-gw>` once and retry |
| `exclude mode requires tunnel_remote` | Set `--tunnel-remote <server ip>` |
| `strategy is stale` in the log | The VPN changed the route table after start — `down`, then `up` |
| The service does not start via `up -d` | Consult `%ProgramData%\proctun\proctun.log`, or run `proctun up -v` in a console |
| A routed application has no connectivity | In `status`: is the tunnel up, is `tun-gw` correct, does the application actually match a rule (`list`)? |
| DNS stopped resolving | Try `set --tunnel-dns off`, or verify that `dns_server` is reachable through the tunnel |
| Nothing works right after start, the wrong applications are tunneled | Most likely the wrong adapters — see [Adapter selection](#adapter-selection) |

## How it works

proctun puts the WAN and TAP adapters into NDIS tunnel mode, so that every
Ethernet frame passes through the engine in user mode. Routes are never added
or removed; individual packets are rewritten and redirected instead.

<details>
<summary><b>Packet path</b></summary>

**classic** — the OS sends everything out through the physical link:

```
  packet on WAN ──▶ should it be tunneled? ──yes──▶ SNAT ──▶ TAP (into the VPN)
                                          └──no──▶ pass unchanged
  reply on TAP ──▶ DNAT ──▶ handed to the process socket
```

A packet that must be tunneled gets its source IP rewritten to the TAP
adapter's address and a new Ethernet header (destination = tunnel gateway MAC,
resolved once by ARP), after which the frame is reinjected into TAP. Ports are
left untouched, so no general connection tracking is required.

**full-tunnel** — the OS already sends everything into the VPN, so the engine
mirrors itself:

```
  packet on TAP ──▶ should it stay direct? ──yes──▶ SNAT ──▶ WAN (past the VPN)
                                           └──no──▶ pass unchanged
  reply on WAN ──▶ is it a known flow? ──▶ DNAT ──▶ back to the TAP stack
```

Traffic native to WAN (the VPN's own transport, LAN) must remain untouched,
therefore extracted flows are recorded in a small (protocol, port) table and
only their replies are translated back. Destination-based exclusions installed
by the VPN client (`route ... net_gateway`) continue to work unchanged.
</details>

<details>
<summary><b>Process matching</b></summary>

WinpkFilter does not report which process a packet belongs to. The engine
resolves it through the OS connection tables (`GetExtendedTcpTable` /
`GetExtendedUdpTable`: local endpoint → PID → full executable path, cached
with a lazy refresh on a miss) and matches that path against the rules as a
case-insensitive substring.

A packet whose process cannot be resolved is treated as tunneled in `exclude`
mode (fail-closed) and as direct in `include` mode.
</details>

<details>
<summary><b>DNS and IPv6</b></summary>

Windows resolves names through the `dnscache` service, so DNS traffic cannot
be attributed to the application that requested it. With `tunnel_dns` enabled,
every IPv4 packet to port 53 is redirected into the tunnel with its
destination rewritten to `dns_server`; the original resolver is remembered per
(protocol, client port) and restored on the reply, as the OS would otherwise
discard it. The trade-off is that DNS of *all* applications goes through the
tunnel.

The tunnel data path is IPv4-only. IPv6 DNS is dropped so that resolvers fall
back to IPv4, and with `block_ipv6` enabled IPv6 of tunneled processes is
dropped as well, which makes applications retry over (tunneled) IPv4. IPv6 of
other applications is left untouched.
</details>

<details>
<summary><b>Kill switch</b></summary>

A monitor thread checks the guarded adapter every two seconds or so — TAP
under the classic strategy, WAN under full-tunnel — verifying that it is up
and still holds the IP address it had at engine start. While it is down,
traffic that would have crossed it is dropped rather than misrouted: the
classic strategy drops tunnel-bound traffic including DNS, full-tunnel drops
the extracted direct flows instead of letting them fall back into the VPN.
This is visible in `status` as `tunnel DOWN` and a rising `killed` counter.
</details>

## Limitations

- The tunnel data path is IPv4-only; IPv6 of tunneled processes is blocked.
- With `tunnel_dns` enabled, DNS of every application goes through the tunnel.
- Adapter parameters and the routing strategy are captured at engine start, so
  a restart is required after a VPN reconnect that changes the TAP IP address
  or the route table.
- OpenVPN must use `dev tap` and `disable-dco`.
- IP fragments pass through unclassified (rare at a normal MTU).

## Building from source

Visual Studio 2026 (C++ x64 toolset), CMake 3.21 or newer, vcpkg.

```powershell
git clone <this repo> && cd proctun
git submodule update --init          # WinpkFilter SDK → vendor/ndisapi

$env:VCPKG_ROOT = "<path to vcpkg>"
cmake --preset win-amd64-release-vs2026-ndis
cmake --build out\build\win-amd64-release-vs2026-ndis --config Release

.\out\build\win-amd64-release-vs2026-ndis\Release\proctun.exe update   # deploy
```

The `win-amd64-release-vs2026` preset (without `-ndis`) builds everything
except the packet engine, which is convenient for CLI work on a machine
without the driver.

Dependencies via vcpkg: CLI11, spdlog, nlohmann-json, ms-gsl. The WinpkFilter
user-mode SDK is included as a submodule; its kernel driver is installed
separately by `proctun init` under the
[vendor's license](https://www.ntkernel.com/windows-packet-filter/).
