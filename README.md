# mcp-network-tools

An MCP (Model Context Protocol) server for local network / local system
diagnostics: interfaces, IP configuration, ARP table, routing table, active
TCP/UDP connections (with owning process), local port availability, LAN
subnet sweeps, interface traffic counters, traceroute, and Wi-Fi status.

**Zero dependencies.** Like `mcp-internet-tools`, this server does not use
the `mcp` Python SDK (`pip install mcp`) or any other third-party package —
not even for the MCP protocol itself. Everything is implemented with the
Python standard library only (`ctypes`, `socket`, `struct`, `subprocess`,
`ipaddress`, `json`, `sys`). Nothing to install beyond Python itself.

On **Windows**, interfaces/ARP/routes/connections/interface-stats are read
directly from the IP Helper API (`iphlpapi.dll`) via `ctypes`, instead of
shelling out to `ipconfig`/`arp`/`route`/`netstat` and parsing their
locale-dependent text output. `traceroute` and `wifi_info` still have to
shell out (`tracert`/`netsh`) since there's no clean structured API for
those, but parsing is limited to locale-independent tokens (numbers, IPs,
`ms`, `*`) rather than matching against translated labels.

This server only talks to the **local network/system** (interfaces,
neighbours on the LAN, local sockets). Remote HTTP/DNS/WHOIS/TLS
diagnostics against the internet are deliberately out of scope — that's the
separate `mcp-internet-tools` server.

**Platform support:** Windows is the primary, fully-implemented target
(tested against the real IP Helper API). Linux has best-effort fallbacks via
`/proc` and `iproute2` (no owning-process resolution for connections; no
DHCP details). macOS is not specifically supported.

## Quick start

No `pip install` needed. Just point your MCP client at:

```bash
python K:\mcp-tools\mcp-network-tools\mcp-network-tools.py
```

(adjust the path if you've moved this folder elsewhere). It's a plain
stdio MCP server — any MCP-compatible client can spawn it directly.

**Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "network-tools": {
      "command": "python",
      "args": ["K:\\mcp-tools\\mcp-network-tools\\mcp-network-tools.py"]
    }
  }
}
```

**Goose** — add to `~/.config/goose/config.yaml` (key names have shifted
between Goose versions — check `goose configure` / your version's docs if
this doesn't match):

```yaml
extensions:
  network-tools:
    type: stdio
    cmd: python
    args: ["K:\\mcp-tools\\mcp-network-tools\\mcp-network-tools.py"]
    enabled: true
```

**Any other MCP client**: configure it to run
`python K:\mcp-tools\mcp-network-tools\mcp-network-tools.py` as a
stdio-based MCP server — no ports, no config files.

## Requirements

- Python 3.10+ (uses `from __future__ import annotations` and `X | None`
  style type hints)
- Windows for full functionality. On Linux, `iproute2` (`ip`) is used for
  interfaces/gateway; `/proc/net/*` for ARP/routes/connections/stats.

## Available tools

### `list_interfaces()`

Local network adapters: name, description, MAC, up/down status, MTU, and
IPv4/IPv6 addresses with prefix length.

### `get_ip_config(interface=None)`

Fuller per-adapter config: everything in `list_interfaces` plus DNS
servers, gateway(s), and DHCP enabled/server (Windows only for DHCP
details). `interface` filters by substring match against name or
description; omit for all adapters.

### `arp_table()`

The local ARP/neighbour cache: IP, MAC, entry type (dynamic/static/other),
owning interface, and a best-effort MAC vendor guess. **IPv4 only** — uses
`GetIpNetTable` on Windows / `/proc/net/arp` on Linux, both IPv4-specific.

The vendor lookup is a small embedded OUI-prefix table (~30 entries:
VMware, VirtualBox, Hyper-V, Raspberry Pi, Apple, common router/IoT
vendors) — **not** a full IEEE OUI database. Absence means "unknown," not
"no vendor." For anything that matters, check
[standards-oui.ieee.org](https://standards-oui.ieee.org/).

### `route_table()`

The local IPv4 routing table: destination, netmask, gateway, interface
index, metric, protocol. IPv4 only, same reasoning as `arp_table`.

### `list_connections(protocol="tcp", state=None, pid=None, resolve_process_names=True)`

Active TCP or UDP connections/listeners with local/remote address+port,
TCP state (`LISTEN`, `ESTABLISHED`, ...), and owning PID. On Windows, the
PID is resolved to a process name via `OpenProcess` +
`QueryFullProcessImageNameW` (cached per PID for the life of the server
process); some system PIDs (e.g. PID 4 / `System`) can't be opened without
elevated privileges and come back with `process_name: null`. Process name
resolution is not implemented on Linux (`process_name` is always `null`
there). `state` filters TCP rows (ignored for UDP, which has no state).

### `local_port_check(port, protocol="tcp", host="0.0.0.0")`

Checks whether a **local** port is free by actually attempting to `bind()`
it (then immediately closing) — not a remote connect like
`mcp-internet-tools`' `tcp_port_check`. If the port is in use, tries to
report the owning connection(s)/process via `list_connections` (Windows
only).

### `subnet_scan(subnet, ports=None, timeout=1.0, max_workers=64, resolve_hostnames=True, resolve_mac=True)`

Sweeps a CIDR subnet for live hosts via ICMP ping (shells out to the OS
`ping`, one process per host, run concurrently via a thread pool — same
"trust the exit code, not the localized text" approach as
`mcp-internet-tools`' `ping`). For each live host: optional reverse-DNS
hostname, optional TCP port scan against `ports`, and (by default) a MAC
address + best-effort vendor guess, resolved from the local ARP cache right
after the ping sweep (pinging a host populates its ARP entry). Capped at
1024 hosts (~a /22) to avoid runaway scans — reject anything larger up
front.

MAC resolution only works for hosts on the **same L2 segment** (same
subnet, no router in between) — that's the nature of ARP. Two things that
look like bugs but aren't:

- **The scanning machine's own IP comes back with `mac: null`.** A host
  doesn't ARP for its own address, so there's nothing to look up.
- **A host reached through a router comes back with `mac: null`** rather
  than the router's MAC — reporting the router's MAC as if it were the
  target's would be actively misleading, so it's left blank instead.

### `network_stats()`

Per-interface traffic counters: bytes/packets in and out, errors, discards.
On Windows this comes from the legacy `GetIfTable` API, which — unlike
`GetAdaptersAddresses` — only knows *internal* device names (e.g.
`\DEVICE\TCPIP_{GUID}`) and returns a row per network-stack layer/filter
binding (LWF/WFP filters, QoS scheduler, etc.), not one row per physical
adapter, so expect many more entries than `list_interfaces` returns. Each
entry is enriched with a `friendly_name` (matched by interface index
against `GetAdaptersAddresses`) where one exists; internal filter/binding
rows will have `friendly_name: null`. Counters are 32-bit and can wrap on
very high-throughput links.

### `traceroute(host, max_hops=30, timeout=2.0, resolve_hostnames=False)`

Wraps `tracert` (Windows) / `traceroute` (POSIX). Per-hop RTTs and IP
addresses are extracted with regexes that only look for numbers, `ms`, and
IPv4-shaped tokens — deliberately **not** matching against status text like
"Request timed out", since that's localized and would silently break on
non-English Windows. A hop with no IP and no times is reported as
`timed_out: true`.

### `wifi_info()`

Current Wi-Fi connection status via `netsh wlan show interfaces`
(Windows) or `nmcli` (Linux, best-effort). Returns parsed common fields
(SSID, signal, channel, radio type, rates) plus the full `raw` key/value
dump from `netsh`, since its labels are localized and the parser only
recognizes English/Dutch variants — check `raw` if a field comes back
`null` on another locale. Returns `connected: false` gracefully if there's
no Wi-Fi hardware or it's not associated.

## Notes

- No SSRF/scope restrictions — this is a local dev tool you run yourself.
  `subnet_scan` and `local_port_check` touch real sockets/ARP/ping on
  whatever network you point them at; don't wire this server up to accept
  targets from untrusted input.
- `arp_table`/`route_table`/`list_connections` are IPv4-only for now (the
  Windows implementation deliberately uses the simpler legacy flat
  `MIB_IP*TABLE` APIs over the newer IPv6-capable ones, trading IPv6
  coverage for much simpler, more robust `ctypes` structs).
- `subnet_scan`'s liveness check is ICMP ping, which some hosts/firewalls
  silently drop even when other ports are open — a host that doesn't
  respond to ping isn't necessarily down, just not answering ICMP.
