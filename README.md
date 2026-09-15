# mcp-network-tools

An MCP (Model Context Protocol) server for local network / local system
diagnostics: interfaces, IP configuration, ARP table, routing table, active
TCP/UDP connections (with owning process), local port availability, LAN
subnet sweeps, interface traffic counters, traceroute, and Wi-Fi status.

**Zero dependencies.** Like `mcp-internet-tools` and `mcp-weather-forecast`,
this server does not use the `mcp` Python SDK (`pip install mcp`) or any
other third-party package — not even for the MCP protocol itself. Everything
is implemented with the Python standard library only (`ctypes`, `socket`,
`struct`, `subprocess`, `ipaddress`, `http.server`, `argparse`, `json`,
`sys`). Nothing to install beyond Python itself, for either transport below.

On **Windows**, interfaces/ARP/routes/connections/interface-stats are read
directly from the IP Helper API (`iphlpapi.dll`) via `ctypes`, instead of
shelling out to `ipconfig`/`arp`/`route`/`netstat` and parsing their
locale-dependent text output. `traceroute` and `wifi_info` still have to
shell out (`tracert`/`netsh`) since there's no clean structured API for
those, but parsing is limited to locale-independent tokens (numbers, IPs,
`ms`, `*`) rather than matching against translated labels.

This server only talks to the **local network/system** (interfaces,
neighbours on the LAN, local sockets) **of the machine it runs on**. Remote
HTTP/DNS/WHOIS/TLS diagnostics against the internet are deliberately out of
scope — that's the separate `mcp-internet-tools` server. That "machine it
runs on" scope matters for Docker — see the **Docker** section below before
containerizing this one.

**Platform support:** Windows is the primary, fully-implemented target
(tested against the real IP Helper API). Linux has best-effort fallbacks via
`/proc` and `iproute2` (no owning-process resolution for connections; no
DHCP details) — written to the same contract as the Windows path and
exercised via the Docker image below, but not yet verified against a bare
Linux host by hand. macOS is not specifically supported.

## Transports

One script, one set of tools, two ways to run it — pick per client with
`--transport`:

```bash
python mcp-network-tools.py --transport stdio
python mcp-network-tools.py --transport streamable-http --host 0.0.0.0 --port 8000
```

- **`stdio`** (default — existing configs keep working unchanged) — the
  server talks JSON-RPC over stdin/stdout. Use this for clients that spawn
  the process directly: **Goose**, **Claude Desktop**, `mcp-tool-manager`.
- **`streamable-http`** — the server listens on `--host`/`--port` and
  serves the MCP endpoint at `POST http://<host>:<port>/mcp`. Use this for
  clients that talk to a running server over HTTP instead of spawning a
  process: **n8n**, or when running the server in **Docker**. `--host
  0.0.0.0` is what you generally want in a container so it accepts
  connections from outside it. This server only implements the
  request/response half of the Streamable HTTP transport (no
  server-initiated SSE stream) since none of its tools need to push
  unsolicited messages — `GET`/`DELETE` on the endpoint return `405`/`200`
  respectively rather than opening a stream or tracking a session.

Run `python mcp-network-tools.py --help` for the full option list:

```
--transport {stdio,streamable-http}
--host HOST
--port PORT
```

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

**Any other stdio MCP client**: configure it to run
`python K:\mcp-tools\mcp-network-tools\mcp-network-tools.py` as a
stdio-based MCP server — no ports, no config files.

**n8n / Docker (streamable-http)** — run the server with the HTTP transport
instead, then point the MCP client node at the endpoint:

```bash
python mcp-network-tools.py --transport streamable-http --host 0.0.0.0 --port 8000
```

MCP endpoint: `http://<host>:8000/mcp`. See the **Docker** section below —
containerizing this specific server needs one extra consideration
(`network_mode: host`) that most other tools in this repo don't.

If you're using `mcp-tool-manager` from this same `mcp-tools` folder, its
`toolboxes.json` already has a `network` entry pointing at this script over
stdio (the default transport, so no `--transport` flag needed there).

## Docker

```bash
docker compose up -d
```

uses the included [`docker-compose.yml`](docker-compose.yml): a bare
`python:3.12-slim` image that `git clone`s/`pull`s this repo and runs
`mcp-network-tools.py --transport streamable-http` — same zero-`pip`-install
pattern as the other tools in this repo (see `mcp-weather-forecast`'s
compose file), plus `iproute2`/`iputils-ping`/`traceroute` so `list_interfaces`,
`subnet_scan` and `traceroute` have something to shell out to on the
Linux fallback path.

**The one thing that's different here versus every other tool in this repo:
`network_mode: host` is required, not optional.** This server's entire
purpose is reporting on the network of the machine it runs on. A container's
default (bridge) network is its *own* isolated virtual interface, ARP table
and routing table — completely disconnected from your real LAN. Run this
server in a normal container and every tool still returns a "successful"
result, just a meaningless one: `list_interfaces` shows the container's
internal `eth0`, `arp_table` is empty, `subnet_scan` of your actual home
network finds nothing. `network_mode: host` makes the container share the
host's real network namespace instead, so it sees what you actually asked
for. Docker grants `NET_RAW` by default, so ICMP `ping`/`traceroute` work
without extra `cap_add`.

**This only works on a Linux Docker host.** Docker Desktop on Windows/Mac
runs Linux containers inside a lightweight VM (WSL2 on Windows); even with
host networking enabled there, the container sees that VM's network, not
your physical machine's real adapters/ARP/routing table — and being a Linux
container, it would hit this server's `/proc`-based POSIX fallback code
paths regardless, never the Windows-specific `iphlpapi.dll` path, so you'd
lose the DHCP details, per-connection process names, and other Windows-only
richness documented below even if the data were otherwise meaningful.

**On Windows, skip Docker and run the script natively instead** — it's a
single dependency-free `.py` file, so there's no packaging benefit to
containerizing it there anyway:

```powershell
python mcp-network-tools.py --transport streamable-http --host 0.0.0.0 --port 8000
```

## Requirements

- Python 3.10+ (uses `from __future__ import annotations` and `X | None`
  style type hints)
- Windows for full functionality. On Linux, `iproute2` (`ip`) is used for
  interfaces/gateway; `/proc/net/*` for ARP/routes/connections/stats;
  `ping`/`traceroute` binaries for `subnet_scan`/`traceroute`.

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
