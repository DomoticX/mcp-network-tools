#!/usr/bin/env python3
"""
mcp-network-tools.py

A dependency-free MCP server for local network / local system diagnostics:
network interfaces, IP configuration, ARP table, routing table, active TCP/
UDP connections (with owning process), local port availability, LAN subnet
sweeps, interface traffic counters, traceroute, and Wi-Fi status.

100% Python standard library - no "pip install mcp", no third-party
packages. The MCP JSON-RPC protocol is implemented natively (same minimal
approach as mcp-internet-tools.py / mcp-weather-forecast.py), over either
stdio or streamable-http (also stdlib-only, via http.server).

On Windows, interfaces/ARP/routes/connections/interface-stats are read
directly from the IP Helper API (iphlpapi.dll) via ctypes, instead of
shelling out to ipconfig/arp/route/netstat and parsing their (locale-
dependent) text output. traceroute and wifi_info still have to shell out
(tracert/netsh) - there's no clean structured API for those - but parsing
is limited to locale-independent tokens (numbers, IPs, "ms", "*") rather
than matching against translated labels. On Linux, the same tools fall
back to /proc and iproute2 (ip).

This server only talks to the **local network/system** (interfaces,
neighbours on the LAN, local sockets) **of the machine it runs on**.
Remote HTTP/DNS/WHOIS/TLS diagnostics against the internet are deliberately
out of scope - that's the separate mcp-internet-tools server. Note that
this "machine it runs on" scope has a real consequence for containerized
deployment - see the "Docker" section of README.md before running this
under Docker without --network host.

Run (stdio, default - e.g. Goose, Claude Desktop):
    python mcp-network-tools.py
    python mcp-network-tools.py --transport stdio

Run (streamable-http - e.g. n8n, Docker):
    python mcp-network-tools.py --transport streamable-http --host 0.0.0.0 --port 8000

    Serves the MCP endpoint at POST http://<host>:<port>/mcp
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Config / limits
# ---------------------------------------------------------------------------

SERVER_NAME = "network-tools"
SERVER_VERSION = "1.0.0"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

IS_WINDOWS = platform.system() == "Windows"

MAX_SUBNET_SCAN_HOSTS = 1024  # roughly a /22 or smaller


# ---------------------------------------------------------------------------
# Windows: IP Helper API (iphlpapi.dll) via ctypes
# ---------------------------------------------------------------------------

if IS_WINDOWS:
    import ctypes
    import ctypes.wintypes as wintypes

    iphlpapi = ctypes.windll.iphlpapi
    kernel32 = ctypes.windll.kernel32

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.c_void_p),
            ("iSockaddrLength", ctypes.c_int),
        ]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_uint8),
    ]

    class IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
    ]

    class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
    ]

    MAX_ADAPTER_ADDRESS_LENGTH = 8

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    # Truncated after Dhcpv4Server (the last field this module reads) -
    # trailing fields (Dhcpv6*, NetworkGuid, ...) are intentionally omitted;
    # traversal only follows the `Next` pointer, whose value is set by the
    # OS regardless of how much of the struct we declared.
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
        ("Ipv6IfIndex", wintypes.DWORD),
        ("ZoneIndices", wintypes.DWORD * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("FirstWinsServerAddress", ctypes.c_void_p),
        ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
        ("Ipv4Metric", ctypes.c_ulong),
        ("Ipv6Metric", ctypes.c_ulong),
        ("Luid", ctypes.c_uint64),
        ("Dhcpv4Server", SOCKET_ADDRESS),
    ]

    iphlpapi.GetAdaptersAddresses.argtypes = [
        wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)
    ]
    iphlpapi.GetAdaptersAddresses.restype = wintypes.ULONG

    iphlpapi.GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    iphlpapi.GetIpNetTable.restype = wintypes.DWORD

    iphlpapi.GetIpForwardTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    iphlpapi.GetIpForwardTable.restype = wintypes.DWORD

    iphlpapi.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG
    ]
    iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

    iphlpapi.GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG
    ]
    iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD

    iphlpapi.GetIfTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    iphlpapi.GetIfTable.restype = wintypes.DWORD

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    def _socket_address_to_str(sock_addr: "SOCKET_ADDRESS") -> str | None:
        if not sock_addr.lpSockaddr or sock_addr.iSockaddrLength == 0:
            return None
        family = ctypes.cast(sock_addr.lpSockaddr, ctypes.POINTER(ctypes.c_ushort))[0]
        if family == socket.AF_INET:
            raw = ctypes.cast(sock_addr.lpSockaddr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents
            return socket.inet_ntoa(bytes(raw[4:8]))
        if family == socket.AF_INET6:
            raw = ctypes.cast(sock_addr.lpSockaddr, ctypes.POINTER(ctypes.c_ubyte * 28)).contents
            return socket.inet_ntop(socket.AF_INET6, bytes(raw[8:24]))
        return None

    _OPER_STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "not_present", 7: "lower_layer_down"}

    def _get_adapters_addresses_windows() -> list[dict[str, Any]]:
        size = wintypes.ULONG(15000)
        flags = 0x2 | 0x4 | 0x80  # SKIP_ANYCAST | SKIP_MULTICAST | INCLUDE_GATEWAYS
        buf = None
        for _ in range(3):
            buf = ctypes.create_string_buffer(size.value)
            ret = iphlpapi.GetAdaptersAddresses(0, flags, None, buf, ctypes.byref(size))
            if ret == 0:
                break
            if ret == 111:  # ERROR_BUFFER_OVERFLOW
                size = wintypes.ULONG(size.value * 2)
                continue
            raise OSError(f"GetAdaptersAddresses failed with code {ret}")
        else:
            raise OSError("GetAdaptersAddresses: could not allocate a large enough buffer")

        adapters = []
        current = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        while current:
            a = current.contents
            mac_len = a.PhysicalAddressLength
            mac = ":".join(f"{b:02X}" for b in bytes(a.PhysicalAddress)[:mac_len]) if mac_len else None

            addresses = []
            u = a.FirstUnicastAddress
            while u:
                ua = u.contents
                ip = _socket_address_to_str(ua.Address)
                if ip:
                    addresses.append({"ip": ip, "prefix_length": ua.OnLinkPrefixLength})
                u = ua.Next

            dns_servers = []
            d = a.FirstDnsServerAddress
            while d:
                da = d.contents
                ip = _socket_address_to_str(da.Address)
                if ip:
                    dns_servers.append(ip)
                d = da.Next

            gateways = []
            g = a.FirstGatewayAddress
            while g:
                ga = g.contents
                ip = _socket_address_to_str(ga.Address)
                if ip:
                    gateways.append(ip)
                g = ga.Next

            dhcp_enabled = bool(a.Flags & 0x4)
            dhcp_server = _socket_address_to_str(a.Dhcpv4Server) if dhcp_enabled else None

            adapters.append({
                "name": a.FriendlyName,
                "description": a.Description,
                "index": a.IfIndex,
                "mac": mac,
                "status": _OPER_STATUS.get(a.OperStatus, "unknown"),
                "mtu": a.Mtu,
                "addresses": addresses,
                "dns_servers": dns_servers,
                "gateways": gateways,
                "dhcp_enabled": dhcp_enabled,
                "dhcp_server": dhcp_server,
            })
            current = a.Next
        return adapters

    def _get_arp_table_windows() -> list[dict[str, Any]]:
        size = wintypes.ULONG(0)
        iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False)
        if ret != 0:
            raise OSError(f"GetIpNetTable failed with code {ret}")
        num_entries = struct.unpack_from("<I", buf, 0)[0]
        type_map = {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}
        entries = []
        offset = 4
        row_size = 24
        for i in range(num_entries):
            idx, phys_len, phys_addr, addr, atype = struct.unpack_from("<II8sII", buf, offset + i * row_size)
            mac_bytes = phys_addr[:phys_len]
            mac = ":".join(f"{b:02X}" for b in mac_bytes) if mac_bytes else None
            entries.append({
                "ip": socket.inet_ntoa(struct.pack("<I", addr)),
                "mac": mac,
                "type": type_map.get(atype, str(atype)),
                "interface_index": idx,
                "vendor": _lookup_mac_vendor(mac),
            })
        return entries

    _ROUTE_PROTO = {
        1: "other", 2: "local", 3: "netmgmt", 4: "icmp", 5: "egp", 6: "ggp", 7: "hello",
        8: "rip", 9: "is-is", 10: "es-is", 11: "cisco-igrp", 12: "bbn-spf-igp", 13: "ospf", 14: "bgp",
    }

    def _get_route_table_windows() -> list[dict[str, Any]]:
        size = wintypes.ULONG(0)
        iphlpapi.GetIpForwardTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetIpForwardTable(buf, ctypes.byref(size), False)
        if ret != 0:
            raise OSError(f"GetIpForwardTable failed with code {ret}")
        num_entries = struct.unpack_from("<I", buf, 0)[0]
        entries = []
        offset = 4
        row_size = 56
        for i in range(num_entries):
            dest, mask, _policy, next_hop, if_index, _fwd_type, proto, _age, _nh_as, m1, _m2, _m3, _m4, _m5 = \
                struct.unpack_from("<14I", buf, offset + i * row_size)
            entries.append({
                "destination": socket.inet_ntoa(struct.pack("<I", dest)),
                "netmask": socket.inet_ntoa(struct.pack("<I", mask)),
                "gateway": socket.inet_ntoa(struct.pack("<I", next_hop)),
                "interface_index": if_index,
                "metric": m1,
                "protocol": _ROUTE_PROTO.get(proto, str(proto)),
            })
        return entries

    _TCP_STATE = {
        1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
        7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
    }

    def _get_tcp_table_windows() -> list[dict[str, Any]]:
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)  # TCP_TABLE_OWNER_PID_ALL
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if ret != 0:
            raise OSError(f"GetExtendedTcpTable failed with code {ret}")
        num_entries = struct.unpack_from("<I", buf, 0)[0]
        entries = []
        offset = 4
        row_size = 24
        for i in range(num_entries):
            state, local_addr, local_port, remote_addr, remote_port, pid = \
                struct.unpack_from("<IIIIII", buf, offset + i * row_size)
            entries.append({
                "local_address": socket.inet_ntoa(struct.pack("<I", local_addr)),
                "local_port": socket.ntohs(local_port & 0xFFFF),
                "remote_address": socket.inet_ntoa(struct.pack("<I", remote_addr)),
                "remote_port": socket.ntohs(remote_port & 0xFFFF),
                "state": _TCP_STATE.get(state, str(state)),
                "pid": pid,
            })
        return entries

    def _get_udp_table_windows() -> list[dict[str, Any]]:
        size = wintypes.DWORD(0)
        iphlpapi.GetExtendedUdpTable(None, ctypes.byref(size), False, socket.AF_INET, 1, 0)  # UDP_TABLE_OWNER_PID
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetExtendedUdpTable(buf, ctypes.byref(size), False, socket.AF_INET, 1, 0)
        if ret != 0:
            raise OSError(f"GetExtendedUdpTable failed with code {ret}")
        num_entries = struct.unpack_from("<I", buf, 0)[0]
        entries = []
        offset = 4
        row_size = 12
        for i in range(num_entries):
            local_addr, local_port, pid = struct.unpack_from("<III", buf, offset + i * row_size)
            entries.append({
                "local_address": socket.inet_ntoa(struct.pack("<I", local_addr)),
                "local_port": socket.ntohs(local_port & 0xFFFF),
                "remote_address": None,
                "remote_port": None,
                "state": None,
                "pid": pid,
            })
        return entries

    _proc_name_cache: dict[int, str | None] = {}

    def _get_process_name(pid: int) -> str | None:
        if pid in _proc_name_cache:
            return _proc_name_cache[pid]
        if pid == 0:
            _proc_name_cache[0] = "System Idle Process"
            return _proc_name_cache[0]
        name = None
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                name = Path(buf.value).name
            kernel32.CloseHandle(handle)
        _proc_name_cache[pid] = name
        return name

    _IFROW_FORMAT = "<512s5I8s16I256s"
    _IFROW_SIZE = struct.calcsize(_IFROW_FORMAT)
    _MIB_IF_OPER_STATUS = {0: "non_operational", 1: "unreachable", 2: "disconnected", 3: "connecting", 4: "connected", 5: "operational"}

    def _get_if_table_windows() -> list[dict[str, Any]]:
        size = wintypes.ULONG(0)
        iphlpapi.GetIfTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(size.value)
        ret = iphlpapi.GetIfTable(buf, ctypes.byref(size), False)
        if ret != 0:
            raise OSError(f"GetIfTable failed with code {ret}")
        num_entries = struct.unpack_from("<I", buf, 0)[0]
        offset = 4
        entries = []
        for i in range(num_entries):
            (name_raw, idx, iftype, mtu, speed, _phys_len, _phys_addr, admin_status, oper_status, _last_change,
             in_octets, in_ucast, in_nucast, in_discards, in_errors, _in_unknown, out_octets, out_ucast,
             out_nucast, out_discards, out_errors, _out_qlen, descr_len, descr_raw) = \
                struct.unpack_from(_IFROW_FORMAT, buf, offset + i * _IFROW_SIZE)
            name = name_raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
            descr = descr_raw[:descr_len].decode("ascii", errors="replace")
            entries.append({
                "name": name,
                "description": descr,
                "index": idx,
                "type": iftype,
                "mtu": mtu,
                "speed_bps": speed,
                "admin_status": "up" if admin_status == 1 else "down",
                "oper_status": _MIB_IF_OPER_STATUS.get(oper_status, str(oper_status)),
                "in_octets": in_octets,
                "in_packets": in_ucast + in_nucast,
                "in_errors": in_errors,
                "in_discards": in_discards,
                "out_octets": out_octets,
                "out_packets": out_ucast + out_nucast,
                "out_errors": out_errors,
                "out_discards": out_discards,
            })
        return entries


# ---------------------------------------------------------------------------
# MAC vendor lookup - small, best-effort OUI prefix table.
#
# NOT a full IEEE OUI database (that has 40000+ entries). Covers common
# virtualization platforms, SBCs and consumer network gear only. Absence
# from this table means "unknown", not "no vendor" - for anything that
# matters, check https://standards-oui.ieee.org/ instead.
# ---------------------------------------------------------------------------

_MAC_VENDOR_OUIS: dict[str, str] = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation", "E4:5F:01": "Raspberry Pi Foundation",
    "A4:83:E7": "Apple", "3C:22:FB": "Apple", "F0:18:98": "Apple", "AC:DE:48": "Apple", "F4:5C:89": "Apple", "00:1E:C2": "Apple",
    "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link",
    "A0:40:A0": "Netgear", "2C:30:33": "Netgear",
    "24:A4:3C": "Ubiquiti Networks", "74:AC:B9": "Ubiquiti Networks",
    "00:1E:58": "D-Link", "C8:D3:A3": "D-Link",
    "1C:87:2C": "ASUSTek", "04:D4:C4": "ASUSTek",
    "FC:65:DE": "Amazon", "44:65:0D": "Amazon",
    "F4:F5:D8": "Google", "54:60:09": "Google",
    "5C:0A:5B": "Samsung", "00:16:6B": "Samsung",
    "00:0E:58": "Sonos",
    "24:0A:C4": "Espressif (ESP8266/ESP32)", "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "00:1C:DF": "Belkin",
}


def _lookup_mac_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    return _MAC_VENDOR_OUIS.get(mac.upper()[:8])


# ---------------------------------------------------------------------------
# POSIX fallbacks (best-effort - this project's primary target is Windows;
# Linux support uses /proc and iproute2, macOS support is minimal)
# ---------------------------------------------------------------------------

def _get_adapters_posix() -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=5, check=True)
        raw_ifaces = json.loads(proc.stdout)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not enumerate interfaces via 'ip addr' ({exc}); this fallback requires iproute2") from exc

    gateways_by_dev: dict[str, list[str]] = {}
    try:
        route_proc = subprocess.run(["ip", "-j", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        for route in json.loads(route_proc.stdout or "[]"):
            dev, gw = route.get("dev"), route.get("gateway")
            if dev and gw:
                gateways_by_dev.setdefault(dev, []).append(gw)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    dns_servers: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    dns_servers.append(parts[1])
    except OSError:
        pass

    adapters = []
    for iface in raw_ifaces:
        name = iface.get("ifname")
        addresses = [
            {"ip": a["local"], "prefix_length": a["prefixlen"]}
            for a in iface.get("addr_info", []) if a.get("local")
        ]
        adapters.append({
            "name": name,
            "description": None,
            "index": iface.get("ifindex"),
            "mac": iface.get("address"),
            "status": "up" if "UP" in (iface.get("flags") or []) else "down",
            "mtu": iface.get("mtu"),
            "addresses": addresses,
            "dns_servers": dns_servers,
            "gateways": gateways_by_dev.get(name, []),
            "dhcp_enabled": None,
            "dhcp_server": None,
        })
    return adapters


def _get_arp_table_posix() -> list[dict[str, Any]]:
    entries = []
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError as exc:
        raise RuntimeError(f"Could not read /proc/net/arp: {exc}") from exc
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hw_type, flags, mac, _mask, device = parts[:6]
        mac_norm = mac.upper() if mac != "00:00:00:00:00:00" else None
        entries.append({
            "ip": ip,
            "mac": mac_norm,
            "type": "dynamic" if flags == "0x2" else "unknown",
            "interface_index": device,
            "vendor": _lookup_mac_vendor(mac_norm),
        })
    return entries


def _get_route_table_posix() -> list[dict[str, Any]]:
    entries = []
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError as exc:
        raise RuntimeError(f"Could not read /proc/net/route: {exc}") from exc
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface, dest_hex, gw_hex, _flags, _refcnt, _use, metric, mask_hex = parts[:8]
        entries.append({
            "destination": socket.inet_ntoa(struct.pack("<I", int(dest_hex, 16))),
            "netmask": socket.inet_ntoa(struct.pack("<I", int(mask_hex, 16))),
            "gateway": socket.inet_ntoa(struct.pack("<I", int(gw_hex, 16))),
            "interface_index": iface,
            "metric": int(metric),
            "protocol": None,
        })
    return entries


def _get_connections_posix(protocol: str) -> list[dict[str, Any]]:
    path = f"/proc/net/{protocol}"
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()[1:]
    except OSError as exc:
        raise RuntimeError(f"Could not read {path}: {exc}") from exc

    def _decode_addr(hex_addr_port: str) -> tuple[str, int]:
        addr_hex, port_hex = hex_addr_port.split(":")
        addr = socket.inet_ntoa(struct.pack("<I", int(addr_hex, 16)))
        return addr, int(port_hex, 16)

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr, local_port = _decode_addr(parts[1])
        remote_addr, remote_port = _decode_addr(parts[2])
        entry: dict[str, Any] = {
            "local_address": local_addr, "local_port": local_port,
            "remote_address": remote_addr if protocol == "tcp" else None,
            "remote_port": remote_port if protocol == "tcp" else None,
            "state": _TCP_STATE_POSIX.get(parts[3], parts[3]) if protocol == "tcp" else None,
            "pid": None,
        }
        entries.append(entry)
    return entries


_TCP_STATE_POSIX = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RCVD", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
    "06": "TIME_WAIT", "07": "CLOSED", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _get_net_dev_posix() -> list[dict[str, Any]]:
    entries = []
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]
    except OSError as exc:
        raise RuntimeError(f"Could not read /proc/net/dev: {exc}") from exc
    for line in lines:
        name, _, rest = line.partition(":")
        fields = rest.split()
        if len(fields) < 16:
            continue
        entries.append({
            "name": name.strip(),
            "description": None, "index": None, "type": None, "mtu": None, "speed_bps": None,
            "admin_status": None, "oper_status": None,
            "in_octets": int(fields[0]), "in_packets": int(fields[1]), "in_errors": int(fields[2]), "in_discards": int(fields[3]),
            "out_octets": int(fields[8]), "out_packets": int(fields[9]), "out_errors": int(fields[10]), "out_discards": int(fields[11]),
        })
    return entries


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _get_adapters() -> list[dict[str, Any]]:
    return _get_adapters_addresses_windows() if IS_WINDOWS else _get_adapters_posix()


def list_interfaces() -> dict[str, Any]:
    adapters = _get_adapters()
    return {"interfaces": [
        {"name": a["name"], "description": a["description"], "mac": a["mac"],
         "status": a["status"], "mtu": a["mtu"], "addresses": a["addresses"]}
        for a in adapters
    ]}


def get_ip_config(interface: str | None = None) -> dict[str, Any]:
    adapters = _get_adapters()
    if interface:
        needle = interface.lower()
        adapters = [a for a in adapters if needle in (a["name"] or "").lower() or needle in (a["description"] or "").lower()]
        if not adapters:
            raise ValueError(f"No interface matching {interface!r} found")
    return {"interfaces": adapters}


def arp_table() -> dict[str, Any]:
    entries = _get_arp_table_windows() if IS_WINDOWS else _get_arp_table_posix()
    return {"count": len(entries), "entries": entries}


def route_table() -> dict[str, Any]:
    entries = _get_route_table_windows() if IS_WINDOWS else _get_route_table_posix()
    return {"count": len(entries), "entries": entries, "ipv4_only": True}


def list_connections(protocol: str = "tcp", state: str | None = None, pid: int | None = None,
                      resolve_process_names: bool = True) -> dict[str, Any]:
    protocol = protocol.lower()
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'")

    if IS_WINDOWS:
        entries = _get_tcp_table_windows() if protocol == "tcp" else _get_udp_table_windows()
        if resolve_process_names:
            for e in entries:
                e["process_name"] = _get_process_name(e["pid"])
    else:
        entries = _get_connections_posix(protocol)
        for e in entries:
            e["process_name"] = None  # PID->process resolution not implemented on POSIX

    if state:
        state_u = state.upper()
        entries = [e for e in entries if e.get("state") == state_u]
    if pid is not None:
        entries = [e for e in entries if e.get("pid") == pid]

    return {"protocol": protocol, "count": len(entries), "connections": entries}


def local_port_check(port: int, protocol: str = "tcp", host: str = "0.0.0.0") -> dict[str, Any]:
    protocol = protocol.lower()
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'")
    port = int(port)
    if not (0 < port < 65536):
        raise ValueError("port must be between 1 and 65535")

    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, sock_type)
    in_use, bind_error = False, None
    try:
        s.bind((host, port))
    except OSError as exc:
        in_use, bind_error = True, str(exc)
    finally:
        s.close()

    result: dict[str, Any] = {"port": port, "protocol": protocol, "host": host, "in_use": in_use}
    if bind_error:
        result["bind_error"] = bind_error
    if in_use and IS_WINDOWS:
        try:
            owners = [c for c in list_connections(protocol=protocol)["connections"] if c["local_port"] == port]
            if owners:
                result["owners"] = owners
        except Exception:
            pass
    return result


def _quick_ping(host: str, timeout: float) -> bool:
    if IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout + 2)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def subnet_scan(subnet: str, ports: list[int] | None = None, timeout: float = 1.0,
                 max_workers: int = 64, resolve_hostnames: bool = True, resolve_mac: bool = True) -> dict[str, Any]:
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts()) or [network.network_address]
    if len(hosts) > MAX_SUBNET_SCAN_HOSTS:
        raise ValueError(f"Subnet too large ({len(hosts)} hosts); max {MAX_SUBNET_SCAN_HOSTS} (roughly a /22 or smaller)")
    timeout = max(0.2, min(float(timeout), 10))
    max_workers = max(1, min(int(max_workers), 256))

    def probe(ip: Any) -> dict[str, Any]:
        ip_s = str(ip)
        alive = _quick_ping(ip_s, timeout)
        entry: dict[str, Any] = {"ip": ip_s, "alive": alive}
        if alive and resolve_hostnames:
            try:
                entry["hostname"] = socket.gethostbyaddr(ip_s)[0]
            except (socket.herror, socket.gaierror, OSError):
                entry["hostname"] = None
        if alive and ports:
            entry["open_ports"] = [p for p in ports if _tcp_probe(ip_s, p, timeout)]
        return entry

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        all_results = list(ex.map(probe, hosts))

    alive_hosts = [r for r in all_results if r["alive"]]

    # Pinging populates the local ARP/neighbour cache for hosts on the same
    # L2 segment, so a fresh arp_table() lookup right after the sweep can
    # attach a MAC (and best-effort vendor) to each live host. Hosts beyond
    # the local subnet (reached via a router) won't resolve - the ARP cache
    # would only show the gateway's MAC for those, so we deliberately leave
    # mac=None rather than report a misleading value.
    if resolve_mac and alive_hosts:
        try:
            arp_by_ip = {e["ip"]: e for e in arp_table()["entries"]}
        except Exception:
            arp_by_ip = {}
        for h in alive_hosts:
            entry = arp_by_ip.get(h["ip"])
            h["mac"] = entry["mac"] if entry else None
            h["vendor"] = entry["vendor"] if entry else None
    return {"subnet": str(network), "scanned": len(hosts), "alive_count": len(alive_hosts), "hosts": alive_hosts}


def network_stats() -> dict[str, Any]:
    entries = _get_if_table_windows() if IS_WINDOWS else _get_net_dev_posix()
    if IS_WINDOWS:
        friendly_names = {a["index"]: a["name"] for a in _get_adapters_addresses_windows()}
        for e in entries:
            e["friendly_name"] = friendly_names.get(e["index"])
    return {"interfaces": entries}


_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_TIME_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def traceroute(host: str, max_hops: int = 30, timeout: float = 2.0, resolve_hostnames: bool = False) -> dict[str, Any]:
    max_hops = max(1, min(int(max_hops), 64))
    timeout = max(0.5, min(float(timeout), 10))
    timeout_ms = int(timeout * 1000)

    if IS_WINDOWS:
        args = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), host]
    else:
        args = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), host]

    start = time.perf_counter()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout * max_hops + 15)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"traceroute to {host} failed: {exc}") from exc
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

    hops = []
    for line in proc.stdout.splitlines():
        m = _HOP_LINE_RE.match(line)
        if not m:
            continue
        hop_num, rest = int(m.group(1)), m.group(2)
        times = [float(t) for t in _TIME_RE.findall(rest)]
        ip_match = _IP_RE.search(rest)
        ip = ip_match.group(1) if ip_match else None
        hop: dict[str, Any] = {"hop": hop_num, "ip": ip, "times_ms": times, "timed_out": ip is None and not times}
        if ip and resolve_hostnames:
            try:
                hop["hostname"] = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                hop["hostname"] = None
        hops.append(hop)

    return {"host": host, "hops": hops, "hop_count": len(hops), "elapsed_ms": elapsed_ms, "command": args, "raw_output": proc.stdout}


def wifi_info() -> dict[str, Any]:
    if IS_WINDOWS:
        try:
            proc = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=10)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            raise RuntimeError(f"Could not run netsh: {exc}") from exc

        raw: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key:
                raw[key] = value

        if not raw:
            return {"connected": False, "raw": {}, "note": "No wireless interface data returned (adapter off, no Wi-Fi hardware, or not connected)."}

        def _find(*labels: str) -> str | None:
            for label in labels:
                for k, v in raw.items():
                    if k.lower() == label.lower():
                        return v
            return None

        return {
            "connected": bool(_find("SSID")),
            "ssid": _find("SSID"),
            "bssid": _find("BSSID"),
            "signal": _find("Signal", "Signaal"),
            "radio_type": _find("Radio type", "Radiotype"),
            "channel": _find("Channel", "Kanaal"),
            "receive_rate_mbps": _find("Receive rate (Mbps)", "Ontvangstsnelheid (Mbps)"),
            "transmit_rate_mbps": _find("Transmit rate (Mbps)", "Verzendsnelheid (Mbps)"),
            "authentication": _find("Authentication", "Verificatie"),
            "raw": raw,
        }

    try:
        proc = subprocess.run(["nmcli", "-t", "-f", "active,ssid,signal,chan,rate", "dev", "wifi"],
                               capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        raise RuntimeError(f"Wi-Fi info not available on this platform (nmcli not found): {exc}") from exc

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 5 and parts[0] == "yes":
            return {"connected": True, "ssid": parts[1], "signal": parts[2], "channel": parts[3], "rate": parts[4]}
    return {"connected": False, "raw": proc.stdout}


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

TOOLS: dict[str, dict[str, Any]] = {}


def register_tool(name: str, description: str, schema: dict[str, Any], handler: Callable[..., dict[str, Any]]) -> None:
    TOOLS[name] = {"description": description, "inputSchema": schema, "handler": handler}


def _string_prop(desc: str) -> dict[str, Any]:
    return {"type": "string", "description": desc}


register_tool(
    "list_interfaces",
    "List local network interfaces/adapters with status, MAC address, MTU and IP addresses.",
    {"type": "object", "properties": {}, "required": []},
    list_interfaces,
)

register_tool(
    "get_ip_config",
    "Get detailed IP configuration (IPs/prefixes, gateways, DNS servers, DHCP status/server) for one or all interfaces.",
    {
        "type": "object",
        "properties": {"interface": _string_prop("Substring to match against interface name/description (default: all interfaces)")},
        "required": [],
    },
    get_ip_config,
)

register_tool(
    "arp_table",
    "List the local ARP/neighbour cache (IP -> MAC mappings), with a best-effort MAC vendor guess. IPv4 only.",
    {"type": "object", "properties": {}, "required": []},
    arp_table,
)

register_tool(
    "route_table",
    "List the local IPv4 routing table (destination/netmask/gateway/interface/metric).",
    {"type": "object", "properties": {}, "required": []},
    route_table,
)

register_tool(
    "list_connections",
    "List active TCP or UDP connections/listeners with local/remote address, state, and owning PID/process name (Windows only for process name).",
    {
        "type": "object",
        "properties": {
            "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp", "description": "Which protocol's table to list"},
            "state": _string_prop("Filter to a specific TCP state (e.g. LISTEN, ESTABLISHED); ignored for UDP"),
            "pid": {"type": "integer", "description": "Filter to a specific owning process ID"},
            "resolve_process_names": {"type": "boolean", "default": True, "description": "Resolve owning PID to a process name (Windows only)"},
        },
        "required": [],
    },
    list_connections,
)

register_tool(
    "local_port_check",
    "Check whether a local TCP/UDP port is free to bind on this machine, by attempting an actual bind (not a remote connect). If in use, tries to report the owning process.",
    {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "description": "Port number to check (1-65535)"},
            "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"},
            "host": _string_prop("Local address to bind to, default 0.0.0.0 (all interfaces)"),
        },
        "required": ["port"],
    },
    local_port_check,
)

register_tool(
    "subnet_scan",
    "Sweep a local subnet (CIDR) for live hosts via ping, with optional hostname resolution, MAC address lookup (via the ARP cache) and TCP port scan per live host. Concurrent, capped at 1024 hosts (~/22).",
    {
        "type": "object",
        "properties": {
            "subnet": _string_prop("CIDR subnet to scan, e.g. '192.168.1.0/24'"),
            "ports": {"type": "array", "items": {"type": "integer"}, "description": "Optional list of TCP ports to probe on each live host"},
            "timeout": {"type": "number", "default": 1.0, "description": "Timeout in seconds per host/port probe"},
            "max_workers": {"type": "integer", "default": 64, "description": "Max concurrent probes"},
            "resolve_hostnames": {"type": "boolean", "default": True, "description": "Reverse-DNS each live host"},
            "resolve_mac": {"type": "boolean", "default": True, "description": "Look up each live host's MAC (and best-effort vendor) via the ARP cache; only resolves for hosts on the same L2 segment"},
        },
        "required": ["subnet"],
    },
    subnet_scan,
)

register_tool(
    "network_stats",
    "Per-interface traffic counters: bytes/packets in and out, errors, discards (and link speed/status on Windows).",
    {"type": "object", "properties": {}, "required": []},
    network_stats,
)

register_tool(
    "traceroute",
    "Trace the network path to a host hop by hop (wraps tracert/traceroute). Reachability/timeouts are parsed from numeric RTTs and IP addresses only, not from localized status text.",
    {
        "type": "object",
        "properties": {
            "host": _string_prop("Hostname or IP to trace"),
            "max_hops": {"type": "integer", "default": 30, "minimum": 1, "maximum": 64},
            "timeout": {"type": "number", "default": 2.0, "minimum": 0.5, "maximum": 10, "description": "Timeout in seconds per probe"},
            "resolve_hostnames": {"type": "boolean", "default": False, "description": "Reverse-DNS each responding hop"},
        },
        "required": ["host"],
    },
    traceroute,
)

register_tool(
    "wifi_info",
    "Current Wi-Fi connection status: SSID, signal strength, channel, radio type, link rates (Windows via netsh, best-effort nmcli fallback elsewhere).",
    {"type": "object", "properties": {}, "required": []},
    wifi_info,
)


# ---------------------------------------------------------------------------
# MCP protocol - minimal native JSON-RPC 2.0 implementation, transport-agnostic
# ---------------------------------------------------------------------------

def handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
    return {
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": (
            "Local network/system toolbox: list_interfaces, get_ip_config, "
            "arp_table, route_table, list_connections (with owning PID/process), "
            "local_port_check, subnet_scan, network_stats, traceroute, wifi_info. "
            "All tools inspect this machine and its local network only - no "
            "internet/remote-host HTTP/DNS/WHOIS here (see mcp-internet-tools "
            "for that)."
        ),
    }


def handle_tools_list() -> dict[str, Any]:
    return {"tools": [{"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]} for name, spec in TOOLS.items()]}


def handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}

    spec = TOOLS.get(name)
    if spec is None:
        return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}

    try:
        result = spec["handler"](**arguments)
        return {"isError": False, "content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
    except Exception as exc:  # noqa: BLE001 - surfaced to the calling model as a tool error
        return {"isError": True, "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}]}


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Process one JSON-RPC 2.0 request/notification object and return the
    response object to send back, or None if nothing should be sent
    (notifications, and the "notifications/initialized" handshake message).
    Shared by both transports - stdio writes the result as a line, the
    streamable-http handler sends it as the HTTP response body."""
    msg_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}
    is_notification = "id" not in request

    try:
        if method == "initialize":
            result = handle_initialize(params)
        elif method == "notifications/initialized":
            return None
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = handle_tools_list()
        elif method == "tools/call":
            result = handle_tools_call(params)
        else:
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
    except Exception as exc:  # noqa: BLE001 - protocol-level failure
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": f"Internal error: {exc}"}}

    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


# ---------------------------------------------------------------------------
# Transport: stdio
# ---------------------------------------------------------------------------

def run_stdio() -> None:
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response: dict[str, Any] | None = {
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": "Parse error: invalid JSON"},
            }
        else:
            response = handle_request(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# Transport: streamable-http (stdlib http.server only - no Flask/FastAPI/
# uvicorn). Implements the request/response half of the MCP "Streamable
# HTTP" transport: POST a single JSON-RPC message (or a JSON array of them)
# to the endpoint and get the JSON-RPC response(s) back in the HTTP
# response body. This server never pushes unsolicited messages, so GET
# (opening a server->client SSE stream) is not supported and returns 405,
# which the spec allows for servers without that capability.
# ---------------------------------------------------------------------------

class _MCPHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def _send_json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status: int, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming convention
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error: invalid JSON"}})
            return

        if isinstance(payload, list):
            responses = [r for r in (handle_request(item) for item in payload) if r is not None]
            if not responses:
                self._send_empty(202)
                return
            self._send_json(200, responses)
            return

        if not isinstance(payload, dict):
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
            return

        response = handle_request(payload)
        if response is None:
            self._send_empty(202)
            return

        extra_headers = {"Mcp-Session-Id": self.headers.get("Mcp-Session-Id") or str(uuid.uuid4())}
        self._send_json(200, response, extra_headers)

    def do_GET(self) -> None:  # noqa: N802
        self._send_empty(405, {"Allow": "POST"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_empty(200)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")


def run_streamable_http(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), _MCPHTTPRequestHandler)
    print(f"{SERVER_NAME}: streamable-http transport listening on http://{host}:{port}/mcp", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mcp-network-tools.py",
        description="MCP server for local network/system diagnostics, over stdio or streamable-http.",
    )
    parser.add_argument(
        "--transport", choices=["stdio", "streamable-http"], default="stdio",
        help="Transport to serve the MCP protocol over (default: stdio)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host/interface to bind for --transport streamable-http (default: 127.0.0.1; use 0.0.0.0 for Docker/n8n)",
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="Port to bind for --transport streamable-http (default: 8000)",
    )
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    if args.transport == "streamable-http":
        run_streamable_http(args.host, args.port)
    else:
        run_stdio()


if __name__ == "__main__":
    main()
