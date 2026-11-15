"""Local network facts: interfaces, ARP table, source address, target parsing."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import subprocess

IS_WINDOWS = os.name == "nt"


def run_powershell(script: str, timeout: int = 60) -> str:
    """Run a PowerShell script and return its stdout as UTF-8 ('' on failure)."""
    if not IS_WINDOWS:
        return ""
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; " + script
    encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode("utf-8", errors="replace").strip()


def run_powershell_json(script: str, timeout: int = 60):
    out = run_powershell(script, timeout)
    if not out:
        return None
    start = min([i for i in (out.find("{"), out.find("[")) if i >= 0], default=-1)
    if start < 0:
        return None
    try:
        return json.loads(out[start:])
    except ValueError:
        return None


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace").stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def source_ip(target: str = "8.8.8.8") -> str:
    """Local address used to reach the target (no packet is sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target, 9))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


_PS_INTERFACES = r"""
$r = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } | ForEach-Object {
  [pscustomobject]@{
    alias   = $_.InterfaceAlias
    desc    = $_.InterfaceDescription
    ip      = $_.IPv4Address[0].IPAddress
    prefix  = [int]$_.IPv4Address[0].PrefixLength
    gateway = $_.IPv4DefaultGateway[0].NextHop
    dns     = @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses } )
    profile = [string](Get-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name
    wifi    = [bool]($_.NetAdapter.PhysicalMediaType -match '802\.11')
  } })
ConvertTo-Json -InputObject $r -Depth 4
"""


def _unix_interfaces() -> list[dict]:
    """Interfaces on Linux (iproute2 JSON) with the default gateway, best effort."""
    found = []
    gateways = {}
    try:
        for route in json.loads(_run(["ip", "-j", "route", "show", "default"]) or "[]"):
            if route.get("gateway") and route.get("dev"):
                gateways[route["dev"]] = route["gateway"]
        for link in json.loads(_run(["ip", "-j", "-4", "addr", "show"]) or "[]"):
            name = link.get("ifname", "")
            for addr in link.get("addr_info", []):
                if addr.get("family") == "inet" and name in gateways:
                    found.append({"alias": name, "desc": "", "ip": addr["local"],
                                  "prefix": int(addr.get("prefixlen", 24)), "gateway": gateways[name],
                                  "dns": [], "profile": "", "wifi": name.startswith(("wl", "wlan"))})
    except (ValueError, KeyError, TypeError):
        pass
    return found


def local_interfaces() -> list[dict]:
    """Active interfaces with a gateway: alias, ip, prefix, gateway, dns, profile, wifi, network."""
    if IS_WINDOWS:
        data = run_powershell_json(_PS_INTERFACES, 40)
    else:
        data = _unix_interfaces()
    if isinstance(data, dict):
        data = [data]
    found = []
    for item in data or []:
        ip = item.get("ip") or ""
        if not ip or ip.startswith("169.254."):
            continue
        try:
            net = ipaddress.ip_network(f"{ip}/{item.get('prefix', 24)}", strict=False)
        except ValueError:
            continue
        item["network"] = str(net)
        item["dns"] = [d for d in (item.get("dns") or []) if d]
        found.append(item)
    if not found:
        ip = source_ip()
        if ip and not ip.startswith("127."):
            found.append({"alias": "", "desc": "", "ip": ip, "prefix": 24, "gateway": _default_gateway(),
                          "dns": [], "profile": "", "wifi": False,
                          "network": str(ipaddress.ip_network(ip + "/24", strict=False))})
    # the interface the system actually routes through comes first (a VPN adapter with a gateway
    # must not beat it), then wired before Wi-Fi
    primary = source_ip()
    found.sort(key=lambda i: (bool(_VIRTUAL_ADAPTER.search(f"{i.get('alias', '')} {i.get('desc', '')}")),
                              i.get("ip") != primary, bool(i.get("wifi"))))
    return found


# tunnels and hypervisor switches are never the network someone means by "the local subnet"
_VIRTUAL_ADAPTER = re.compile(r"vpn|\btap\b|\btun\d*\b|wireguard|openvpn|anyconnect|fortinet|zerotier|tailscale|"
                              r"hyper-v|vethernet|vmware|virtualbox|loopback|docker|wsl", re.I)


def _default_gateway() -> str:
    match = re.search(r"default via (\S+)", _run(["ip", "route", "show", "default"]))
    if match:
        return match.group(1)
    match = re.search(r"gateway:\s*(\S+)", _run(["route", "-n", "get", "default"]))
    return match.group(1) if match else ""


_MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_arp(text: str) -> dict[str, str]:
    """Parse `arp -a` / `ip neigh` output: ip -> MAC (valid unicast entries only)."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        mac = _MAC_RE.search(line)
        # "name-10.0.0.9.lan (192.168.1.33) at ..." : the address is the one in parentheses
        ip = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line) or _IP_RE.search(line)
        if not mac or not ip:
            continue
        # macOS prints octets without leading zeros (0:11:32:...): normalize them
        value = ":".join(part.zfill(2) for part in re.split("[:-]", mac.group(1))).upper()
        if value in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") or int(value[:2], 16) & 0x01:
            continue  # broadcast, incomplete or multicast
        table[ip.group(1)] = value
    return table


def arp_table() -> dict[str, str]:
    """ARP cache of this machine. Sources are tried from the cheapest and most reliable down:
    the kernel table on Linux, then the tools; `-n` avoids slow reverse DNS lookups."""
    try:
        with open("/proc/net/arp", encoding="ascii", errors="replace") as handle:
            table = parse_arp(handle.read())
        if table:
            return table
    except OSError:
        pass
    commands = [["arp", "-a"]] if IS_WINDOWS else [["ip", "neigh"], ["arp", "-an"]]
    for cmd in commands:
        table = parse_arp(_run(cmd, 10))
        if table:
            return table
    return {}


class ExactNetwork(ipaddress.IPv4Network):
    """A fragment of an explicit a-b range: every address counts, none is dropped as network/broadcast."""

    def hosts(self):
        return iter(self)


def parse_targets(specs: list[str]) -> list[ipaddress.IPv4Network]:
    """Turn CIDRs, single IPs and ranges (a.b.c.d-e) into networks."""
    nets: list[ipaddress.IPv4Network] = []
    for spec in specs:
        for part in str(spec).split(","):
            part = part.strip()
            if not part:
                continue
            match = re.fullmatch(r"(\d+\.\d+\.\d+\.)(\d+)-(\d+)", part)
            if match:
                lo, hi = int(match.group(2)), int(match.group(3))
                if lo > hi or hi > 255:
                    raise ValueError(f"invalid range: {part}")
                first = ipaddress.ip_address(match.group(1) + str(lo))
                last = ipaddress.ip_address(match.group(1) + str(hi))
                nets.extend(ExactNetwork(str(net)) for net in ipaddress.summarize_address_range(first, last))
            else:
                try:
                    net = ipaddress.ip_network(part, strict=False)
                except ValueError:
                    net = None
                if net is None or net.version != 4:
                    raise ValueError(f"'{part}' is not a valid target: use 192.168.1.0/24, 192.168.1.7 or "
                                     "192.168.1.10-50 (host names and IPv6 are not supported)")
                nets.append(net)
    return nets


def expand_hosts(nets, exclude=()) -> list[str]:
    seen, hosts = set(exclude), []
    for net in nets:
        for addr in net.hosts():
            text = str(addr)
            if text not in seen:
                seen.add(text)
                hosts.append(text)
    return hosts


def ip_key(ip: str):
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (999,)
