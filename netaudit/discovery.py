"""Host discovery: ping, TCP probe, ARP table, DNS names."""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import os
import socket
import subprocess
import sys

from . import knowledge as K
from . import netinfo, portscan


def _ping_command(ip: str) -> list[str]:
    if netinfo.IS_WINDOWS:
        return ["ping", "-n", "1", "-w", "900", ip]
    if sys.platform == "darwin" or "bsd" in sys.platform:
        return ["ping", "-c", "1", "-W", "1000", ip]   # milliseconds on macOS/BSD
    return ["ping", "-c", "1", "-W", "1", ip]           # seconds on Linux


_PING_ENV = dict(os.environ, LC_ALL="C", LANG="C")     # the "ttl=" check needs untranslated output


def _ping(ip: str) -> bool:
    try:
        proc = subprocess.run(_ping_command(ip), capture_output=True, timeout=4,
                              env=None if netinfo.IS_WINDOWS else _PING_ENV)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    # On Windows exit code 0 is also returned for "destination host unreachable".
    return b"ttl=" in proc.stdout.lower()


def ping_sweep(ips: list[str]) -> set[str]:
    alive: set[str] = set()
    with cf.ThreadPoolExecutor(max_workers=96) as pool:
        for ip, ok in zip(ips, pool.map(_ping, ips)):
            if ok:
                alive.add(ip)
    return alive


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def reverse_dns(ips: list[str]) -> dict[str, str]:
    names: dict[str, str] = {}
    with cf.ThreadPoolExecutor(max_workers=32) as pool:
        for ip, name in zip(ips, pool.map(_rdns, ips)):
            if name and name != ip:
                names[ip] = name
    return names


async def discover(ips: list[str], log, should_abort=None, stats: dict | None = None) -> dict[str, dict]:
    """Return {ip: {alive_by: [...], mac, vendor, hostname}} for the hosts that are up.
    `stats`, when given, receives 'local_errors' (connections lost to local socket exhaustion)
    and 'ping_works' (False when this machine cannot ping at all)."""
    loop = asyncio.get_running_loop()
    stats = stats if stats is not None else {}
    log(f"Pinging {len(ips)} address{'' if len(ips) == 1 else 'es'} ...")
    pinged = await loop.run_in_executor(None, ping_sweep, ips)
    log(f"  {len(pinged)} answer ping.")
    stats["ping_works"] = True
    if not pinged and len(ips) > 1:
        # containers and restricted accounts often cannot send ICMP at all: say so instead of "0 hosts"
        stats["ping_works"] = await loop.run_in_executor(None, _ping, "127.0.0.1")
        if not stats["ping_works"]:
            log("  ping is not usable from this machine: relying on TCP probes and the ARP table.")

    silent = [ip for ip in ips if ip not in pinged]
    tcp_alive: set[str] = set()
    if silent:
        log(f"TCP probe on {len(silent)} addresses that do not answer ping ...")
        res = await portscan.scan({ip: K.DISCOVERY_PORTS for ip in silent},
                                  workers=len(K.DISCOVERY_PORTS), timeout=0.8, max_sockets=600,
                                  should_abort=should_abort)
        tcp_alive = {ip for ip, ports in res.open.items() if ports}
        stats["local_errors"] = stats.get("local_errors", 0) + res.local_errors
        log(f"  {len(tcp_alive)} answer on TCP only.")

    arp = await loop.run_in_executor(None, netinfo.arp_table)
    wanted = set(ips)
    arp_only = {ip for ip in arp if ip in wanted and ip not in pinged and ip not in tcp_alive}
    if arp_only:
        log(f"  {len(arp_only)} seen only in the ARP table (no answer to ping or TCP).")

    alive = sorted(pinged | tcp_alive | arp_only, key=netinfo.ip_key)
    log(f"Resolving DNS names for {len(alive)} hosts ...")
    names = await loop.run_in_executor(None, reverse_dns, alive)

    hosts: dict[str, dict] = {}
    for ip in alive:
        by = []
        if ip in pinged:
            by.append("ping")
        if ip in tcp_alive:
            by.append("tcp")
        if ip in arp:
            by.append("arp")
        mac = arp.get(ip, "")
        vendor = K.vendor_for(mac)
        hosts[ip] = {
            "ip": ip, "alive_by": by, "mac": mac, "vendor": vendor,
            "mac_random": vendor == K.RANDOM_MAC, "hostname": names.get(ip, ""),
        }
    return hosts
