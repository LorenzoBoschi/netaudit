"""Optional nmap integration: version detection on services the built-in probes left unknown.

nmap is not required. When installed it is only used on ports already found open,
never on print ports and never on printer-like hosts.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from . import knowledge as K

_CANDIDATES = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]


def find_nmap() -> str:
    found = shutil.which("nmap")
    if found:
        return found
    for path in _CANDIDATES:
        if os.path.exists(path):
            return path
    return ""


def parse_xml(text: str) -> dict[int, dict]:
    """nmap XML -> {port: {'service':..., 'product':...}} for the ports it recognized."""
    found: dict[int, dict] = {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return found
    for port in root.iter("port"):
        state = port.find("state")
        service = port.find("service")
        if state is None or state.get("state") != "open" or service is None:
            continue
        if service.get("method") != "probed":
            continue  # "table" = guessed from the port number alone: adds nothing
        product = " ".join(part for part in (service.get("product"), service.get("version"),
                                             service.get("extrainfo")) if part)
        name = service.get("name", "")
        if service.get("tunnel") == "ssl":
            name = "ssl/" + name
        try:
            number = int(port.get("portid", ""))
        except ValueError:
            continue
        if name or product:
            found[number] = {"service": name, "product": product[:100]}
    return found


def _run(nmap: str, ip: str, ports: list[int]) -> dict[int, dict]:
    cmd = [nmap, "-Pn", "-n", "-sT", "-T4", "--max-retries", "1", "-sV", "--version-light",
           "-p", ",".join(map(str, ports)), "-oX", "-", ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=240)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_xml(proc.stdout.decode("utf-8", "replace"))


def identify(nmap: str, pending: dict[str, list[int]]) -> dict[str, dict[int, dict]]:
    """pending = {ip: [ports still unknown]}. Print ports are always excluded."""
    jobs = {ip: [p for p in ports if p not in K.NEVER_SEND] for ip, ports in pending.items()}
    jobs = {ip: ports for ip, ports in jobs.items() if ports}
    results: dict[str, dict[int, dict]] = {}
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_run, nmap, ip, ports): ip for ip, ports in jobs.items()}
        for future in cf.as_completed(futures):
            try:
                data = future.result()
            except Exception:
                data = {}
            if data:
                results[futures[future]] = data
    return results
