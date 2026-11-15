"""Targeted UDP probes: NetBIOS names (137), SNMP (161) and SSDP/UPnP discovery (1900).

SNMP: a single read of sysDescr with the default community 'public'. It is the only check
that uses a default value; disable it with --no-snmp.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import time

_NBNS_QUERY_TAIL = (b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
                    + b"\x00\x21\x00\x01")
_SYSDESCR_OID = bytes.fromhex("06082b06010201010100")
_SSDP_REQUEST = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                 b"MX: 2\r\nST: ssdp:all\r\n\r\n")


def nbns_request() -> bytes:
    return os.urandom(2) + _NBNS_QUERY_TAIL


def _tlv(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def snmp_request(community: bytes = b"public") -> bytes:
    """SNMP v2c GET of sysDescr.0."""
    request_id = bytes([1 + os.urandom(1)[0] % 0x7E]) + os.urandom(3)  # positive, minimal 4-byte integer
    varbinds = _tlv(0x30, _tlv(0x30, _SYSDESCR_OID + b"\x05\x00"))
    pdu = _tlv(0xA0, _tlv(0x02, request_id) + b"\x02\x01\x00\x02\x01\x00" + varbinds)
    return _tlv(0x30, b"\x02\x01\x01" + _tlv(0x04, community) + pdu)


def parse_nbns(data: bytes) -> dict:
    """'Node status' response: computer name, domain/workgroup, MAC."""
    if len(data) < 57:
        return {}
    count = data[56]
    names, pos = [], 57
    for _ in range(count):
        if pos + 18 > len(data):
            break
        raw, suffix, flags = data[pos:pos + 15], data[pos + 15], struct.unpack_from(">H", data, pos + 16)[0]
        names.append((raw.decode("latin-1", "replace").strip(), suffix, bool(flags & 0x8000)))
        pos += 18
    info: dict = {}
    for name, suffix, group in names:
        if suffix == 0x00 and not group and "name" not in info:
            info["name"] = name
        if suffix == 0x00 and group and "domain" not in info:
            info["domain"] = name
        if suffix == 0x20 and not group:
            info["file_server"] = True
    if pos + 6 <= len(data):
        mac = data[pos:pos + 6]
        if any(mac):
            info["mac"] = ":".join(f"{b:02X}" for b in mac)
    return info


def _ber_length(data: bytes, pos: int):
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    size = first & 0x7F
    return int.from_bytes(data[pos + 1:pos + 1 + size], "big"), pos + 1 + size


def parse_snmp(data: bytes) -> str:
    """Extract sysDescr from an SNMP response; '' when it is not a valid response."""
    if not data or data[0] != 0x30:
        return ""
    idx = data.find(_SYSDESCR_OID)
    if idx < 0:
        return ""
    pos = idx + len(_SYSDESCR_OID)
    try:
        if data[pos] != 0x04:
            return "(SNMP response without a description)"
        length, start = _ber_length(data, pos + 1)
        text = data[start:start + length].decode("utf-8", "replace")
    except (IndexError, ValueError):
        return ""
    return " ".join(text.split())[:200] or "(empty description)"


def parse_ssdp(data: bytes) -> dict:
    """SSDP response headers of interest: server, st, location."""
    if not data.startswith((b"HTTP/1.1 200", b"NOTIFY")):
        return {}
    info = {}
    for line in data.decode("latin-1", "replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in ("server", "st", "nt", "location", "usn"):
            name = "st" if key.strip().lower() == "nt" else key.strip().lower()
            info[name] = value.strip()[:200]
    return info


def sweep(ips: list[str], nbns: bool = True, snmp: bool = True, ssdp_from: str = "",
          wait: float = 3.0, nbns_port: int = 137, snmp_port: int = 161) -> dict[str, dict]:
    """Send the probes to every host and collect the answers.
    -> {ip: {'nbns': {...}, 'snmp': '...', 'ssdp': {'server':..., 'types': [...]}}}
    ssdp_from: local address of the interface to use for the multicast search ('' = skip)."""
    results: dict[str, dict] = {}
    socks = {}
    try:
        if nbns:
            socks["nbns"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if snmp:
            socks["snmp"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if ssdp_from:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((ssdp_from, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ssdp_from))
                socks["ssdp"] = sock
            except OSError:
                pass
        for sock in socks.values():
            sock.setblocking(False)
        wanted = set(ips)
        for _round in range(2):  # two rounds: UDP does not guarantee delivery
            if "ssdp" in socks:
                try:
                    socks["ssdp"].sendto(_SSDP_REQUEST, ("239.255.255.250", 1900))
                except OSError:
                    pass
            for ip in ips:
                try:
                    if "nbns" in socks and "nbns" not in results.get(ip, {}):
                        socks["nbns"].sendto(nbns_request(), (ip, nbns_port))
                    if "snmp" in socks and "snmp" not in results.get(ip, {}):
                        socks["snmp"].sendto(snmp_request(), (ip, snmp_port))
                except OSError:
                    pass
                time.sleep(0.004)
            deadline = time.time() + wait / 2
            while socks:
                left = deadline - time.time()
                if left <= 0:
                    break
                readable, _w, _x = select.select(list(socks.values()), [], [], left)
                for sock in readable:
                    try:
                        data, (src, _port) = sock.recvfrom(4096)
                    except OSError:
                        continue  # on Windows an ICMP "port unreachable" surfaces as an error
                    if src not in wanted:
                        continue
                    if sock is socks.get("nbns"):
                        parsed = parse_nbns(data)
                        if parsed:
                            results.setdefault(src, {})["nbns"] = parsed
                    elif sock is socks.get("snmp"):
                        text = parse_snmp(data)
                        if text:
                            results.setdefault(src, {})["snmp"] = text
                    else:
                        parsed = parse_ssdp(data)
                        if parsed:
                            entry = results.setdefault(src, {}).setdefault("ssdp", {"server": "", "types": []})
                            entry["server"] = entry["server"] or parsed.get("server", "")
                            kind = parsed.get("st", "")
                            if kind and kind not in entry["types"] and len(entry["types"]) < 20:
                                entry["types"].append(kind)
    finally:
        for sock in socks.values():
            sock.close()
    return results
