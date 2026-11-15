"""A fictional network for `--demo`: shows what a report looks like without touching any network."""
from __future__ import annotations

import datetime as dt
import re

from . import __version__
from . import knowledge as K
from . import rules

NAMING = r"^(PC-\d+|SRV-|DC\d|nas|gw|printer|cam|srv)"
SERVERS = r"^(SRV|DC)"
DOMAIN = "acme.local"


def _rec(port, service="", product="", info="", source="banner", flags=(), kind="", **extra):
    rec = {"port": port, "service": service or K.PORT_INFO.get(port, ""), "product": product, "info": info,
           "source": source if (service or product) else "port", "flags": list(flags), "kind": kind}
    rec.update(extra)
    return rec


def _cert(now: dt.datetime, cn: str, issuer: str, days: int, version: str = "TLSv1.3", **extra) -> dict:
    """Certificate facts dated relative to today, so the demo never shows stale dates."""
    return dict({"cn": cn, "issuer_cn": issuer, "days_left": days, "self_signed": cn == issuer, "version": version,
                 "not_after": (now + dt.timedelta(days=days)).strftime("%Y-%m-%d")}, **extra)


def _windows(ip, name, build, mac, vendor, ports, domain=DOMAIN, signing=True, smb1=False, rdp=None, extra=()):
    host = {"ip": ip, "hostname": f"{name.lower()}.{DOMAIN}", "mac": mac, "vendor": vendor,
            "alive_by": ["ping", "arp"],
            "smb": {"smb2": True, "status": 0, "dialect": "3.1.1" if build >= 14393 else "3.0.2",
                    "signing_enabled": True, "signing_required": signing, "smb1": smb1,
                    "ntlm": {"netbios_name": name, "dns_name": f"{name}.{domain}" if domain != name else name,
                             "dns_domain": domain, "build": build}},
            "ports": [_rec(p) for p in ports] + list(extra)}
    if rdp:
        host["rdp"] = {"nla_required": rdp == "nla", "code": rdp}
    return host


def sample_hosts(now: dt.datetime | None = None) -> list[dict]:
    now = now or dt.datetime.now()
    hosts = [
        {"ip": "192.168.10.1", "hostname": "gw.acme.local", "is_gateway": True, "mac": "00:08:A2:10:20:30",
         "vendor": "Netgate", "alive_by": ["ping", "arp"],
         "ssdp": {"server": "FreeBSD UPnP/1.1 MiniUPnPd/2.2",
                  "types": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]},
         "ports": [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"), _rec(53),
                   _rec(443, "HTTPS", "pfSense (nginx)", "pfSense - Login", "http", flags=["login_page"],
                        kind="firewall", tls=_cert(now, "gw.acme.local", "gw.acme.local", 18))]},
        {"ip": "192.168.10.2", "hostname": "", "mac": "34:0A:33:AA:00:02", "vendor": "D-Link International",
         "alive_by": ["ping", "arp"], "snmp": "DGS-1210-28 Gigabit Smart Managed Switch",
         "ports": [_rec(23, "Telnet", "", "", "banner"),
                   _rec(80, "HTTP", "D-Link", "Login", "http", flags=["login_page"], kind="network")]},
        {"ip": "192.168.10.5", "hostname": "printer-1f.acme.local", "mac": "00:20:6B:AA:00:05",
         "vendor": "Konica Minolta", "alive_by": ["ping", "arp"],
         "ports": [_rec(80, "HTTP", "Konica Minolta", "bizhub", "http", kind="printer"), _rec(515), _rec(631),
                   _rec(9100, info="not probed: print port")]},
        {"ip": "192.168.10.10", "hostname": "nas01.acme.local", "mac": "00:11:32:AA:00:10", "vendor": "Synology",
         "alive_by": ["ping", "arp"],
         "smb": {"smb2": True, "status": 0, "dialect": "3.1.1", "signing_enabled": True, "signing_required": False,
                 "smb1": False, "ntlm": {"netbios_name": "NAS01", "dns_name": "nas01", "build": 0}},
         "ports": [_rec(22, "SSH", "SSH-2.0-OpenSSH_8.2"), _rec(445), _rec(873), _rec(3260), _rec(6281),
                   _rec(3306, "MySQL/MariaDB", "MariaDB 10.11.6"),
                   _rec(5001, "HTTPS", "Synology (nginx)", "NAS01 - Synology NAS", "http", kind="nas",
                        tls=_cert(now, "nas01.acme.example", "R11", -21))]},
        {"ip": "192.168.10.11", "hostname": "srv01-bmc.acme.local", "mac": "10:98:36:AA:00:11", "vendor": "Dell",
         "alive_by": ["ping", "arp"],
         "ports": [_rec(22, "SSH", "SSH-2.0-OpenSSH_7.4"),
                   _rec(443, "HTTPS", "Dell iDRAC", "iDRAC9 login", "http", flags=["tls_legacy"], kind="bmc",
                        tls=_cert(now, "idrac-DEMO123", "idrac-DEMO123", 410, "TLSv1.2", legacy="TLSv1.1")),
                   _rec(5900)]},
        _windows("192.168.10.20", "DC01", 20348, "00:15:5D:AA:00:20", "Microsoft (Hyper-V)",
                 (53, 88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985), rdp="nla"),
        _windows("192.168.10.21", "SRV-FILE", 14393, "00:15:5D:AA:00:21", "Microsoft (Hyper-V)",
                 (135, 139, 445, 3389, 5938, 5985), signing=False, rdp="nla"),
        _windows("192.168.10.22", "SRV-APP", 9600, "00:15:5D:AA:00:22", "Microsoft (Hyper-V)",
                 (135, 139, 445, 1433, 3389), signing=False, smb1=True, rdp="standard",
                 extra=[_rec(80, "HTTP", "Microsoft IIS (Microsoft-IIS/8.5)", "IIS Windows Server", "http",
                             kind="web", outdated="IIS 8.5 or older (unsupported Windows Server)")]),
        _windows("192.168.10.101", "PC-001", 26100, "08:92:04:AA:01:01", "Dell", (135, 139, 445)),
        _windows("192.168.10.102", "PC-002", 26100, "08:92:04:AA:01:02", "Dell", (135, 139, 445, 5938)),
        _windows("192.168.10.103", "PC-003", 19045, "08:92:04:AA:01:03", "Dell", (135, 139, 445), signing=False),
        _windows("192.168.10.104", "PC-004", 26100, "08:92:04:AA:01:04", "Dell", (135, 139, 445),
                 extra=[_rec(8000, "HTTP", "uvicorn", "HTTP 404", "http", flags=["dev_server"]), _rec(57621)]),
        _windows("192.168.10.150", "LAPTOP-7QK2", 22621, "A4:C3:F0:AA:01:50", "Intel", (135, 445),
                 domain="LAPTOP-7QK2"),
        {"ip": "192.168.10.160", "hostname": "", "mac": "DA:A1:19:AA:01:60", "vendor": K.RANDOM_MAC,
         "mac_random": True, "alive_by": ["arp"], "ports": []},
        {"ip": "192.168.10.161", "hostname": "cam-entrance.acme.local", "mac": "00:40:8C:AA:01:61",
         "vendor": "Axis Communications", "alive_by": ["ping", "arp"],
         "ports": [_rec(80, "HTTP", "IP camera (webserver)", "", "http", flags=["http_auth", "basic_auth_plain"],
                        kind="camera",
                        http={"status": 401, "title": "", "server": "webserver", "auth": "Basic realm=\"camera\""}),
                   _rec(554)]},
    ]
    dc = next(host for host in hosts if host["ip"] == "192.168.10.20")
    dc["ldap"] = {"naming_context": "DC=acme,DC=local", "dns_host": "DC01.acme.local", "domain_level": 6,
                  "forest_level": 6, "dc_level": 7}
    for host in hosts:
        host["ports"].sort(key=lambda rec: rec["port"])
    return hosts


def build() -> dict:
    """A complete audit dictionary for the fictional Acme network."""
    finished = dt.datetime.now()
    started = finished - dt.timedelta(seconds=192)
    hosts = sample_hosts(finished)
    server_regex = re.compile(SERVERS, re.I)
    for host in hosts:
        rules.classify(host, server_regex)
    rules.link_multihomed(hosts)
    targets = ["192.168.10.0/24"]
    findings = rules.build_findings(hosts, targets, None, re.compile(NAMING, re.I), DOMAIN)
    scan = {"profile": "standard", "speed": "normal", "ports_per_host": len(K.ports_for("standard")),
            "nbns": True, "snmp": True, "ssdp": True, "nmap": False, "local": False,
            "source_host": "AUDIT-PC", "source_ip": "192.168.10.200", "seen_from": started.strftime("%H:%M"),
            "seen_to": finished.strftime("%H:%M"), "date": finished.strftime("%Y-%m-%d"), "excluded": [],
            "naming": True, "domain": DOMAIN,
            # the same keys a real run saves, so --regenerate reproduces the demo exactly
            "naming_pattern": NAMING, "server_pattern": SERVERS, "domain_option": DOMAIN,
            "interrupted": False, "local_errors": 0}
    return {
        "meta": {"tool": "NetAudit", "version": __version__, "client": "Acme Ltd (demo)", "operator": "demo",
                 "started": started.strftime("%Y-%m-%d %H:%M"), "finished": finished.strftime("%Y-%m-%d %H:%M"),
                 "duration": "3 min 12 s", "targets": targets, "target_networks": targets, "profile": "standard",
                 "source": "AUDIT-PC (192.168.10.200)", "interrupted": False,
                 "warnings": ["Demonstration data: this network does not exist."],
                 "authorization": "not applicable (demonstration data)", "scan": scan, "baseline": "",
                 "exposure": rules.exposure(findings)},
        "hosts": hosts, "findings": findings, "positives": rules.build_positives(hosts),
        "limits": rules.build_limits(scan, hosts), "local": None, "diff": None,
    }
