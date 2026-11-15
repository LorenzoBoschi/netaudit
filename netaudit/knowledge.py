"""Knowledge tables: ports, services, vendors, Windows releases, outdated software.

Everything that is "knowledge" rather than "logic" lives here so it can be updated in one place.
"""
from __future__ import annotations

import os
import re

# --------------------------------------------------------------------------- ports

PORT_INFO = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 79: "Finger", 80: "HTTP",
    81: "HTTP (alternate)", 88: "Kerberos", 102: "Siemens S7 (PLC)", 110: "POP3", 111: "RPCbind",
    135: "MSRPC", 139: "NetBIOS session", 143: "IMAP", 161: "SNMP", 389: "LDAP", 427: "SLP",
    443: "HTTPS", 445: "SMB", 464: "Kerberos password change", 465: "SMTPS", 502: "Modbus (PLC)",
    512: "rexec", 513: "rlogin", 514: "rsh", 515: "LPD (printing)", 548: "AFP", 554: "RTSP",
    587: "SMTP submission", 593: "RPC over HTTP", 623: "IPMI", 631: "IPP (printing)", 636: "LDAPS",
    873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "Microsoft SQL Server", 1521: "Oracle DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2179: "Hyper-V VM console", 2222: "SSH (alternate)", 2375: "Docker API (unencrypted)",
    2376: "Docker API (TLS)", 3000: "HTTP application", 3128: "HTTP proxy", 3260: "iSCSI",
    3268: "LDAP Global Catalog", 3269: "LDAPS Global Catalog", 3306: "MySQL/MariaDB", 3389: "RDP",
    3493: "NUT (UPS)", 4443: "HTTPS (alternate)", 4899: "Radmin", 5000: "HTTP/UPnP/AirPlay",
    5001: "HTTPS (e.g. Synology DSM)", 5040: "Windows CDP", 5060: "SIP", 5061: "SIP TLS",
    5357: "WSD", 5432: "PostgreSQL", 5510: "Synology Active Backup", 5555: "Android ADB",
    5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5901: "VNC", 5938: "TeamViewer", 5984: "CouchDB",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6281: "Synology Hyper Backup Vault", 6379: "Redis",
    6443: "Kubernetes API", 7000: "AirPlay", 7070: "AnyDesk", 7680: "Windows Delivery Optimization",
    8000: "HTTP (alternate)", 8006: "Proxmox VE", 8008: "HTTP (alternate)", 8009: "AJP",
    8040: "ScreenConnect", 8041: "ScreenConnect relay", 8080: "HTTP (alternate)",
    8081: "HTTP (alternate)", 8088: "HTTP (alternate)", 8291: "MikroTik Winbox",
    8443: "HTTPS (alternate)", 8728: "MikroTik API", 8888: "HTTP (alternate)", 9000: "HTTP application",
    9042: "Cassandra", 9090: "HTTP management", 9100: "RAW printing (JetDirect)", 9200: "Elasticsearch",
    9389: "AD Web Services", 9443: "HTTPS (alternate)", 10000: "Webmin/NDMP", 10250: "Kubelet",
    11211: "Memcached", 19999: "Netdata", 27017: "MongoDB", 27036: "Steam", 32400: "Plex",
    37777: "Dahua DVR", 47001: "WinRM", 57621: "Spotify", 62078: "iPhone sync",
}

# Ports that never receive any data: a printer would print whatever arrives.
NEVER_SEND = set(range(9100, 9117)) | {515}

# Windows/AD/storage services recognized by number: probing them adds nothing.
BY_NUMBER_ONLY = {53, 88, 135, 139, 464, 593, 636, 2179, 3260, 3268, 3269, 5040, 7680, 9389, 47001}

HTTP_FIRST = {80, 81, 3000, 5000, 5357, 5985, 7000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9200,
              2375, 19999, 32400, 47001}
TLS_FIRST = {443, 465, 993, 995, 2376, 4443, 5001, 5061, 5986, 6443, 8006, 8443, 9443, 10250}

DB_PORTS = {
    1433: "Microsoft SQL Server", 1521: "Oracle DB", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}
REMOTE_TOOLS = {5938: "TeamViewer", 7070: "AnyDesk", 4899: "Radmin", 8040: "ScreenConnect",
                8041: "ScreenConnect"}
CONSUMER_SOFTWARE = {27036: "Steam", 57621: "Spotify", 32400: "Plex"}
STORAGE_PORTS = {445: "SMB", 2049: "NFS", 873: "rsync", 3260: "iSCSI", 548: "AFP",
                 6281: "Hyper Backup Vault", 5510: "Active Backup"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM HTTPS"}
PRINT_PORTS = {515, 631} | set(range(9100, 9117))
INDUSTRIAL_PORTS = {102: "Siemens S7", 502: "Modbus"}
# Servers people start by hand while developing. Production servers that merely share a framework
# (Jetty in Jenkins, Kestrel behind IIS, gunicorn, aiohttp in Home Assistant) are deliberately absent.
DEV_SERVER_MARKS = ("uvicorn", "werkzeug", "simplehttp", "hypercorn", "tornadoserver", "express", "next.js",
                    "development server", "webpack")
DEV_BODY_MARKS = ("/@vite/client", "webpack-dev-server")

DISCOVERY_PORTS = [22, 80, 135, 139, 443, 445, 3389, 5900, 7000, 8080, 9100, 62078]

# Common high ports added to the standard profile (on top of 1-1024 and PORT_INFO).
_EXTRA_STANDARD = [
    1025, 1026, 1027, 1099, 1111, 1234, 1311, 1500, 1720, 1900, 2000, 2001, 2082, 2083, 2086, 2087,
    2100, 2121, 2181, 2323, 2379, 2380, 2401, 2483, 2525, 3001, 3050, 3261, 3263, 3264, 3265, 3299,
    3333, 3478, 3690, 4000, 4040, 4369, 4444, 4567, 4848, 5002, 5003, 5004, 5005, 5006, 5050, 5222,
    5269, 5353, 5500, 5544, 5566, 5631, 5666, 5800, 5902, 5903, 6000, 6001, 6080, 6666, 6667, 7001,
    7002, 7443, 7474, 7547, 7777, 8001, 8002, 8010, 8020, 8022, 8042, 8060, 8069, 8082, 8083, 8084,
    8085, 8086, 8089, 8090, 8091, 8096, 8123, 8139, 8181, 8200, 8222, 8243, 8280, 8333, 8444,
    8460, 8462, 8470, 8500, 8800, 8834, 8880, 8883, 9001, 9002, 9009, 9080, 9091, 9092, 9093,
    9101, 9102, 9103, 9112, 9113, 9114, 9115, 9116, 9300, 9418, 9500, 9600, 9800, 9981, 9999,
    10001, 10443, 11111, 12345, 13000, 15672, 16992, 16993, 18080, 20000, 25565,
    27015, 28017, 30000, 32768, 37215, 44443, 49152, 49153, 49154, 50000, 50001,
    50070, 50443, 51413, 54321, 55555, 60000, 61616,
]

PROFILES = ("quick", "standard", "full")


def ports_for(profile: str) -> list[int]:
    """TCP port list for a profile: quick, standard or full."""
    if profile == "quick":
        return sorted(PORT_INFO)
    if profile == "standard":
        return sorted(set(range(1, 1025)) | set(PORT_INFO) | set(_EXTRA_STANDARD))
    if profile == "full":
        return list(range(1, 65536))
    raise ValueError(f"unknown profile: {profile}")


SPEEDS = {
    # workers per host, connect timeout (s), cap on simultaneous connections
    "careful": (40, 1.0, 400),
    "normal": (80, 0.8, 720),
    "fast": (80, 0.5, 720),
}

# --------------------------------------------------------------------------- Windows

_W10_NOTE = "out of support since 10/2025 unless enrolled in ESU or an LTSC edition: edition to be verified"

# Dates checked against Microsoft's release-health pages (Windows 10, Windows 11, Windows Server
# release information) on 2026-11-15. Review them at least twice a year.
# build -> (product, state, note). state: ok | warning | verify | eol
# Over SMB Windows reports the base build of its family: 19041 covers all of Windows 10
# 2004-22H2, 22621 covers Windows 11 22H2-23H2, 26100 covers 24H2-25H2.
WINDOWS_BUILDS = {
    2600: ("Windows XP", "eol", "out of support since 2014"),
    3790: ("Windows Server 2003", "eol", "out of support since 2015"),
    6002: ("Windows Vista / Server 2008", "eol", "out of support"),
    6003: ("Windows Server 2008", "eol", "out of support"),
    7600: ("Windows 7 / Server 2008 R2", "eol", "out of support since 2020"),
    7601: ("Windows 7 / Server 2008 R2", "eol", "out of support since 2020"),
    9200: ("Windows 8 / Server 2012", "eol", "out of support since 10/2023"),
    9600: ("Windows 8.1 / Server 2012 R2", "eol", "out of support since 10/2023"),
    10240: ("Windows 10 1507", "eol", "out of support"),
    10586: ("Windows 10 1511", "eol", "out of support"),
    14393: ("Windows Server 2016 / Windows 10 1607", "warning", "Server 2016: end of support 01/2027"),
    15063: ("Windows 10 1703", "eol", "out of support"),
    16299: ("Windows 10 1709", "eol", "out of support"),
    17134: ("Windows 10 1803", "eol", "out of support"),
    17763: ("Windows Server 2019 / Windows 10 1809", "ok", "Server 2019: supported until 01/2029"),
    18362: ("Windows 10 1903", "eol", "out of support"),
    18363: ("Windows 10 1909", "eol", "out of support"),
    19041: ("Windows 10 (2004-22H2)", "verify", _W10_NOTE),
    19042: ("Windows 10 20H2", "verify", _W10_NOTE),
    19043: ("Windows 10 21H1", "verify", _W10_NOTE),
    19044: ("Windows 10 21H2", "verify", _W10_NOTE),
    19045: ("Windows 10 22H2", "verify", _W10_NOTE),
    20348: ("Windows Server 2022", "ok", "supported until 10/2031"),
    22000: ("Windows 11 21H2", "eol", "out of support"),
    22621: ("Windows 11 22H2-23H2", "eol", "out of support (23H2 Enterprise since 11/2026)"),
    22631: ("Windows 11 23H2", "eol", "out of support (Home/Pro since 11/2025, Enterprise since 11/2026)"),
    26100: ("Windows 11 24H2-25H2 / Server 2025", "ok",
            "25H2 supported until 10/2027 (Home/Pro) and Server 2025 until 11/2034; 24H2 Home/Pro ended "
            "10/2026 (not distinguishable over SMB)"),
    26200: ("Windows 11 25H2", "ok", "supported until 10/2027 (Home/Pro), 10/2028 (Enterprise)"),
}


def windows_product(build: int):
    """Return (product, state, note) for a Windows build number."""
    if build in WINDOWS_BUILDS:
        return WINDOWS_BUILDS[build]
    if build > max(WINDOWS_BUILDS):
        return (f"Windows (build {build})", "ok", "recent build not in the table")
    if build < 10240:
        return (f"Windows (build {build})", "eol", "pre-Windows 10 release, out of support")
    return (f"Windows (build {build})", "unknown", "build not in the table")


# AD functional levels as reported by the LDAP rootDSE.
AD_FUNCTIONAL_LEVELS = {0: "2000", 1: "2003 interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012",
                        6: "2012 R2", 7: "2016", 10: "2025"}

# --------------------------------------------------------------------------- outdated software

# (pattern on Server / X-Powered-By / banner, label). Deliberately conservative:
# only branches that have been end-of-life for years.
OUTDATED_SOFTWARE = [(re.compile(p, re.I), label) for p, label in [
    (r"Apache/(1\.|2\.[0-2]\.)", "Apache httpd 2.2 or older (end of life)"),
    (r"Microsoft-IIS/([1-7]\.\d|8\.[05])", "IIS 8.5 or older (unsupported Windows Server)"),
    # 7.4 and 8.x are left alone: enterprise distributions still patch them
    (r"PHP/([1-5]\.|7\.[0-3]\b)", "PHP 7.3 or older (end of life)"),
    (r"OpenSSL/(0\.|1\.0\.)", "OpenSSL 1.0 or older (end of life)"),
    (r"nginx/(0\.|1\.\d\.|1\.1[0-7]\.)", "nginx older than 1.18 (unsupported release)"),
    (r"Jetty\(([1-8])\.", "Jetty 8 or older (end of life)"),
    (r"Apache-Coyote/1\.[01]|Tomcat/[1-7]\.", "Tomcat 7 or older (end of life)"),
    (r"lighttpd/1\.[0-3]\.", "lighttpd 1.3 or older (end of life)"),
]]


def outdated_software(text: str) -> str:
    """Label of the first outdated-software pattern found in text, or ''."""
    for regex, label in OUTDATED_SOFTWARE:
        if regex.search(text):
            return label
    return ""


# --------------------------------------------------------------------------- vendors (OUI)

_BUILTIN_OUI = {
    "000C29": "VMware", "005056": "VMware", "00155D": "Microsoft (Hyper-V)", "001132": "Synology",
    "9009D0": "Synology", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "00206B": "Konica Minolta", "525400": "QEMU/KVM", "00E04C": "Realtek", "001B21": "Intel",
    "080027": "VirtualBox", "001C42": "Parallels", "00090F": "Fortinet", "001E67": "Intel",
    "F4F5E8": "Google", "3C5AB4": "Google", "001788": "Philips Hue",
}
_OUI_FILES = [
    r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes",
    r"C:\Program Files\Nmap\nmap-mac-prefixes",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
]
_oui_cache = None
RANDOM_MAC = "Randomized MAC"


def _load_oui() -> dict:
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    table = dict(_BUILTIN_OUI)
    for path in _OUI_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("#") or " " not in line:
                        continue
                    prefix, name = line.rstrip("\n").split(" ", 1)
                    table[prefix.upper()] = name.strip()
            break
        except OSError:
            continue
    _oui_cache = table
    return table


def mac_is_random(mac: str) -> bool:
    """True when the MAC is locally administered (private/randomized address)."""
    try:
        return bool(int(mac.replace(":", "").replace("-", "")[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor_for(mac: str) -> str:
    if not mac:
        return ""
    digits = mac.replace(":", "").replace("-", "").upper()
    table = _load_oui()
    for size in (9, 7, 6):
        hit = table.get(digits[:size])
        if hit:
            return hit  # registered prefixes win: QEMU/KVM (52:54:00) has the "local" bit set too
    return RANDOM_MAC if mac_is_random(mac) else ""
