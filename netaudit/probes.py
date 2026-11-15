"""Service identification probes.

Probe safety rules:
- no login attempts: credentials are never sent and passwords are never tried;
- nothing is ever sent to print ports (a printer would print it);
- on printer-like hosts, unknown ports are only listened to.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import html
import os
import re
import ssl
import struct
import tempfile
import urllib.parse
import warnings

from . import __version__
from . import knowledge as K

CONNECT_TIMEOUT = 3.5
MAX_PROBED_PORTS = 100          # per host; beyond this only well-known ports are identified
HOST_BUDGET_SECONDS = 300       # per host, for identifying all of its services
SAFE_HTTP_ON_PRINTERS = {80, 443, 631, 8080, 8443}

# (regular expression, device kind, product). Order = specificity: earlier wins.
_FINGERPRINTS = [(re.compile(p, re.I), kind, product) for p, kind, product in [
    (r"\bidrac\d*\b", "bmc", "Dell iDRAC"),
    (r"integrated lights-out|\bhpe?[ -]ilo\b|\bilo [2-6]\b", "bmc", "HPE iLO"),
    (r"supermicro", "bmc", "Supermicro IPMI"), (r"megarac", "bmc", "AMI MegaRAC"),
    (r"xclarity|\bimm2?\b", "bmc", "Lenovo XClarity/IMM"), (r"\bipmi\b", "bmc", "IPMI"),
    (r"nethsecurity", "firewall", "NethSecurity"), (r"nethserver", "server", "NethServer"),
    (r"pfsense", "firewall", "pfSense"), (r"opnsense", "firewall", "OPNsense"),
    (r"fortigate|fortinet", "firewall", "Fortinet FortiGate"), (r"watchguard", "firewall", "WatchGuard"),
    (r"sonicwall", "firewall", "SonicWall"), (r"routeros|mikrotik", "firewall", "MikroTik RouterOS"),
    (r"draytek|vigor", "firewall", "DrayTek"), (r"fritz!box", "firewall", "FRITZ!Box"),
    (r"sophos (xg|firewall|utm)", "firewall", "Sophos Firewall"),
    (r"openwrt|/cgi-bin/luci", "firewall", "OpenWrt"), (r"zyxel", "network", "Zyxel"),
    (r"synology|diskstation", "nas", "Synology"), (r"\bqnap\b", "nas", "QNAP"),
    (r"truenas|freenas", "nas", "TrueNAS"), (r"readynas", "nas", "Netgear ReadyNAS"),
    (r"asustor", "nas", "ASUSTOR"), (r"openmediavault", "nas", "OpenMediaVault"),
    (r"\bdgs-\d|\bdes-\d|d-link", "network", "D-Link"), (r"procurve", "network", "HP ProCurve"),
    (r"\baruba\b", "network", "Aruba"), (r"netgear", "network", "Netgear"),
    (r"tp-link|omada", "network", "TP-Link"), (r"ubiquiti|unifi (os|network)|\bubnt\b", "network", "Ubiquiti"),
    (r"\bcisco\b", "network", "Cisco"), (r"smart switch|managed switch", "network", "Managed switch"),
    (r"konica|bizhub|pagescope|/wcd/", "printer", "Konica Minolta"),
    (r"laserjet|officejet|hp-chaisoe|\bhp (color|page)", "printer", "HP"),
    (r"\bbrother\b", "printer", "Brother"), (r"kyocera", "printer", "Kyocera"),
    (r"\bricoh\b|web image monitor", "printer", "Ricoh"), (r"\bepson\b", "printer", "Epson"),
    (r"\bxerox\b", "printer", "Xerox"), (r"lexmark", "printer", "Lexmark"),
    (r"imagerunner|\bcanon (inc|ir)", "printer", "Canon"),
    (r"mailstore", "app", "MailStore"), (r"proxmox", "hypervisor", "Proxmox VE"),
    (r"vmware esxi|vsphere|id_eesx_welcome", "hypervisor", "VMware ESXi/vSphere"),
    (r"vmware,? inc", "hypervisor", "VMware"), (r"\bveeam\b", "app", "Veeam"),
    (r"zabbix", "app", "Zabbix"), (r"grafana", "app", "Grafana"), (r"jenkins", "app", "Jenkins"),
    (r"gitlab", "app", "GitLab"), (r"portainer", "app", "Portainer"),
    (r"home assistant", "app", "Home Assistant"), (r"phpmyadmin", "app", "phpMyAdmin"),
    (r"webmin", "app", "Webmin"), (r"hikvision", "camera", "Hikvision"), (r"\bdahua\b", "camera", "Dahua"),
    (r"netdata", "app", "Netdata"), (r"airtunes", "apple", "Apple AirPlay"),
    (r"you know, for search", "db", "Elasticsearch"), (r"\b3cx\b", "voip", "3CX"),
    (r"yealink|\bsnom\b|grandstream", "voip", "VoIP phone/PBX"),
    (r"nextcloud|owncloud", "app", "Nextcloud/ownCloud"), (r"outlook web|\bowa\b", "app", "Outlook Web App"),
    (r"microsoft-iis", "web", "Microsoft IIS"),
]]


# Products whose pattern is an ordinary word: trusted in titles, headers and certificates,
# never in free page text ("my brother's blog" is not a printer).
_NOT_IN_BODY = {"IPMI", "DrayTek", "Aruba", "Cisco", "Brother", "Epson", "Xerox", "Ricoh", "HP", "Canon",
                "Kyocera", "Lexmark", "Dahua", "VoIP phone/PBX", "3CX", "Managed switch", "Supermicro IPMI",
                "Lenovo XClarity/IMM", "Zyxel", "TP-Link", "Sophos Firewall", "Outlook Web App", "Veeam",
                "VMware"}
_TRUSTED_TEXT_ONLY = {"app", "web", "voip", "apple"}


def fingerprint(text: str, body: str = ""):
    """Recognize device kind and product. `text` is the trusted part (title, headers, certificate,
    SNMP/SSDP description); `body` is free page text, matched only against unambiguous patterns."""
    for regex, kind, product in _FINGERPRINTS:
        if regex.search(text):
            return kind, product
    if body:
        # applications are named in titles and headers; a page that merely mentions one is not it
        matches = [(kind, product) for regex, kind, product in _FINGERPRINTS
                   if kind not in _TRUSTED_TEXT_ONLY and product not in _NOT_IN_BODY and regex.search(body)]
        # a page that names several products is a dashboard or a link list, not one of them
        if len({product for _kind, product in matches}) == 1:
            return matches[0]
    return "", ""


def product_rank(product: str) -> int:
    """Position of the product in the fingerprint list: lower = more specific."""
    for index, (_regex, _kind, name) in enumerate(_FINGERPRINTS):
        if name in product:
            return index
    return len(_FINGERPRINTS)


# --------------------------------------------------------------------------- basics

def tls_context(legacy_only: bool = False) -> ssl.SSLContext:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            if legacy_only:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, AttributeError):
            pass
    return ctx


async def _open(ip, port, tls=None, timeout=CONNECT_TIMEOUT):
    if tls is None:
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=tls, server_hostname=""), timeout + 3)


def _close(writer) -> None:
    try:
        transport = writer.transport
        if transport is not None:
            transport.abort()
    except Exception:
        pass


async def _read_some(reader, size, timeout) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(size), timeout)
    except Exception:
        return b""


async def _read_exact(reader, size, timeout) -> bytes:
    return await asyncio.wait_for(reader.readexactly(size), timeout)


def _clean(text: str, limit: int) -> str:
    """Names sent by a device: no control characters, bounded length."""
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def printable(data: bytes, limit: int = 100) -> str:
    text = data[:limit].decode("latin-1", errors="replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text).strip(". ")


# --------------------------------------------------------------------------- certificates

def decode_cert(der: bytes) -> dict:
    """Extract subject, issuer, SAN and validity from a DER certificate."""
    if not der:
        return {}
    info: dict = {"sha256": hashlib.sha256(der).hexdigest()}
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(ssl.DER_cert_to_PEM_cert(der))
            path = handle.name
        decoded = ssl._ssl._test_decode_cert(path)  # the only X.509 decoder in the standard library
    except Exception:
        decoded = None
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    if not decoded:
        return info

    def flat(name):
        return {key: value for rdn in decoded.get(name, ()) for key, value in rdn}

    subject, issuer = flat("subject"), flat("issuer")
    info.update(
        cn=_clean(subject.get("commonName", ""), 120), org=_clean(subject.get("organizationName", ""), 120),
        issuer_cn=_clean(issuer.get("commonName", ""), 120),
        issuer_org=_clean(issuer.get("organizationName", ""), 120),
        san=[_clean(str(value), 120) for _kind, value in decoded.get("subjectAltName", ())][:12],
        self_signed=decoded.get("subject") == decoded.get("issuer"),
    )
    utc = dt.timezone.utc
    try:
        expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), utc)
        info["not_after"] = expires.strftime("%Y-%m-%d")
        info["days_left"] = (expires - dt.datetime.now(utc)).days
    except Exception:
        pass
    try:
        begins = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notBefore"]), utc)
        info["not_before"] = begins.strftime("%Y-%m-%d")
    except Exception:
        pass
    return info


# --------------------------------------------------------------------------- HTTP

def _html_title(body: bytes) -> str:
    """Text of the first <title>. Plain string searches: a regular expression here could be driven
    into quadratic time by a hostile page made of thousands of unclosed <title> tags."""
    head = body[:16384]
    low = head.lower()
    start = low.find(b"<title")
    close = low.find(b">", start) if start >= 0 else -1
    end = low.find(b"</title", close) if close >= 0 else -1
    if end < 0:
        return ""
    try:
        text = html.unescape(head[close + 1:end][:600].decode("utf-8", "replace"))
    except ValueError:  # absurd numeric character references
        return ""
    return re.sub(r"\s+", " ", text).replace("\xa0", " ").strip()[:120]


def parse_http(raw: bytes):
    """Parse a raw HTTP response. None when it is not HTTP."""
    if not raw.startswith(b"HTTP/"):
        return None
    head, _sep, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1", "replace").split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        return None
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep:
            headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1", "replace").strip()
    return {
        "status": status, "title": _html_title(body), "server": headers.get("server", "")[:80],
        "location": headers.get("location", "")[:200], "auth": headers.get("www-authenticate", "")[:80],
        "powered_by": headers.get("x-powered-by", "")[:60],
        "_body": body[:8000].decode("utf-8", "replace").lower(),
    }


async def _read_http(reader, timeout: float) -> bytes:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    data = b""
    while len(data) < 65536:
        left = deadline - loop.time()
        if left <= 0:
            break
        chunk = await _read_some(reader, 8192, left)
        if not chunk:
            break
        data += chunk
        head, sep, body = data.partition(b"\r\n\r\n")
        if sep:
            match = re.search(rb"content-length:\s*(\d{1,9})\b", head, re.I)
            if match and len(body) >= int(match.group(1)):
                break
            if body.endswith(b"0\r\n\r\n"):
                break
    return data


async def http_get(ip: str, port: int, use_tls: bool, path: str = "/", timeout: float = 5.0):
    """GET over http/https. Returns {'http':..., 'tls':..., 'raw':...} or None."""
    try:
        reader, writer = await _open(ip, port, tls_context() if use_tls else None)
    except Exception:
        return None
    info: dict = {}
    raw = b""
    try:
        if use_tls:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is not None:
                info["tls"] = {"version": ssl_object.version() or ""}
                info["tls"].update(decode_cert(ssl_object.getpeercert(binary_form=True) or b""))
        default = 443 if use_tls else 80
        host = ip if port == default else f"{ip}:{port}"
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetAudit/{__version__}\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "replace"))
        await asyncio.wait_for(writer.drain(), 3)
        raw = await _read_http(reader, timeout)
    except Exception:
        pass
    finally:
        _close(writer)
    parsed = parse_http(raw)
    if parsed:
        info["http"] = parsed
    elif raw:
        info["raw"] = printable(raw)
    return info or None


def same_origin_path(ip: str, port: int, use_tls: bool, path: str, location: str) -> str:
    """Path to follow for a redirect that stays on the same scheme, address and port; '' otherwise.
    A device must not be able to send the probe to another host or another port."""
    scheme = "https" if use_tls else "http"
    try:
        base = f"{scheme}://{ip}:{port}{path}"
        target = urllib.parse.urlsplit(urllib.parse.urljoin(base, location))
        target_port = target.port or (443 if target.scheme == "https" else 80)
    except ValueError:
        return ""
    if target.scheme != scheme or target.hostname != ip or target_port != port:
        return ""
    result = (target.path or "/") + (f"?{target.query}" if target.query else "")
    return result if re.fullmatch(r"[\x21-\x7e]{1,300}", result) else ""


async def http_probe(ip: str, port: int, use_tls: bool, path: str = "/"):
    """Like http_get, following a single redirect that stays on the same host."""
    info = await http_get(ip, port, use_tls, path)
    http = (info or {}).get("http")
    if http and http["status"] in (301, 302, 303, 307, 308) and http["location"]:
        target = same_origin_path(ip, port, use_tls, path, http["location"])
        if target and target != path:
            second = await http_get(ip, port, use_tls, target)
            if second and second.get("http"):
                if "tls" in info:
                    second.setdefault("tls", info["tls"])
                second["http"]["redirect_from"] = path
                return second
    return info


async def tls_legacy_version(ip: str, port: int) -> str:
    """Negotiated version when the server still accepts TLS 1.0/1.1, else ''."""
    try:
        _reader, writer = await _open(ip, port, tls_context(legacy_only=True), 3)
    except Exception:
        return ""
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        version = (ssl_object.version() or "") if ssl_object else ""
        # only a genuinely old version counts: if the cap could not be applied this may be TLS 1.2/1.3
        return version if version in ("TLSv1", "TLSv1.1") else ""
    finally:
        _close(writer)


# --------------------------------------------------------------------------- banners

def parse_banner(data: bytes, port: int):
    """Recognize protocols where the server speaks first. -> (service, product) or None."""
    if data.startswith(b"SSH-"):
        return "SSH", data.split(b"\n", 1)[0].decode("latin-1", "replace").strip()[:80]
    if data.startswith(b"RFB "):
        return "VNC", data[:12].decode("latin-1", "replace").strip()
    if data.startswith(b"220"):
        line = data.split(b"\n", 1)[0].decode("latin-1", "replace").strip()[:100]
        if "FTP" in line.upper() or port == 21:
            return "FTP", line
        return "SMTP", line
    if data.startswith(b"+OK"):
        return "POP3", printable(data, 80)
    if data.startswith(b"* OK"):
        return "IMAP", printable(data, 80)
    if len(data) >= 3 and data[0] == 0xFF and data[1] in (0xFB, 0xFC, 0xFD, 0xFE):
        return "Telnet", ""  # the server opens with IAC option negotiation
    if len(data) > 5 and data[3] == 0 and data[4] == 0x0A:
        version = data[5:].split(b"\x00", 1)[0].decode("latin-1", "replace")
        name = "MariaDB" if "mariadb" in version.lower() else "MySQL"
        return "MySQL/MariaDB", f"{name} {version}"[:80]
    if len(data) > 5 and data[3] == 0 and data[4] == 0xFF:
        return "MySQL/MariaDB", "access denied for this host: " + printable(data[7:], 60)
    if data.startswith(b"HTTP/"):
        return "HTTP", printable(data, 60)
    return None


def ssh_version(product: str):
    """(major, minor) from an OpenSSH banner, else None."""
    match = re.search(r"OpenSSH[_ ](\d+)\.(\d+)", product)
    return (int(match.group(1)), int(match.group(2))) if match else None


def ssh_protocol_1(product: str) -> bool:
    """True when the banner advertises SSH protocol 1 (SSH-1.x, including 1.99 = v1 and v2)."""
    return bool(re.match(r"SSH-1\.", product))


async def vnc_security(reader, writer, banner: bytes) -> dict:
    """Read the security types a VNC server offers (without authenticating)."""
    info = {"version": banner[:12].decode("latin-1", "replace").strip(), "types": []}
    try:
        minor = int(banner[8:11])
    except ValueError:
        return info
    try:
        if minor >= 7:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            count = (await _read_exact(reader, 1, 3))[0]
            if count:
                info["types"] = list(await _read_exact(reader, count, 3))
        else:
            writer.write(b"RFB 003.003\n")
            await writer.drain()
            info["types"] = [struct.unpack(">I", await _read_exact(reader, 4, 3))[0]]
    except Exception:
        pass
    info["no_auth"] = 1 in info["types"]
    return info


# --------------------------------------------------------------------------- SMB

_SMB2_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}


def _nb(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command: int, message_id: int, credit_charge: int = 0) -> bytes:
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, credit_charge, 0, command, 31, 0, 0,
                       message_id, 0, 0, 0, b"\x00" * 16)


def smb2_negotiate_request(with_311: bool = True) -> bytes:
    """SMB2 NEGOTIATE. With SMB 3.1.1 the mandatory negotiate contexts are appended."""
    dialects = [0x0202, 0x0210, 0x0300, 0x0302] + ([0x0311] if with_311 else [])
    dialect_bytes = b"".join(struct.pack("<H", d) for d in dialects)
    guid = os.urandom(16)
    if not with_311:
        body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0, guid, 0) + dialect_bytes
        return _nb(_smb2_header(0, 0) + body)
    padding = (-(64 + 36 + len(dialect_bytes))) % 8
    context_offset = 64 + 36 + len(dialect_bytes) + padding
    preauth = struct.pack("<HHI", 1, 38, 0) + struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
    preauth += b"\x00" * ((-len(preauth)) % 8)
    encryption = struct.pack("<HHI", 2, 6, 0) + struct.pack("<HHH", 2, 2, 1)
    body = (struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0x7F, guid, context_offset, 2, 0)
            + dialect_bytes + b"\x00" * padding + preauth + encryption)
    return _nb(_smb2_header(0, 0) + body)


def _ntlm_negotiate() -> bytes:
    flags = 0xA2888207
    return (b"NTLMSSP\x00" + struct.pack("<II", 1, flags) + struct.pack("<HHI", 0, 0, 40)
            + struct.pack("<HHI", 0, 0, 40) + bytes([10, 0, 0x61, 0x4A, 0, 0, 0, 15]))


def smb2_session_setup_request() -> bytes:
    """First step of authentication ('negotiate' only): the server answers with its name and build.
    The step that carries credentials is never sent."""
    ntlm = _ntlm_negotiate()
    spnego = (bytes.fromhex("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a0428") + ntlm)
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(spnego), 0) + spnego
    return _nb(_smb2_header(1, 1, 1) + body)


def smb1_negotiate_request() -> bytes:
    header = (b"\xffSMB" + b"\x72" + b"\x00" * 4 + b"\x18" + struct.pack("<H", 0xC001)
              + b"\x00" * 12 + struct.pack("<HHHH", 0xFFFF, 0xFEFF, 0, 0))
    dialect = b"\x02NT LM 0.12\x00"
    return _nb(header + b"\x00" + struct.pack("<H", len(dialect)) + dialect)


def parse_smb2_negotiate(data: bytes) -> dict:
    """Parse the SMB2 NEGOTIATE response (without the NetBIOS header)."""
    if data[:4] != b"\xfeSMB" or len(data) < 72:
        return {}
    status = struct.unpack_from("<I", data, 8)[0]
    if status != 0:
        return {"smb2": True, "status": status}
    mode, dialect = struct.unpack_from("<HH", data, 66)
    return {"smb2": True, "status": 0, "dialect": _SMB2_DIALECTS.get(dialect, hex(dialect)),
            "signing_enabled": bool(mode & 1), "signing_required": bool(mode & 2)}


def parse_ntlm_challenge(data: bytes) -> dict:
    """Extract names and version from the NTLM 'challenge' message found in the response."""
    start = data.find(b"NTLMSSP\x00")
    if start < 0:
        return {}
    msg = data[start:]
    if len(msg) < 48 or struct.unpack_from("<I", msg, 8)[0] != 2:
        return {}
    flags = struct.unpack_from("<I", msg, 20)[0]
    info: dict = {}
    info_len, _max, info_off = struct.unpack_from("<HHI", msg, 40)
    if flags & 0x02000000 and len(msg) >= 56:
        major, minor, build = struct.unpack_from("<BBH", msg, 48)
        info.update(os_major=major, os_minor=minor, build=build)
    names = {1: "netbios_name", 2: "netbios_domain", 3: "dns_name", 4: "dns_domain", 5: "dns_forest"}
    pos, end = info_off, min(len(msg), info_off + info_len)
    while pos + 4 <= end:
        av_id, av_len = struct.unpack_from("<HH", msg, pos)
        pos += 4
        if av_id == 0:
            break
        if av_id in names:
            info[names[av_id]] = _clean(msg[pos:pos + av_len].decode("utf-16-le", "replace"), 80)
        pos += av_len
    return info


async def _recv_nb(reader, timeout: float) -> bytes:
    header = await _read_exact(reader, 4, timeout)
    length = int.from_bytes(header[1:4], "big")
    if not 0 < length <= 1 << 20:
        return b""
    return await _read_exact(reader, length, timeout)


async def _smb2_dialogue(ip: str, port: int, with_311: bool) -> dict:
    out: dict = {}
    reader, writer = await _open(ip, port)
    try:
        writer.write(smb2_negotiate_request(with_311))
        await writer.drain()
        out.update(parse_smb2_negotiate(await _recv_nb(reader, 4)))
        if out.get("status") == 0:
            try:  # the identity step is optional: never lose dialect and signing because of it
                writer.write(smb2_session_setup_request())
                await writer.drain()
                ntlm = parse_ntlm_challenge(await _recv_nb(reader, 4))
            except Exception:
                ntlm = {}
            if ntlm:
                out["ntlm"] = ntlm
    finally:
        _close(writer)
    return out


async def smb_info(ip: str, port: int = 445) -> dict:
    """Dialect, signing, SMBv1 and server identity. No credentials are sent."""
    out: dict = {}
    for with_311 in (True, False):  # some old servers reject a negotiate that carries contexts
        try:
            attempt = await _smb2_dialogue(ip, port, with_311)
        except Exception as exc:
            attempt = {}
            out.setdefault("error", type(exc).__name__)
        if attempt.get("status") == 0:
            out = attempt
            break
        if attempt and not out.get("smb2"):
            out.update(attempt)
    try:
        reader, writer = await _open(ip, port)
        try:
            writer.write(smb1_negotiate_request())
            await writer.drain()
            data = await _recv_nb(reader, 3)
            ok = (data[:4] == b"\xffSMB" and len(data) >= 37 and data[4] == 0x72
                  and struct.unpack_from("<I", data, 5)[0] == 0 and data[32] >= 1
                  and struct.unpack_from("<H", data, 33)[0] != 0xFFFF)
            out["smb1"] = bool(ok)
            if ok:
                out["smb1_signing_required"] = bool(data[35] & 0x08)
        finally:
            _close(writer)
    except Exception:
        out.setdefault("smb1", False)
    return out


# --------------------------------------------------------------------------- RDP

_RDP_REQUEST = bytes.fromhex("030000130ee000000000000100080000000000")


def parse_rdp_response(data: bytes) -> dict:
    """Interpret the answer to a request for standard RDP security only (no NLA).
    -> {'nla_required': True|False|None, 'code': str}"""
    if len(data) < 11 or data[0] != 3 or data[5] != 0xD0:
        return {}
    if len(data) < 19:
        return {"nla_required": False, "code": "legacy"}
    kind, value = data[11], struct.unpack_from("<I", data, 15)[0]
    if kind == 3:
        if value == 5:
            return {"nla_required": True, "code": "nla"}
        if value == 1:
            return {"nla_required": False, "code": "tls_only"}
        return {"nla_required": None, "code": f"refused_{value}"}
    if kind == 2:
        return {"nla_required": False, "code": "standard"}
    return {}


async def rdp_check(ip: str, port: int = 3389) -> dict:
    try:
        reader, writer = await _open(ip, port)
    except Exception:
        return {}
    try:
        writer.write(_RDP_REQUEST)
        await writer.drain()
        return parse_rdp_response(await _read_some(reader, 64, 4))
    except Exception:
        return {}
    finally:
        _close(writer)


# --------------------------------------------------------------------------- LDAP rootDSE

def _ber(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def _ber_read(data: bytes, pos: int):
    """Read one TLV at pos. -> (tag, content, next_pos). Raises IndexError when truncated."""
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise IndexError("truncated")
    return tag, data[pos:pos + length], pos + length


_ROOTDSE_ATTRS = [b"defaultNamingContext", b"dnsHostName", b"domainFunctionality", b"forestFunctionality",
                  b"domainControllerFunctionality", b"vendorName", b"vendorVersion", b"namingContexts"]


def ldap_rootdse_request() -> bytes:
    """Anonymous read of the rootDSE: the public entry every directory exposes without a bind."""
    search = _ber(0x63, _ber(0x04, b"") + _ber(0x0A, b"\x00") + _ber(0x0A, b"\x00") + _ber(0x02, b"\x00")
                  + _ber(0x02, b"\x0a") + _ber(0x01, b"\x00") + _ber(0x87, b"objectClass")
                  + _ber(0x30, b"".join(_ber(0x04, name) for name in _ROOTDSE_ATTRS)))
    return _ber(0x30, _ber(0x02, b"\x01") + search)


def parse_ldap_rootdse(data: bytes):
    """-> (attributes {name: [values]}, done). done is True once SearchResultDone was seen."""
    attributes: dict[str, list[str]] = {}
    done = False
    pos = 0
    try:
        while pos < len(data):
            tag, message, pos = _ber_read(data, pos)
            if tag != 0x30:
                break
            _tag, _msgid, inner = _ber_read(message, 0)
            op_tag, op, _end = _ber_read(message, inner)
            if op_tag == 0x65:
                done = True
                break
            if op_tag != 0x64:
                continue
            _t, _dn, after_dn = _ber_read(op, 0)
            _t, attr_list, _e = _ber_read(op, after_dn)
            apos = 0
            while apos < len(attr_list):
                _t, attr, apos = _ber_read(attr_list, apos)
                _t, name, after_name = _ber_read(attr, 0)
                _t, values, _e = _ber_read(attr, after_name)
                vpos, items = 0, []
                while vpos < len(values):
                    _t, value, vpos = _ber_read(values, vpos)
                    items.append(value.decode("utf-8", "replace"))
                attributes[name.decode("ascii", "replace")] = items
    except (IndexError, ValueError):
        pass
    return attributes, done


async def ldap_rootdse(ip: str, port: int = 389) -> dict:
    try:
        reader, writer = await _open(ip, port)
    except Exception:
        return {}
    data = b""
    try:
        writer.write(ldap_rootdse_request())
        await writer.drain()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 4
        while len(data) < 65536 and loop.time() < deadline:
            chunk = await _read_some(reader, 8192, deadline - loop.time())
            if not chunk:
                break
            data += chunk
            if parse_ldap_rootdse(data)[1]:
                break
    except Exception:
        pass
    finally:
        _close(writer)
    attributes, _done = parse_ldap_rootdse(data)
    if not attributes:
        return {}

    def first(name):
        return _clean((attributes.get(name) or [""])[0], 200)

    def level(name):
        try:
            return int(first(name))
        except ValueError:
            return None

    info = {"naming_context": first("defaultNamingContext") or first("namingContexts"),
            "dns_host": first("dnsHostName"), "vendor": " ".join(filter(None, [first("vendorName"),
                                                                              first("vendorVersion")]))}
    for key, name in (("domain_level", "domainFunctionality"), ("forest_level", "forestFunctionality"),
                      ("dc_level", "domainControllerFunctionality")):
        value = level(name)
        if value is not None:
            info[key] = value
    return {key: value for key, value in info.items() if value not in ("", None)}


# --------------------------------------------------------------------------- identification

CERT_DECODER_AVAILABLE = hasattr(getattr(ssl, "_ssl", None), "_test_decode_cert")


def is_printer_like(port_set) -> bool:
    """True for a host that should be treated gently as a printer.
    A print port alone does not make a printer: Windows print servers, Linux hosts (CUPS, or a
    metrics exporter on 9100) and NAS units with a USB printer are computers and get the full
    probes. The print ports themselves are never written to in any case (K.NEVER_SEND)."""
    port_set = set(port_set)
    windows_like = 135 in port_set and 445 in port_set
    return bool(port_set & K.PRINT_PORTS) and not windows_like and not port_set & {22, 445}


def new_record(port: int) -> dict:
    known = K.PORT_INFO.get(port, "")
    return {"port": port, "service": known, "product": "", "info": "",
            "source": "port" if known else "", "flags": [], "kind": ""}


def _apply_http(rec: dict, info: dict, use_tls: bool):
    http, tls = info.get("http"), info.get("tls")
    text_parts = []
    body = ""
    if tls:
        rec["tls"] = tls
        text_parts += [tls.get("cn", ""), tls.get("org", "")]
    if http:
        body = http.pop("_body", "")
        rec["http"] = http
        rec["service"] = "HTTPS" if use_tls else "HTTP"
        rec["source"] = "http"
        text_parts += [http["title"], http["server"], http["powered_by"], http["auth"]]
        server = http["server"].lower()
        if "netdata" in server or "netdata" in body[:2000]:
            rec["flags"].append("netdata")
        announced = server + " " + http["powered_by"].lower()
        if any(mark in announced for mark in K.DEV_SERVER_MARKS) or any(mark in body for mark in K.DEV_BODY_MARKS):
            rec["flags"].append("dev_server")
        if "you know, for search" in body or '"cluster_name"' in body:
            rec["flags"].append("elastic_open")
        if rec["port"] == 2375 and '"apiversion"' in body:
            rec["flags"].append("docker_api")
        if http["status"] == 401:
            rec["flags"].append("http_auth")
            if not use_tls and "basic" in http["auth"].lower():
                rec["flags"].append("basic_auth_plain")
        elif re.search(r'type=["\']?password', body):
            rec["flags"].append("login_page")
        if re.search(r"<title>\s*index of /|<h1>\s*index of /|directory listing for /", body):
            rec["flags"].append("dir_listing")
        outdated = K.outdated_software(http["server"] + " " + http["powered_by"])
        if outdated:
            rec["outdated"] = outdated
        rec["info"] = http["title"] or f"HTTP {http['status']}"
        rec["product"] = http["server"]
    elif tls:
        rec["service"] = f"TLS ({rec['service']})" if rec["service"] else "TLS"
        rec["source"] = "tls"
        rec["info"] = "certificate: " + (tls.get("cn") or "?")
    kind, product = fingerprint(" ".join(part for part in text_parts if part), body)
    if kind:
        rec["kind"] = kind
        rec["product"] = product if not rec["product"] else f"{product} ({rec['product']})"


async def _banner_step(ip: str, port: int, rec: dict) -> bool:
    try:
        reader, writer = await _open(ip, port)
    except Exception:
        return False
    try:
        data = await _read_some(reader, 512, 2.0)
        if not data:
            return False
        parsed = parse_banner(data, port)
        if parsed:
            rec["service"], rec["product"] = parsed
            rec["source"] = "banner"
            if parsed[0] == "VNC":
                rec["vnc"] = await vnc_security(reader, writer, data)
                if rec["vnc"].get("no_auth"):
                    rec["flags"].append("vnc_noauth")
            elif parsed[0] == "SSH" and ssh_protocol_1(parsed[1]):
                rec["flags"].append("ssh_v1")
            outdated = K.outdated_software(parsed[1])
            if outdated:
                rec["outdated"] = outdated
        else:
            rec["info"] = "unrecognized response: " + printable(data, 48)
            rec["source"] = "banner"
        return True
    finally:
        _close(writer)


async def _redis_step(ip: str, port: int, rec: dict) -> bool:
    try:
        reader, writer = await _open(ip, port)
    except Exception:
        return False
    try:
        writer.write(b"PING\r\n")
        await writer.drain()
        data = await _read_some(reader, 128, 2.5)
    except Exception:
        data = b""
    finally:
        _close(writer)
    if data.startswith(b"+PONG"):
        rec.update(service="Redis", product="Redis without authentication", source="protocol")
        rec["flags"].append("redis_noauth")
        return True
    if data.startswith(b"-"):
        rec.update(service="Redis", product="Redis (authentication required)", source="protocol")
        return True
    return False


async def identify_port(ip: str, port: int, windows_like: bool, printer_like: bool) -> dict:
    rec = new_record(port)
    if port in K.NEVER_SEND:
        rec["info"] = "not probed: print port"
        rec["source"] = "port"
        return rec
    if windows_like and port >= 49152 and port not in K.PORT_INFO:
        rec.update(service="Dynamic RPC (Windows)", source="port")
        return rec
    if port in K.BY_NUMBER_ONLY or port in (389, 445, 3389):
        return rec  # 389, 445 and 3389 are enriched by the dedicated host-level checks
    if port == 6379 and not printer_like and await _redis_step(ip, port, rec):
        return rec

    if printer_like and port not in SAFE_HTTP_ON_PRINTERS:
        steps = ["banner"]
        rec["info"] = "listen only: printer-like host"
    elif port in K.TLS_FIRST:
        steps = ["tls", "http", "banner"]
    elif port in K.HTTP_FIRST:
        steps = ["http", "tls", "banner"]
    else:
        steps = ["banner", "tls", "http"]

    path = "/version" if port == 2375 else "/"
    deferred = None
    for step in steps:
        if step == "banner":
            if await _banner_step(ip, port, rec):
                break
        else:
            use_tls = step == "tls"
            info = await http_probe(ip, port, use_tls, path)
            plain = (info or {}).get("http") or {}
            if (not use_tls and "tls" in steps[steps.index(step) + 1:] and plain.get("status") == 400
                    and re.search(r"https|ssl|tls", plain.get("title", "") + plain.get("_body", ""), re.I)):
                deferred = info
                continue  # an HTTPS service answering "plain HTTP sent to HTTPS port": try TLS next
            if info and (info.get("http") or info.get("tls")):
                _apply_http(rec, info, use_tls)
                if use_tls:
                    tls = rec.setdefault("tls", {})
                    legacy = tls.get("version", "")
                    if legacy not in ("TLSv1", "TLSv1.1"):
                        legacy = await tls_legacy_version(ip, port)
                    if legacy:
                        rec["flags"].append("tls_legacy")
                        tls["legacy"] = legacy
                break
            if info and info.get("raw") and not rec["info"]:
                rec["info"] = "unrecognized response: " + info["raw"][:48]
    if deferred and rec["source"] in ("", "port"):
        _apply_http(rec, deferred, False)  # TLS did not work either: keep what the plain answer said
    return rec


async def identify_host(ip: str, ports: list[int], host_sem: asyncio.Semaphore) -> dict:
    """Identify every service of a host. -> {'ports': [...], 'smb': {...}, 'rdp': {...}, 'ldap': {...}}"""
    async with host_sem:
        port_set = set(ports)
        windows_like = 135 in port_set and 445 in port_set
        printer_like = is_printer_like(port_set)
        port_sem = asyncio.Semaphore(4)

        async def one(port):
            async with port_sem:
                try:
                    return await asyncio.wait_for(
                        identify_port(ip, port, windows_like, printer_like), 40)
                except Exception:
                    return new_record(port)

        async def guarded(coro, limit):
            try:
                return await asyncio.wait_for(coro, limit)
            except Exception:
                return {}

        # A host with hundreds of open ports is a tarpit or a honeypot: probing each one would take
        # hours. Probe the well-known ports and a sample of the rest, and say so for the others.
        probed = ports
        skipped: list[int] = []
        if len(ports) > MAX_PROBED_PORTS:
            known = [p for p in ports if p in K.PORT_INFO]
            other = [p for p in ports if p not in K.PORT_INFO]
            room = max(0, MAX_PROBED_PORTS - len(known))
            probed, skipped = known + other[:room], other[room:]
        # ... and a slow host gets a fixed time budget: what is not identified by then is reported as such
        tasks = {asyncio.ensure_future(one(port)): port for port in probed}
        records = []
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=HOST_BUDGET_SECONDS)
            for task in pending:
                task.cancel()
                rec = new_record(tasks[task])
                rec["info"] = "not probed: time budget for this host exhausted"
                records.append(rec)
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            records += [task.result() for task in done]
        for port in skipped:
            rec = new_record(port)
            rec["info"] = "not probed: too many open ports on this host"
            records.append(rec)
        result = {"ports": sorted(records, key=lambda r: r["port"])}
        if 445 in port_set:
            result["smb"] = await guarded(smb_info(ip), 25)
        if 3389 in port_set:
            result["rdp"] = await guarded(rdp_check(ip), 10)
        if 389 in port_set and not printer_like:
            result["ldap"] = await guarded(ldap_rootdse(ip), 10)
        return result
