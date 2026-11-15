"""NetAudit tests. Run:  python -m unittest discover -s tests -v

They only use 127.0.0.1: fake local services exercise the scanner, the probes, the rules
and the report without touching the network.
"""
import asyncio
import csv
import datetime as dt
import faulthandler
import ipaddress
import json
import os
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netaudit import knowledge as K  # noqa: E402
from netaudit import cli, localcheck, netinfo, nmapx, portscan, probes, report, rules, udp  # noqa: E402


def setUpModule():
    # The suite takes well under a minute. If it ever stalls (seen on Windows when security software
    # delays loopback connections), print where it is stuck and end instead of hanging forever.
    faulthandler.dump_traceback_later(600, exit=True)


def tearDownModule():
    faulthandler.cancel_dump_traceback_later()


# --------------------------------------------------------------------------- fake services

class _Banner(socketserver.BaseRequestHandler):
    banner = b""

    def handle(self):
        self.request.sendall(self.banner)
        try:
            self.request.settimeout(1.5)
            self.request.recv(64)
        except OSError:
            pass


class _Ssh(_Banner):
    banner = b"SSH-1.99-OpenSSH_6.6.1\r\n"


class _MySql(_Banner):
    banner = b"\x5a\x00\x00\x00\x0a10.11.11-MariaDB\x00" + b"\x00" * 40


class _Telnet(_Banner):
    banner = b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23"


class _Vnc(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"RFB 003.008\n")
        try:
            self.request.settimeout(2)
            self.request.recv(12)
            self.request.sendall(b"\x02\x01\x02")  # two types: None and VNC
            self.request.recv(8)
        except OSError:
            pass


class _Http(socketserver.BaseRequestHandler):
    status = b"200 OK"
    headers = b"Server: nginx\r\n"
    body = b"<html><head><title>Synology&nbsp;NAS - login</title></head><body><input type=password></body></html>"

    def handle(self):
        try:
            self.request.settimeout(2)
            self.request.recv(2048)
        except OSError:
            return
        self.request.sendall(b"HTTP/1.1 " + self.status + b"\r\n" + self.headers + b"Content-Type: text/html\r\n"
                             b"Content-Length: " + str(len(self.body)).encode() + b"\r\n\r\n" + self.body)


class _HttpBasic(_Http):
    status = b"401 Unauthorized"
    headers = b"Server: Apache/2.2.15 (CentOS)\r\nWWW-Authenticate: Basic realm=\"router\"\r\n"
    body = b"<html><title>401</title></html>"


class _HttpListing(_Http):
    headers = b"Server: SimpleHTTP/0.6 Python/3.12\r\n"
    body = b"<html><head><title>Directory listing for /</title></head><body><h1>Directory listing for /</h1></body></html>"


class _Ldap(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2)
            self.request.recv(1024)
        except OSError:
            return
        ber = probes._ber

        def attr(name, value):
            return ber(0x30, ber(0x04, name) + ber(0x31, ber(0x04, value)))
        entry = ber(0x64, ber(0x04, b"") + ber(0x30, attr(b"defaultNamingContext", b"DC=acme,DC=local")
                                               + attr(b"dnsHostName", b"dc01.acme.local")
                                               + attr(b"domainFunctionality", b"4")
                                               + attr(b"domainControllerFunctionality", b"7")))
        done = ber(0x65, ber(0x0A, b"\x00") + ber(0x04, b"") + ber(0x04, b""))
        self.request.sendall(ber(0x30, ber(0x02, b"\x01") + entry) + ber(0x30, ber(0x02, b"\x01") + done))


class _SmbNegotiateOnly(socketserver.BaseRequestHandler):
    """Answers SMB2 NEGOTIATE (3.1.1, signing not required) and then hangs up on the session setup."""

    def handle(self):
        try:
            self.request.settimeout(2)
            data = self.request.recv(1024)
        except OSError:
            return
        if data[4:8] != b"\xfeSMB":
            return  # the SMB1 probe gets no answer
        payload = b"\xfeSMB" + b"\x00" * 60 + struct.pack("<HHH", 65, 1, 0x0311) + b"\x00" * 60
        self.request.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)
        try:
            self.request.recv(1024)
        except OSError:
            pass


class _HttpsOnly(_Http):
    """What nginx says when plain HTTP reaches an HTTPS port (the test cannot complete a TLS handshake)."""
    status = b"400 Bad Request"
    body = b"<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head></html>"


def _find_openssl() -> str:
    found = shutil.which("openssl")
    if found:
        return found
    git = shutil.which("git")  # Git for Windows ships an openssl that is not on PATH
    if git:
        root = os.path.dirname(os.path.dirname(os.path.abspath(git)))
        for parts in (("mingw64", "bin"), ("usr", "bin")):
            candidate = os.path.join(root, *parts, "openssl.exe")
            if os.path.exists(candidate):
                return candidate
    return ""


def _make_tls_context():
    """A server context with a self-signed certificate made on the spot, so that no private key is
    kept in the repository. The Python standard library cannot create certificates: this needs the
    openssl program, and without it the TLS tests are skipped. -> context or None"""
    openssl = _find_openssl()
    if not openssl:
        return None
    with tempfile.TemporaryDirectory() as folder:
        config, key, cert = (os.path.join(folder, name) for name in ("req.cnf", "key.pem", "cert.pem"))
        with open(config, "w", encoding="ascii") as handle:
            handle.write("[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                         "[dn]\nCN = netaudit-test.local\nO = NetAudit Test\n"
                         "[ext]\nsubjectAltName = DNS:netaudit-test.local, DNS:localhost, IP:127.0.0.1\n")
        try:
            subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                            "-config", config, "-keyout", key, "-out", cert],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)  # read into memory: the files go away with the folder
            return context
        except (OSError, subprocess.SubprocessError, ssl.SSLError):
            return None


_TLS = _make_tls_context()
_NEEDS_TLS = unittest.skipIf(_TLS is None, "the openssl program was not found: TLS tests skipped")


class _TlsHttp(_Http):
    """A real HTTPS service with a throwaway self-signed certificate."""
    headers = b"Server: nginx\r\n"
    body = b"<html><head><title>Secure console</title></head><body></body></html>"

    def handle(self):
        try:
            self.request.settimeout(3)
            self.request = _TLS.wrap_socket(self.request, server_side=True)
        except OSError:
            return  # a plain-text client: hang up, as many TLS servers do
        super().handle()


class _Redis(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2)
            if self.request.recv(64).startswith(b"PING"):
                self.request.sendall(b"+PONG\r\n")
        except OSError:
            pass


class _UdpResponder(threading.Thread):
    """Answers every datagram with a fixed payload."""

    def __init__(self, payload: bytes):
        super().__init__(daemon=True)
        self.payload = payload
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self):
        while self.running:
            try:
                _data, peer = self.sock.recvfrom(2048)
                self.sock.sendto(self.payload, peer)
            except OSError:
                continue
        self.sock.close()


class _Silent(socketserver.BaseRequestHandler):
    """Simulates a print port: records whether it receives any data."""
    received = []

    def handle(self):
        try:
            self.request.settimeout(1.5)
            data = self.request.recv(64)
            if data:
                _Silent.received.append(data)
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _start(handler):
    server = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --------------------------------------------------------------------------- parsers

class ParserTests(unittest.TestCase):
    def test_http(self):
        raw = (b"HTTP/1.1 302 Found\r\nServer: nginx/1.26.1\r\nLocation: /login.html\r\n\r\n"
               b"<html><title> Net&amp;Sec \n UI</title></html>")
        parsed = probes.parse_http(raw)
        self.assertEqual(parsed["status"], 302)
        self.assertEqual(parsed["server"], "nginx/1.26.1")
        self.assertEqual(parsed["title"], "Net&Sec UI")
        self.assertEqual(parsed["location"], "/login.html")
        self.assertIsNone(probes.parse_http(b"SSH-2.0-x"))
        self.assertIsNone(probes.parse_http(b"HTTP/1.1 abc"))

    def test_hostile_pages_cannot_stall_or_crash_the_parser(self):
        import time
        head = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"
        started = time.perf_counter()
        for body in (b"<title>" * 10000, b"<title><" * 9000, b"<title" + b" a" * 30000,
                     b"<title>&#" + b"9" * 5000 + b";</title>", b"<TITLE>ok</TITLE>" + b"<" * 60000):
            parsed = probes.parse_http(head + body)
            self.assertEqual(parsed["status"], 200)
            self.assertLessEqual(len(parsed["title"]), 120)
        self.assertLess(time.perf_counter() - started, 1.0)       # linear, not quadratic
        self.assertEqual(probes.parse_http(head + b"<TiTle lang=en>\n Hello&nbsp;World </tItLe>")["title"],
                         "Hello World")

    def test_redirects_never_leave_the_probed_port(self):
        follow = probes.same_origin_path
        self.assertEqual(follow("10.0.0.5", 8080, False, "/", "/login.html"), "/login.html")
        self.assertEqual(follow("10.0.0.5", 8080, False, "/ui/", "login.html?x=1"), "/ui/login.html?x=1")
        self.assertEqual(follow("10.0.0.5", 8080, False, "/", "http://10.0.0.5:8080/a"), "/a")
        self.assertEqual(follow("10.0.0.5", 443, True, "/", "https://10.0.0.5/admin"), "/admin")
        for elsewhere in ("http://10.0.0.6:8080/a", "http://10.0.0.5:9090/a", "https://10.0.0.5:8080/a",
                          "//evil.example/a", "http://evil.example/", "http://10.0.0.5/a", "/a b", "http://[::1"):
            self.assertEqual(follow("10.0.0.5", 8080, False, "/", elsewhere), "", elsewhere)

    def test_banner(self):
        self.assertEqual(probes.parse_banner(b"SSH-2.0-dropbear\r\n", 222), ("SSH", "SSH-2.0-dropbear"))
        self.assertEqual(probes.parse_banner(_MySql.banner, 23306)[1], "MariaDB 10.11.11-MariaDB")
        self.assertEqual(probes.parse_banner(b"220 mail ESMTP Postfix\r\n", 2525)[0], "SMTP")
        self.assertEqual(probes.parse_banner(b"220 ProFTPD Server\r\n", 21)[0], "FTP")
        self.assertEqual(probes.parse_banner(_Telnet.banner, 2323)[0], "Telnet")
        self.assertIsNone(probes.parse_banner(b"\x00\x01\x02", 9999))
        self.assertEqual(probes.ssh_version("SSH-2.0-OpenSSH_7.4"), (7, 4))
        self.assertTrue(probes.ssh_protocol_1("SSH-1.99-OpenSSH_3.9"))
        self.assertFalse(probes.ssh_protocol_1("SSH-2.0-OpenSSH_9.6"))

    def test_rdp(self):
        nla = bytes.fromhex("030000130ed00000123400") + bytes([3, 0, 8, 0]) + struct.pack("<I", 5)
        self.assertEqual(probes.parse_rdp_response(nla), {"nla_required": True, "code": "nla"})
        plain = bytes.fromhex("030000130ed00000123400") + bytes([2, 0, 8, 0]) + struct.pack("<I", 0)
        self.assertEqual(probes.parse_rdp_response(plain)["code"], "standard")
        tls = bytes.fromhex("030000130ed00000123400") + bytes([3, 0, 8, 0]) + struct.pack("<I", 1)
        self.assertEqual(probes.parse_rdp_response(tls), {"nla_required": False, "code": "tls_only"})
        old = bytes.fromhex("0300000b06d00000123400")
        self.assertFalse(probes.parse_rdp_response(old)["nla_required"])
        self.assertEqual(probes.parse_rdp_response(b"garbage"), {})

    def test_smb_packets(self):
        legacy = probes.smb2_negotiate_request(with_311=False)
        self.assertEqual(len(legacy), 4 + 64 + 36 + 8)
        modern = probes.smb2_negotiate_request()
        self.assertEqual(int.from_bytes(modern[1:4], "big"), len(modern) - 4)
        payload = modern[4:]
        offset, count = struct.unpack_from("<IH", payload, 64 + 28)
        self.assertEqual(offset % 8, 0)
        self.assertEqual(count, 2)
        self.assertEqual(struct.unpack_from("<HH", payload, offset), (1, 38))       # pre-auth integrity
        self.assertEqual(struct.unpack_from("<HH", payload, offset + 48), (2, 6))    # encryption, 8-aligned
        self.assertEqual(len(payload), offset + 48 + 8 + 6)
        self.assertEqual(len(probes._ntlm_negotiate()), 40)
        setup = probes.smb2_session_setup_request()
        self.assertEqual(int.from_bytes(setup[1:4], "big"), len(setup) - 4)
        self.assertEqual(setup[4 + 64 + 24], 0x60)  # the SPNEGO blob starts at the declared offset (88)
        smb1 = probes.smb1_negotiate_request()
        self.assertEqual(smb1[4:8], b"\xffSMB")
        self.assertEqual(len(smb1), 4 + 32 + 3 + 12)

    def test_smb2_negotiate_response(self):
        header = b"\xfeSMB" + b"\x00" * 60
        parsed = probes.parse_smb2_negotiate(header + struct.pack("<HHH", 65, 3, 0x0311) + b"\x00" * 60)
        self.assertEqual(parsed["dialect"], "3.1.1")
        self.assertTrue(parsed["signing_required"])
        parsed = probes.parse_smb2_negotiate(header + struct.pack("<HHH", 65, 1, 0x0210) + b"\x00" * 60)
        self.assertFalse(parsed["signing_required"])
        refused = b"\xfeSMB" + b"\x00" * 4 + struct.pack("<I", 0xC00000BB) + b"\x00" * 60
        self.assertEqual(probes.parse_smb2_negotiate(refused), {"smb2": True, "status": 0xC00000BB})
        self.assertEqual(probes.parse_smb2_negotiate(b"junk"), {})

    def test_ntlm_challenge(self):
        def av(kind, text):
            data = text.encode("utf-16-le")
            return struct.pack("<HH", kind, len(data)) + data
        info = av(1, "PC101") + av(2, "ACME") + av(3, "PC101.acme.local") + av(4, "acme.local") + b"\x00" * 4
        msg = (b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56)
               + struct.pack("<I", 0x02898205) + b"\x11" * 8 + b"\x00" * 8
               + struct.pack("<HHI", len(info), len(info), 56) + struct.pack("<BBH", 10, 0, 19045) + b"\x00\x00\x00\x0f"
               + info)
        parsed = probes.parse_ntlm_challenge(b"prefix-bytes" + msg)
        self.assertEqual(parsed["build"], 19045)
        self.assertEqual(parsed["netbios_name"], "PC101")
        self.assertEqual(parsed["dns_domain"], "acme.local")
        self.assertEqual(probes.parse_ntlm_challenge(b"nothing"), {})
        self.assertEqual(probes.parse_ntlm_challenge(msg[:30]), {})

    def test_ldap(self):
        request = probes.ldap_rootdse_request()
        tag, content, end = probes._ber_read(request, 0)
        self.assertEqual((tag, end), (0x30, len(request)))
        self.assertIn(b"domainFunctionality", content)
        big = probes._ber(0x04, b"x" * 300)
        self.assertEqual(probes._ber_read(big, 0)[1], b"x" * 300)
        self.assertEqual(probes.parse_ldap_rootdse(b"\x30\x05\x02"), ({}, False))

    def test_udp_parsers(self):
        self.assertEqual(len(udp.nbns_request()), 50)
        request = udp.snmp_request()
        self.assertEqual(request[1], len(request) - 2)
        self.assertEqual(len(request), 43)
        long_one = udp.snmp_request(b"c" * 250)                    # long-form BER lengths
        self.assertEqual(long_one[:2], b"\x30\x82")
        self.assertEqual(int.from_bytes(long_one[2:4], "big"), len(long_one) - 4)
        text = b"D-Link DGS-1210-28 Gigabit Switch"
        reply = (b"\x30\x40\x02\x01\x01\x04\x06public\xa2\x33\x02\x04abcd\x02\x01\x00\x02\x01\x00\x30\x25\x30\x23"
                 + bytes.fromhex("06082b06010201010100") + b"\x04" + bytes([len(text)]) + text)
        self.assertEqual(udp.parse_snmp(reply), text.decode())
        self.assertEqual(udp.parse_snmp(b"junk"), "")
        names = (b"SERVER01       \x00\x04\x00" + b"WORKGROUP      \x00\x84\x00" + b"SERVER01       \x20\x04\x00")
        packet = b"\x00" * 56 + bytes([3]) + names + bytes.fromhex("001132aabbcc")
        parsed = udp.parse_nbns(packet)
        self.assertEqual(parsed["name"], "SERVER01")
        self.assertEqual(parsed["domain"], "WORKGROUP")
        self.assertEqual(parsed["mac"], "00:11:32:AA:BB:CC")
        ssdp = (b"HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0 miniupnpd/2.2\r\n"
                b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://10.0.0.1:5000/root.xml\r\n\r\n")
        self.assertIn("InternetGatewayDevice", udp.parse_ssdp(ssdp)["st"])
        self.assertEqual(udp.parse_ssdp(b"garbage"), {})

    def test_fingerprint(self):
        self.assertEqual(probes.fingerprint("NAS01 - Synology NAS")[0], "nas")
        self.assertEqual(probes.fingerprint("idrac-DEMO123 Dell Inc.")[0], "bmc")
        self.assertEqual(probes.fingerprint("<script>RT='/DGS-1210-28_1.00.B001/';</script>")[0], "network")
        self.assertEqual(probes.fingerprint("NethSecurity")[0], "firewall")
        self.assertEqual(probes.fingerprint("page with link rel canonical and unified complex text"), ("", ""))
        self.assertLess(probes.product_rank("NethSecurity"), probes.product_rank("OpenWrt"))

    def test_nmap_xml(self):
        xml = ("<nmaprun><host><ports>"
               "<port protocol='tcp' portid='222'><state state='open'/>"
               "<service name='ssh' product='Dropbear sshd' method='probed'/></port>"
               "<port protocol='tcp' portid='5938'><state state='open'/>"
               "<service name='teamviewer' method='table'/></port>"
               "</ports></host></nmaprun>")
        self.assertEqual(nmapx.parse_xml(xml), {222: {"service": "ssh", "product": "Dropbear sshd"}})
        self.assertEqual(nmapx.parse_xml("not xml"), {})

    def test_arp(self):
        windows = "  192.168.1.1           00-09-0f-10-20-30     dynamic\n  224.0.0.22  01-00-5e-00-00-16  static\n"
        self.assertEqual(netinfo.parse_arp(windows), {"192.168.1.1": "00:09:0F:10:20:30"})
        mac = "? (192.168.1.5) at 0:11:32:aa:0:2 on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0\n"
        self.assertEqual(netinfo.parse_arp(mac), {"192.168.1.5": "00:11:32:AA:00:02"})
        linux = "192.168.1.7 dev eth0 lladdr b8:27:eb:01:02:03 REACHABLE\n192.168.1.8 dev eth0 FAILED\n"
        self.assertEqual(netinfo.parse_arp(linux), {"192.168.1.7": "B8:27:EB:01:02:03"})
        named = "host-10.0.0.9.lan (192.168.1.33) at b8:27:eb:01:02:04 [ether] on eth0\n"
        self.assertEqual(netinfo.parse_arp(named), {"192.168.1.33": "B8:27:EB:01:02:04"})
        proc = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.9      0x1         0x2         b8:27:eb:01:02:05     *        eth0\n"
                "192.168.1.10     0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        self.assertEqual(netinfo.parse_arp(proc), {"192.168.1.9": "B8:27:EB:01:02:05"})


class KnowledgeTests(unittest.TestCase):
    def test_profiles(self):
        self.assertEqual(len(K.ports_for("full")), 65535)
        self.assertIn(3389, K.ports_for("quick"))
        self.assertTrue(set(K.ports_for("quick")) <= set(K.ports_for("standard")))
        self.assertTrue(set(range(9100, 9117)) <= K.NEVER_SEND)
        self.assertEqual(set(K.SPEEDS), {"careful", "normal", "fast"})

    def test_mac(self):
        self.assertTrue(K.mac_is_random("CE:BE:F4:AA:00:01"))
        self.assertFalse(K.mac_is_random("00:11:32:AA:00:02"))
        self.assertEqual(K.vendor_for("CE:BE:F4:AA:00:01"), K.RANDOM_MAC)
        self.assertIn("Synology", K.vendor_for("00:11:32:AA:00:02"))
        self.assertEqual(K.vendor_for(""), "")

    def test_windows(self):
        self.assertEqual(K.windows_product(19045)[1], "verify")
        self.assertEqual(K.windows_product(19041)[1], "verify")
        self.assertEqual(K.windows_product(9600)[1], "eol")
        self.assertEqual(K.windows_product(20348)[1], "ok")
        self.assertEqual(K.windows_product(99999)[1], "ok")
        self.assertEqual(K.windows_product(12345)[1], "unknown")

    def test_outdated(self):
        self.assertTrue(K.outdated_software("Apache/2.2.15 (CentOS)"))
        self.assertTrue(K.outdated_software("Microsoft-IIS/7.5"))
        self.assertTrue(K.outdated_software("nginx X-Powered-By: PHP/5.6.40"))
        self.assertEqual(K.outdated_software("nginx/1.26.1"), "")
        self.assertEqual(K.outdated_software("Apache/2.4.58 (Ubuntu) Microsoft-IIS/10.0"), "")

    def test_targets(self):
        nets = netinfo.parse_targets(["192.168.1.0/30", "10.0.0.5", "10.0.1.10-12"])
        hosts = netinfo.expand_hosts(nets, exclude={"10.0.1.11"})
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2", "10.0.0.5", "10.0.1.10", "10.0.1.12"])
        whole = netinfo.expand_hosts(netinfo.parse_targets(["192.168.1.10-50"]))
        self.assertEqual(whole, [f"192.168.1.{n}" for n in range(10, 51)])     # a range loses no address
        for bad in (["10.0.0.50-10"], ["not-an-ip"], ["fe80::1"]):
            with self.assertRaises(ValueError):
                netinfo.parse_targets(bad)
        self.assertTrue(all(n.is_private for n in nets))
        self.assertFalse(ipaddress.ip_network("8.8.8.0/24").is_private)


# --------------------------------------------------------------------------- live scanner and probes

class LiveLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = {}
        for name, handler in (("ssh", _Ssh), ("mysql", _MySql), ("vnc", _Vnc), ("http", _Http), ("print", _Silent),
                              ("telnet", _Telnet), ("basic", _HttpBasic), ("listing", _HttpListing), ("ldap", _Ldap),
                              ("smb", _SmbNegotiateOnly), ("httpsonly", _HttpsOnly), ("tls", _TlsHttp),
                              ("redis", _Redis)):
            if name == "tls" and _TLS is None:
                continue
            cls.servers[name] = _start(handler)

    @classmethod
    def tearDownClass(cls):
        for server, _port in cls.servers.values():
            server.shutdown()
            server.server_close()

    def port(self, name):
        return self.servers[name][1]

    def test_scan_finds_only_open_ports(self):
        closed = _free_port()
        ports = [self.port(n) for n in ("ssh", "mysql", "vnc", "http")] + [closed]
        result = asyncio.run(portscan.scan({"127.0.0.1": ports}, workers=8, timeout=0.8, max_sockets=32))
        self.assertEqual(sorted(result.open["127.0.0.1"]), sorted(ports[:-1]))
        self.assertFalse(result.aborted)

    def test_scan_aborts_when_network_changes(self):
        result = asyncio.run(portscan.scan({"127.0.0.1": list(range(40000, 46000))}, workers=4, timeout=1.0,
                                           max_sockets=8, should_abort=lambda: True))
        self.assertTrue(result.aborted)
        self.assertIn("127.0.0.1", result.incomplete)

    def test_batches_respect_socket_cap(self):
        seen = []
        targets = {f"127.0.0.{i}": [1] for i in range(1, 8)}
        asyncio.run(portscan.scan(targets, workers=80, timeout=0.2, max_sockets=3,
                                  on_batch=lambda group, index, total: seen.append(len(group))))
        self.assertEqual(seen, [3, 3, 1])
        self.assertGreater(portscan.estimate_seconds(26, 65535, 80, 0.8, 720), 600)

    def test_identification(self):
        names = ("ssh", "mysql", "vnc", "http", "telnet", "basic", "listing")
        ports = sorted(self.port(n) for n in names)

        async def go():
            return await probes.identify_host("127.0.0.1", ports, asyncio.Semaphore(2))
        by_port = {rec["port"]: rec for rec in asyncio.run(go())["ports"]}
        ssh = by_port[self.port("ssh")]
        self.assertEqual(ssh["service"], "SSH")
        self.assertIn("ssh_v1", ssh["flags"])
        self.assertIn("MariaDB", by_port[self.port("mysql")]["product"])
        self.assertIn("vnc_noauth", by_port[self.port("vnc")]["flags"])
        self.assertEqual(by_port[self.port("telnet")]["service"], "Telnet")
        web = by_port[self.port("http")]
        self.assertEqual((web["service"], web["http"]["title"], web["kind"]), ("HTTP", "Synology NAS - login", "nas"))
        self.assertIn("login_page", web["flags"])
        basic = by_port[self.port("basic")]
        self.assertIn("basic_auth_plain", basic["flags"])
        self.assertIn("Apache", basic["outdated"])
        listing = by_port[self.port("listing")]
        self.assertIn("dir_listing", listing["flags"])
        self.assertIn("dev_server", listing["flags"])

    def test_ldap_rootdse(self):
        info = asyncio.run(probes.ldap_rootdse("127.0.0.1", self.port("ldap")))
        self.assertEqual(info, {"naming_context": "DC=acme,DC=local", "dns_host": "dc01.acme.local",
                                "domain_level": 4, "dc_level": 7})

    @_NEEDS_TLS
    def test_tls_service_and_certificate(self):
        port = self.port("tls")
        info = asyncio.run(probes.http_get("127.0.0.1", port, use_tls=True))
        tls = info["tls"]
        self.assertEqual((tls["cn"], tls["org"], tls["self_signed"]), ("netaudit-test.local", "NetAudit Test", True))
        self.assertIn("localhost", tls["san"])
        self.assertIn(tls["days_left"], (3648, 3649, 3650))
        self.assertRegex(tls["not_after"], r"^\d{4}-\d\d-\d\d$")
        self.assertIn(tls["version"], ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(info["http"]["title"], "Secure console")
        # an unknown port: banner (nothing), then TLS succeeds; modern server, so no legacy-TLS flag
        rec = asyncio.run(probes.identify_port("127.0.0.1", port, False, False))
        self.assertEqual((rec["service"], rec["info"], rec["source"]), ("HTTPS", "Secure console", "http"))
        self.assertNotIn("tls_legacy", rec["flags"])
        self.assertEqual(asyncio.run(probes.tls_legacy_version("127.0.0.1", port)), "")

    @_NEEDS_TLS
    def test_https_on_an_http_first_port_is_identified_over_tls(self):
        port = self.port("tls")
        K.HTTP_FIRST.add(port)
        try:
            rec = asyncio.run(probes.identify_port("127.0.0.1", port, False, False))
        finally:
            K.HTTP_FIRST.discard(port)
        self.assertEqual(rec["service"], "HTTPS")
        self.assertEqual(rec["tls"]["cn"], "netaudit-test.local")

    def test_redis_without_a_password_is_flagged(self):
        rec = probes.new_record(6379)
        self.assertTrue(asyncio.run(probes._redis_step("127.0.0.1", self.port("redis"), rec)))
        self.assertIn("redis_noauth", rec["flags"])
        other = probes.new_record(6379)
        self.assertFalse(asyncio.run(probes._redis_step("127.0.0.1", self.port("ssh"), other)))
        self.assertEqual(other["flags"], [])

    def test_udp_sweep_collects_netbios_and_snmp(self):
        names = (b"SERVER01       \x00\x04\x00" + b"WORKGROUP      \x00\x84\x00")
        nbns = _UdpResponder(b"\x00" * 56 + bytes([2]) + names + bytes.fromhex("001132aabbcc"))
        text = b"Demo Switch 24-port"
        snmp = _UdpResponder(b"\x30\x32\x02\x01\x01\x04\x06public\xa2\x25\x02\x04abcd\x02\x01\x00\x02\x01\x00\x30\x17\x30\x15"
                             + bytes.fromhex("06082b06010201010100") + b"\x04" + bytes([len(text)]) + text)
        nbns.start()
        snmp.start()
        try:
            found = udp.sweep(["127.0.0.1"], wait=1.0, nbns_port=nbns.port, snmp_port=snmp.port)
            silent = udp.sweep(["127.0.0.1"], snmp=False, wait=0.6, nbns_port=_free_port())
        finally:
            nbns.running = snmp.running = False
        self.assertEqual(found["127.0.0.1"]["nbns"]["name"], "SERVER01")
        self.assertEqual(found["127.0.0.1"]["snmp"], "Demo Switch 24-port")
        self.assertEqual(silent, {})

    def test_slow_host_is_cut_off_at_its_time_budget(self):
        async def fake_identify(ip, port, windows_like, printer_like):
            if port == 2:
                await asyncio.sleep(30)
            return probes.new_record(port)
        original, budget = probes.identify_port, probes.HOST_BUDGET_SECONDS
        probes.identify_port, probes.HOST_BUDGET_SECONDS = fake_identify, 0.3
        try:
            result = asyncio.run(probes.identify_host("10.255.255.1", [1, 2, 3], asyncio.Semaphore(1)))
        finally:
            probes.identify_port, probes.HOST_BUDGET_SECONDS = original, budget
        info = {rec["port"]: rec["info"] for rec in result["ports"]}
        self.assertEqual(sorted(info), [1, 2, 3])
        self.assertIn("time budget", info[2])
        self.assertEqual(info[1], "")

    def test_smb_keeps_negotiate_result_when_identity_step_fails(self):
        info = asyncio.run(probes.smb_info("127.0.0.1", self.port("smb")))
        self.assertEqual((info.get("dialect"), info.get("signing_required"), info.get("smb1")), ("3.1.1", False, False))
        self.assertNotIn("ntlm", info)

    def test_https_on_an_http_first_port_is_not_called_plain_http(self):
        port = self.port("httpsonly")
        K.HTTP_FIRST.add(port)
        try:
            rec = asyncio.run(probes.identify_port("127.0.0.1", port, False, False))
        finally:
            K.HTTP_FIRST.discard(port)
        # TLS was attempted after the 400; it cannot succeed against the fake, so the plain answer is kept
        self.assertEqual(rec["http"]["status"], 400)
        self.assertIn("HTTPS port", rec["info"])

    def _cancelled_scan(self, fake, ports, delay):
        """Run a scan with a fake connect function and cancel it after `delay` seconds."""
        async def go():
            result = portscan.ScanResult()
            task = asyncio.ensure_future(portscan.scan({"10.255.255.1": ports}, workers=2, timeout=1.0,
                                                       max_sockets=4, result=result))
            await asyncio.sleep(delay)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return result
        original = portscan.tcp_open
        portscan.tcp_open = fake
        try:
            return asyncio.run(go())
        finally:
            portscan.tcp_open = original

    def test_cancelled_scan_keeps_partial_results(self):
        async def slow_after_first(ip, port, timeout, state=None):
            if port == 1:
                return True
            await asyncio.sleep(30)
            return False
        result = self._cancelled_scan(slow_after_first, [1, 2, 3, 4], 0.3)
        self.assertEqual(result.open.get("10.255.255.1"), [1])
        self.assertIn("10.255.255.1", result.incomplete)

    def test_cancel_during_reconfirmation_keeps_found_ports(self):
        calls = {"n": 0}

        async def hangs_on_second_look(ip, port, timeout, state=None):
            calls["n"] += 1
            if calls["n"] <= 2:
                return True          # first pass: both ports open
            await asyncio.sleep(30)  # re-confirmation never returns
            return True
        result = self._cancelled_scan(hangs_on_second_look, [1, 2], 0.3)
        self.assertEqual(result.open.get("10.255.255.1"), [1, 2])
        self.assertIn("10.255.255.1", result.incomplete)

    def test_many_open_ports_are_not_all_probed(self):
        seen = []

        async def fake_identify(ip, port, windows_like, printer_like):
            seen.append(port)
            return probes.new_record(port)
        original = probes.identify_port
        probes.identify_port = fake_identify
        try:
            ports = [22, 80] + list(range(20000, 20300))
            result = asyncio.run(probes.identify_host("10.255.255.1", ports, asyncio.Semaphore(1)))
        finally:
            probes.identify_port = original
        self.assertEqual(len(seen), probes.MAX_PROBED_PORTS)
        self.assertTrue({22, 80} <= set(seen))
        self.assertEqual(len(result["ports"]), len(ports))
        self.assertIn("too many open ports", result["ports"][-1]["info"])

    def test_printer_ports_never_receive_data(self):
        _Silent.received.clear()
        port = self.port("print")
        rec = asyncio.run(probes.identify_port("127.0.0.1", port, windows_like=False, printer_like=True))
        self.assertEqual(_Silent.received, [])
        self.assertIn("listen only", rec["info"])
        rec = asyncio.run(probes.identify_port("127.0.0.1", 9100, False, True))
        self.assertIn("not probed", rec["info"])

    def test_dead_port_is_harmless(self):
        closed = _free_port()
        rec = asyncio.run(probes.identify_port("127.0.0.1", closed, False, False))
        self.assertEqual(rec["port"], closed)
        self.assertEqual(asyncio.run(probes.smb_info("127.0.0.1", closed)).get("smb1"), False)
        self.assertEqual(asyncio.run(probes.rdp_check("127.0.0.1", closed)), {})
        self.assertEqual(asyncio.run(probes.ldap_rootdse("127.0.0.1", closed)), {})


# --------------------------------------------------------------------------- rules and report

def _rec(port, service="", product="", flags=(), kind="", **extra):
    # like the real probes: a record nothing answered on is attributed by port number only
    rec = {"port": port, "service": service or K.PORT_INFO.get(port, ""), "product": product, "info": "",
           "source": "banner" if (service or product) else "port", "flags": list(flags), "kind": kind}
    rec.update(extra)
    return rec


def _sample_hosts():
    def ntlm(name, build, domain="acme.local"):
        return {"netbios_name": name, "dns_name": f"{name}.{domain}" if domain else name,
                "dns_domain": domain, "build": build}
    signed = {"smb2": True, "status": 0, "dialect": "3.1.1", "signing_required": True, "smb1": False}
    hosts = [
        {"ip": "10.0.0.1", "hostname": "fw.acme.local", "is_gateway": True, "mac": "00:09:0F:10:20:30", "vendor": "",
         "ssdp": {"server": "miniupnpd", "types": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]},
         "ports": [_rec(222, "SSH", "SSH-2.0-dropbear"), _rec(443, "HTTPS", "OpenWrt", kind="firewall"),
                   _rec(9090, "HTTPS", "NethSecurity", kind="firewall"),
                   _rec(19999, "HTTP", "Netdata", flags=["netdata"], kind="app")]},
        {"ip": "10.0.0.2", "hostname": "", "mac": "34:0A:33:AA:00:02", "vendor": "D-Link International",
         "ports": [_rec(80, "HTTP", "D-Link", kind="network")], "snmp": "DGS-1210-28 Gigabit Smart Switch"},
        {"ip": "10.0.0.14", "hostname": "printer.acme.local", "mac": "00:20:6B:AA:00:14", "vendor": "Konica Minolta",
         "ports": [_rec(80, "HTTP", "Konica Minolta", kind="printer"), _rec(9100)]},
        {"ip": "10.0.0.22", "hostname": "nas.acme.local", "mac": "90:09:D0:AA:00:22", "vendor": "Synology",
         "smb": dict(signed, signing_required=False),
         "ports": [_rec(445), _rec(3260), _rec(6281), _rec(23306, "MySQL/MariaDB", "MariaDB 10.11.11"),
                   _rec(8443, "HTTPS", "Synology (nginx)", kind="nas",
                        tls={"cn": "nas.acme.org", "days_left": -29, "not_after": "2026-10-10",
                             "self_signed": False, "version": "TLSv1.3"})]},
        {"ip": "10.0.0.23", "hostname": "dc01.acme.local", "mac": "00:15:5D:AA:00:23", "vendor": "Microsoft (Hyper-V)",
         "smb": dict(signed, ntlm=ntlm("DC01", 20348)), "rdp": {"nla_required": True, "code": "nla"},
         "ldap": {"naming_context": "DC=acme,DC=local", "domain_level": 4, "dc_level": 7},
         "ports": [_rec(p) for p in (53, 88, 135, 389, 445, 3389, 5938, 5985)]},
        {"ip": "10.0.0.24", "hostname": "srv-idrac.acme.local", "mac": "10:98:36:AA:00:24", "vendor": "Dell",
         "ports": [_rec(22, "SSH", "SSH-2.0-OpenSSH_7.4"), _rec(5900, "VNC", "RFB 003.008"),
                   _rec(443, "HTTPS", "Dell iDRAC", kind="bmc",
                        tls={"cn": "idrac-DEMO123", "days_left": 74, "not_after": "2027-02-10",
                             "self_signed": True, "version": "TLSv1.2"})]},
        {"ip": "10.0.0.110", "hostname": "dock01.acme.local", "mac": "08:92:04:AA:01:10", "vendor": "Dell",
         "smb": dict(signed, smb1=True, ntlm=ntlm("PC101", 19045)), "ports": [_rec(135), _rec(445)]},
        {"ip": "10.0.0.111", "hostname": "pc102.acme.local", "mac": "08:92:04:AA:01:11", "vendor": "Dell",
         "smb": dict(signed, ntlm=ntlm("PC102", 26100, domain="PC102")), "ports": [_rec(135), _rec(445)]},
        {"ip": "10.0.0.112", "hostname": "pc103.acme.local", "mac": "CC:96:E5:AA:01:12", "vendor": "Intel",
         "smb": dict(signed, ntlm=ntlm("PC103", 26100)),
         "ports": [_rec(135), _rec(445), _rec(8000, "HTTP", "uvicorn", flags=["dev_server"]), _rec(57621),
                   _rec(8081, "HTTP", "Apache/2.2.15", flags=["basic_auth_plain"],
                        outdated="Apache httpd 2.2 or older (end of life)", http={"auth": "Basic realm=x"})]},
        {"ip": "10.0.0.180", "hostname": "phone-01.acme.local", "mac": "06:32:76:AA:01:80", "vendor": K.RANDOM_MAC,
         "mac_random": True, "ports": []},
        {"ip": "10.0.0.220", "hostname": "plc.acme.local", "mac": "00:1B:1B:00:00:01", "vendor": "Siemens",
         "ports": [_rec(102), _rec(502)]},
    ]
    for host in hosts:
        rules.classify(host)
    return hosts


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.hosts = _sample_hosts()
        naming = re.compile(r"^(PC|DC|fw|nas|srv|printer|plc)", re.I)
        self.findings = rules.build_findings(self.hosts, ["10.0.0.0/24"], None, naming)
        self.by_key = {f["key"]: f for f in self.findings}

    def ips(self, key):
        return {h["ip"] for h in self.by_key[key]["hosts"]}

    def test_classification(self):
        category = {h["ip"]: h["category"] for h in self.hosts}
        expected = {"10.0.0.1": "firewall", "10.0.0.2": "network", "10.0.0.14": "printer", "10.0.0.22": "nas",
                    "10.0.0.23": "dc", "10.0.0.24": "bmc", "10.0.0.110": "windows", "10.0.0.180": "mobile",
                    "10.0.0.220": "ics"}
        for ip, kind in expected.items():
            self.assertEqual(category[ip], kind, ip)
        by_ip = {h["ip"]: h for h in self.hosts}
        self.assertEqual(by_ip["10.0.0.110"]["name"], "PC101.acme.local")
        self.assertEqual(by_ip["10.0.0.110"]["os_state"], "verify")
        self.assertEqual(by_ip["10.0.0.1"]["type"], "Firewall/gateway: NethSecurity")
        self.assertIn("signing required", next(r for r in by_ip["10.0.0.23"]["ports"] if r["port"] == 445)["product"])
        self.assertIn("NLA", next(r for r in by_ip["10.0.0.23"]["ports"] if r["port"] == 3389)["info"])
        self.assertIn("2008 R2", next(r for r in by_ip["10.0.0.23"]["ports"] if r["port"] == 389)["info"])

    def test_expected_findings(self):
        expected = {
            "smb1": {"10.0.0.110"}, "smb_signing": {"10.0.0.22"}, "db_exposed": {"10.0.0.22"},
            "bmc": {"10.0.0.24"}, "remote_tool_server": {"10.0.0.23"}, "storage": {"10.0.0.22"},
            "cert_expired": {"10.0.0.22"}, "http_admin": {"10.0.0.2", "10.0.0.14"}, "snmp_public": {"10.0.0.2"},
            "os_check": {"10.0.0.110"}, "dns_mismatch": {"10.0.0.110"}, "dev_services": {"10.0.0.112"},
            "consumer_sw": {"10.0.0.112"}, "vnc_open": {"10.0.0.24"}, "cert_selfsigned": {"10.0.0.24"},
            "netdata": {"10.0.0.1"}, "upnp_igd": {"10.0.0.1"}, "ad_level": {"10.0.0.23"},
            "industrial": {"10.0.0.220"}, "basic_auth_plain": {"10.0.0.112"}, "outdated_sw": {"10.0.0.112"},
        }
        for key, ips in expected.items():
            self.assertIn(key, self.by_key, key)
            self.assertEqual(self.ips(key), ips, key)
        self.assertEqual(self.ips("unmanaged"), {"10.0.0.111", "10.0.0.180"})
        self.assertIn("workgroup", next(h for h in self.by_key["unmanaged"]["hosts"] if h["ip"] == "10.0.0.111")["evidence"])
        self.assertIn("flat", self.by_key)
        for absent in ("rdp_no_nla", "ssh_old", "os_eol", "telnet"):
            self.assertNotIn(absent, self.by_key)

    def test_ids_order_and_catalog(self):
        severities = [f["severity"] for f in self.findings]
        self.assertEqual(severities, sorted(severities, key=rules.SEVERITIES.index))
        self.assertEqual(self.findings[0]["id"], "H1")
        self.assertEqual(len({f["id"] for f in self.findings}), len(self.findings))
        for key, entry in rules.CATALOG.items():
            self.assertIn(entry["severity"], rules.SEVERITIES, key)
            self.assertIn(entry["when"], rules.WHEN_LABEL, key)
            self.assertTrue(entry["title"] and entry["risk"] and entry["action"], key)
            self.assertRegex(entry["attack"], r"^(T\d{4}(\.\d{3})?)?$", key)

    def test_catalog_reference_lists_every_finding(self):
        text = rules.catalog_markdown()
        for key, entry in rules.CATALOG.items():
            self.assertIn(f"`{key}`", text)
            self.assertIn(entry["title"], text)
        project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(project, "FINDINGS.md"), encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), text.strip(), "FINDINGS.md is stale: run --catalog")

    def test_positives(self):
        text = " ".join(rules.build_positives(self.hosts))
        self.assertIn("requires NLA", text)
        self.assertIn("Domain controllers", text)
        self.assertNotIn("database ports", text)

    def test_scoring(self):
        self.assertEqual(rules.exposure([]), {"score": 0, "rating": "Minimal"})
        full = rules.exposure(self.findings)
        self.assertTrue(0 < full["score"] <= 100)
        fewer = rules.exposure([f for f in self.findings if f["severity"] != "HIGH"])
        self.assertLess(fewer["score"], full["score"])
        scores = rules.host_scores(self.findings)
        self.assertGreaterEqual(scores["10.0.0.22"]["HIGH"], 3)
        self.assertEqual(scores["10.0.0.22"]["score"],
                         sum(rules.WEIGHTS[s] * scores["10.0.0.22"][s] for s in rules.SEVERITIES))

    def test_review_regressions(self):
        # a Windows machine that hosts a network-vendor web console is still a Windows machine
        host = {"ip": "10.0.0.40", "hostname": "srv-unifi.acme.local",
                "smb": {"smb2": True, "status": 0, "dialect": "3.1.1", "signing_required": True, "smb1": False,
                        "ntlm": {"netbios_name": "SRV-UNIFI", "dns_name": "SRV-UNIFI.acme.local",
                                 "dns_domain": "acme.local", "build": 20348}},
                "ports": [_rec(135), _rec(445), _rec(3389), _rec(8443, "HTTPS", "Ubiquiti", kind="network")]}
        rules.classify(host)
        self.assertEqual(host["category"], "server")
        # free page text must not turn a blog into a printer, but trusted text still identifies devices
        self.assertEqual(probes.fingerprint("", "welcome to my brother's blog about vigor and cisco"), ("", ""))
        self.assertEqual(probes.fingerprint("Brother HL-L2350DW series")[0], "printer")
        self.assertEqual(probes.fingerprint("", "location.replace('/wcd/index.html')")[0], "printer")
        # an SMB1-only host must not be counted as "SMBv1 disabled"
        only_v1 = [{"ip": "10.0.0.41", "smb": {"smb1": True}, "ports": [_rec(445)]}]
        self.assertFalse(any("SMBv1 is disabled" in line for line in rules.build_positives(only_v1)))
        # a port that completed TLS counts as HTTPS for the "HTTP only" finding
        switch = {"ip": "10.0.0.42", "hostname": "", "vendor": "D-Link", "ports": [
            _rec(80, "HTTP", "D-Link", kind="network"), _rec(4443, "TLS (HTTPS (alternate))", tls={"cn": "sw"})]}
        rules.classify(switch)
        self.assertNotIn("http_admin", {f["key"] for f in rules.build_findings([switch], [], None)})

    # ---- scenarios from the third review: does each rule fire on the right device? ----

    @staticmethod
    def _host(ip, ports, **extra):
        host = {"ip": ip, "hostname": "", "mac": "", "vendor": "", "ports": ports}
        host.update(extra)
        return host

    @staticmethod
    def _keys(hosts, networks=("10.1.0.0/24",), **kwargs):
        server_regex = kwargs.pop("server_regex", None)
        for host in hosts:
            rules.classify(host, server_regex)
        return {f["key"]: {h["ip"] for h in f["hosts"]} for f in rules.build_findings(hosts, list(networks), None,
                                                                                    **kwargs)}

    def test_a_print_port_does_not_make_a_printer(self):
        samba = {"smb2": True, "status": 0, "dialect": "3.1.1", "signing_required": True, "smb1": False}
        linux = self._host("10.1.0.5", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"), _rec(80, "HTTP", "nginx"),
                                        _rec(445), _rec(9100)], smb=samba)
        winsrv = self._host("10.1.0.6", [_rec(135), _rec(445), _rec(515), _rec(3389), _rec(5985)],
                            smb=dict(samba, ntlm={"netbios_name": "SRV1", "dns_name": "SRV1.acme.local",
                                                  "dns_domain": "acme.local", "build": 20348}))
        nas = self._host("10.1.0.7", [_rec(445), _rec(515), _rec(631), _rec(3260),
                                      _rec(5001, "HTTPS", "Synology (nginx)", kind="nas")], smb=samba)
        printer = self._host("10.1.0.8", [_rec(80, "HTTP", "HP", kind="printer"), _rec(9100)])
        keys = self._keys([linux, winsrv, nas, printer])
        self.assertEqual([h["category"] for h in (linux, winsrv, nas, printer)], ["linux", "server", "nas", "printer"])
        self.assertEqual(keys["printer"], {"10.1.0.8"})
        self.assertIn("10.1.0.7", keys["storage"])
        self.assertIn("10.1.0.6", keys["admin_exposure"])
        self.assertTrue(probes.is_printer_like({80, 9100}))
        for computer in ({22, 80, 9100}, {135, 445, 515}, {445, 631, 3260}):
            self.assertFalse(probes.is_printer_like(computer), computer)

    def test_evidence_says_when_it_rests_on_the_port_number(self):
        nas = self._host("10.1.0.7", [_rec(21, "FTP", "vsFTPd 3.0.5"), _rec(23), _rec(445), _rec(3260),
                                      _rec(5001, "HTTPS", "Synology (nginx)", kind="nas")])
        rules.classify(nas)
        found = {f["key"]: " | ".join(h["evidence"] for h in f["hosts"])
                 for f in rules.build_findings([nas], ["10.1.0.0/24"], None)}
        self.assertEqual(found["telnet"], "port 23 (by port number)")        # nothing answered: say so
        self.assertEqual(found["ftp"], "port 21: vsFTPd 3.0.5")              # the service identified itself
        self.assertIn("3260", found["storage"])
        self.assertNotIn("445", found["storage"])                            # file sharing is what a NAS is for

    def test_workstation_findings_do_not_move_the_exposure_index(self):
        network = [{"key": "smb1", "severity": "HIGH", "hosts": [{"ip": "10.0.0.5"}]}]
        local = [{"key": "local_firewall", "severity": "HIGH", "hosts": [{"ip": "10.0.0.9"}]},
                 {"key": "local_llmnr", "severity": "MEDIUM", "hosts": [{"ip": "10.0.0.9"}]}]
        self.assertEqual(rules.exposure(local), {"score": 0, "rating": "Minimal"})
        self.assertEqual(rules.exposure(network + local), rules.exposure(network))
        self.assertGreater(rules.exposure(network)["score"], 0)
        self.assertEqual([name for _floor, name in rules.EXPOSURE_BANDS], ["Severe", "Elevated", "Limited", "Minimal"])

    def test_management_boards_and_hypervisors_are_recognized(self):
        for text, kind in (("iDRAC9", "bmc"), ("iLO 5", "bmc"), ("HPE-iLO-Server/1.30", "bmc"),
                           ("Integrated Lights-Out 4", "bmc"), ('" + ID_EESX_Welcome + "', "hypervisor"),
                           ("VMware, Inc", "hypervisor"), ("Proxmox Virtual Environment", "hypervisor")):
            self.assertEqual(probes.fingerprint(text)[0], kind, text)
        self.assertEqual(probes.fingerprint("", "partner logos: vmware, inc and others"), ("", ""))
        # a page linking to several products is a dashboard, not one of them
        self.assertEqual(probes.fingerprint("", "links: pfsense, synology nas, proxmox"), ("", ""))
        self.assertEqual(probes.fingerprint("", "welcome to pfsense")[1], "pfSense")

    def test_windows_identity_outranks_position_and_ports(self):
        ntlm = {"netbios_name": "DC1", "dns_name": "DC1.acme.local", "dns_domain": "acme.local", "build": 20348}
        smb = {"smb2": True, "status": 0, "dialect": "3.1.1", "signing_required": True, "smb1": False, "ntlm": ntlm}
        gateway_dc = self._host("10.1.0.1", [_rec(53), _rec(88), _rec(389), _rec(445), _rec(3389)],
                                smb=smb, is_gateway=True, rdp={"nla_required": True, "code": "nla"})
        hidden_dc = self._host("10.1.0.2", [_rec(135), _rec(445), _rec(9389)], smb=smb)
        vpro = self._host("10.1.0.3", [_rec(135), _rec(445), _rec(623)],
                          smb=dict(smb, ntlm=dict(ntlm, netbios_name="PC9", dns_name="PC9.acme.local", build=26100)))
        for host in (gateway_dc, hidden_dc, vpro):
            rules.classify(host)
        self.assertEqual([h["category"] for h in (gateway_dc, hidden_dc, vpro)], ["dc", "dc", "windows"])
        self.assertIn("default gateway", gateway_dc["roles"])

    def test_unix_servers_count_as_critical(self):
        named = self._host("10.1.0.10", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"), _rec(443, "HTTPS", "nginx")],
                           hostname="srv-web.acme.local")
        database = self._host("10.1.0.11", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"), _rec(5432)])
        appliance = self._host("10.1.0.12", [_rec(22, "SSH", "SSH-2.0-dropbear_2016.74"), _rec(80, "HTTP", "x")])
        pc = self._host("10.1.0.20", [_rec(135), _rec(445)])
        keys = self._keys([named, database, appliance, pc], server_regex=re.compile("^srv", re.I))
        self.assertEqual([h["category"] for h in (named, database, appliance)], ["unix_server", "unix_server", "linux"])
        self.assertEqual(keys["admin_exposure"], {"10.1.0.10", "10.1.0.11"})
        self.assertIn("flat", keys)
        self.assertEqual(keys["ssh_old"], {"10.1.0.12"})          # old dropbear is caught too

    def test_a_samba_dns_suffix_is_not_an_ad_domain(self):
        def samba(ip):
            return self._host(ip, [_rec(445)], smb={"smb2": True, "status": 0, "signing_required": True,
                                                    "ntlm": {"dns_name": "box", "dns_domain": "fritz.box", "build": 0}})

        def workgroup_pc(ip, name):
            return self._host(ip, [_rec(135), _rec(445)], smb={"smb2": True, "status": 0, "signing_required": True,
                              "ntlm": {"netbios_name": name, "dns_name": name, "dns_domain": name, "build": 26100}})
        hosts = [samba("10.1.0.30"), samba("10.1.0.31"), workgroup_pc("10.1.0.40", "PC-A"),
                 workgroup_pc("10.1.0.41", "PC-B")]
        keys = self._keys(hosts)
        self.assertEqual(rules.infer_domain(hosts), "")
        self.assertNotIn("unmanaged", keys)

    def test_unmanaged_needs_evidence_and_unknown_devices_are_reported_mildly(self):
        self.assertIn("QEMU", K.vendor_for("52:54:00:12:34:56"))          # a KVM guest, not a random MAC
        silent = self._host("10.1.0.50", [], vendor="Dell", mac="08:92:04:AA:00:50")
        child = self._host("10.1.0.51", [_rec(135), _rec(445)], smb={"smb2": True, "status": 0, "signing_required": True,
                           "ntlm": {"netbios_name": "PC5", "dns_name": "PC5.sales.acme.local",
                                    "dns_domain": "sales.acme.local", "dns_forest": "acme.local", "build": 26100}})
        linux = self._host("10.1.0.52", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6")], hostname="build01.acme.local")
        keys = self._keys([silent, child, linux], naming=re.compile(r"^PC\d+", re.I), expected_domain="acme.local")
        self.assertNotIn("unmanaged", keys)
        self.assertEqual(keys["unidentified"], {"10.1.0.50"})
        self.assertEqual(rules.CATALOG["unidentified"]["severity"], "MEDIUM")

    def test_segmentation_is_not_overcounted(self):
        gateway = self._host("10.1.0.1", [_rec(443, "HTTPS", "pfSense", kind="firewall")], is_gateway=True)
        nas = self._host("10.1.0.2", [_rec(445), _rec(5001, "HTTPS", "Synology (nginx)", kind="nas")],
                         smb={"smb2": True, "status": 0, "signing_required": True, "smb1": False})
        pc = self._host("10.1.0.3", [_rec(135), _rec(445)])
        ghost_printer = self._host("10.1.0.4", [], vendor="Brother Industries")
        keys = self._keys([gateway, nas, pc, ghost_printer])
        for key in ("flat", "storage", "printer"):
            self.assertNotIn(key, keys)                 # gateway + one file server is not a flat network

    def test_port_numbers_do_not_override_what_answered(self):
        web = self._host("10.1.0.60", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"), _rec(7070, "HTTP", "nginx"),
                                       _rec(9200, "HTTP", "nginx"), _rec(8040, "HTTPS", "nginx"),
                                       _rec(993, "TLS (IMAPS)", "Outlook Web App", kind="app", tls={"cn": "owa"})])
        jenkins = self._host("10.1.0.61", [_rec(22, "SSH", "SSH-2.0-OpenSSH_9.6"),
                                           _rec(8080, "HTTP", "Jenkins (Jetty(10.0.18))", flags=["dev_server"],
                                                kind="app", http={"title": "Dashboard [Jenkins]"})])
        keys = self._keys([web, jenkins])
        for key in ("db_exposed", "remote_tool_client", "remote_tool_server", "dev_services"):
            self.assertNotIn(key, keys)
        self.assertEqual(keys["sensitive_app"], {"10.1.0.61"})     # Jenkins yes; a certificate name on IMAPS no

    def test_dev_server_marks(self):
        def flags(headers, body=b"<html></html>"):
            rec = probes.new_record(3000)
            probes._apply_http(rec, {"http": probes.parse_http(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + body)}, False)
            return rec["flags"]
        self.assertIn("dev_server", flags(b"X-Powered-By: Express\r\n"))
        self.assertIn("dev_server", flags(b"Server: PHP 8.3.1 Development Server\r\n"))
        self.assertIn("dev_server", flags(b"", b'<script type="module" src="/@vite/client"></script>'))
        for production in (b"Server: Jetty(10.0.18)\r\n", b"Server: Kestrel\r\n", b"Server: gunicorn\r\n",
                           b"Server: Python/3.12 aiohttp/3.9.5\r\n", b"Server: nginx/1.26.1\r\n"):
            self.assertNotIn("dev_server", flags(production), production)

    def test_positives_only_vouch_for_what_was_measured(self):
        answered = self._host("10.1.0.70", [_rec(3389)], rdp={"nla_required": True, "code": "nla"})
        silent = self._host("10.1.0.71", [_rec(3389)])
        self.assertTrue(any("Remote Desktop requires NLA" in line for line in rules.build_positives([answered])))
        self.assertFalse(any("Remote Desktop" in line for line in rules.build_positives([answered, silent])))
        half = [self._host(f"10.1.0.8{i}", [_rec(445)], smb={"smb2": True, "status": 0, "signing_required": i == 0})
                for i in range(3)]
        self.assertFalse(any("signing" in line for line in rules.build_positives(half)))

    def test_certificate_expiry_follows_the_certificate_lifetime(self):
        def expiring(days_left, lifetime):
            end = dt.date(2026, 6, 30)
            tls = {"cn": "x", "days_left": days_left, "not_after": end.isoformat(),
                   "not_before": (end - dt.timedelta(days=lifetime)).isoformat()}
            host = self._host("10.1.0.90", [_rec(443, "HTTPS", "nginx", tls=tls)])
            return "cert_expiring" in self._keys([host])
        self.assertTrue(expiring(20, 365))
        self.assertFalse(expiring(4, 6))        # a healthy 6-day certificate, renewed every few days
        self.assertTrue(expiring(1, 6))
        self.assertFalse(expiring(25, 45))
        self.assertTrue(expiring(10, 45))

    def test_scanning_workstation_os_and_audit_date(self):
        me = self._host("10.1.0.99", [], is_self=True, smb={"ntlm": {"dns_name": "OLDPC", "build": 7601}})
        self.assertEqual(self._keys([me])["os_eol"], {"10.1.0.99"})
        self.assertEqual(K.windows_product(6001)[1], "eol")
        local = localcheck.normalize({"ip": "10.1.0.99", "computer": "PC", "last_update": "2026-11-01",
                                      "uac_enabled": True, "llmnr_disabled": True, "lsa_protection": True})
        on_the_day = {f["key"] for f in rules.build_findings([], [], local, reference_date="2026-11-15")}
        self.assertNotIn("local_updates", on_the_day)
        much_later = {f["key"] for f in rules.build_findings([], [], local, reference_date="2027-03-01")}
        self.assertIn("local_updates", much_later)
        # a third-party firewall or a policy-managed machine is not a disabled firewall
        managed = dict(local, firewall=[{"name": "Domain", "enabled": False}],
                       firewall_products=[{"name": "Vendor Firewall", "active": True}],
                       defender_realtime=False, defender_mode="Passive Mode", antivirus=[])
        keys = {f["key"] for f in rules.build_findings([], [], managed, reference_date="2026-11-15")}
        self.assertFalse({"local_firewall", "local_defender"} & keys)

    def test_domain_given_in_netbios_form(self):
        hosts = [h for h in _sample_hosts() if h["ip"] in ("10.0.0.110", "10.0.0.112")]
        for host in hosts:
            host["smb"]["ntlm"]["netbios_domain"] = "ACME"
        for expected in ("ACME", "acme", "acme.local"):
            keys = {f["key"] for f in rules.build_findings(hosts, [], None, None, expected)}
            self.assertNotIn("unmanaged", keys, expected)
        self.assertIn("unmanaged", {f["key"] for f in rules.build_findings(hosts, [], None, None, "other.local")})

    def test_flat_network_fires_for_a_range_target(self):
        fragments = [str(n) for n in netinfo.parse_targets(["10.0.0.1-250"])]
        self.assertGreater(len(fragments), 1)
        self.assertIn("flat", {f["key"] for f in rules.build_findings(self.hosts, fragments, None)})

    def test_diff_across_profiles_compares_common_ports_only(self):
        def audit(profile, ports):
            return {"meta": {"started": "x", "targets": ["10.0.0.0/24"], "scan": {"profile": profile}},
                    "hosts": [{"ip": "10.0.0.5", "name": "a", "ports": [_rec(p) for p in ports]}], "findings": []}
        delta = rules.diff(audit("full", [80, 40000]), audit("standard", [80, 443]))
        self.assertEqual(delta["closed"], [])                      # 40000 was never looked at this time
        self.assertEqual(delta["opened"][0]["ports"], [443])
        self.assertIn("standard", delta["notes"][0])
        self.assertEqual(rules.diff(audit("full", [80]), audit("full", [80]))["notes"], [])

    def test_csv_neutralizes_formulas(self):
        import io
        buffer = io.StringIO()
        writer = report._SafeCsv(buffer)
        writer.writerow(["=cmd|' /C calc'!A0", "+1", "-2", "@x", "safe", 5, "x;=cmd", "a\x1b[31mb\r\n=c"])
        self.assertEqual(buffer.getvalue().strip(),
                         "\"'=cmd|' /C calc'!A0\",\"'+1\",\"'-2\",\"'@x\",\"safe\",\"5\",\"x;'=cmd\",\"a [31mb  =c\"")

    def test_hostile_names_cannot_break_the_report(self):
        evil = "<script>alert(1)</script>\"'><img src=x onerror=1>"
        long_name = "x" * 300
        hosts = [{"ip": "10.0.0.9", "hostname": evil, "mac": "", "vendor": evil,
                  "snmp": evil, "ports": [_rec(80, "HTTP", evil, info=evil, http={"title": evil, "status": 200},
                                               tls={"cn": evil, "issuer_cn": evil, "version": "TLSv1.3"})]},
                 {"ip": "10.0.0.14", "hostname": long_name, "ports": []}]
        for host in hosts:
            rules.classify(host)
        findings = rules.build_findings(hosts, ["10.0.0.0/24"], None)
        page = report.render({"meta": {"client": evil, "targets": [evil], "warnings": [evil]}, "hosts": hosts,
                              "findings": findings, "positives": [evil], "limits": [evil], "local": None,
                              "diff": None})
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn(long_name, page)

    def test_local_workstation_section_renders(self):
        local = localcheck.normalize({
            "ip": "10.0.0.150", "computer": "PC150", "domain": "acme.local", "os": "Windows 11 Pro",
            "build": "26200", "firewall": [{"name": "Domain", "enabled": True}], "rdp_enabled": True,
            "rdp_nla": True, "smb1": None, "smb_signing_required": None, "antivirus": [], "defender_realtime": "?",
            "bitlocker": 8, "listening": {"port": 445, "process": "System"}, "shares": []})
        page = report.render({"meta": {"targets": []}, "hosts": [], "findings": [], "positives": [],
                              "limits": [], "local": local, "diff": {"previous_date": "x"}})
        for needle in ("Scanning workstation", "PC150", "not detected", "state 8", "445 (System)",
                       "No difference from the previous audit"):
            self.assertIn(needle, page, needle)

    def test_more_review_regressions(self):
        self.assertEqual(rules.build_positives([]), [])
        # an Apple device that follows the naming convention is managed
        mac = {"ip": "10.0.0.50", "hostname": "MAC-012.acme.local", "vendor": "Apple", "ports": [_rec(5000), _rec(7000)]}
        rules.classify(mac)
        self.assertEqual(mac["category"], "apple")
        naming = re.compile(r"^(PC|MAC)-\d+", re.I)
        self.assertNotIn("unmanaged", {f["key"] for f in rules.build_findings([mac], [], None, naming)})
        self.assertIn("unmanaged", {f["key"] for f in rules.build_findings([mac], [], None, re.compile("^PC-"))})
        # ordinary words and query strings are not products
        for text in ("Luci soggiorno - controllo", "var qts=2; load()", "we use jenkins and grafana here"):
            self.assertEqual(probes.fingerprint("", text), ("", ""), text)
        self.assertEqual(probes.fingerprint("Luci soggiorno"), ("", ""))
        self.assertEqual(probes.fingerprint("Jenkins")[1], "Jenkins")
        # a known service on a high port of a Windows host is not "dynamic RPC"
        rec = asyncio.run(probes.identify_port("127.0.0.1", 57621, True, True))
        self.assertEqual(rec["service"], "Spotify")
        host = {"ports": [_rec(445), _rec(57621), _rec(49670, "Dynamic RPC (Windows)")]}
        self.assertEqual(report._port_list(host), "445, 57621 + 1 dynamic RPC")
        # overlapping targets are one segment
        flat = [f for f in rules.build_findings(self.hosts, ["10.0.0.0/23", "10.0.0.7"], None) if f["key"] == "flat"]
        self.assertEqual(len(flat[0]["hosts"]), 1)
        # a finding on a port outside the common list is neither new nor resolved
        def audit(profile, findings):
            return {"meta": {"started": "x", "scan": {"profile": profile}}, "hosts": [], "findings": findings}
        db = [{"key": "db_exposed", "hosts": [{"ip": "10.0.0.5", "evidence": "port 40000: MariaDB"}]}]
        self.assertEqual(rules.diff(audit("full", db), audit("standard", []))["resolved"], [])
        self.assertEqual(len(rules.diff(audit("full", db), audit("full", []))["resolved"]), 1)

    def test_multihomed(self):
        hosts = [{"ip": "10.0.0.5", "name": "mac1.acme.local"}, {"ip": "10.0.0.6", "name": "MAC1"},
                 {"ip": "10.0.0.7", "name": "other"}]
        rules.link_multihomed(hosts)
        self.assertEqual(hosts[0]["roles"], ["also at 10.0.0.6"])
        self.assertNotIn("roles", hosts[2])

    def test_local_findings(self):
        local = localcheck.normalize({
            "ip": "10.0.0.150", "computer": "PC150", "firewall": {"name": "Public", "enabled": True},
            "rdp_enabled": True, "rdp_nla": True, "smb1": False, "smb_signing_required": True,
            "llmnr_disabled": False, "netbios": [{"adapter": "eth", "option": 0}],
            "rules": {"port": "3389", "profile": "Any", "name": "Remote Desktop"},
            "antivirus": [{"name": "Other AV", "active": True, "updated": True},
                          {"name": "Windows Defender", "active": False, "updated": True}],
            "defender_realtime": False, "uac_enabled": True, "wdigest_cleartext": False, "lsa_protection": True,
            "laptop": True, "bitlocker": 2, "guest_enabled": False, "last_update": "2020-01-01"})
        keys = {f["key"] for f in rules.build_findings([], [], local)}
        self.assertEqual(keys, {"local_exposure", "local_llmnr", "local_bitlocker", "local_updates"})
        bad = dict(local, antivirus=[{"name": "AV", "active": False}], uac_enabled=False, wdigest_cleartext=True,
                   firewall=[{"name": "Domain", "enabled": False}])
        keys = {f["key"] for f in rules.build_findings([], [], bad)}
        self.assertTrue({"local_defender", "local_uac", "local_wdigest", "local_firewall"} <= keys)
        self.assertIsNone(localcheck.normalize("oops"))

    def _audit(self):
        scan = {"profile": "standard", "ports_per_host": 1259, "nbns": True, "snmp": True, "ssdp": True,
                "nmap": False, "local": False, "source_host": "pc", "source_ip": "10.0.0.150",
                "seen_from": "10:00", "seen_to": "10:03", "date": "2026-11-15", "excluded": ["10.0.0.99"],
                "naming": True, "domain": "acme.local"}
        self.hosts[1]["scan_quality"] = "intermittent"
        return {"meta": {"client": "Test <Ltd>", "operator": "tester", "started": "2026-11-15 10:00",
                         "targets": ["10.0.0.0/24"], "profile": "standard", "source": "pc (10.0.0.150)",
                         "duration": "1 min 0 s", "warnings": ["sample warning"], "scan": scan},
                "hosts": self.hosts, "findings": self.findings, "positives": rules.build_positives(self.hosts),
                "limits": rules.build_limits(scan, self.hosts), "local": None, "diff": None}

    def test_limits(self):
        text = " ".join(self._audit()["limits"])
        for needle in ("1,259", "NetBIOS (137), SNMP (161), SSDP (1900)", "10.0.0.2 (answers intermittently",
                       "10.0.0.99", "nmap integration was not available", "'public'", "IPv6 was not examined",
                       "by port number"):
            self.assertIn(needle, text)
        self.assertIn("No UDP port", " ".join(rules.build_limits({"profile": "full"}, [])))

    def test_report_and_outputs(self):
        audit = self._audit()
        page = report.render(audit)
        self.assertIn("Test &lt;Ltd&gt;", page)
        self.assertIn("SMBv1 enabled", page)
        self.assertIn("sample warning", page)
        self.assertIn("MITRE ATT&amp;CK T1557.001", page)
        self.assertEqual(page.count("<article class='finding "), len(self.findings))
        for anchor in re.findall(r"href='#([^']+)'", page):
            self.assertIn(f"id='{anchor}'", page, anchor)
        self.assertNotRegex(page, r"(src|href)=['\"]https?://")
        with tempfile.TemporaryDirectory() as folder:
            paths = report.write_outputs(audit, folder)
            self.assertEqual(set(map(os.path.basename, paths.values())),
                             {"report.html", "audit.json", "inventory.csv", "findings.csv", "summary.md"})
            for path in paths.values():
                self.assertGreater(os.path.getsize(path), 50)
            with open(paths["audit.json"], encoding="utf-8") as handle:
                self.assertEqual(len(json.load(handle)["hosts"]), len(self.hosts))
            with open(paths["summary.md"], encoding="utf-8") as handle:
                self.assertIn("Exposure index", handle.read())

    def test_report_handles_an_empty_audit(self):
        page = report.render({"meta": {"targets": []}, "hosts": [], "findings": [], "positives": [],
                              "limits": [], "local": None, "diff": None})
        self.assertIn("No findings", page)
        self.assertIn("Minimal exposure", page)

    def test_diff(self):
        current = self._audit()
        previous = json.loads(json.dumps(current))
        previous["hosts"] = [h for h in previous["hosts"] if h["ip"] != "10.0.0.180"]
        nas = next(h for h in previous["hosts"] if h["ip"] == "10.0.0.22")
        nas["ports"] = [r for r in nas["ports"] if r["port"] != 23306]
        previous["findings"] = [f for f in previous["findings"] if f["key"] != "db_exposed"]
        delta = rules.diff(previous, current)
        self.assertEqual([h["ip"] for h in delta["new_hosts"]], ["10.0.0.180"])
        self.assertEqual(delta["opened"], [{"ip": "10.0.0.22", "name": "nas", "ports": [23306]}])
        self.assertTrue(any("Database" in item for item in delta["new_findings"]))
        self.assertEqual(delta["resolved"], [])
        current["diff"] = delta
        self.assertIn("Changes since the previous audit", report.render(current))


# --------------------------------------------------------------------------- command line

class CliTests(unittest.TestCase):
    def setUp(self):
        # these tests never need the real interfaces, and asking PowerShell for them is slow
        self._interfaces = netinfo.local_interfaces
        netinfo.local_interfaces = lambda: []

    def tearDown(self):
        netinfo.local_interfaces = self._interfaces

    def test_config_file_supplies_defaults(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "client.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"client": "Acme", "targets": ["10.1.0.0/24"], "exclude": ["10.1.0.9", "10.1.0.10"],
                           "server-regex": "^SRV", "profile": "full"}, handle)
            args = cli.parse_args(["--config", path, "--profile", "quick"])
            self.assertEqual((args.client, args.targets, args.exclude, args.server_regex, args.profile),
                             ("Acme", ["10.1.0.0/24"], "10.1.0.9,10.1.0.10", "^SRV", "quick"))
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"nonsense": 1}, handle)
            with self.assertRaises(SystemExit):
                cli.parse_args(["--config", path])

    def test_demo_report(self):
        from netaudit import demo
        audit = demo.build()
        keys = {f["key"] for f in audit["findings"]}
        self.assertTrue({"flat", "smb1", "os_eol", "rdp_no_nla", "telnet", "bmc", "db_exposed", "unmanaged",
                         "upnp_igd", "basic_auth_plain", "cert_expired", "cert_expiring"} <= keys, keys)
        self.assertEqual(len({h["ip"] for h in audit["hosts"]}), len(audit["hosts"]))
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(cli.main(["--demo", "--output", folder]), cli.EXIT_OK)
            with open(os.path.join(folder, "report.html"), encoding="utf-8") as handle:
                page = handle.read()
            self.assertIn("Acme Ltd (demo)", page)
            for anchor in re.findall(r"href='#([^']+)'", page):
                self.assertIn(f"id='{anchor}'", page, anchor)

    def test_config_values_are_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "client.json")
            for bad in ({"profile": "fulll"}, {"allow-public": "false"}, {"speed": "warp"}, {"fail-on": "all"},
                        {"max-addresses": "many"}, {"client": 5}, {"targets": 5}, {"targets": None},
                        {"targets": [1, 2]}):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(bad, handle)
                with self.assertRaises(SystemExit, msg=str(bad)):
                    cli.parse_args(["--config", path])
        with self.assertRaises(ValueError):
            K.ports_for("fulll")

    def test_exclude_understands_networks_and_ranges(self):
        run = cli.Run(cli.parse_args(["10.9.0.0/27", "--authorized", "--exclude", "10.9.0.0/29,10.9.0.20-22"]))
        self.assertEqual(cli.prepare(run), cli.EXIT_OK)
        self.assertFalse({"10.9.0.5", "10.9.0.20", "10.9.0.22"} & set(run.candidates))
        self.assertIn("10.9.0.8", run.candidates)
        bad = cli.Run(cli.parse_args(["10.9.0.0/27", "--authorized", "--exclude", "nonsense"]))
        self.assertEqual(cli.prepare(bad), cli.EXIT_USAGE)

    def test_interrupted_audit_gives_no_reassurance(self):
        with tempfile.TemporaryDirectory() as folder:
            run = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized", "--profile", "full", "--output", folder]))
            run.targets = ["10.9.0.0/29"]
            run.hosts = {"10.9.0.2": {"ip": "10.9.0.2", "alive_by": ["ping"], "mac": "", "vendor": "",
                                      "mac_random": False, "hostname": ""}}
            partial = cli.portscan.ScanResult()
            partial.open["10.9.0.2"] = [8080]
            partial.incomplete.add("10.9.0.2")
            run.partials.append(partial)
            run.interrupted = True
            self.assertEqual(cli.finalize(run), cli.EXIT_CANCELLED)
            with open(os.path.join(folder, "audit.json"), encoding="utf-8") as handle:
                audit = json.load(handle)
            self.assertEqual(audit["positives"], [])
            self.assertTrue(audit["limits"][0].startswith("THE AUDIT WAS INTERRUPTED"))
            self.assertEqual(audit["hosts"][0]["scan_quality"], "partial")
            self.assertEqual([r["port"] for r in audit["hosts"][0]["ports"]], [8080])   # kept despite Ctrl+C

    def test_interrupted_audit_is_not_compared_with_the_baseline(self):
        from netaudit import demo
        with tempfile.TemporaryDirectory() as folder:
            baseline = os.path.join(folder, "old.json")
            with open(baseline, "w", encoding="utf-8") as handle:
                json.dump(demo.build(), handle)
            out = os.path.join(folder, "out")
            run = cli.Run(cli.parse_args(["192.168.10.0/24", "--authorized", "--baseline", baseline,
                                          "--output", out]))
            run.targets = ["192.168.10.0/24"]
            run.hosts = {"192.168.10.1": {"ip": "192.168.10.1", "alive_by": ["ping"], "mac": "", "vendor": "",
                                          "mac_random": False, "hostname": ""}}
            run.interrupted = True
            cli.finalize(run)
            with open(os.path.join(out, "audit.json"), encoding="utf-8") as handle:
                audit = json.load(handle)
            self.assertIsNone(audit["diff"])
            self.assertTrue(any("Comparison" in w for w in audit["meta"]["warnings"]))

    def test_regenerating_a_demo_audit_changes_nothing(self):
        from netaudit import demo
        original = demo.build()
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "audit.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(original, handle)
            self.assertEqual(cli.main(["--regenerate", path]), cli.EXIT_OK)
            with open(path, encoding="utf-8") as handle:
                again = json.load(handle)

        def shape(audit):
            return ([(h["ip"], h["category"], h["type"]) for h in audit["hosts"]],
                    [(f["id"], f["key"], [(x["ip"], x["evidence"]) for x in f["hosts"]]) for f in audit["findings"]],
                    audit["positives"], audit["limits"])
        self.assertEqual(shape(again), shape(json.loads(json.dumps(original))))

    def test_damaged_baseline_does_not_cost_the_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            baseline = os.path.join(folder, "old.json")
            with open(baseline, "w", encoding="utf-8") as handle:
                handle.write("[]")
            out = os.path.join(folder, "out")
            run = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized", "--baseline", baseline, "--output", out]))
            run.targets = ["10.9.0.0/29"]
            self.assertEqual(cli.finalize(run), cli.EXIT_OK)
            self.assertTrue(os.path.exists(os.path.join(out, "report.html")))
            with open(os.path.join(out, "audit.json"), encoding="utf-8") as handle:
                self.assertIsNone(json.load(handle)["diff"])

    def test_regenerate_reuses_the_original_options(self):
        def regenerated(**saved):
            hosts = [h for h in _sample_hosts() if h["ip"] == "10.0.0.110"]
            audit = {"meta": {"started": "2026-11-15 10:00", "targets": ["10.0.0.0/24"],
                              "scan": dict({"profile": "standard", "ports_per_host": 10}, **saved)},
                     "hosts": hosts, "findings": [], "positives": [], "limits": [], "local": None, "diff": None}
            with tempfile.TemporaryDirectory() as folder:
                path = os.path.join(folder, "audit.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(audit, handle)
                cli.main(["--regenerate", path])
                with open(path, encoding="utf-8") as handle:
                    return json.load(handle)
        self.assertEqual(regenerated()["hosts"][0]["category"], "windows")
        self.assertEqual(regenerated(server_pattern="^PC1")["hosts"][0]["category"], "server")
        self.assertNotIn("unmanaged", {f["key"] for f in regenerated()["findings"]})
        self.assertIn("unmanaged", {f["key"] for f in regenerated(naming_pattern="^ZZZ")["findings"]})

    def test_end_to_end_self_test(self):
        with tempfile.TemporaryDirectory() as folder:
            code = cli.main(["--self-test", "--profile", "quick", "--no-local", "--no-nmap", "--output", folder])
            self.assertEqual(code, cli.EXIT_OK)
            with open(os.path.join(folder, "audit.json"), encoding="utf-8") as handle:
                audit = json.load(handle)
            self.assertEqual([h["ip"] for h in audit["hosts"]], ["127.0.0.1"])
            self.assertFalse(audit["meta"]["interrupted"])
            self.assertEqual(audit["meta"]["scan"]["ports_per_host"], len(K.ports_for("quick")))
            for name in ("report.html", "summary.md", "inventory.csv", "findings.csv", "audit.log"):
                self.assertTrue(os.path.exists(os.path.join(folder, name)), name)

    def test_authorization_is_never_assumed(self):
        import io
        args = cli.parse_args(["10.9.0.0/29"])

        class FakeTerminal(io.StringIO):
            def isatty(self):
                return True
        original = sys.stdin
        try:
            sys.stdin = io.StringIO("YES\n")                 # not a terminal: refuse without --authorized
            self.assertFalse(cli.confirm_authorization(args, ["10.9.0.0/29"]))
            sys.stdin = FakeTerminal("no\n")
            self.assertFalse(cli.confirm_authorization(args, ["10.9.0.0/29"]))
            sys.stdin = FakeTerminal("yes\n")
            self.assertTrue(cli.confirm_authorization(args, ["10.9.0.0/29"]))
            sys.stdin = FakeTerminal("")                     # end of input
            self.assertFalse(cli.confirm_authorization(args, ["10.9.0.0/29"]))
        finally:
            sys.stdin = original
        self.assertTrue(cli.confirm_authorization(cli.parse_args(["10.9.0.0/29", "--authorized"]), ["x"]))

    def test_cross_check_marks_inconsistent_hosts(self):
        answers = [{"10.9.0.2": [80], "10.9.0.3": [22]},      # quick pass
                   {"10.9.0.2": [], "10.9.0.3": [22, 8080]},  # standard pass misses port 80 on .2
                   {"10.9.0.2": []}]                           # careful repeat still misses it
        calls = []

        async def fake_scan(targets, workers, timeout, max_sockets, **kwargs):
            calls.append((sorted(targets), workers))
            result = kwargs.get("result") or portscan.ScanResult()
            result.open.update(answers[len(calls) - 1])
            return result
        run = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized"]))
        original = portscan.scan
        portscan.scan = fake_scan
        try:
            interrupted = asyncio.run(cli.scan_ports(run, ["10.9.0.2", "10.9.0.3"], None))
        finally:
            portscan.scan = original
        self.assertFalse(interrupted)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[2], (["10.9.0.2"], K.SPEEDS["careful"][0]))     # only the doubtful host, slower
        self.assertEqual(run.quality, {"10.9.0.2": "intermittent"})
        self.assertEqual(run.open_ports, {"10.9.0.2": {80}, "10.9.0.3": {22, 8080}})

    def test_runs_in_the_same_minute_do_not_overwrite_each_other(self):
        with tempfile.TemporaryDirectory() as folder:
            base = os.path.join(folder, "Acme_2026-11-15_1030")
            self.assertEqual(cli.unique_folder(base), base)
            for expected in (base, base + "_2", base + "_3"):
                target = cli.unique_folder(base)
                self.assertEqual(target, expected)
                os.makedirs(target)
                with open(os.path.join(target, "audit.json"), "w", encoding="utf-8") as handle:
                    json.dump({"meta": {}}, handle)
            self.assertTrue(cli.find_baseline(folder, "Acme").endswith(os.path.join("Acme_2026-11-15_1030_3",
                                                                                     "audit.json")))

    def test_report_overview_and_reading_guide(self):
        from netaudit import demo
        page = report.render(demo.build())
        self.assertIn("class='overview'", page)
        self.assertIn("The most widespread high finding is", page)
        self.assertIn("How to read this report", page)
        partial = demo.build()
        partial["meta"]["interrupted"] = True
        self.assertIn("interrupted before completion", report.render(partial))
        clean = {"meta": {"targets": ["10.0.0.0/24"]}, "hosts": [], "findings": [], "positives": [], "limits": [],
                 "local": None, "diff": None}
        self.assertIn("not proof that the network is secure", report.render(clean))

    def test_csv_delimiter_option(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(cli.main(["--demo", "--output", folder, "--csv-delimiter", "semicolon"]), cli.EXIT_OK)
            with open(os.path.join(folder, "inventory.csv"), encoding="utf-8-sig") as handle:
                self.assertTrue(handle.readline().startswith('"Client";"Audit date";"Address";"Name";"Domain"'))
            self.assertEqual(cli.main(["--demo", "--output", folder]), cli.EXIT_OK)
            with open(os.path.join(folder, "findings.csv"), encoding="utf-8-sig") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(rows[0][:6], ["Client", "Audit date", "ID", "Key", "Severity", "Severity rank"])
            self.assertEqual(rows[1][0], "Acme Ltd (demo)")
            self.assertIn(rows[1][4], ("High", "Medium", "Low"))
            self.assertEqual([row[5] for row in rows[1:]], sorted(row[5] for row in rows[1:]))

    def test_catalog_option_writes_a_utf8_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "FINDINGS.md")
            self.assertEqual(cli.main(["--catalog", path]), cli.EXIT_OK)
            with open(path, "rb") as handle:
                data = handle.read()
            self.assertFalse(data.startswith(b"\xef\xbb\xbf"))          # no byte-order mark
            self.assertEqual(data.decode("utf-8"), rules.catalog_markdown() + "\n")
            self.assertEqual(cli.main(["--catalog", os.path.join(folder, "no", "such", "x.md")]), cli.EXIT_USAGE)

    def test_helpers(self):
        self.assertEqual(cli._NMAP_NAMES["ftp"], "FTP")
        self.assertEqual(cli._NMAP_NAMES["vnc"], "VNC")
        self.assertEqual(cli.plural(1, "host"), "1 host")
        self.assertEqual(cli.plural(3, "host"), "3 hosts")
        self.assertEqual(cli.slugify("Acme & Sons Ltd."), "Acme_Sons_Ltd")
        self.assertEqual(cli.slugify(""), "audit")
        self.assertEqual(cli.fmt_duration(125), "2 min 5 s")
        findings = [{"severity": "MEDIUM"}]
        self.assertTrue(cli.threshold_met(findings, "medium"))
        self.assertTrue(cli.threshold_met(findings, "low"))
        self.assertFalse(cli.threshold_met(findings, "high"))
        self.assertFalse(cli.threshold_met(findings, "none"))

    def test_baseline_auto(self):
        with tempfile.TemporaryDirectory() as folder:
            def audit(name, meta):
                os.makedirs(os.path.join(folder, name))
                with open(os.path.join(folder, name, "audit.json"), "w", encoding="utf-8") as handle:
                    json.dump({"meta": meta}, handle)
            audit("Acme_2025-12-01_0900", {})
            audit("Acme_2026-01-01_0900", {})
            audit("Acme_2026-01-15_0900", {"interrupted": True})     # newer, but no yardstick
            audit("Acme_2026-02-01_0900", {})
            audit("Acme_Ltd_2026-03-01_0900", {})                      # a different client
            current = os.path.join(folder, "Acme_2026-02-01_0900")
            self.assertTrue(cli.find_baseline(folder, "Acme", current).endswith(
                os.path.join("Acme_2026-01-01_0900", "audit.json")))
            self.assertTrue(cli.find_baseline(folder, "Acme Ltd").endswith(
                os.path.join("Acme_Ltd_2026-03-01_0900", "audit.json")))
            self.assertEqual(cli.find_baseline(folder, "Other"), "")

    def test_prepare_rejects_bad_input(self):
        def code(argv):
            return cli.prepare(cli.Run(cli.parse_args(argv)))
        self.assertEqual(code(["8.8.8.0/24", "--authorized"]), cli.EXIT_USAGE)
        self.assertEqual(code(["10.0.0.0/8", "--authorized"]), cli.EXIT_USAGE)
        self.assertEqual(code(["10.0.0.300", "--authorized"]), cli.EXIT_USAGE)
        self.assertEqual(code(["10.0.0.0/30", "--authorized", "--naming", "("]), cli.EXIT_USAGE)

    def test_one_mode_per_run(self):
        for argv in (["--demo", "--self-test"], ["--regenerate", "x.json", "--demo"], ["--catalog", "--self-test"],
                     ["--demo", "10.0.0.0/24"], ["--regenerate", "x.json", "10.0.0.0/24"]):
            with self.assertRaises(SystemExit, msg=str(argv)):
                cli.parse_args(argv)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "client.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"client": "Acme", "targets": ["10.9.0.0/29"]}, handle)
            self.assertEqual(cli.parse_args(["--config", path]).targets, ["10.9.0.0/29"])
            self.assertEqual(cli.parse_args(["--config", path, "10.9.1.0/29"]).targets, ["10.9.1.0/29"])
            self.assertEqual(cli.parse_args(["--config", path, "--demo"]).targets, [])   # no clash with the file

    def test_audit_files_are_checked_before_use(self):
        with tempfile.TemporaryDirectory() as folder:
            def saved(name, content):
                path = os.path.join(folder, name)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(content)
                return path
            for name, content, reason in (("text.json", "not json", "not a JSON file"),
                                          ("list.json", "[]", "not a NetAudit audit.json"),
                                          ("nohosts.json", '{"meta": {}}', "not a NetAudit audit.json"),
                                          ("badhost.json", '{"meta": {}, "hosts": [5]}', "not a NetAudit audit.json")):
                data, problem = cli.read_audit_file(saved(name, content))
                self.assertIsNone(data, name)
                self.assertIn(reason, problem)
            self.assertIn("does not exist", cli.read_audit_file(os.path.join(folder, "missing.json"))[1])
            # a hand-edited file is repaired rather than crashing the rules later
            saved("audit.json", json.dumps({"meta": {}, "hosts": [
                {"ip": "10.0.0.5", "ports": [{"port": 80}, {"port": "x"}, "junk"]}, {"ip": "10.0.0.6"}]}))
            data, problem = cli.read_audit_file(folder)                     # the results folder is accepted too
            self.assertEqual(problem, "")
            self.assertEqual([r["port"] for r in data["hosts"][0]["ports"]], [80])
            self.assertEqual(data["hosts"][0]["ports"][0]["flags"], [])
            self.assertEqual(data["hosts"][1]["ports"], [])
            self.assertEqual(cli.main(["--regenerate", folder]), cli.EXIT_OK)
            # a wrong --baseline is refused before anything is scanned, not after
            for wrong in (os.path.join(folder, "missing.json"), os.path.join(folder, "list.json")):
                run = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized", "--baseline", wrong,
                                              "--output", os.path.join(folder, "out")]))
                self.assertEqual(cli.prepare(run), cli.EXIT_USAGE)
            good = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized", "--baseline", folder,
                                           "--output", os.path.join(folder, "out")]))
            self.assertEqual(cli.prepare(good), cli.EXIT_OK)
            self.assertEqual(len(good.baseline_data["hosts"]), 2)

    def test_unwritable_output_is_reported_before_the_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            blocker = os.path.join(folder, "file.txt")
            with open(blocker, "w", encoding="utf-8") as handle:
                handle.write("x")
            run = cli.Run(cli.parse_args(["10.9.0.0/29", "--authorized", "--output", os.path.join(blocker, "out")]))
            self.assertEqual(cli.prepare(run), cli.EXIT_USAGE)
            self.assertEqual(cli.main(["--demo", "--output", os.path.join(blocker, "out")]), cli.EXIT_USAGE)

    def test_regenerate_redoes_the_comparison(self):
        from netaudit import demo
        with tempfile.TemporaryDirectory() as folder:
            old = demo.build()
            old["hosts"] = old["hosts"][:-1]
            old_path = os.path.join(folder, "old.json")
            with open(old_path, "w", encoding="utf-8") as handle:
                json.dump(old, handle)
            current = demo.build()
            current["meta"]["baseline"] = old_path
            current["diff"] = {"stale": True}
            path = os.path.join(folder, "audit.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(current, handle)
            self.assertEqual(cli.main(["--regenerate", path]), cli.EXIT_OK)
            with open(path, encoding="utf-8") as handle:
                again = json.load(handle)
            self.assertEqual(len(again["diff"]["new_hosts"]), 1)
            os.remove(old_path)                                              # the baseline is gone: no stale diff
            self.assertEqual(cli.main(["--regenerate", path]), cli.EXIT_OK)
            with open(path, encoding="utf-8") as handle:
                self.assertIsNone(json.load(handle)["diff"])

    def test_interrupted_summary_is_marked_partial(self):
        from netaudit import demo
        audit = demo.build()
        text = report.summary_text(audit)
        self.assertNotIn("PARTIAL AUDIT", text)
        self.assertIn("Longer term", text)
        high = next(f for f in audit["findings"] if f["severity"] == "HIGH" and f["key"] != "flat")
        self.assertIn(high["hosts"][0]["ip"], text)                          # a ticket must say where
        audit["meta"]["interrupted"] = True
        audit["meta"]["warnings"] = ["The audit was interrupted by the operator: the results are partial."]
        text = report.summary_text(audit)
        self.assertIn("PARTIAL AUDIT", text)
        self.assertIn("interrupted by the operator", text)

    def test_a_reporting_failure_keeps_the_collected_data(self):
        async def fake_collect(run):
            run.hosts = {"10.9.0.2": {"ip": "10.9.0.2", "alive_by": ["ping"], "mac": "", "vendor": "",
                                      "mac_random": False, "hostname": "nas"}}
            run.open_ports = {"10.9.0.2": {23, 445}}

        def broken_finalize(run):
            raise RuntimeError("disk full")
        saved = cli.collect, cli.finalize, os.getcwd()
        with tempfile.TemporaryDirectory() as folder:
            os.chdir(folder)
            cli.collect, cli.finalize = fake_collect, broken_finalize
            try:
                code = cli.main(["10.9.0.0/29", "--authorized", "--client", "Acme", "--no-local"])
            finally:
                cli.collect, cli.finalize = saved[0], saved[1]
                os.chdir(saved[2])
            self.assertEqual(code, cli.EXIT_CANCELLED)
            rescue = [name for name in os.listdir(folder) if name.startswith("netaudit_rescue_")]
            self.assertEqual(len(rescue), 1)
            out = os.path.join(folder, "rebuilt")
            # the rescue file has the audit.json shape: --regenerate turns it into a report
            self.assertEqual(cli.main(["--regenerate", os.path.join(folder, rescue[0]), "--output", out]), cli.EXIT_OK)
            with open(os.path.join(out, "audit.json"), encoding="utf-8") as handle:
                rebuilt = json.load(handle)
            self.assertEqual([r["port"] for r in rebuilt["hosts"][0]["ports"]], [23, 445])
            self.assertIn("telnet", {f["key"] for f in rebuilt["findings"]})
            self.assertTrue(rebuilt["limits"])
            self.assertTrue(any("Rescued data" in w for w in rebuilt["meta"]["warnings"]))

    def test_regenerate_roundtrip(self):
        hosts = _sample_hosts()
        audit = {"meta": {"client": "Acme", "started": "2026-11-15 10:00", "targets": ["10.0.0.0/24"]},
                 "hosts": hosts, "findings": [], "positives": [], "limits": ["kept"], "local": None, "diff": None}
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "audit.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(audit, handle)
            self.assertEqual(cli.main(["--regenerate", path, "--fail-on", "high"]), cli.EXIT_FINDINGS)
            with open(path, encoding="utf-8") as handle:
                again = json.load(handle)
            self.assertTrue(any(f["key"] == "smb1" for f in again["findings"]))
            self.assertEqual(again["limits"], ["kept"])
            self.assertTrue(os.path.exists(os.path.join(folder, "report.html")))
            self.assertEqual(cli.main(["--regenerate", os.path.join(folder, "missing.json")]), cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
