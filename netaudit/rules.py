"""Device classification and the rules that turn collected facts into findings."""
from __future__ import annotations

import datetime as dt
import ipaddress
import math
import re
from collections import Counter

from . import knowledge as K
from . import probes

LABELS = {
    "bmc": "Hardware management (BMC)", "firewall": "Firewall/gateway", "network": "Network device",
    "nas": "NAS/storage", "printer": "Printer", "dc": "Domain controller", "server": "Windows server",
    "hypervisor": "Hypervisor", "windows": "Windows PC", "apple": "Apple device",
    "linux": "Linux/appliance", "unix_server": "Server (Linux/Unix)", "camera": "Video surveillance",
    "voip": "VoIP", "ics": "Industrial device",
    "mobile": "Device with randomized MAC", "unknown": "Unidentified",
}
CRITICAL = {"dc", "server", "unix_server", "nas", "bmc", "hypervisor", "firewall", "ics"}
SERVERS = {"dc", "server", "unix_server", "hypervisor"}
ENDPOINTS = {"windows", "apple", "mobile", "unknown"}
INFRA = {"bmc", "firewall", "network", "nas", "printer", "hypervisor", "camera"}
SENSITIVE_APPS = ("MailStore", "phpMyAdmin", "Veeam", "Webmin", "Portainer", "Jenkins", "GitLab",
                  "Zabbix", "Grafana", "Nextcloud", "Outlook Web App")
_VENDOR_HINTS = [("synology", "nas"), ("qnap", "nas"), ("konica", "printer"), ("kyocera", "printer"),
                 ("brother", "printer"), ("lexmark", "printer"), ("ricoh", "printer"), ("epson", "printer"),
                 ("d-link", "network"), ("ubiquiti", "network"), ("tp-link", "network"),
                 ("netgear", "network"), ("aruba", "network"),   # Cisco is left out: phones, cameras, APs
                 ("mikrotik", "firewall"), ("fortinet", "firewall"), ("apple", "apple"),
                 ("hikvision", "camera"), ("dahua", "camera"), ("yealink", "voip"), ("grandstream", "voip")]

SEVERITIES = ["HIGH", "MEDIUM", "LOW"]
WEIGHTS = {"HIGH": 10, "MEDIUM": 4, "LOW": 1}
EXPOSURE_BANDS = [(75, "Severe"), (50, "Elevated"), (25, "Limited"), (0, "Minimal")]
WHEN_LABEL = {"now": "This week", "30d": "Within 30 days", "structural": "Longer term"}
RDP_TEXT = {
    "nla": "NLA (CredSSP) required",
    "tls_only": "TLS required but NLA not enforced",
    "standard": "standard RDP security accepted: NLA not enforced",
    "legacy": "legacy RDP security (old server, no NLA)",
}
PORT_BASED = "Attribution based on the port number alone: confirm on the host."


def _c(severity, title, risk, action, when, attack=""):
    return {"severity": severity, "title": title, "risk": risk, "action": action, "when": when,
            "attack": attack}


# key -> severity, title, risk, action, when, MITRE ATT&CK technique
CATALOG = {
    "flat": _c("HIGH", "Flat network: critical systems and workstations share one segment",
               "A single compromised device (phishing, an infected personal laptop) has direct network access "
               "to servers, storage and management interfaces. This is the typical ransomware propagation "
               "scenario.",
               "Separate servers, workstations, management (BMC, switches, firewall), printers and guest/BYOD "
               "into VLANs and allow only the required flows between them.", "structural", "T1021"),
    "smb_signing": _c("HIGH", "SMB signing not required",
                      "It enables NTLM relay: anyone on the network can capture an authentication (for example via "
                      "LLMNR/NetBIOS poisoning) and relay it to a host that does not require signing, gaining "
                      "access with the victim's privileges.",
                      "Enable the Group Policy 'Microsoft network server: Digitally sign communications (always)' on "
                      "servers and clients and require signing on NAS and Samba too. Check first for old copiers "
                      "that scan to a shared folder: devices that cannot sign will stop working. Also turn off "
                      "LLMNR (policy 'Turn off multicast name resolution') and NetBIOS over TCP/IP (per adapter, "
                      "or for all DHCP clients with the Microsoft vendor option 001 'Microsoft Disable Netbios "
                      "Option').", "now", "T1557.001"),
    "smb1": _c("HIGH", "SMBv1 enabled",
               "SMBv1 is the protocol exploited by WannaCry and NotPetya and has no protection against tampering "
               "or downgrade.",
               "Find out who still uses it first (Set-SmbServerConfiguration -AuditSmb1Access $true, then event "
               "3000 in the SMBServer audit log): old copiers and scanners may depend on it. Then disable it: "
               "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol on Windows 8.1 / Server 2012 R2 "
               "and later (a restart is needed), minimum protocol SMB2 on NAS and Samba.", "now", "T1210"),
    "os_eol": _c("HIGH", "Operating system out of support",
                 "It no longer receives security updates: every new vulnerability stays open.",
                 "Upgrade (on Windows 11, installing the current feature update is enough) or replace. Isolate "
                 "in a dedicated VLAN whatever cannot be upgraded, and verify the edition and any extended "
                 "support program (ESU/LTSC).", "30d", "T1210"),
    "rdp_no_nla": _c("HIGH", "Remote Desktop without mandatory NLA",
                     "Without Network Level Authentication a full logon session is offered to anyone before they "
                     "authenticate, which exposes the host to pre-authentication vulnerabilities and makes "
                     "password guessing cheaper.",
                     "Enable the Group Policy 'Require user authentication for remote connections by using "
                     "Network Level Authentication' (Remote Desktop Session Host > Security), or the matching "
                     "checkbox in the Remote Desktop settings of the host.", "now", "T1021.001"),
    "vnc_noauth": _c("HIGH", "VNC without authentication",
                     "Anyone on the network can view and control the screen.",
                     "Disable VNC or enforce strong authentication and restrict it to administrative "
                     "workstations.", "now", "T1021.005"),
    "service_noauth": _c("HIGH", "Service accessible without authentication",
                         "Data or administrative functions can be read and changed by anyone on the network.",
                         "Enable authentication and bind the service to localhost or to the hosts that need it.",
                         "now", "T1210"),
    "telnet": _c("HIGH", "Telnet enabled",
                 "Credentials and commands travel in clear text.",
                 "Disable Telnet and use SSH.", "now", "T1040"),
    "db_exposed": _c("HIGH", "Database reachable from the network",
                     "Anyone on the network can attempt to log in to the database or attack it directly.",
                     "Restrict the port to the application servers, or to the workstations that connect to it "
                     "directly if the application works that way; review accounts and updates.", "now", "T1210"),
    "bmc": _c("HIGH", "Hardware management interface on the user network",
              "iDRAC, iLO and IPMI give full control of the server (console, power, virtual media): anyone who "
              "reaches it controls the host and everything it runs.",
              "Move it to a management VLAN reachable only from administrative workstations; update the "
              "firmware; make sure the password is not the factory default.", "now", "T1078.001"),
    "industrial": _c("HIGH", "Industrial control protocol reachable from the user network",
                     "Modbus has no authentication and many S7 controllers run without access protection: "
                     "anyone who reaches the port may be able to read and write process values.",
                     "Isolate PLCs and controllers in a dedicated network segment behind a firewall that allows "
                     "only the engineering stations.", "now"),
    "remote_tool_server": _c("HIGH", "Third-party remote access software on servers",
                             "It is an entry point that bypasses firewall and VPN: if the account or password "
                             "is compromised the intruder lands directly on the servers. " + PORT_BASED,
                             "Confirm which program is listening. If it is the approved tool of your IT "
                             "provider, verify two-factor authentication and the allow-list of accounts, disable "
                             "incoming LAN connections and remove it from domain controllers; otherwise "
                             "uninstall it.", "now", "T1219"),
    "storage": _c("HIGH", "Backup and block-storage services reachable from the user network",
                  "iSCSI, NFS, rsync and backup-vault ports usually carry backups or server disks: ransomware "
                  "started on a client can encrypt or delete them together with production data.",
                  "Restrict these ports to the servers that need them (ordinary file sharing over SMB can "
                  "stay); use CHAP and an initiator allow-list on iSCSI; keep immutable snapshots and an "
                  "offline or off-site copy.",
                  "30d", "T1490"),
    "unmanaged": _c("HIGH", "Devices that do not look managed on the user network",
                    "Devices with no control over patching and antivirus have direct access to servers and "
                    "storage.",
                    "Identify the owners; move them to an isolated guest/BYOD network; consider 802.1X or "
                    "blocking unknown devices.", "now", "T1200"),
    "local_firewall": _c("HIGH", "Windows Firewall disabled on the scanning workstation",
                         "The workstation accepts incoming connections unfiltered.",
                         "Re-enable the firewall on every profile.", "now", "T1562.004"),
    "local_defender": _c("HIGH", "No real-time antivirus active on the scanning workstation",
                         "Malware is not blocked on execution.",
                         "Re-enable real-time protection or check the third-party antivirus.", "now",
                         "T1562.001"),
    "local_uac": _c("HIGH", "User Account Control disabled on the scanning workstation",
                    "Every program started by an administrator runs with full privileges without a prompt.",
                    "Set EnableLUA back to 1 (Group Policy 'User Account Control: Run all administrators in "
                    "Admin Approval Mode').", "now", "T1548.002"),
    "local_wdigest": _c("HIGH", "WDigest stores clear-text credentials on the scanning workstation",
                        "With UseLogonCredential enabled, passwords of logged-on users sit in memory in clear "
                        "text and can be dumped.",
                        "Set UseLogonCredential to 0 under the WDigest registry key.", "now", "T1003.001"),
    "os_check": _c("MEDIUM", "Windows 10: out of support unless extended, to be verified",
                   "Windows 10 stopped receiving security updates in 10/2025 unless the host is enrolled in ESU "
                   "or runs an LTSC edition. This cannot be determined from the network.",
                   "Verify the edition and ESU enrollment; otherwise upgrade to Windows 11 or replace.", "30d",
                   "T1210"),
    "unidentified": _c("MEDIUM", "Unidentified devices on the network",
                       "A device that answers on the network but gives nothing away cannot be matched to the "
                       "inventory: it may be a hardened PC, or something that should not be there.",
                       "Trace each one from its switch port or DHCP lease, then add it to the inventory or "
                       "remove it.", "30d", "T1200"),
    "snmp_public": _c("MEDIUM", "SNMP with the default community 'public'",
                      "Anyone on the network can read the device configuration, interfaces and tables.",
                      "Disable SNMP v1/v2c or change the community, preferring SNMPv3 and restricting the "
                      "sources. Check first which print queues and monitoring tools rely on the current community.",
                      "30d", "T1602.001"),
    "http_admin": _c("MEDIUM", "Administration interface over HTTP only",
                     "The administration password travels in clear text on the network.",
                     "Enable HTTPS where available, update the firmware, change factory passwords and move "
                     "management to a dedicated VLAN.", "30d", "T1040"),
    "basic_auth_plain": _c("MEDIUM", "HTTP Basic authentication without encryption",
                           "Every request carries the user name and password in a trivially decodable form.",
                           "Serve it over HTTPS where the device or application supports it; otherwise keep it "
                           "on a network segment that only its administrators can reach.",
                           "30d", "T1040"),
    "cert_expired": _c("MEDIUM", "Expired certificate",
                       "Users get used to clicking through browser warnings and can no longer spot an "
                       "interception attack.",
                       "Renew the certificate and restore automatic renewal.", "now", "T1557"),
    "admin_exposure": _c("MEDIUM", "Administrative access to servers reachable from the user network",
                         "RDP, WinRM and SSH on servers are reachable from the user network: a compromised "
                         "client can attempt to log in directly.",
                         "Restrict administration ports to IT workstations with the local firewall or "
                         "inter-VLAN rules.", "30d", "T1021"),
    "mgmt_ui": _c("MEDIUM", "Firewall, switch and NAS management reachable from the user network",
                  "The administration interfaces of the infrastructure are exposed to every connected device.",
                  "Restrict them to IT workstations or a management VLAN; enable two-factor authentication "
                  "where available.", "30d", "T1021"),
    "sensitive_app": _c("MEDIUM", "Applications holding sensitive data reachable from the user network",
                        "Archives, consoles and panels with confidential data are reachable from every user "
                        "device.",
                        "Check version and updates, restrict access to the users concerned and install valid "
                        "certificates.", "30d", "T1213"),
    "vnc_open": _c("MEDIUM", "VNC remote access or screen sharing enabled",
                   "VNC often relies on weak passwords and no encryption.",
                   "Disable it when not needed; otherwise restrict it to administrative workstations.", "30d",
                   "T1021.005"),
    "ftp": _c("MEDIUM", "FTP in clear text",
              "Credentials and files travel unencrypted.",
              "Replace it with SFTP or FTPS.", "30d", "T1040"),
    "netdata": _c("MEDIUM", "Netdata monitoring accessible without authentication",
                  "It exposes processes, users, connections and system metrics to anyone on the network.",
                  "Restrict the port to IT workstations or disable the service.", "30d", "T1082"),
    "outdated_sw": _c("MEDIUM", "End-of-life server software",
                      "The version announced by the service no longer receives security fixes.",
                      "Update the software or the device firmware; if that is not possible, restrict access "
                      "to the service.", "30d", "T1210"),
    "ssh_v1": _c("MEDIUM", "SSH protocol 1 accepted",
                 "SSH-1 has known cryptographic weaknesses that allow session interception.",
                 "Disable protocol 1 and update the SSH server.", "30d", "T1557"),
    "ssh_old": _c("MEDIUM", "Outdated SSH version",
                  "Old releases have known vulnerabilities and weak algorithms.",
                  "Update the system or the firmware.", "30d", "T1210"),
    "upnp_igd": _c("MEDIUM", "UPnP port mapping enabled on the gateway",
                   "Any device on the network, including malware, can open ports from the Internet towards "
                   "internal hosts without authentication.",
                   "Disable UPnP/NAT-PMP on the firewall or router.", "30d"),
    "dev_services": _c("MEDIUM", "Development services exposed by workstations",
                       "Development servers and APIs are listening on every interface, often without "
                       "authentication.",
                       "Bind them to localhost or to the clients that need them and make sure they require "
                       "authentication.", "30d", "T1190"),
    "printer": _c("LOW", "Printers on the user network: firmware and administrator password to verify",
                  "Printers keep documents and credentials (address books, LDAP, SMTP) and are rarely updated. "
                  "Nothing was found wrong with them: this is a reminder to check what the audit cannot see.",
                  "Check the firmware and that the administrator password is not the factory default; "
                  "disable the protocols nobody uses (LPD, RAW, SLP).", "30d"),
    "wide_surface": _c("MEDIUM", "Very large exposed surface",
                       "Every listening service is a potential entry point.",
                       "Disable unneeded services and packages and restrict the rest to the sources that use "
                       "them.", "30d", "T1046"),
    "remote_tool_client": _c("MEDIUM", "Third-party remote access software on workstations",
                             "Unless it is the approved corporate tool, it is an uncontrolled way in. "
                             + PORT_BASED,
                             "Check that it is the approved tool, with two-factor authentication and incoming "
                             "LAN connections disabled.", "30d", "T1219"),
    "local_exposure": _c("MEDIUM", "The scanning workstation exposes RDP or SMB on public networks too",
                         "On an external network (hotel, customer site) Remote Desktop and shares stay "
                         "reachable.",
                         "Limit the RDP and SMB firewall rules to the Domain profile (the Private profile on a "
                         "PC that is not in a domain).", "30d", "T1021.001"),
    "local_llmnr": _c("MEDIUM", "LLMNR or NetBIOS enabled on the scanning workstation",
                      "They allow name-resolution poisoning and the capture of authentications on the network.",
                      "Turn off LLMNR with the Group Policy 'Turn off multicast name resolution' and NetBIOS "
                      "over TCP/IP per adapter, or for all DHCP clients with the Microsoft vendor option 001 "
                      "'Microsoft Disable Netbios Option'.", "now", "T1557.001"),
    "local_updates": _c("MEDIUM", "No Windows update installed recently on the scanning workstation",
                        "Missing monthly updates leave known vulnerabilities open.",
                        "Install pending updates and check the update policy.", "now", "T1210"),
    "local_av_outdated": _c("MEDIUM", "Antivirus definitions out of date on the scanning workstation",
                            "Recent malware is not recognized.",
                            "Update the antivirus and check why updates are failing.", "now", "T1562.001"),
    "local_bitlocker": _c("MEDIUM", "System drive not encrypted on the scanning workstation (a laptop)",
                          "If the laptop is lost or stolen, its data and cached credentials are readable.",
                          "Enable BitLocker on the system drive and escrow the recovery key.", "30d"),
    "local_guest": _c("MEDIUM", "Guest account enabled on the scanning workstation",
                      "It gives anonymous access to the machine.",
                      "Disable the built-in Guest account.", "now", "T1078.001"),
    "os_warn": _c("LOW", "Operating system close to end of support",
                  "In a few months it will stop receiving security updates.",
                  "Plan the migration.", "structural"),
    "cert_expiring": _c("LOW", "Certificate expiring within 30 days",
                        "When it expires, warnings appear and some services stop working.",
                        "Check that automatic renewal works, or renew it by hand if it is self-signed.", "30d"),
    "cert_selfsigned": _c("LOW", "Self-signed or default certificates on management interfaces",
                          "They do not allow the identity of the device to be verified.",
                          "Install certificates issued by an internal or public CA.", "structural", "T1557"),
    "tls_legacy": _c("LOW", "TLS 1.0 or 1.1 still accepted",
                     "These protocols are deprecated and have known weaknesses.",
                     "Disable them and keep TLS 1.2 and 1.3 only.", "structural", "T1557"),
    "dir_listing": _c("LOW", "Web directory listing enabled",
                      "The web server shows the list of files in a folder, which may reveal backups or "
                      "configuration files.",
                      "Disable directory browsing on the web server.", "30d", "T1083"),
    "ad_level": _c("LOW", "Old Active Directory functional level",
                   "Functional levels of Windows Server 2012 R2 or earlier lack recent security features and "
                   "suggest legacy domain controllers.",
                   "Plan to raise the domain and forest functional level after retiring old domain "
                   "controllers.", "structural"),
    "local_lsa": _c("LOW", "LSA protection not enabled on the scanning workstation",
                    "Without RunAsPPL, tools running as administrator can read credentials from LSASS memory.",
                    "Enable LSA protection (RunAsPPL) by Group Policy after testing compatibility.",
                    "structural", "T1003.001"),
    "consumer_sw": _c("LOW", "Non-business software listening on the network",
                      "It increases the exposed surface. " + PORT_BASED,
                      "Consider a policy on permitted software.", "structural"),
    "dns_mismatch": _c("LOW", "DNS records out of sync",
                       "The DNS name does not match the real host name: inventory and logs become unreliable.",
                       "Enable DNS scavenging and clean up stale records.", "structural"),
}


def catalog_markdown() -> str:
    """Every finding the tool can raise, as a Markdown reference document."""
    lines = ["# NetAudit findings reference", "",
             "Every finding NetAudit can raise, grouped by severity. Generated with `python -m netaudit --catalog`.",
             ""]
    for severity in SEVERITIES:
        entries = [(key, entry) for key, entry in CATALOG.items() if entry["severity"] == severity]
        lines += [f"## {severity.capitalize()} ({len(entries)})", ""]
        for key, entry in entries:
            lines += [f"### {entry['title']}", "",
                      f"- **Key:** `{key}`",
                      f"- **Timeframe:** {WHEN_LABEL[entry['when']]}"
                      + (f"\n- **MITRE ATT&CK:** {entry['attack']}" if entry["attack"] else ""),
                      f"- **Risk:** {entry['risk']}",
                      f"- **Recommended action:** {entry['action']}", ""]
    return "\n".join(lines)


def short_name(name: str) -> str:
    return name.split(".")[0] if name else ""


def display_name(host: dict) -> str:
    return short_name(host.get("name") or host.get("hostname") or "")


# --------------------------------------------------------------------------- classification

def annotate(host: dict) -> None:
    """Fill the SMB, RDP and LDAP port records with readable text from the structured results."""
    by_port = {rec["port"]: rec for rec in host.get("ports", [])}
    smb = host.get("smb") or {}
    if 445 in by_port and smb.get("smb2") and smb.get("status") == 0:
        signing = "signing required" if smb.get("signing_required") else "signing NOT required"
        by_port[445].update(source="protocol", info="",
                            product=f"SMB {smb.get('dialect', '?')}, {signing}"
                            + (", SMBv1 enabled" if smb.get("smb1") else ""))
    rdp = host.get("rdp") or {}
    if 3389 in by_port and rdp:
        code = rdp.get("code") or {True: "nla", False: "standard"}.get(rdp.get("nla_required"), "")
        text = RDP_TEXT.get(code, f"security negotiation refused (code {code[8:]})"
                            if code.startswith("refused_") else "")
        by_port[3389].update(source="protocol", info=text)
    ldap = host.get("ldap") or {}
    if 389 in by_port and ldap:
        parts = [ldap.get("naming_context", "")]
        if "domain_level" in ldap:
            parts.append("functional level " + K.AD_FUNCTIONAL_LEVELS.get(ldap["domain_level"],
                                                                          str(ldap["domain_level"])))
        by_port[389].update(source="protocol", product=ldap.get("vendor", "") or by_port[389].get("product", ""),
                            info=", ".join(p for p in parts if p))


def classify(host: dict, server_regex=None) -> None:
    """Complete the host with name, category, type and operating system."""
    annotate(host)
    ports = {rec["port"] for rec in host.get("ports", [])}
    kinds = [rec["kind"] for rec in host.get("ports", []) if rec.get("kind")]
    products = [rec["product"] for rec in host.get("ports", []) if rec.get("kind") and rec.get("product")]
    smb = host.get("smb") or {}
    ntlm = smb.get("ntlm") or {}
    nbns = host.get("nbns") or {}
    ldap = host.get("ldap") or {}
    for text in (host.get("snmp") or "", (host.get("ssdp") or {}).get("server", "")):
        if text:
            kind, product = probes.fingerprint(text)
            if kind:
                kinds.append(kind)
                products.append(product)

    host["name"] = (ntlm.get("dns_name") or ldap.get("dns_host") or nbns.get("name")
                    or host.get("hostname") or "")
    host["domain"] = ntlm.get("dns_domain") or ""
    build = ntlm.get("build") or 0
    if build >= 2600:
        # Windows proved its identity over SMB: a web page it hosts (a UniFi console, a printer
        # portal) says what it runs, not what it is
        kinds = []
    is_windows = build >= 2600 or (135 in ports and bool(ports & {445, 3389}))
    host["os"], host["os_state"], host["os_note"] = "", "", ""
    if build >= 2600:
        host["os"], host["os_state"], host["os_note"] = K.windows_product(build)
    elif is_windows:
        host["os"] = "Windows"
    elif smb.get("smb2"):
        host["os"] = "Samba or compatible"

    vendor_kind = ""
    vendor = (host.get("vendor") or "").lower()
    for needle, kind in _VENDOR_HINTS:
        if needle in vendor:
            vendor_kind = kind
            break
    name = short_name(host["name"] or host.get("hostname") or "")
    named_server = bool(server_regex and name and server_regex.search(name))

    # Order matters. What a machine proves about itself (Windows over SMB, a management-board page)
    # outranks what merely runs on it or where it sits (default gateway, a print port, a vendor prefix).
    unix_like = not is_windows and (bool(smb.get("smb2")) or 22 in ports)
    if "bmc" in kinds or (623 in ports and not is_windows):
        category = "bmc"
    elif is_windows:
        if {88, 389} <= ports or ports & {3268, 9389} or "dc_level" in ldap:
            category = "dc"
        elif ports & {5985, 5986} or build == 20348 or named_server:
            category = "server"
        else:
            category = "windows"
    elif "firewall" in kinds or host.get("is_gateway"):
        category = "firewall"
    elif "hypervisor" in kinds:
        category = "hypervisor"
    elif "nas" in kinds or vendor_kind == "nas":
        category = "nas"
    elif "printer" in kinds or vendor_kind == "printer" or (ports & {9100, 515} and not unix_like):
        category = "printer"   # a print port on a Linux or Samba host is a print queue, not a printer
    elif ports & set(K.INDUSTRIAL_PORTS):
        category = "ics"
    elif "camera" in kinds or vendor_kind == "camera":
        category = "camera"
    elif "voip" in kinds or vendor_kind == "voip":
        category = "voip"
    elif "network" in kinds or vendor_kind in ("network", "firewall"):
        category = "network"
    elif "apple" in kinds or vendor_kind == "apple" or 62078 in ports or (7000 in ports and ports & {5000, 5900}):
        category = "apple"
    elif unix_like:
        # a server by name (--server-regex) or because it serves a database
        category = "unix_server" if named_server or ports & set(K.DB_PORTS) else "linux"
    elif not ports and host.get("mac_random"):
        category = "mobile"
    else:
        category = "unknown"

    host["category"] = category
    label = LABELS[category]
    product = min((p for p in products if p), key=probes.product_rank, default="")
    host["type"] = f"{label}: {product}" if product else label
    roles = []
    if 2179 in ports and is_windows:
        roles.append("Hyper-V")
    if host.get("is_gateway"):
        roles.append("default gateway")
    if host.get("is_self"):
        roles.append("this workstation")
    host["roles"] = roles


def link_multihomed(hosts: list[dict]) -> None:
    """Note devices that appear on more than one address (same name, or same port set on Apple devices)."""
    groups: dict[str, list[dict]] = {}
    for host in hosts:
        key = display_name(host).lower()
        if key and key != "localhost":
            groups.setdefault(key, []).append(host)
    for members in groups.values():
        if len(members) > 1:
            for host in members:
                others = [h["ip"] for h in members if h is not host]
                shown = ", ".join(others[:4]) + (f" and {len(others) - 4} more" if len(others) > 4 else "")
                host.setdefault("roles", []).append(f"also at {shown}")


def infer_domain(hosts: list[dict]) -> str:
    """The Active Directory domain most Windows hosts belong to ('' when there is no clear one).
    Only real Windows machines count: a Samba box reports its DNS suffix (fritz.box, lan) as a domain."""
    counts = Counter(h["domain"].lower() for h in hosts if h.get("domain")
                     and ((h.get("smb") or {}).get("ntlm") or {}).get("build", 0) >= 2600
                     and h["domain"].lower() != display_name(h).lower())
    if not counts:
        return ""
    domain, count = counts.most_common(1)[0]
    return domain if count >= 2 else ""


# --------------------------------------------------------------------------- findings

def _in_network(ip: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _days_between(date_text: str, reference: str = ""):
    """Days from date_text to the reference date (the day of the audit; today when not given)."""
    try:
        end = dt.date.fromisoformat(reference[:10]) if reference else dt.date.today()
        return (end - dt.date.fromisoformat(date_text)).days
    except (ValueError, TypeError):
        return None


def _expiry_warning_days(tls: dict) -> int:
    """Warn 30 days ahead, but never earlier than the last third of the certificate's life:
    a healthy 6-day or 45-day auto-renewed certificate is not 'about to expire' all the time."""
    try:
        life = (dt.date.fromisoformat(tls["not_after"]) - dt.date.fromisoformat(tls["not_before"])).days
    except (KeyError, ValueError, TypeError):
        return 30
    return max(1, min(30, life // 3))


def _ssh_is_old(product: str) -> bool:
    version = probes.ssh_version(product)
    if version:
        return version < (7, 4)
    return bool(re.search(r"dropbear_(0\.|201[0-7])", product, re.I))


def _local_hits(local: dict, add_local, reference_date: str = "") -> None:
    off = [p["name"] for p in local.get("firewall", []) if not p.get("enabled")]
    other_firewall = [p.get("name", "?") for p in local.get("firewall_products") or [] if p.get("active")]
    if off and not other_firewall:  # a third-party firewall switches the Windows one off on purpose
        add_local("local_firewall", "disabled profiles: " + ", ".join(off))
    antivirus = local.get("antivirus") or []
    if antivirus:
        # Security Center list: one active product is enough (Defender turns itself off next to another AV)
        active = [item for item in antivirus if item.get("active")]
        if not active:
            add_local("local_defender", "no active product among: "
                      + ", ".join(item.get("name", "?") for item in antivirus))
        elif not any(item.get("updated") for item in active):
            add_local("local_av_outdated", ", ".join(item.get("name", "?") for item in active))
    elif local.get("defender_realtime") is False and "passive" not in str(local.get("defender_mode") or "").lower():
        # passive mode means another antivirus is in charge (the usual case on servers)
        add_local("local_defender", "Microsoft Defender real-time protection is off "
                                    "(check whether a third-party antivirus is installed)")
    if local.get("uac_enabled") is False:
        add_local("local_uac", "EnableLUA = 0")
    if local.get("wdigest_cleartext"):
        add_local("local_wdigest", "UseLogonCredential = 1")
    if local.get("smb1"):
        add_local("smb1", "SMBv1 enabled in the local SMB server configuration")
    if local.get("smb_signing_required") is False:
        add_local("smb_signing", "RequireSecuritySignature = False")
    if local.get("rdp_enabled") and not local.get("rdp_nla"):
        add_local("rdp_no_nla", "Remote Desktop enabled without NLA")
    exposed = []
    for rule in local.get("rules", []):
        profile = rule.get("profile", "")
        if "Public" in profile or profile in ("Any", "0", ""):
            if "3389" in rule.get("port", "") and not local.get("rdp_enabled"):
                continue
            exposed.append(f"port {rule.get('port')} ({rule.get('name')}): profiles {profile or 'all'}")
    if exposed:
        add_local("local_exposure", "; ".join(exposed[:4]))
    notes = []
    if not local.get("llmnr_disabled"):
        notes.append("LLMNR not disabled by policy")
    if any(item.get("option") != 2 for item in local.get("netbios", [])):
        notes.append("NetBIOS over TCP/IP not disabled")
    if notes:
        add_local("local_llmnr", "; ".join(notes))
    age = _days_between(local.get("last_update", ""), reference_date)
    if age is not None and age > 45:
        add_local("local_updates", f"last update installed on {local['last_update']} "
                                   f"({age} days before the audit)")
    if local.get("laptop") and local.get("bitlocker") == 2:
        add_local("local_bitlocker", "BitLocker protection is off on the system drive")
    if local.get("guest_enabled"):
        add_local("local_guest", "built-in Guest account is enabled")
    if local.get("lsa_protection") is False:
        add_local("local_lsa", "RunAsPPL not set")


def build_findings(hosts: list[dict], networks: list[str], local: dict | None,
                   naming=None, expected_domain: str = "", reference_date: str = "") -> list[dict]:
    """reference_date (YYYY-MM-DD) is the day of the audit: ages are measured against it, so that
    regenerating a report months later does not invent 'no recent update' findings."""
    hits: dict[str, list[dict]] = {}

    def add(key, host, evidence):
        hits.setdefault(key, []).append({"ip": host["ip"], "name": display_name(host), "evidence": evidence})

    domain = (expected_domain or infer_domain(hosts)).lower()

    for host in hosts:
        # the operating system is judged for every host, the scanning workstation included
        if host.get("os_state") == "eol":
            add("os_eol", host, f"{host.get('os')}: {host.get('os_note')}")
        elif host.get("os_state") == "verify":
            add("os_check", host, f"{host.get('os')}")
        elif host.get("os_state") == "warning":
            add("os_warn", host, f"{host.get('os')}: {host.get('os_note')}")
        if host.get("is_self"):
            continue  # its services are judged by the local checks, which are more precise
        records = host.get("ports", [])
        ports = {rec["port"] for rec in records}
        category = host.get("category", "unknown")
        smb = host.get("smb") or {}
        rdp = host.get("rdp") or {}
        ldap = host.get("ldap") or {}
        ssdp = host.get("ssdp") or {}
        name = display_name(host)

        if smb.get("smb1"):
            add("smb1", host, "accepts the NT LM 0.12 dialect (SMBv1)")
        if smb.get("smb2") and smb.get("status") == 0 and smb.get("signing_required") is False:
            state = "enabled but not required" if smb.get("signing_enabled", True) else "not enabled"
            add("smb_signing", host, f"SMB {smb.get('dialect', '?')}: signing {state}")
        if rdp.get("nla_required") is False:
            add("rdp_no_nla", host, RDP_TEXT.get(rdp.get("code", "standard"), "NLA not enforced"))

        has_https = any(rec["service"] == "HTTPS" or rec.get("tls") for rec in records)
        plain_http = [rec["port"] for rec in records if rec["service"] == "HTTP"]
        for rec in records:
            port, flags = rec["port"], rec.get("flags", [])
            service = rec.get("service", "")
            by_number = rec.get("source") in ("", "port")  # nothing answered: only the port number speaks
            # the report promises that such evidence is marked, so that it is confirmed before acting
            label = f"port {port}" + (" (by port number)" if by_number else "")
            if "vnc_noauth" in flags:
                add("vnc_noauth", host, f"{label}: the server offers security type 'None'")
            elif service == "VNC" or (port in (5900, 5901) and rec.get("source") in ("", "port")):
                add("vnc_open", host, f"{label}: {rec.get('product') or 'VNC'}")
            noauth = [f for f in flags if f in ("redis_noauth", "elastic_open", "docker_api")]
            if noauth:
                names = {"redis_noauth": "Redis answers without a password",
                         "elastic_open": "Elasticsearch answers without authentication",
                         "docker_api": "unencrypted Docker API without authentication"}
                add("service_noauth", host, f"{label}: {names[noauth[0]]}")
            elif service == "MySQL/MariaDB" or (port in K.DB_PORTS and service not in ("HTTP", "HTTPS", "SSH")):
                # a web server that happens to listen on 9200 or 5984 is not a database
                add("db_exposed", host, f"{label}: {rec.get('product') or K.DB_PORTS.get(port, service)}")
            if "netdata" in flags:
                add("netdata", host, label + (f": {rec['product']}" if rec.get("product") else ""))
            if "tls_legacy" in flags:
                add("tls_legacy", host, f"{label}: accepts {rec.get('tls', {}).get('legacy', 'TLS 1.0/1.1')}")
            if "basic_auth_plain" in flags:
                add("basic_auth_plain", host, f"{label}: {rec.get('http', {}).get('auth', 'Basic')}")
            if "dir_listing" in flags:
                add("dir_listing", host, f"{label}: {rec.get('info', '')}")
            if "ssh_v1" in flags:
                add("ssh_v1", host, f"{label}: {rec.get('product')}")
            if rec.get("outdated"):
                add("outdated_sw", host, f"{label}: {rec['outdated']} - {rec.get('product', '')}")
            if port == 23 or service == "Telnet":
                add("telnet", host, label)
            if service == "FTP":
                add("ftp", host, f"{label}: {rec.get('product', '')}")
            if port in K.INDUSTRIAL_PORTS:
                add("industrial", host, f"{label}: {K.INDUSTRIAL_PORTS[port]}")
            if port in K.REMOTE_TOOLS and by_number and category in SERVERS | ENDPOINTS | {"linux"}:
                key = "remote_tool_server" if category in SERVERS else "remote_tool_client"
                add(key, host, f"{label}: {K.REMOTE_TOOLS[port]}")
            if port in K.CONSUMER_SOFTWARE and by_number:
                add("consumer_sw", host, f"{label}: {K.CONSUMER_SOFTWARE[port]}")
            tls = rec.get("tls") or {}
            days = tls.get("days_left")
            if days is not None and days < 0:
                add("cert_expired", host, f"{label}: '{tls.get('cn', '?')}' expired on {tls.get('not_after')}")
            elif days is not None and days <= _expiry_warning_days(tls):
                add("cert_expiring", host, f"{label}: '{tls.get('cn', '?')}' expires on {tls.get('not_after')}")
            if tls.get("self_signed") and category in INFRA:
                add("cert_selfsigned", host, f"{label}: '{tls.get('cn', '?')}'")
            if service == "SSH" and _ssh_is_old(rec.get("product", "")):
                add("ssh_old", host, f"{label}: {rec.get('product')}")
            if (rec.get("kind") == "app" and rec.get("http")
                    and any(app in rec.get("product", "") for app in SENSITIVE_APPS)):
                add("sensitive_app", host, f"{label}: {rec.get('product')}"
                    + (f" - {rec['http']['title']}" if rec["http"].get("title") else ""))
            if "dev_server" in flags and not rec.get("kind") and category in ("windows", "apple", "linux", "unknown"):
                add("dev_services", host, f"{label}: {rec.get('product')}")

        if category in INFRA and plain_http and not has_https:
            add("http_admin", host, "web interface on port" + ("s " if len(plain_http) > 1 else " ")
                + ", ".join(map(str, plain_http)) + ", no HTTPS port")
        if category == "bmc":
            add("bmc", host, "open ports: " + ", ".join(map(str, sorted(ports))))
        admin = sorted(ports & set(K.ADMIN_PORTS))
        if category in SERVERS and admin:
            add("admin_exposure", host, ", ".join(f"{K.ADMIN_PORTS[p]} ({p})" for p in admin))
        if category in ("firewall", "network", "nas"):
            ui = [rec["port"] for rec in records if rec["service"] in ("HTTP", "HTTPS", "SSH", "Telnet")]
            if ui:
                add("mgmt_ui", host, "management ports: " + ", ".join(map(str, ui)))
        # Serving files over SMB is what a NAS is for. The finding is about backup targets and block
        # or bulk storage (iSCSI, NFS, rsync, backup vaults) answering to the whole user network.
        storage = sorted(ports & {3260, 6281, 5510, 2049, 873})
        if storage:
            add("storage", host, ", ".join(f"{K.STORAGE_PORTS[p]} ({p})" for p in storage))
        if category == "printer" and ports:
            add("printer", host, "open ports: " + ", ".join(map(str, sorted(ports))))
        static = [p for p in ports if p < 49152]
        if len(static) >= 20 and category != "dc":
            add("wide_surface", host, f"{len(static)} open TCP ports")
        if host.get("snmp"):
            add("snmp_public", host, host["snmp"][:120])
        if category == "firewall" and any("InternetGatewayDevice" in t or "WANIPConnection" in t
                                          or "WANPPPConnection" in t for t in ssdp.get("types", [])):
            add("upnp_igd", host, "answers SSDP as an Internet Gateway Device"
                + (f" ({ssdp['server']})" if ssdp.get("server") else ""))
        level = ldap.get("domain_level")
        # only for Windows domain controllers: a Samba AD DC reports 2008 R2 by design
        if level is not None and level <= 6 and "dc_level" in ldap and str(host.get("os", "")).startswith("Windows"):
            add("ad_level", host, "domain functional level: Windows Server "
                + K.AD_FUNCTIONAL_LEVELS.get(level, str(level)))
        real = short_name((smb.get("ntlm") or {}).get("dns_name") or (smb.get("ntlm") or {}).get("netbios_name") or "")
        dns = short_name(host.get("hostname") or "")
        if real and dns and dns.lower() != "localhost" and real.lower() != dns.lower():
            add("dns_mismatch", host, f"DNS says '{dns}', the host identifies itself as '{real}'")

        # Unmanaged devices: only on positive evidence (a name outside the convention, a Windows PC
        # outside the domain, a randomized MAC). A device that merely gives nothing away is reported
        # separately and more mildly as unidentified.
        if category in ENDPOINTS:
            reason = ""
            ntlm = smb.get("ntlm") or {}
            windows_pc = category == "windows" and ntlm.get("build", 0) >= 2600
            host_domain = (host.get("domain") or "").lower()
            workgroup = ((host.get("nbns") or {}).get("domain") or "")
            # the expected domain may be given in DNS form (corp.local) or NetBIOS form (CORP);
            # a child domain (sales.corp.local) belongs to its forest
            aliases = {host_domain, host_domain.split(".")[0], (ntlm.get("netbios_domain") or "").lower(),
                       (ntlm.get("dns_forest") or "").lower()} - {""}
            member = bool(domain) and (domain in aliases or host_domain.endswith("." + domain))
            if naming and name and not naming.search(name):
                reason = f"name '{name}' does not follow the naming convention"
            elif domain and windows_pc and host_domain and host_domain == name.lower():
                # a workgroup PC reports its own name as the domain
                reason = f"Windows PC not joined to the domain (workgroup), expected {domain}"
            elif domain and windows_pc and host_domain and not member:
                reason = f"member of '{host_domain}', not of the domain {domain}"
            elif domain and windows_pc and not host_domain:
                reason = "Windows PC not joined to the domain" + (f" (workgroup {workgroup})" if workgroup else "")
            elif category == "mobile":
                reason = "randomized MAC, no open ports (probably a smartphone, tablet or guest laptop)"
            if reason:
                add("unmanaged", host, reason)
            elif category == "unknown" and not name:
                add("unidentified", host, "answers on the network but exposes nothing that identifies it"
                    + (f" (network card: {host['vendor']})" if host.get("vendor") else ""))

    # flat network: judged per segment. Fragments of a range are widened to their /24, so that
    # "10.0.0.20-40" is evaluated as one segment instead of several tiny ones.
    segments = []
    for net_text in networks:
        try:
            net = ipaddress.ip_network(net_text, strict=False)
        except ValueError:
            continue
        if net.prefixlen > 24:
            net = net.supernet(new_prefix=24)
        if net not in segments:
            segments.append(net)
    # overlapping targets (10.0.0.0/23 plus 10.0.0.7) are one segment, not two
    segments = [net for net in segments if not any(net != other and net.subnet_of(other) for other in segments)]
    for net in segments:
        net_text = str(net)
        inside = [h for h in hosts if _in_network(h["ip"], net)]
        # the default gateway is in every segment by definition: it does not make a network "flat"
        critical = [h for h in inside if h.get("category") in CRITICAL and h.get("ports")
                    and not h.get("is_gateway")]
        endpoints = [h for h in inside if h.get("category") in ENDPOINTS and not h.get("is_self")]
        if len(critical) >= 2 and endpoints:
            kinds = Counter(LABELS[h["category"]] for h in critical)
            summary = ", ".join(f"{n} x {label}" for label, n in kinds.most_common())
            hits.setdefault("flat", []).append({
                "ip": net_text, "name": "",
                "evidence": f"Same segment: {summary}, together with {len(endpoints)} user "
                            f"device{'' if len(endpoints) == 1 else 's'}. The critical systems answer from the "
                            "scanning workstation."})

    if local:
        me = {"ip": local.get("ip", ""), "name": local.get("computer", "")}
        _local_hits(local, lambda key, evidence: hits.setdefault(key, []).append(
            {"ip": me["ip"], "name": me["name"], "evidence": evidence}), reference_date)

    findings = []
    counters = {sev: 0 for sev in SEVERITIES}
    for severity in SEVERITIES:
        for key, entry in CATALOG.items():
            if entry["severity"] != severity or key not in hits:
                continue
            counters[severity] += 1
            findings.append({"id": f"{severity[0]}{counters[severity]}", "key": key, **entry,
                             "hosts": hits[key]})
    return findings


def build_positives(hosts: list[dict]) -> list[str]:
    if not hosts:
        return []  # nothing was examined: there is nothing to vouch for
    out = []
    # every statement is about what was measured: a host whose check did not answer is not vouched for
    exposing = [h for h in hosts if any(rec["port"] == 3389 for rec in h.get("ports", [])) and not h.get("is_self")]
    if exposing and all((h.get("rdp") or {}).get("nla_required") is True for h in exposing):
        out.append("Remote Desktop requires NLA on " + ("the only host that exposes it." if len(exposing) == 1
                                                        else f"all {len(exposing)} hosts that expose it."))
    speaking = [h for h in hosts if (h.get("smb") or {}).get("smb2") or (h.get("smb") or {}).get("smb1")]
    if speaking and not any(h["smb"].get("smb1") for h in speaking):
        out.append("SMBv1 is disabled on " + ("the only host" if len(speaking) == 1 else f"all {len(speaking)} hosts")
                   + " running SMB.")
    smb = [h for h in speaking if h["smb"].get("smb2")]
    signed = [h for h in smb if h["smb"].get("signing_required")]
    dcs = [h for h in hosts if h.get("category") == "dc"]
    if dcs and all((h.get("smb") or {}).get("signing_required") for h in dcs):
        out.append("Domain controllers require SMB signing.")
    elif signed and len(signed) == len(smb):
        out.append("SMB signing is required on " + ("the only host" if len(smb) == 1 else f"all {len(smb)} hosts")
                   + " running SMB.")
    ports = {rec["port"] for h in hosts for rec in h.get("ports", [])}
    services = {rec["service"] for h in hosts for rec in h.get("ports", [])}
    if not ports & {21, 23} and not services & {"FTP", "Telnet"}:
        out.append("No Telnet or FTP service was found.")
    if not (ports & set(K.DB_PORTS)) and "MySQL/MariaDB" not in services:
        out.append("No service was found on the well-known database ports.")
    closed = [h for h in hosts if not h.get("ports") and not h.get("is_self")]
    if len(closed) == 1:
        out.append("1 device exposes none of the TCP ports checked.")
    elif closed:
        out.append(f"{len(closed)} devices expose none of the TCP ports checked.")
    return out


# --------------------------------------------------------------------------- scoring

def exposure(findings: list[dict]) -> dict:
    """Relative exposure index (0-100) for tracking between audits, with a rating label.
    Each finding weighs by severity and, more gently, by how many hosts it affects."""
    raw = 0.0
    for finding in findings:
        if finding["key"].startswith("local_"):
            continue  # the auditor's own PC must not move the figure for the network being audited
        affected = len({item["ip"] for item in finding["hosts"]})
        breadth = min(1 + (max(affected, 1) - 1) * 0.25, 2.0)
        raw += WEIGHTS[finding["severity"]] * breadth
    score = round(100 * (1 - math.exp(-raw / 120)))
    # words deliberately different from the severities (Low/Medium/High), which mean something else
    rating = next(name for floor, name in EXPOSURE_BANDS if score >= floor)
    return {"score": score, "rating": rating}


def host_scores(findings: list[dict]) -> dict[str, dict]:
    """Per-address tally: {ip: {'score': n, 'HIGH': n, 'MEDIUM': n, 'LOW': n}}."""
    table: dict[str, dict] = {}
    for finding in findings:
        for ip in {item["ip"] for item in finding["hosts"]}:
            entry = table.setdefault(ip, {"score": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
            entry[finding["severity"]] += 1
            entry["score"] += WEIGHTS[finding["severity"]]
    return table


# --------------------------------------------------------------------------- limits and diff

def build_limits(scan: dict, hosts: list[dict]) -> list[str]:
    """Plain-language list of what this audit did not cover, from the recorded scan facts."""
    profile = scan.get("profile", "standard")
    count = scan.get("ports_per_host")
    count_text = f"{count:,}" if isinstance(count, int) else "?"
    limits = []
    if scan.get("interrupted"):
        limits.append("THE AUDIT WAS INTERRUPTED: discovery, port scan and identification are incomplete. "
                      "Absence of a finding means nothing here; repeat the audit.")
    # This text is read by the customer: it names no command-line options.
    if scan.get("local_errors"):
        limits.append(f"The scanning workstation ran out of network sockets {scan['local_errors']:,} times: some "
                      "open ports may have been missed. The audit should be repeated at a slower speed.")
    limits += [
        ("TCP ports planned per host" if scan.get("interrupted") else "TCP ports checked per host")
        + f": {count_text} ({profile} profile)."
        + ("" if profile == "full" else " Ports outside that list were not checked; only an audit with the full "
           "profile looks at all 65,535."),
    ]
    udp = [name for name, on in (("NetBIOS (137)", scan.get("nbns")), ("SNMP (161)", scan.get("snmp")),
                                 ("SSDP (1900)", scan.get("ssdp"))) if on]
    limits.append("UDP probes were limited to " + ", ".join(udp) + "." if udp else "No UDP port was checked.")
    limits += [
        "The audit is unauthenticated: it does not log in to anything, so it does not measure patch levels or "
        "match software against vulnerability (CVE) databases. Windows versions come from the build number "
        "reported over SMB, which identifies the family (for example Windows 10 2004-22H2) rather than the "
        "exact update: confirm them against the inventory.",
        f"Only what is reachable from {scan.get('source_host', 'the scanning workstation')} "
        f"({scan.get('source_ip', '?')}) is visible. Internet exposure, cloud services and any network that "
        "workstation was not connected to (other VLANs, sites or Wi-Fi networks) are not covered, and a "
        "different vantage point may see different things.",
        f"Only devices switched on between {scan.get('seen_from', '?')} and {scan.get('seen_to', '?')} on "
        f"{scan.get('date', '?')} are included.",
        "IPv6 was not examined.",
        "No password was tried: factory credentials must be checked by hand."
        + (" The one exception is a read with the default SNMP community 'public'." if scan.get("snmp") else ""),
        "Nothing was sent to print ports; on printers, unknown ports were only listened to.",
        "Evidence marked 'by port number' means the port was open but the service did not identify itself: "
        "confirm it on the device.",
    ]
    doubtful = {"partial": "scan interrupted, partial coverage",
                "intermittent": "answers intermittently under scan, port list less certain"}
    noted = [f"{h['ip']} ({doubtful[h['scan_quality']]})" for h in hosts if h.get("scan_quality") in doubtful]
    if noted:
        limits.append("Lower confidence for: " + ", ".join(noted) + ".")
    if scan.get("remote_targets"):
        limits.append("Some targets are outside the scanning workstation's own subnet: there, devices that "
                      "answer neither ping nor the TCP probes were not found, and network card vendors are "
                      "unknown.")
    if scan.get("excluded"):
        limits.append("Addresses excluded on request: " + ", ".join(scan["excluded"]) + ".")
    if not scan.get("naming") and not scan.get("domain"):
        limits.append("Recognition of unmanaged devices was limited because no naming convention or domain "
                      "was supplied for comparison.")
    if scan.get("nmap") is False:
        limits.append("Services that the built-in probes did not recognize stay attributed by port number "
                      "(the optional nmap integration was not available).")
    if not scan.get("local"):
        limits.append("The configuration of the scanning workstation itself was not checked.")
    if scan.get("ping_works") is False:
        limits.append("Ping could not be used from the scanning workstation: hosts that answer neither the TCP "
                      "probes nor ARP were not found.")
    if scan.get("cert_details") is False:
        limits.append("This Python build cannot decode certificates: expired, expiring and self-signed "
                      "certificates were not checked.")
    return limits


def diff(previous: dict, current: dict) -> dict:
    """Comparison with a previous audit (audit.json file)."""
    old = {h["ip"]: h for h in previous.get("hosts", [])}
    new = {h["ip"]: h for h in current.get("hosts", [])}
    old_meta, new_meta = previous.get("meta") or {}, current.get("meta") or {}

    # A full audit sees ports a standard one never looks at: compare only what both checked.
    order = list(K.PROFILES)
    profiles = [(m.get("scan") or {}).get("profile") or m.get("profile") for m in (old_meta, new_meta)]
    notes = []
    comparable = None
    if all(p in order for p in profiles) and profiles[0] != profiles[1]:
        narrower = min(profiles, key=order.index)
        comparable = set(K.ports_for(narrower))
        notes.append(f"The previous audit used the {profiles[0]} profile and this one the {profiles[1]} profile: "
                     f"ports are compared only within the {narrower} list.")
    if old_meta.get("targets") and new_meta.get("targets") and set(old_meta["targets"]) != set(new_meta["targets"]):
        notes.append("The two audits cover different targets: hosts outside the common part appear as new or gone.")

    def ports(host):
        found = {rec["port"] for rec in host.get("ports", [])}
        return found & comparable if comparable is not None else found

    result = {
        "previous_date": old_meta.get("started", ""), "notes": notes,
        "new_hosts": [{"ip": ip, "name": display_name(new[ip]), "type": new[ip].get("type", "")}
                      for ip in new if ip not in old],
        "gone_hosts": [{"ip": ip, "name": display_name(old[ip]), "type": old[ip].get("type", "")}
                       for ip in old if ip not in new],
        "opened": [], "closed": [],
    }
    for ip in new:
        if ip in old:
            added, removed = sorted(ports(new[ip]) - ports(old[ip])), sorted(ports(old[ip]) - ports(new[ip]))
            if added:
                result["opened"].append({"ip": ip, "name": display_name(new[ip]), "ports": added})
            if removed:
                result["closed"].append({"ip": ip, "name": display_name(new[ip]), "ports": removed})

    def in_scope(item):
        # a finding observed on a port the other audit never looked at is neither new nor resolved
        match = re.match(r"port (\d+)", item.get("evidence") or "")
        return comparable is None or not match or int(match.group(1)) in comparable

    def pairs(audit):
        return {(f["key"], h["ip"]) for f in audit.get("findings", []) for h in f.get("hosts", [])
                if in_scope(h)}

    def title(key):
        return CATALOG[key]["title"] if key in CATALOG else key

    before, after = pairs(previous), pairs(current)
    result["new_findings"] = sorted(f"{title(k)} - {ip}" for k, ip in after - before)
    result["resolved"] = sorted(f"{title(k)} - {ip}" for k, ip in before - after)
    return result
