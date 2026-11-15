# NetAudit findings reference

Every finding NetAudit can raise, grouped by severity. Generated with `python -m netaudit --catalog`.

## High (18)

### Flat network: critical systems and workstations share one segment

- **Key:** `flat`
- **Timeframe:** Longer term
- **MITRE ATT&CK:** T1021
- **Risk:** A single compromised device (phishing, an infected personal laptop) has direct network access to servers, storage and management interfaces. This is the typical ransomware propagation scenario.
- **Recommended action:** Separate servers, workstations, management (BMC, switches, firewall), printers and guest/BYOD into VLANs and allow only the required flows between them.

### SMB signing not required

- **Key:** `smb_signing`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1557.001
- **Risk:** It enables NTLM relay: anyone on the network can capture an authentication (for example via LLMNR/NetBIOS poisoning) and relay it to a host that does not require signing, gaining access with the victim's privileges.
- **Recommended action:** Enable the Group Policy 'Microsoft network server: Digitally sign communications (always)' on servers and clients and require signing on NAS and Samba too. Check first for old copiers that scan to a shared folder: devices that cannot sign will stop working. Also turn off LLMNR (policy 'Turn off multicast name resolution') and NetBIOS over TCP/IP (per adapter, or for all DHCP clients with the Microsoft vendor option 001 'Microsoft Disable Netbios Option').

### SMBv1 enabled

- **Key:** `smb1`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1210
- **Risk:** SMBv1 is the protocol exploited by WannaCry and NotPetya and has no protection against tampering or downgrade.
- **Recommended action:** Find out who still uses it first (Set-SmbServerConfiguration -AuditSmb1Access $true, then event 3000 in the SMBServer audit log): old copiers and scanners may depend on it. Then disable it: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol on Windows 8.1 / Server 2012 R2 and later (a restart is needed), minimum protocol SMB2 on NAS and Samba.

### Operating system out of support

- **Key:** `os_eol`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1210
- **Risk:** It no longer receives security updates: every new vulnerability stays open.
- **Recommended action:** Upgrade (on Windows 11, installing the current feature update is enough) or replace. Isolate in a dedicated VLAN whatever cannot be upgraded, and verify the edition and any extended support program (ESU/LTSC).

### Remote Desktop without mandatory NLA

- **Key:** `rdp_no_nla`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1021.001
- **Risk:** Without Network Level Authentication a full logon session is offered to anyone before they authenticate, which exposes the host to pre-authentication vulnerabilities and makes password guessing cheaper.
- **Recommended action:** Enable the Group Policy 'Require user authentication for remote connections by using Network Level Authentication' (Remote Desktop Session Host > Security), or the matching checkbox in the Remote Desktop settings of the host.

### VNC without authentication

- **Key:** `vnc_noauth`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1021.005
- **Risk:** Anyone on the network can view and control the screen.
- **Recommended action:** Disable VNC or enforce strong authentication and restrict it to administrative workstations.

### Service accessible without authentication

- **Key:** `service_noauth`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1210
- **Risk:** Data or administrative functions can be read and changed by anyone on the network.
- **Recommended action:** Enable authentication and bind the service to localhost or to the hosts that need it.

### Telnet enabled

- **Key:** `telnet`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1040
- **Risk:** Credentials and commands travel in clear text.
- **Recommended action:** Disable Telnet and use SSH.

### Database reachable from the network

- **Key:** `db_exposed`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1210
- **Risk:** Anyone on the network can attempt to log in to the database or attack it directly.
- **Recommended action:** Restrict the port to the application servers, or to the workstations that connect to it directly if the application works that way; review accounts and updates.

### Hardware management interface on the user network

- **Key:** `bmc`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1078.001
- **Risk:** iDRAC, iLO and IPMI give full control of the server (console, power, virtual media): anyone who reaches it controls the host and everything it runs.
- **Recommended action:** Move it to a management VLAN reachable only from administrative workstations; update the firmware; make sure the password is not the factory default.

### Industrial control protocol reachable from the user network

- **Key:** `industrial`
- **Timeframe:** This week
- **Risk:** Modbus has no authentication and many S7 controllers run without access protection: anyone who reaches the port may be able to read and write process values.
- **Recommended action:** Isolate PLCs and controllers in a dedicated network segment behind a firewall that allows only the engineering stations.

### Third-party remote access software on servers

- **Key:** `remote_tool_server`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1219
- **Risk:** It is an entry point that bypasses firewall and VPN: if the account or password is compromised the intruder lands directly on the servers. Attribution based on the port number alone: confirm on the host.
- **Recommended action:** Confirm which program is listening. If it is the approved tool of your IT provider, verify two-factor authentication and the allow-list of accounts, disable incoming LAN connections and remove it from domain controllers; otherwise uninstall it.

### Backup and block-storage services reachable from the user network

- **Key:** `storage`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1490
- **Risk:** iSCSI, NFS, rsync and backup-vault ports usually carry backups or server disks: ransomware started on a client can encrypt or delete them together with production data.
- **Recommended action:** Restrict these ports to the servers that need them (ordinary file sharing over SMB can stay); use CHAP and an initiator allow-list on iSCSI; keep immutable snapshots and an offline or off-site copy.

### Devices that do not look managed on the user network

- **Key:** `unmanaged`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1200
- **Risk:** Devices with no control over patching and antivirus have direct access to servers and storage.
- **Recommended action:** Identify the owners; move them to an isolated guest/BYOD network; consider 802.1X or blocking unknown devices.

### Windows Firewall disabled on the scanning workstation

- **Key:** `local_firewall`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1562.004
- **Risk:** The workstation accepts incoming connections unfiltered.
- **Recommended action:** Re-enable the firewall on every profile.

### No real-time antivirus active on the scanning workstation

- **Key:** `local_defender`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1562.001
- **Risk:** Malware is not blocked on execution.
- **Recommended action:** Re-enable real-time protection or check the third-party antivirus.

### User Account Control disabled on the scanning workstation

- **Key:** `local_uac`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1548.002
- **Risk:** Every program started by an administrator runs with full privileges without a prompt.
- **Recommended action:** Set EnableLUA back to 1 (Group Policy 'User Account Control: Run all administrators in Admin Approval Mode').

### WDigest stores clear-text credentials on the scanning workstation

- **Key:** `local_wdigest`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1003.001
- **Risk:** With UseLogonCredential enabled, passwords of logged-on users sit in memory in clear text and can be dumped.
- **Recommended action:** Set UseLogonCredential to 0 under the WDigest registry key.

## Medium (25)

### Windows 10: out of support unless extended, to be verified

- **Key:** `os_check`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1210
- **Risk:** Windows 10 stopped receiving security updates in 10/2025 unless the host is enrolled in ESU or runs an LTSC edition. This cannot be determined from the network.
- **Recommended action:** Verify the edition and ESU enrollment; otherwise upgrade to Windows 11 or replace.

### Unidentified devices on the network

- **Key:** `unidentified`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1200
- **Risk:** A device that answers on the network but gives nothing away cannot be matched to the inventory: it may be a hardened PC, or something that should not be there.
- **Recommended action:** Trace each one from its switch port or DHCP lease, then add it to the inventory or remove it.

### SNMP with the default community 'public'

- **Key:** `snmp_public`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1602.001
- **Risk:** Anyone on the network can read the device configuration, interfaces and tables.
- **Recommended action:** Disable SNMP v1/v2c or change the community, preferring SNMPv3 and restricting the sources. Check first which print queues and monitoring tools rely on the current community.

### Administration interface over HTTP only

- **Key:** `http_admin`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1040
- **Risk:** The administration password travels in clear text on the network.
- **Recommended action:** Enable HTTPS where available, update the firmware, change factory passwords and move management to a dedicated VLAN.

### HTTP Basic authentication without encryption

- **Key:** `basic_auth_plain`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1040
- **Risk:** Every request carries the user name and password in a trivially decodable form.
- **Recommended action:** Serve it over HTTPS where the device or application supports it; otherwise keep it on a network segment that only its administrators can reach.

### Expired certificate

- **Key:** `cert_expired`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1557
- **Risk:** Users get used to clicking through browser warnings and can no longer spot an interception attack.
- **Recommended action:** Renew the certificate and restore automatic renewal.

### Administrative access to servers reachable from the user network

- **Key:** `admin_exposure`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1021
- **Risk:** RDP, WinRM and SSH on servers are reachable from the user network: a compromised client can attempt to log in directly.
- **Recommended action:** Restrict administration ports to IT workstations with the local firewall or inter-VLAN rules.

### Firewall, switch and NAS management reachable from the user network

- **Key:** `mgmt_ui`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1021
- **Risk:** The administration interfaces of the infrastructure are exposed to every connected device.
- **Recommended action:** Restrict them to IT workstations or a management VLAN; enable two-factor authentication where available.

### Applications holding sensitive data reachable from the user network

- **Key:** `sensitive_app`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1213
- **Risk:** Archives, consoles and panels with confidential data are reachable from every user device.
- **Recommended action:** Check version and updates, restrict access to the users concerned and install valid certificates.

### VNC remote access or screen sharing enabled

- **Key:** `vnc_open`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1021.005
- **Risk:** VNC often relies on weak passwords and no encryption.
- **Recommended action:** Disable it when not needed; otherwise restrict it to administrative workstations.

### FTP in clear text

- **Key:** `ftp`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1040
- **Risk:** Credentials and files travel unencrypted.
- **Recommended action:** Replace it with SFTP or FTPS.

### Netdata monitoring accessible without authentication

- **Key:** `netdata`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1082
- **Risk:** It exposes processes, users, connections and system metrics to anyone on the network.
- **Recommended action:** Restrict the port to IT workstations or disable the service.

### End-of-life server software

- **Key:** `outdated_sw`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1210
- **Risk:** The version announced by the service no longer receives security fixes.
- **Recommended action:** Update the software or the device firmware; if that is not possible, restrict access to the service.

### SSH protocol 1 accepted

- **Key:** `ssh_v1`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1557
- **Risk:** SSH-1 has known cryptographic weaknesses that allow session interception.
- **Recommended action:** Disable protocol 1 and update the SSH server.

### Outdated SSH version

- **Key:** `ssh_old`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1210
- **Risk:** Old releases have known vulnerabilities and weak algorithms.
- **Recommended action:** Update the system or the firmware.

### UPnP port mapping enabled on the gateway

- **Key:** `upnp_igd`
- **Timeframe:** Within 30 days
- **Risk:** Any device on the network, including malware, can open ports from the Internet towards internal hosts without authentication.
- **Recommended action:** Disable UPnP/NAT-PMP on the firewall or router.

### Development services exposed by workstations

- **Key:** `dev_services`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1190
- **Risk:** Development servers and APIs are listening on every interface, often without authentication.
- **Recommended action:** Bind them to localhost or to the clients that need them and make sure they require authentication.

### Very large exposed surface

- **Key:** `wide_surface`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1046
- **Risk:** Every listening service is a potential entry point.
- **Recommended action:** Disable unneeded services and packages and restrict the rest to the sources that use them.

### Third-party remote access software on workstations

- **Key:** `remote_tool_client`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1219
- **Risk:** Unless it is the approved corporate tool, it is an uncontrolled way in. Attribution based on the port number alone: confirm on the host.
- **Recommended action:** Check that it is the approved tool, with two-factor authentication and incoming LAN connections disabled.

### The scanning workstation exposes RDP or SMB on public networks too

- **Key:** `local_exposure`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1021.001
- **Risk:** On an external network (hotel, customer site) Remote Desktop and shares stay reachable.
- **Recommended action:** Limit the RDP and SMB firewall rules to the Domain profile (the Private profile on a PC that is not in a domain).

### LLMNR or NetBIOS enabled on the scanning workstation

- **Key:** `local_llmnr`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1557.001
- **Risk:** They allow name-resolution poisoning and the capture of authentications on the network.
- **Recommended action:** Turn off LLMNR with the Group Policy 'Turn off multicast name resolution' and NetBIOS over TCP/IP per adapter, or for all DHCP clients with the Microsoft vendor option 001 'Microsoft Disable Netbios Option'.

### No Windows update installed recently on the scanning workstation

- **Key:** `local_updates`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1210
- **Risk:** Missing monthly updates leave known vulnerabilities open.
- **Recommended action:** Install pending updates and check the update policy.

### Antivirus definitions out of date on the scanning workstation

- **Key:** `local_av_outdated`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1562.001
- **Risk:** Recent malware is not recognized.
- **Recommended action:** Update the antivirus and check why updates are failing.

### System drive not encrypted on the scanning workstation (a laptop)

- **Key:** `local_bitlocker`
- **Timeframe:** Within 30 days
- **Risk:** If the laptop is lost or stolen, its data and cached credentials are readable.
- **Recommended action:** Enable BitLocker on the system drive and escrow the recovery key.

### Guest account enabled on the scanning workstation

- **Key:** `local_guest`
- **Timeframe:** This week
- **MITRE ATT&CK:** T1078.001
- **Risk:** It gives anonymous access to the machine.
- **Recommended action:** Disable the built-in Guest account.

## Low (10)

### Printers on the user network: firmware and administrator password to verify

- **Key:** `printer`
- **Timeframe:** Within 30 days
- **Risk:** Printers keep documents and credentials (address books, LDAP, SMTP) and are rarely updated. Nothing was found wrong with them: this is a reminder to check what the audit cannot see.
- **Recommended action:** Check the firmware and that the administrator password is not the factory default; disable the protocols nobody uses (LPD, RAW, SLP).

### Operating system close to end of support

- **Key:** `os_warn`
- **Timeframe:** Longer term
- **Risk:** In a few months it will stop receiving security updates.
- **Recommended action:** Plan the migration.

### Certificate expiring within 30 days

- **Key:** `cert_expiring`
- **Timeframe:** Within 30 days
- **Risk:** When it expires, warnings appear and some services stop working.
- **Recommended action:** Check that automatic renewal works, or renew it by hand if it is self-signed.

### Self-signed or default certificates on management interfaces

- **Key:** `cert_selfsigned`
- **Timeframe:** Longer term
- **MITRE ATT&CK:** T1557
- **Risk:** They do not allow the identity of the device to be verified.
- **Recommended action:** Install certificates issued by an internal or public CA.

### TLS 1.0 or 1.1 still accepted

- **Key:** `tls_legacy`
- **Timeframe:** Longer term
- **MITRE ATT&CK:** T1557
- **Risk:** These protocols are deprecated and have known weaknesses.
- **Recommended action:** Disable them and keep TLS 1.2 and 1.3 only.

### Web directory listing enabled

- **Key:** `dir_listing`
- **Timeframe:** Within 30 days
- **MITRE ATT&CK:** T1083
- **Risk:** The web server shows the list of files in a folder, which may reveal backups or configuration files.
- **Recommended action:** Disable directory browsing on the web server.

### Old Active Directory functional level

- **Key:** `ad_level`
- **Timeframe:** Longer term
- **Risk:** Functional levels of Windows Server 2012 R2 or earlier lack recent security features and suggest legacy domain controllers.
- **Recommended action:** Plan to raise the domain and forest functional level after retiring old domain controllers.

### LSA protection not enabled on the scanning workstation

- **Key:** `local_lsa`
- **Timeframe:** Longer term
- **MITRE ATT&CK:** T1003.001
- **Risk:** Without RunAsPPL, tools running as administrator can read credentials from LSASS memory.
- **Recommended action:** Enable LSA protection (RunAsPPL) by Group Policy after testing compatibility.

### Non-business software listening on the network

- **Key:** `consumer_sw`
- **Timeframe:** Longer term
- **Risk:** It increases the exposed surface. Attribution based on the port number alone: confirm on the host.
- **Recommended action:** Consider a policy on permitted software.

### DNS records out of sync

- **Key:** `dns_mismatch`
- **Timeframe:** Longer term
- **Risk:** The DNS name does not match the real host name: inventory and logs become unreliable.
- **Recommended action:** Enable DNS scavenging and clean up stale records.

