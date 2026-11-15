# Changelog

## 2.0.0

- Everything in English: options, messages, report, documentation, tests.
- New report: sidebar navigation, exposure index, summary charts, findings with risk, action, timeframe and
  MITRE ATT&CK technique, remediation plan, filterable and sortable inventory, light/dark theme, print layout.
- New checks: SMB up to 3.1.1, Telnet, SSH protocol 1, HTTP Basic authentication in clear text, web directory
  listings, end-of-life server software, LDAP rootDSE (AD functional level), UPnP port mapping on the gateway,
  industrial protocols, and on the local workstation UAC, WDigest, LSA protection, disk encryption, updates,
  antivirus definitions and the Guest account.
- New options: `--config`, `--baseline auto`, `--demo`, `--catalog`, `--fail-on`, `--regenerate`, `--no-ssdp`,
  `--csv-delimiter`.
- New outputs: `summary.md`, `audit.log`; CSV files renamed `inventory.csv` and `findings.csv`.
- Robustness: a partial report is written after Ctrl+C or an unexpected error; address ranges are scanned in full
  and `--exclude` accepts CIDR blocks and ranges; comparisons across profiles only use the ports both audits checked; values
  from a configuration file are validated; CSV cells are neutralized against spreadsheet formulas; a hostile
  device cannot stall the audit with a crafted web page or hundreds of open ports; findings link to the host
  details; `FINDINGS.md` documents every finding; `pip install .` adds a `netaudit` command.
- Rule accuracy: a print port no longer turns a Linux server, a Windows print server or a NAS into a printer;
  Windows identity outranks the gateway role; iLO, iDRAC9 and ESXi are recognized; Linux/Unix servers count as
  critical systems; a Samba DNS suffix is not taken for an AD domain; unmanaged devices need positive evidence
  and devices that give nothing away are reported separately as unidentified; port numbers no longer override
  a service that answered; certificate expiry follows the certificate lifetime; positive statements only cover
  what was measured; the scanning workstation's operating system is judged too.
- First-use experience: wrong targets, a wrong `--baseline` and an unwritable output folder are reported before
  anything is scanned; the offline modes (`--demo`, `--self-test`, `--regenerate`, `--catalog`) cannot be mixed
  with each other or with targets; when the report cannot be written the collected data is saved in a file that
  `--regenerate` accepts; `--regenerate` takes a results folder and redoes the comparison with the stored
  baseline; `Run_audit.bat` finds Python through `py` too and says how to install it.
- Report wording for the customer: exposure bands renamed Minimal / Limited / Elevated / Severe, findings about
  the scanning workstation no longer move the index, the last timeframe is called "Longer term", evidence that
  rests on the port number alone says so, the limitations no longer mention command-line options, corrected
  Group Policy names in the recommended actions, printers on the user network lowered to low severity.
- CSV files carry the client, the audit date, a stable finding `Key` and a sortable severity rank; `summary.md`
  marks a partial audit and lists the hosts behind each high finding.
- Portability: ping on macOS/BSD, KVM guests, the Linux ARP table, the open-file limit on Unix, VPN and
  virtual adapters ignored when choosing the default target, policy-managed firewall/RDP/LSA settings.

## 1.0.0

- First version: discovery, two-pass port scan, service identification, findings, HTML/JSON/CSV report.
