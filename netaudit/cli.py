"""Command line: orchestrates discovery, scanning, identification, rules and reporting."""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import getpass
import glob
import ipaddress
import json
import os
import platform
import re
import socket
import sys
import time

from . import __version__
from . import discovery, localcheck, netinfo, nmapx, portscan, probes, report, rules, udp
from . import knowledge as K

LEGAL = ("Scanning networks without authorization is a criminal offense in most countries\n"
         "(in Italy: art. 615-ter of the Criminal Code). Use NetAudit only on networks you own\n"
         "or for which you hold a written engagement.")
EXIT_OK, EXIT_CANCELLED, EXIT_USAGE, EXIT_FINDINGS = 0, 1, 2, 3
CONFIG_KEYS = {"targets", "client", "operator", "profile", "speed", "exclude", "naming", "server_regex",
               "domain", "baseline", "output", "no_udp", "no_snmp", "no_ssdp", "no_nmap", "no_local",
               "fail_on", "max_addresses", "allow_public", "csv_delimiter"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="Identification-only network security audit: hosts, ports, services, findings, report.",
        epilog="Examples:\n"
               "  python -m netaudit --client \"Acme Ltd\"                    local subnet, standard profile\n"
               "  python -m netaudit 192.168.1.0/24 --profile full --naming \"^PC-\\d+\"\n"
               "  python -m netaudit --config acme.json --baseline auto\n"
               "  python -m netaudit --self-test",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("targets", nargs="*", help="networks or addresses: CIDR, IP, ranges a.b.c.10-50 "
                                                   "(default: the local subnet)")
    parser.add_argument("--client", default="", help="client or site name shown in the report")
    parser.add_argument("--operator", default="", help="who runs the audit (default: current user)")
    parser.add_argument("--profile", choices=K.PROFILES, default="standard",
                        help="quick: ~110 known ports; standard: ~1,300 ports; full: all 65,535")
    parser.add_argument("--speed", choices=list(K.SPEEDS), default="normal",
                        help="careful for slow networks or fragile devices")
    parser.add_argument("--exclude", default="", help="addresses not to touch: IPs, CIDR blocks or ranges, "
                                                      "comma separated")
    parser.add_argument("--authorized", action="store_true",
                        help="declare the authorization without the interactive question")
    parser.add_argument("--allow-public", action="store_true", help="allow non-private addresses")
    parser.add_argument("--max-addresses", type=int, default=4096, help="address limit per audit")
    parser.add_argument("--naming", default="", help="regular expression of managed device names, "
                                                     "e.g. \"^PC-\\d+\"")
    parser.add_argument("--server-regex", default="", help="regular expression of server names")
    parser.add_argument("--domain", default="", help="expected Active Directory domain (default: inferred)")
    parser.add_argument("--baseline", default="", help="previous audit.json to compare with, or 'auto' for "
                                                       "the latest audit of the same client")
    parser.add_argument("--output", default="", help="results folder")
    parser.add_argument("--config", default="", help="JSON file with default options for a client")
    parser.add_argument("--csv-delimiter", choices=["comma", "semicolon"], default="comma",
                        help="separator for the CSV files (semicolon suits Excel in many European locales)")
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="none",
                        help="exit with code 3 when findings of this severity or higher exist")
    parser.add_argument("--no-udp", action="store_true", help="skip all UDP probes")
    parser.add_argument("--no-snmp", action="store_true", help="skip the SNMP read with community 'public'")
    parser.add_argument("--no-ssdp", action="store_true", help="skip the UPnP/SSDP multicast search")
    parser.add_argument("--no-nmap", action="store_true", help="do not use nmap even when installed")
    parser.add_argument("--no-local", action="store_true", help="skip the check of the local workstation")
    parser.add_argument("--self-test", action="store_true", help="try the tool on 127.0.0.1 only")
    parser.add_argument("--demo", action="store_true",
                        help="write a sample report for a fictional network, with no network traffic")
    parser.add_argument("--catalog", nargs="?", const="-", default="", metavar="FILE",
                        help="write the reference of every finding the tool can raise (Markdown) to FILE, "
                             "or print it when no file is given")
    parser.add_argument("--regenerate", default="", metavar="AUDIT_JSON",
                        help="rebuild findings and report from an existing audit.json, with no network traffic")
    parser.add_argument("--version", action="version", version=f"NetAudit {__version__}")
    return parser


def load_config(path: str) -> dict:
    """Read a client configuration file: a JSON object whose keys mirror the long options."""
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("the configuration must be a JSON object")
    config = {}
    for key, value in data.items():
        name = key.lstrip("-").replace("-", "_")
        if name not in CONFIG_KEYS:
            raise ValueError(f"unknown option '{key}'")
        if name == "targets":
            if not isinstance(value, (str, list)) or not all(isinstance(item, str) for item in list(value)):
                raise ValueError("'targets' must be a string or a list of strings")
            value = [value] if isinstance(value, str) else list(value)
        elif name == "exclude" and isinstance(value, list):
            value = ",".join(map(str, value))
        config[name] = value
    return config


_FLAGS = ("no_udp", "no_snmp", "no_ssdp", "no_nmap", "no_local", "allow_public")
_CHOICES = {"profile": K.PROFILES, "speed": tuple(K.SPEEDS), "fail_on": ("none", "low", "medium", "high"),
            "csv_delimiter": ("comma", "semicolon")}


def parse_args(argv=None):
    parser = build_parser()
    probe, _rest = parser.parse_known_args(argv)
    config_targets: list[str] = []
    if probe.config:
        try:
            config = load_config(probe.config)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(f"cannot read --config {probe.config}: {exc}")
        config_targets = config.pop("targets", [])
        parser.set_defaults(**config)
    args = parser.parse_args(argv)
    # one mode per run; targets given on the command line make no sense with the offline modes
    modes = [name for name, on in (("--demo", args.demo), ("--self-test", args.self_test),
                                   ("--regenerate", bool(args.regenerate)), ("--catalog", bool(args.catalog))) if on]
    if len(modes) > 1:
        parser.error(f"{' and '.join(modes)} cannot be used together")
    if modes and args.targets:
        parser.error(f"{modes[0]} does not take targets (got: {' '.join(args.targets)})")
    if not modes and not args.targets:
        args.targets = config_targets  # targets from the config file apply to a real audit only
    # values that came from the config file skip argparse's own checks: validate them here
    for name, allowed in _CHOICES.items():
        if getattr(args, name) not in allowed:
            parser.error(f"{name.replace('_', '-')} must be one of {', '.join(allowed)} (got {getattr(args, name)!r})")
    for name in _FLAGS:
        if not isinstance(getattr(args, name), bool):
            parser.error(f"{name.replace('_', '-')} must be true or false (got {getattr(args, name)!r})")
    if not isinstance(args.max_addresses, int) or isinstance(args.max_addresses, bool) or args.max_addresses < 1:
        parser.error("max-addresses must be a positive whole number")
    for name in ("client", "operator", "naming", "server_regex", "domain", "baseline", "output", "exclude"):
        if not isinstance(getattr(args, name), str):
            parser.error(f"{name.replace('_', '-')} must be text (got {getattr(args, name)!r})")
    return args


def confirm_authorization(args, targets: list[str]) -> bool:
    print(LEGAL)
    if args.authorized or args.self_test:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        print("\nNon-interactive run: add --authorized to declare the authorization.")
        return False
    try:
        answer = input(f"\nDo you confirm you are authorized to examine {', '.join(targets)}? Type YES: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().upper() in ("YES", "Y")


def read_audit_file(path: str):
    """Load an audit.json (a results folder is accepted too). -> (audit, '') or (None, reason)."""
    if os.path.isdir(path):
        path = os.path.join(path, "audit.json")
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return None, f"{path} does not exist"
    except OSError as exc:
        return None, f"{path} cannot be read ({exc.strerror or exc})"
    except ValueError:
        return None, f"{path} is not a JSON file"
    if (not isinstance(data, dict) or not isinstance(data.get("meta"), dict) or not isinstance(data.get("hosts"), list)
            or not all(isinstance(h, dict) and isinstance(h.get("ip"), str) for h in data["hosts"])):
        return None, f"{path} is not a NetAudit audit.json (it needs a 'meta' section and a list of 'hosts')"
    for host in data["hosts"]:  # tolerate hand-edited or older files: give every record its fields
        ports = host.get("ports")
        host["ports"] = [rec for rec in ports if isinstance(rec, dict) and isinstance(rec.get("port"), int)] \
            if isinstance(ports, list) else []
        for rec in host["ports"]:
            for key, default in (("service", ""), ("product", ""), ("info", ""), ("source", ""), ("kind", "")):
                if not isinstance(rec.get(key), str):
                    rec[key] = default
            if not isinstance(rec.get("flags"), list):
                rec["flags"] = []
    return data, ""


def plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


# nmap names its services in lower case; the rules compare the names the built-in probes use
_NMAP_NAMES = {"ftp": "FTP", "ssh": "SSH", "telnet": "Telnet", "vnc": "VNC", "http": "HTTP", "http-proxy": "HTTP",
               "http-alt": "HTTP", "https": "HTTPS", "https-alt": "HTTPS", "ssl/http": "HTTPS",
               "ssl/https": "HTTPS", "ssl/https-alt": "HTTPS", "mysql": "MySQL/MariaDB", "smtp": "SMTP",
               "pop3": "POP3", "imap": "IMAP", "redis": "Redis"}


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


def slugify(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", text).strip("_") or "audit"


def unique_folder(path: str) -> str:
    """The path itself, or path_2, path_3... when it already holds an audit: two runs started in the
    same minute must not overwrite each other."""
    candidate, number = path, 1
    while os.path.exists(os.path.join(candidate, "audit.json")):
        number += 1
        candidate = f"{path}_{number}"
    return candidate


def find_baseline(reports_dir: str, client: str, current: str = "") -> str:
    """Latest audit.json of the same client in the reports folder ('' when none)."""
    pattern = os.path.join(glob.escape(reports_dir), "*", "audit.json")
    # exact client name followed by the timestamp: "Acme" must not pick up "Acme_Ltd"
    folder = re.compile(re.escape(slugify(client)) + r"_\d{4}-\d{2}-\d{2}_\d{4}(_\d+)?")
    candidates = sorted(p for p in glob.glob(pattern)
                        if folder.fullmatch(os.path.basename(os.path.dirname(p)))
                        and os.path.abspath(os.path.dirname(p)) != os.path.abspath(current or os.devnull))
    for path in reversed(candidates):
        try:
            with open(path, encoding="utf-8") as handle:
                if not json.load(handle)["meta"].get("interrupted"):
                    return path  # an interrupted audit is no yardstick
        except Exception:
            continue
    return ""


class Run:
    """State of one audit, filled in phase by phase so a partial report is always possible."""

    def __init__(self, args):
        self.args = args
        self.started = dt.datetime.now()
        self.lines: list[str] = []
        self.warnings: list[str] = []
        self.hosts: dict[str, dict] = {}
        self.open_ports: dict[str, set] = {}
        self.quality: dict[str, str] = {}
        self.interrupted = False
        self.local = None
        self.interface = None
        self.targets: list[str] = []        # CIDR fragments, used by the rules
        self.target_labels: list[str] = []  # targets as typed, used for display
        self.networks = []
        self.candidates: list[str] = []
        self.excluded: set[str] = set()
        self.exclude_spec: list[str] = []
        self.baseline_data = None         # the --baseline audit, read and checked before the scan starts
        self.partials: list = []          # scan results kept by reference so Ctrl+C does not lose them
        self.local_errors = 0
        self.ping_works = True
        self.gateways: set[str] = set()
        self.source = ""
        self.probe_ip = "127.0.0.1"
        self.seen_from = self.started
        self.nmap_used = None
        self.naming = None
        self.server_regex = None

    def log(self, message: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        self.lines.append(line)
        print(line, flush=True)


def prepare(run: Run) -> int:
    """Resolve targets and options, ask for authorization. -> exit code (EXIT_OK to continue)."""
    args = run.args
    try:
        run.naming = re.compile(args.naming, re.I) if args.naming else None
        run.server_regex = re.compile(args.server_regex, re.I) if args.server_regex else None
    except re.error as exc:
        print(f"Invalid regular expression in --naming or --server-regex: {exc}")
        return EXIT_USAGE
    # everything that can be checked without touching the system is checked first, so a typo is
    # reported at once rather than after the interfaces have been queried or the scan has run
    specs = ["127.0.0.1"] if args.self_test else list(args.targets)
    try:
        run.networks = netinfo.parse_targets(specs)
        run.exclude_spec = [x.strip() for x in args.exclude.split(",") if x.strip()]
        excluded_nets = netinfo.parse_targets(run.exclude_spec)
    except ValueError as exc:
        print(f"Invalid target or --exclude: {exc}")
        return EXIT_USAGE
    if args.baseline and args.baseline != "auto":
        run.baseline_data, problem = read_audit_file(args.baseline)
        if problem:
            print(f"Cannot use --baseline: {problem}.")
            return EXIT_USAGE
    try:
        os.makedirs(args.output or os.path.join(os.getcwd(), "reports"), exist_ok=True)
    except OSError as exc:
        where = f"--output {args.output}" if args.output else f"the 'reports' folder in {os.getcwd()}"
        print(f"Cannot write results to {where} ({exc.strerror or exc}). Pass a folder you can write to "
              "with --output.")
        return EXIT_USAGE
    interfaces = [] if args.self_test else netinfo.local_interfaces()
    if not specs:
        if not interfaces:
            print("No local network detected: pass a target, for example 192.168.1.0/24.")
            return EXIT_USAGE
        specs = [interfaces[0]["network"]]
        label = " ".join(x for x in (interfaces[0].get("alias"), interfaces[0].get("profile")) if x)
        print(f"No target given: using the local subnet {specs[0]}" + (f" ({label})" if label else "") + ".")
        run.networks = netinfo.parse_targets(specs)
    if not run.networks:
        print("No valid target.")
        return EXIT_USAGE
    run.targets = [str(net) for net in run.networks]
    # what the operator typed, for the prompt and the report: "10.0.0.10-50", not six CIDR fragments
    run.target_labels = [part.strip() for spec in specs for part in str(spec).split(",") if part.strip()]
    if not args.self_test and not args.allow_public and not all(net.is_private for net in run.networks):
        print("One or more targets are not private addresses. If you are authorized add --allow-public.")
        return EXIT_USAGE
    total = sum(net.num_addresses for net in run.networks)
    if total > args.max_addresses:
        print(f"{total} addresses exceed the limit of {args.max_addresses}: narrow the targets or raise "
              "--max-addresses.")
        return EXIT_USAGE
    if sum(net.num_addresses for net in excluded_nets) > 1 << 20:
        print("--exclude covers too many addresses: narrow the targets instead.")
        return EXIT_USAGE
    run.excluded = {str(addr) for net in excluded_nets for addr in net}
    if not confirm_authorization(args, run.target_labels):
        print("Audit cancelled.")
        return EXIT_CANCELLED
    self_ips = {i["ip"] for i in interfaces}
    run.gateways = {i.get("gateway") for i in interfaces if i.get("gateway")}
    run.candidates = netinfo.expand_hosts(run.networks, exclude=run.excluded | self_ips)
    run.interface = next((i for i in interfaces
                          if any(ipaddress.ip_address(i["ip"]) in net for net in run.networks)), None)
    run.probe_ip = run.candidates[0] if run.candidates else "127.0.0.1"
    run.source = netinfo.source_ip(run.probe_ip)
    return EXIT_OK


async def scan_ports(run: Run, ips: list[str], should_abort) -> bool:
    """Two-pass scan with cross-check. Fills run.open_ports / run.quality. -> True when interrupted."""
    args, log = run.args, run.log
    workers, timeout, cap = K.SPEEDS[args.speed]
    quick = K.ports_for("quick")

    def tracked() -> portscan.ScanResult:
        result = portscan.ScanResult()
        run.partials.append(result)
        return result

    log(f"Quick scan: {len(quick)} known ports on {plural(len(ips), 'host')} ...")
    first = await portscan.scan({ip: quick for ip in ips}, workers, timeout, cap, should_abort=should_abort,
                                result=tracked())
    for ip in ips:
        run.open_ports[ip] = set(first.open.get(ip, []))
        if ip in first.incomplete:
            run.quality[ip] = "partial"
    if first.aborted:
        return True
    if args.profile == "quick":
        return False

    full = K.ports_for(args.profile)
    estimate = portscan.estimate_seconds(len(ips), len(full), workers, timeout, cap)
    log(f"{args.profile.capitalize()} scan: {len(full):,} ports on {plural(len(ips), 'host')}, estimated "
        f"{fmt_duration(estimate)} ...")

    def progress(ip, pct, found):
        log(f"  {ip}: {pct}%  open so far: {len(found)}")

    def batch(group, index, total):
        log(f"  batch of {len(group)} hosts ({index}/{total})")

    second = await portscan.scan({ip: full for ip in ips}, workers, timeout, cap,
                                 on_progress=progress, should_abort=should_abort, on_batch=batch, result=tracked())
    doubtful = []
    for ip in ips:
        found = set(second.open.get(ip, []))
        if ip in second.incomplete:
            run.quality[ip] = "partial"
        elif run.open_ports[ip] - found:
            doubtful.append(ip)  # ports seen in the first pass and missed in the second
        run.open_ports[ip] |= found
    if second.aborted:
        return True

    if doubtful:
        slow_workers, slow_timeout, slow_cap = K.SPEEDS["careful"]
        log(f"Cross-check: {plural(len(doubtful), 'host')} answered inconsistently, repeating at careful "
            "speed ...")
        third = await portscan.scan({ip: full for ip in doubtful}, slow_workers, slow_timeout, slow_cap,
                                    on_progress=progress, should_abort=should_abort, result=tracked())
        for ip in doubtful:
            found = set(third.open.get(ip, []))
            if ip in third.incomplete:
                run.quality[ip] = "partial"
            elif run.open_ports[ip] - found:
                run.quality[ip] = "intermittent"
            run.open_ports[ip] |= found
        if third.aborted:
            return True
    return False


def _quiet_exceptions(loop, context) -> None:
    """A host that drops the connection abruptly is not an error worth showing."""
    if isinstance(context.get("exception"), (ConnectionError, OSError)):
        return
    loop.default_exception_handler(context)


async def collect(run: Run) -> None:
    """All the network work. Every phase stores what it found on the Run object."""
    args, log = run.args, run.log
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_quiet_exceptions)

    def should_abort() -> bool:
        return not args.self_test and netinfo.source_ip(run.probe_ip) != run.source

    log(f"NetAudit {__version__} - targets {', '.join(run.target_labels or run.targets)} - {args.profile} profile, "
        f"{args.speed} speed")

    # 1. discovery
    if args.self_test:
        run.hosts = {"127.0.0.1": {"ip": "127.0.0.1", "alive_by": ["local"], "mac": "", "vendor": "",
                                   "mac_random": False, "hostname": "localhost"}}
    else:
        stats: dict = {}
        run.hosts = await discovery.discover(run.candidates, log, should_abort, stats)
        run.local_errors += stats.get("local_errors", 0)
        run.ping_works = stats.get("ping_works", True)
    for ip, host in run.hosts.items():
        host["is_gateway"] = ip in run.gateways
    log(f"{plural(len(run.hosts), 'host')} up.")
    run.seen_from = dt.datetime.now()
    ips = sorted(run.hosts, key=netinfo.ip_key)

    # 2. ports
    if ips:
        run.interrupted = await scan_ports(run, ips, should_abort)
    if run.interrupted:
        run.warnings.append("The workstation changed network during the scan: the audit was stopped and the "
                            "results are partial. Repeat it while staying connected to the same network.")
        log("WARNING: the network changed during the scan; stopping and saving partial results.")
        return

    # 3. identification
    todo = {ip: sorted(run.open_ports.get(ip, ())) for ip in ips if run.open_ports.get(ip)}
    log(f"Identifying services on {plural(len(todo), 'host')} "
        f"({plural(sum(map(len, todo.values())), 'open port')}) ...")
    sem = asyncio.Semaphore(8)
    results = await asyncio.gather(*[probes.identify_host(ip, ports, sem) for ip, ports in todo.items()],
                                   return_exceptions=True)
    for ip, result in zip(todo, results):
        if isinstance(result, dict):
            run.hosts[ip].update(result)
    if should_abort():
        run.interrupted = True
        run.warnings.append("The workstation changed network while services were being identified: some "
                            "services may be left unidentified.")
        return

    # 4. UDP
    if not args.no_udp and not args.self_test and ips:
        ssdp_from = run.interface["ip"] if run.interface and not args.no_ssdp else ""
        names = ["NetBIOS names"] + ([] if args.no_snmp else ["SNMP"]) + (["UPnP/SSDP"] if ssdp_from else [])
        log("UDP probes: " + ", ".join(names) + " ...")
        answers = await loop.run_in_executor(
            None, lambda: udp.sweep(ips, nbns=True, snmp=not args.no_snmp, ssdp_from=ssdp_from))
        for ip, data in answers.items():
            run.hosts[ip].update(data)
            if not run.hosts[ip].get("mac") and data.get("nbns", {}).get("mac"):
                run.hosts[ip]["mac"] = data["nbns"]["mac"]
                run.hosts[ip]["vendor"] = K.vendor_for(run.hosts[ip]["mac"])
        log("  " + ", ".join(f"{sum(1 for d in answers.values() if key in d)} {label}" for key, label in
                              (("nbns", "NetBIOS"), ("snmp", "SNMP"), ("ssdp", "UPnP"))) + " answers.")

    # 5. optional nmap
    nmap = "" if args.no_nmap else nmapx.find_nmap()
    run.nmap_used = None if args.no_nmap else bool(nmap)
    if nmap:
        pending = {}
        for ip in ips:
            records = run.hosts[ip].get("ports", [])
            port_set = {rec["port"] for rec in records}
            if probes.is_printer_like(port_set):
                continue
            windows_like = 135 in port_set and 445 in port_set
            unknown = [rec["port"] for rec in records
                       if rec.get("source") in ("", "port") and rec["port"] not in K.BY_NUMBER_ONLY
                       and rec["port"] not in (389, 445, 3389) and not (windows_like and rec["port"] >= 49152)]
            if unknown:
                pending[ip] = unknown
        if pending:
            log(f"nmap: version detection on {sum(map(len, pending.values()))} unidentified ports ...")
            extra = await loop.run_in_executor(None, lambda: nmapx.identify(nmap, pending))
            for ip, data in extra.items():
                for rec in run.hosts[ip].get("ports", []):
                    if rec["port"] in data:
                        name = data[rec["port"]]["service"]
                        rec.update(service=_NMAP_NAMES.get(name, name) or rec["service"],
                                   product=data[rec["port"]]["product"] or rec["product"], source="nmap")
                        if rec.get("info", "").startswith("unrecognized response"):
                            rec["info"] = ""

    # 6. local workstation
    if not args.no_local and netinfo.IS_WINDOWS:
        log("Checking the local workstation ...")
        run.local = await loop.run_in_executor(None, localcheck.collect)


def self_host(interface: dict, local: dict | None) -> dict:
    host = {"ip": interface["ip"], "alive_by": ["local"], "mac": "", "vendor": "", "mac_random": False,
            "hostname": socket.gethostname(), "is_self": True, "ports": []}
    if local:
        host["hostname"] = local.get("computer") or host["hostname"]
        for item in local.get("listening", []):
            port = item.get("port")
            if not port:
                continue
            host["ports"].append({"port": port, "service": K.PORT_INFO.get(port, ""),
                                  "product": item.get("process", ""),
                                  "info": "listening on " + item.get("address", ""),
                                  "source": "local", "flags": [], "kind": ""})
        try:
            build = int(local.get("build") or 0)
        except ValueError:
            build = 0
        host["smb"] = {"ntlm": {"dns_name": local.get("computer", ""), "build": build,
                                "dns_domain": local.get("domain", "") if local.get("domain_joined") else ""}}
    elif netinfo.IS_WINDOWS:
        # no local check (--no-local): still say what this machine is, from what Python knows
        try:
            build = int(platform.version().split(".")[-1])
        except ValueError:
            build = 0
        host["smb"] = {"ntlm": {"dns_name": socket.gethostname(), "build": build, "dns_domain": ""}}
    return host


def threshold_met(findings: list[dict], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    order = ["low", "medium", "high"]
    return any(order.index(f["severity"].lower()) >= order.index(fail_on) for f in findings)


def finalize(run: Run) -> int:
    """Classification, rules and outputs. Works on whatever the collection managed to gather."""
    args = run.args
    for partial in run.partials:  # includes passes cut short by Ctrl+C
        run.local_errors += partial.local_errors
        for ip, ports in partial.open.items():
            run.open_ports.setdefault(ip, set()).update(ports)
        for ip in partial.incomplete:
            run.quality.setdefault(ip, "partial")
    if run.local_errors:
        run.warnings.append(f"The workstation ran out of network sockets {run.local_errors:,} times during the "
                            "scan: some open ports may have been missed. Repeat with --speed careful.")
    for ip in run.hosts:
        if run.interrupted:
            run.quality.setdefault(ip, "partial")
        run.hosts[ip].setdefault("ports", [probes.new_record(p) for p in sorted(run.open_ports.get(ip, ()))])
        if ip in run.quality:
            run.hosts[ip]["scan_quality"] = run.quality[ip]
    if run.local and run.interface:
        run.local["ip"] = run.interface["ip"]
    if run.interface:
        run.hosts[run.interface["ip"]] = self_host(run.interface, run.local)

    host_list = [run.hosts[ip] for ip in sorted(run.hosts, key=netinfo.ip_key)]
    for host in host_list:
        rules.classify(host, run.server_regex)
    rules.link_multihomed(host_list)
    finished = dt.datetime.now()
    findings = rules.build_findings(host_list, run.targets, run.local, run.naming, args.domain,
                                    finished.strftime("%Y-%m-%d"))
    try:
        operator = args.operator or getpass.getuser()
    except Exception:  # no usable user database (some containers and services)
        operator = "unknown"
    scan = {
        "profile": args.profile, "speed": args.speed, "ports_per_host": len(K.ports_for(args.profile)),
        "nbns": not args.no_udp and not args.self_test, "snmp": not args.no_udp and not args.no_snmp
        and not args.self_test, "ssdp": bool(run.interface) and not args.no_udp and not args.no_ssdp
        and not args.self_test, "nmap": run.nmap_used, "local": bool(run.local),
        "source_host": socket.gethostname(), "source_ip": run.source,
        "seen_from": run.seen_from.strftime("%H:%M"), "seen_to": finished.strftime("%H:%M"),
        "date": finished.strftime("%Y-%m-%d"), "excluded": run.exclude_spec,
        "naming": bool(run.naming), "domain": args.domain or rules.infer_domain(host_list),
        # kept so that --regenerate reproduces the same classification
        "naming_pattern": args.naming, "server_pattern": args.server_regex, "domain_option": args.domain,
        "interrupted": run.interrupted, "local_errors": run.local_errors,
        "ping_works": run.ping_works, "cert_details": probes.CERT_DECODER_AVAILABLE,
        "remote_targets": bool(run.targets) and not args.self_test and not run.interface,
    }
    audit = {
        "meta": {
            "tool": "NetAudit", "version": __version__, "schema": 2, "client": args.client, "operator": operator,
            "started": run.started.strftime("%Y-%m-%d %H:%M"), "finished": finished.strftime("%Y-%m-%d %H:%M"),
            "duration": fmt_duration((finished - run.started).total_seconds()),
            "targets": run.target_labels or run.targets, "target_networks": run.targets,
            "profile": args.profile, "source": f"{socket.gethostname()} ({run.source})",
            "interrupted": run.interrupted, "warnings": run.warnings,
            "authorization": f"declared by {operator}", "scan": scan,
            "exposure": rules.exposure(findings),
        },
        # an interrupted audit proves nothing by absence: no reassurances
        "hosts": host_list, "findings": findings,
        "positives": [] if run.interrupted else rules.build_positives(host_list),
        "limits": rules.build_limits(scan, host_list), "local": run.local, "diff": None,
    }
    reports_dir = os.path.join(os.getcwd(), "reports")
    outdir = args.output or unique_folder(
        os.path.join(reports_dir, f"{slugify(args.client)}_{run.started:%Y-%m-%d_%H%M}"))
    baseline, previous = args.baseline, run.baseline_data
    if baseline == "auto":
        baseline = find_baseline(reports_dir, args.client, outdir)
        if not baseline:
            run.log("No previous audit found for this client: comparison skipped.")
    if baseline and run.interrupted:
        # a partial audit would show every host it did not reach as "gone" and its findings as "resolved"
        run.warnings.append("Comparison with the previous audit skipped: this audit was interrupted.")
        baseline = ""
    audit["meta"]["baseline"] = os.path.abspath(baseline) if baseline else ""
    if baseline:
        if previous is None:
            previous, problem = read_audit_file(baseline)
            if problem:
                run.warnings.append(f"Comparison with the previous audit skipped: {problem}.")
        if previous is not None:
            run.log(f"Comparing with {baseline} (audit of {previous['meta'].get('started', 'unknown date')}).")
            try:
                audit["diff"] = rules.diff(previous, audit)
            except Exception as exc:  # a damaged baseline must never cost the audit just completed
                audit["diff"] = None
                run.warnings.append(f"Baseline not usable ({type(exc).__name__}: {exc}): comparison skipped.")

    paths = report.write_outputs(audit, outdir, ";" if args.csv_delimiter == "semicolon" else ",")
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in rules.SEVERITIES}
    print()
    run.log(f"{'Stopped' if run.interrupted else 'Done'} in {audit['meta']['duration']}: "
            f"{plural(len(host_list), 'host')}, {counts['HIGH']} high, "
            f"{counts['MEDIUM']} medium, {counts['LOW']} low findings. Exposure index "
            f"{audit['meta']['exposure']['score']}/100 ({audit['meta']['exposure']['rating']}).")
    for finding in findings:
        if finding["severity"] == "HIGH":
            print(f"   [HIGH] {finding['id']} {finding['title']} ({len(finding['hosts'])})")
    try:
        with open(os.path.join(outdir, "audit.log"), "w", encoding="utf-8") as handle:
            handle.write("\n".join(run.lines) + "\n")
    except OSError:
        pass
    print(f"\nReport: {paths['report.html']}")
    print(f"Data:   {paths['audit.json']}  (usable as --baseline for the next audit)")
    if threshold_met(findings, args.fail_on):
        return EXIT_FINDINGS
    return EXIT_CANCELLED if run.interrupted else EXIT_OK


def regenerate(args) -> int:
    """Re-apply classification and rules to a saved audit: not a single packet on the network."""
    source = args.regenerate
    if os.path.isdir(source):
        source = os.path.join(source, "audit.json")
    audit, problem = read_audit_file(source)
    if problem:
        print(f"Cannot regenerate: {problem}.")
        return EXIT_USAGE
    hosts, meta = audit["hosts"], audit["meta"]
    saved = meta.get("scan") if isinstance(meta.get("scan"), dict) else {}
    # default to the options of the original run, so the classification is reproduced
    naming_text = args.naming or str(saved.get("naming_pattern") or "")
    server_text = args.server_regex or str(saved.get("server_pattern") or "")
    args.domain = args.domain or str(saved.get("domain_option") or "")
    try:
        naming = re.compile(naming_text, re.I) if naming_text else None
        server_regex = re.compile(server_text, re.I) if server_text else None
    except re.error as exc:
        print(f"Invalid regular expression in --naming or --server-regex: {exc}")
        return EXIT_USAGE
    if saved:
        saved.update(naming_pattern=naming_text, server_pattern=server_text, domain_option=args.domain,
                     naming=bool(naming))
    for host in hosts:
        host.pop("roles", None)
        rules.classify(host, server_regex)
    rules.link_multihomed(hosts)
    audit["findings"] = rules.build_findings(hosts, meta.get("target_networks") or meta.get("targets", []),
                                             audit.get("local"), naming, args.domain,
                                             saved.get("date") or str(meta.get("started", ""))[:10])
    audit["positives"] = [] if saved.get("interrupted") else rules.build_positives(hosts)
    if saved:
        saved["domain"] = args.domain or rules.infer_domain(hosts)
        audit["limits"] = rules.build_limits(saved, hosts)
    meta["exposure"] = rules.exposure(audit["findings"])
    if args.client:
        meta["client"] = args.client
    # the stored comparison referred to the old findings: redo it against the same baseline, or drop it
    baseline = args.baseline if args.baseline and args.baseline != "auto" else str(meta.get("baseline") or "")
    audit["diff"] = None
    if baseline and not saved.get("interrupted"):
        previous, problem = read_audit_file(baseline)
        if problem:
            print(f"Comparison dropped: {problem}.")
        else:
            try:
                audit["diff"] = rules.diff(previous, audit)
                meta["baseline"] = os.path.abspath(baseline)
            except Exception as exc:
                print(f"Comparison dropped: baseline not usable ({type(exc).__name__}: {exc}).")
    outdir = args.output or os.path.dirname(os.path.abspath(source))
    try:
        paths = report.write_outputs(audit, outdir, ";" if args.csv_delimiter == "semicolon" else ",")
    except OSError as exc:
        print(f"Cannot write the results to {outdir} ({exc.strerror or exc}).")
        return EXIT_USAGE
    counts = {sev: sum(1 for f in audit["findings"] if f["severity"] == sev) for sev in rules.SEVERITIES}
    print(f"Regenerated: {plural(len(hosts), 'host')}, {counts['HIGH']} high, {counts['MEDIUM']} medium, "
          f"{counts['LOW']} low findings.\nReport: {paths['report.html']}")
    return EXIT_FINDINGS if threshold_met(audit["findings"], args.fail_on) else EXIT_OK


def write_demo(args) -> int:
    """Sample report built from fictional data: useful to see the output before a real audit."""
    from . import demo
    audit = demo.build()
    outdir = args.output or os.path.join(os.getcwd(), "reports", "demo")
    try:
        paths = report.write_outputs(audit, outdir, ";" if args.csv_delimiter == "semicolon" else ",")
    except OSError as exc:
        print(f"Cannot write the demo to {outdir} ({exc.strerror or exc}).")
        return EXIT_USAGE
    print(f"Demo report for a fictional network (no network traffic): {paths['report.html']}")
    return EXIT_OK


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if sys.version_info < (3, 9):
        print("NetAudit needs Python 3.9 or later.")
        return EXIT_USAGE
    args = parse_args(argv)
    if args.catalog == "-":
        print(rules.catalog_markdown())
        return EXIT_OK
    if args.catalog:
        try:
            with open(args.catalog, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(rules.catalog_markdown() + "\n")
        except OSError as exc:
            print(f"Cannot write {args.catalog}: {exc}")
            return EXIT_USAGE
        print(f"Findings reference written to {args.catalog}")
        return EXIT_OK
    if args.regenerate:
        return regenerate(args)
    if args.demo:
        return write_demo(args)
    run = Run(args)
    code = prepare(run)
    if code != EXIT_OK:
        return code
    portscan.raise_file_limit()
    print()
    try:
        asyncio.run(collect(run))
    except KeyboardInterrupt:
        run.interrupted = True
        run.warnings.append("The audit was interrupted by the operator: the results are partial.")
        print("\nInterrupted: writing a partial report ...")
    except Exception as exc:  # never lose what was already collected
        run.interrupted = True
        run.warnings.append(f"Unexpected error during collection ({type(exc).__name__}: {exc}): "
                            "the results are partial.")
        print(f"\nUnexpected error ({type(exc).__name__}: {exc}): writing a partial report ...")
    if not run.hosts and run.interrupted:
        print("Nothing was collected: no report written.")
        return EXIT_CANCELLED
    try:
        return finalize(run)
    except Exception as exc:
        # the scan is done and must not be lost to a reporting problem: save the raw data
        reason = f"{type(exc).__name__}: {exc}"
        rescue = os.path.abspath(f"netaudit_rescue_{run.started:%Y-%m-%d_%H%M}.json")
        hosts = []
        for ip in sorted(run.hosts, key=netinfo.ip_key):
            host = dict(run.hosts[ip])
            host.setdefault("ports", [probes.new_record(p) for p in sorted(run.open_ports.get(ip, ()))])
            hosts.append(host)
        # the same shape as audit.json, so that --regenerate can turn it into a report later
        rescued = {"meta": {"tool": "NetAudit", "version": __version__, "schema": 2, "client": run.args.client,
                            "started": run.started.strftime("%Y-%m-%d %H:%M"),
                            "targets": run.target_labels or run.targets, "target_networks": run.targets,
                            "interrupted": run.interrupted,
                            "warnings": run.warnings + [f"Rescued data: the report could not be written at the "
                                                        f"time of the audit ({reason})."],
                            "scan": {"profile": run.args.profile, "speed": run.args.speed,
                                     "ports_per_host": len(K.ports_for(run.args.profile)),
                                     "date": run.started.strftime("%Y-%m-%d"), "interrupted": run.interrupted,
                                     "source_host": socket.gethostname(), "source_ip": run.source,
                                     "excluded": run.exclude_spec, "naming_pattern": run.args.naming,
                                     "server_pattern": run.args.server_regex, "domain_option": run.args.domain,
                                     "local": bool(run.local), "local_errors": run.local_errors}},
                   "hosts": hosts, "findings": [], "positives": [], "limits": [], "local": run.local, "diff": None}
        try:
            with open(rescue, "w", encoding="utf-8") as handle:
                json.dump(rescued, handle, ensure_ascii=False, indent=1, default=str)
            print(f"\nThe report could not be written ({reason}).\nThe collected data was saved to {rescue}\n"
                  f"Build the report from it with:  python -m netaudit --regenerate \"{rescue}\" --output <folder>")
        except Exception:
            print(f"\nThe report could not be written ({reason}) and the collected data could not be saved.")
        return EXIT_CANCELLED
