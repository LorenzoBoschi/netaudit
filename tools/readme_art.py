"""Draws the pictures of the README, so that they follow the code.

    python tools/readme_art.py            banner, pipeline diagram and screenshots
    python tools/readme_art.py --no-shots  the two SVG drawings only

The figures in the banner are read from the program (number of findings in the catalog). The
screenshots are taken from the demo report, which describes a network that does not exist, with
an installed Chrome or Edge in headless mode. Development tool only: NetAudit itself needs neither.
"""
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netaudit import demo, report, rules  # noqa: E402

DOCS = ROOT / "docs"
FONT = "Bahnschrift, 'DIN Alternate', 'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', Arial, sans-serif"
INK, INK2, MUTED, ACCENT, LINK = "#f0efec", "#c3c2b7", "#898781", "#3987e5", "#6da7ec"
HIGH, MEDIUM, LOW, GOOD = "#d03b3b", "#ec835a", "#fab219", "#0ca30c"


def banner() -> str:
    """A subnet drawn as a grid of addresses: most are empty, some answer, a few carry a finding."""
    rnd = random.Random(53)
    cells, columns, rows, size, gap, left, top = [], 23, 10, 14, 6, 762, 46
    lit = {}
    for color, count in ((ACCENT, 15), (GOOD, 4), (LOW, 3), (MEDIUM, 4), (HIGH, 3)):
        while count:
            spot = (rnd.randrange(columns), rnd.randrange(rows))
            if spot not in lit:
                lit[spot] = color
                count -= 1
    for row in range(rows):
        for column in range(columns):
            x, y = left + column * (size + gap), top + row * (size + gap)
            color = lit.get((column, row))
            if color:
                blink = f" class='tw t{(column + row) % 3}'" if (column * 7 + row) % 4 == 0 else ""
                cells.append(f"<rect{blink} x='{x}' y='{y}' width='{size}' height='{size}' rx='3' fill='{color}'/>")
            else:
                cells.append(f"<rect x='{x}' y='{y}' width='{size}' height='{size}' rx='3' fill='#1c1c1b'/>")
    right = left + columns * (size + gap) - gap
    bottom = top + rows * (size + gap) - gap
    tiles = [(f"{len(rules.CATALOG)} findings", "with risk, fix and timeframe"),
             ("0 logins tried", "identification only"),
             ("0 packages", "Python standard library only"),
             ("1 HTML file", "the report, works offline")]
    boxes = []
    for index, (figure, caption) in enumerate(tiles):
        x = 72 + index * 270
        boxes.append(f"<rect x='{x}' y='278' width='250' height='82' rx='12' fill='#161615' stroke='#2c2c2a'/>"
                     f"<text x='{x + 20}' y='316' font-size='28' font-weight='700' fill='{LINK}'>{figure}</text>"
                     f"<text x='{x + 20}' y='343' font-size='16' fill='{INK2}'>{caption}</text>")
    label = "NetAudit: a security audit of the local network from one PC, in one HTML report"
    return f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1280 400' role='img' aria-label='{label}'>
<title>{label}</title>
<defs>
  <radialGradient id='glow' cx='0.82' cy='0.2' r='0.6'>
    <stop offset='0' stop-color='{ACCENT}' stop-opacity='0.20'/><stop offset='1' stop-color='{ACCENT}' stop-opacity='0'/>
  </radialGradient>
  <linearGradient id='beam' x1='0' y1='0' x2='1' y2='0'>
    <stop offset='0' stop-color='{ACCENT}' stop-opacity='0'/><stop offset='1' stop-color='{ACCENT}' stop-opacity='0.55'/>
  </linearGradient>
  <clipPath id='frame'><rect width='1280' height='400' rx='24'/></clipPath>
  <clipPath id='grid'><rect x='{left}' y='{top}' width='{right - left}' height='{bottom - top}'/></clipPath>
</defs>
<style>
  text {{ font-family: {FONT}; }}
  .tw {{ animation: tw 4.5s ease-in-out infinite; }} .t1 {{ animation-delay: -1.5s; }} .t2 {{ animation-delay: -3s; }}
  .sweep {{ animation: sweep 7s linear infinite; }}
  @keyframes tw {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: .45; }} }}
  @keyframes sweep {{ from {{ transform: translateX({left - 60}px); }} to {{ transform: translateX({right}px); }} }}
  @media (prefers-reduced-motion: reduce) {{ .tw, .sweep {{ animation: none !important; }} .sweep {{ opacity: 0; }} }}
</style>
<g clip-path='url(#frame)'>
<rect width='1280' height='400' fill='#0b0b0b'/>
<rect width='1280' height='400' fill='url(#glow)'/>
{''.join(cells)}
<g clip-path='url(#grid)'><g class='sweep'><rect y='{top}' width='60' height='{bottom - top}' fill='url(#beam)'/>
<rect x='59' y='{top}' width='1.5' height='{bottom - top}' fill='{LINK}'/></g></g>
<text x='72' y='134' font-size='66' font-weight='700' letter-spacing='9' fill='{INK}'>NET<tspan fill='{ACCENT}'>AUDIT</tspan></text>
<text x='74' y='184' font-size='25' fill='{INK2}'>A security audit of the local network, from one PC.</text>
<text x='74' y='220' font-size='19' fill='{MUTED}'>Identification only: no logins tried, nothing changed on the network.</text>
{''.join(boxes)}
</g>
</svg>
"""


def pipeline() -> str:
    """How an audit flows: what is collected, how it is judged, what is written."""
    steps = [("Discovery", "ping, TCP probe, ARP table, DNS names"),
             ("Port scan", "two passes, every open port confirmed"),
             ("Identification", "banners, HTTP and TLS, SMB, RDP, LDAP"),
             ("UDP", "NetBIOS names, SNMP 'public', UPnP"),
             ("nmap (optional)", "only on ports left unidentified"),
             ("Scanning workstation", "firewall, antivirus, policies (Windows)")]
    rows, lines = [], []
    for index, (title, text) in enumerate(steps):
        y = 96 + index * 41
        rows.append(f"<text x='270' y='{y}' font-size='13.5' font-weight='600' fill='{INK}'>{title}</text>"
                    f"<text x='270' y='{y + 16}' font-size='11.5' fill='{MUTED}'>{text}</text>")
        if index:
            lines.append(f"M266 {y - 17}H534")
    title = "How a NetAudit run flows"
    desc = ("The operator starts NetAudit on one PC. It collects in six phases from the local network without "
            "logging in or changing anything, applies the rules to classify devices and raise findings, and writes "
            "a results folder. The saved audit.json is the baseline of the next audit.")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 470" role="img" aria-labelledby="t d" font-family="{FONT.replace("'", "")}">
  <title id="t">{title}</title>
  <desc id="d">{desc}</desc>
  <defs>
    <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0 0L10 5L0 10z" fill="{MUTED}"/>
    </marker>
  </defs>
  <rect width="920" height="470" rx="18" fill="#0d0d0d"/>
  <g fill="#1a1a19" stroke="#383835" stroke-width="1.2">
    <rect x="30" y="60" width="160" height="210" rx="10"/>
    <rect x="30" y="340" width="160" height="100" rx="10"/>
    <rect x="610" y="40" width="280" height="130" rx="10"/>
    <rect x="610" y="210" width="280" height="130" rx="10"/>
  </g>
  <rect x="250" y="40" width="300" height="300" rx="12" fill="#16202e" stroke="{ACCENT}" stroke-width="1.6"/>
  <g fill="none" stroke="#383835" stroke-width="1.2" stroke-dasharray="5 4">
    <rect x="250" y="380" width="300" height="60" rx="10"/>
    <rect x="610" y="380" width="280" height="60" rx="10"/>
  </g>
  <g fill="{INK}" font-size="15" font-weight="600" text-anchor="middle">
    <text x="110" y="90">Local network</text>
    <text x="110" y="370">Operator</text>
    <text x="400" y="68" fill="{LINK}">Collection</text>
    <text x="750" y="68">Rules</text>
    <text x="750" y="238">Results folder</text>
  </g>
  <g fill="{MUTED}" font-size="12.5" text-anchor="middle">
    <text x="110" y="118">hosts, open ports,</text>
    <text x="110" y="136">services</text>
    <text x="110" y="172">no login is tried</text>
    <text x="110" y="190">nothing is changed</text>
    <text x="110" y="226">print ports are</text>
    <text x="110" y="244">never sent data</text>
    <text x="110" y="394">python -m netaudit</text>
    <text x="110" y="412">or Run_audit.bat,</text>
    <text x="110" y="430">declares authorization</text>
    <text x="750" y="94">classify every device</text>
    <text x="750" y="112">{len(rules.CATALOG)} findings: risk, action,</text>
    <text x="750" y="130">timeframe, ATT&amp;CK technique</text>
    <text x="750" y="152">exposure index 0-100</text>
    <text x="750" y="264">report.html, self-contained</text>
    <text x="750" y="282">audit.json, all the data</text>
    <text x="750" y="300">inventory.csv, findings.csv</text>
    <text x="750" y="318">summary.md, audit.log</text>
    <text x="400" y="406">Ctrl+C or a change of network:</text>
    <text x="400" y="424">a report marked as partial is still written</text>
    <text x="750" y="406">audit.json is the --baseline of the next</text>
    <text x="750" y="424">audit, or the input of --regenerate</text>
  </g>
  {''.join(rows)}
  <g stroke="#2a3a52" stroke-width="1"><path d="{''.join(lines)}"/></g>
  <g stroke="{MUTED}" stroke-width="1.4" fill="none" marker-end="url(#a)">
    <path d="M192 165H248" marker-start="url(#a)"/>
    <path d="M190 390H220V318H248"/>
    <path d="M550 105H608"/>
    <path d="M750 170V208"/>
    <path d="M750 340V378" stroke-dasharray="5 4"/>
    <path d="M400 340V378" stroke-dasharray="5 4"/>
  </g>
</svg>
"""


def find_browser() -> str:
    candidates = [shutil.which(name) for name in ("chrome", "google-chrome", "chromium", "msedge")]
    for base in (os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
                 os.environ.get("LOCALAPPDATA", "")):
        if base:
            candidates += [os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                           os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")]
    candidates.append("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    return next((path for path in candidates if path and os.path.exists(path)), "")


def screenshots() -> list[str]:
    """Pictures of the demo report: the top in light and dark, and the findings."""
    browser = find_browser()
    if not browser:
        print("No Chrome or Edge found: screenshots skipped.")
        return []
    made = []
    with tempfile.TemporaryDirectory() as work:
        page = report.render(demo.build())
        light = pathlib.Path(work, "report.html")
        dark = pathlib.Path(work, "report-dark.html")
        findings = pathlib.Path(work, "report-findings.html")
        light.write_text(page, encoding="utf-8")
        dark.write_text(page.replace("<html lang='en'>", "<html lang='en' data-theme='dark'>", 1), encoding="utf-8")
        # a headless screenshot starts at the top of the page: hide what comes before the findings
        findings.write_text(page.replace("</head>", "<style>main > *:has(~ #findings){display:none}"
                                                    "#findings{margin-top:0}</style></head>", 1), encoding="utf-8")
        shots = [("report.png", light.as_uri(), "1400,1000"), ("report-dark.png", dark.as_uri(), "1400,1000"),
                 ("findings.png", findings.as_uri(), "1400,1000")]
        for name, url, size in shots:
            target = DOCS / name
            subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                            f"--user-data-dir={pathlib.Path(work, 'profile')}", f"--window-size={size}",
                            f"--screenshot={target}", url],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
            if target.exists():
                made.append(name)
    return made


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    for name, text in (("banner.svg", banner()), ("pipeline.svg", pipeline())):
        (DOCS / name).write_text(text, encoding="utf-8", newline="\n")
        print("drawn", name)
    if "--no-shots" not in sys.argv:
        for name in screenshots():
            print("taken", name)


if __name__ == "__main__":
    main()
