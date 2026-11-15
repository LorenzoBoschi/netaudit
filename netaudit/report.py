"""Outputs: self-contained HTML report, full JSON, CSV files and a short text summary."""
from __future__ import annotations

import csv
import html
import json
import os
import re

from . import __version__
from . import rules

SEV_CLASS = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
SEV_LABEL = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
# shape + label, so severity never relies on color alone
SEV_ICON = {
    "HIGH": "<svg viewBox='0 0 12 12' aria-hidden='true'><path d='M6 1 11.2 10.5H.8z'/></svg>",
    "MEDIUM": "<svg viewBox='0 0 12 12' aria-hidden='true'><path d='M6 .8 11.2 6 6 11.2.8 6z'/></svg>",
    "LOW": "<svg viewBox='0 0 12 12' aria-hidden='true'><circle cx='6' cy='6' r='4.6'/></svg>",
}

_CSS = """
:root{color-scheme:light;
 --page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#6b6a65;--grid:#e1e0d9;--axis:#c3c2b7;
 --border:rgba(11,11,11,.10);--accent:#2a78d6;--link:#1c5cab;--wash:#eef3fb;
 --high:#d03b3b;--medium:#ec835a;--low:#fab219;--good:#0ca30c;--spine:#0b0b0b;--spine-ink:#f0efec;--spine-mute:#898781;
 --display:"Bahnschrift","DIN Alternate","Avenir Next Condensed","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
 --body:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",sans-serif;
 --mono:"Cascadia Mono","Cascadia Code",Consolas,"SF Mono",Menlo,monospace}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;
 --page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;
 --border:rgba(255,255,255,.10);--accent:#3987e5;--link:#6da7ec;--wash:#16202e;--spine:#141413;--spine-ink:#f0efec}}
:root[data-theme="dark"]{color-scheme:dark;
 --page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;
 --border:rgba(255,255,255,.10);--accent:#3987e5;--link:#6da7ec;--wash:#16202e;--spine:#141413;--spine-ink:#f0efec}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:20px}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 var(--body);-webkit-font-smoothing:antialiased;overflow-wrap:break-word}
h1,.meta dd,.spine .client,.host summary>*,.facts,.finding h3{min-width:0;overflow-wrap:anywhere}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.mono,code{font-family:var(--mono);font-size:.92em}
code{background:var(--wash);padding:1px 5px;border-radius:3px}
.layout{display:grid;grid-template-columns:248px minmax(0,1fr);min-height:100vh}
.spine{background:var(--spine);color:var(--spine-ink);padding:28px 22px;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;gap:22px}
.wordmark{font:700 19px/1 var(--display);letter-spacing:.16em}
.wordmark i{font-style:normal;color:var(--accent)}
.spine .client{font:600 15px/1.3 var(--display);letter-spacing:.02em;border-top:1px solid rgba(255,255,255,.16);padding-top:14px}
.spine .client small{display:block;font:400 12px/1.5 var(--body);color:var(--spine-mute);letter-spacing:0;margin-top:3px}
.spine nav{display:flex;flex-direction:column;gap:1px}
.spine nav a{color:var(--spine-ink);display:flex;gap:11px;align-items:baseline;padding:6px 8px;margin:0 -8px;border-radius:5px;font-size:13.5px}
.spine nav a:hover{background:rgba(255,255,255,.08);text-decoration:none}
.spine nav a span{font:11px var(--mono);color:var(--spine-mute);min-width:16px}
.tally{display:grid;gap:7px;font-size:13px;border-top:1px solid rgba(255,255,255,.16);padding-top:14px}
.tally div{display:flex;align-items:center;gap:9px}.tally b{margin-left:auto;font:600 14px var(--mono)}
.spine .foot{margin-top:auto;font:10.5px/1.6 var(--mono);letter-spacing:.08em;color:var(--spine-mute);text-transform:uppercase}
.themebtn{background:none;border:1px solid rgba(255,255,255,.22);color:var(--spine-ink);border-radius:5px;padding:5px 9px;font:12px var(--body);cursor:pointer;margin-bottom:12px}
.themebtn:hover{background:rgba(255,255,255,.08)}
main{padding:0 44px 60px;max-width:1180px;width:100%}
.strip{font:11px var(--mono);letter-spacing:.2em;text-transform:uppercase;color:var(--ink2);border-bottom:1px solid var(--ink);padding:26px 0 10px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
.cover h1{font:700 clamp(34px,5vw,58px)/1.02 var(--display);letter-spacing:-.01em;margin:30px 0 8px}
.cover .lede{font-size:18px;color:var(--ink2);margin:0 0 26px}
.meta{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;margin:0;border-top:1px solid var(--grid)}
.meta div{padding:11px 16px 11px 0;border-bottom:1px solid var(--grid)}
.meta dt{font:10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.meta dd{margin:2px 0 0;font-weight:600}
h2{font:700 25px/1.15 var(--display);letter-spacing:.01em;margin:58px 0 20px;padding-top:16px;border-top:1px solid var(--ink);display:flex;gap:14px;align-items:baseline}
h2 .num{font:500 12px var(--mono);letter-spacing:.14em;color:var(--muted)}
h3{font:600 17px/1.3 var(--display);letter-spacing:.01em;margin:0}
h4{font:10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:0 0 5px;font-weight:500}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px 22px}
.notice{border-left:4px solid var(--low);margin:22px 0 0}
.grid{display:grid;gap:14px;margin-top:14px}.g2{grid-template-columns:repeat(auto-fit,minmax(min(330px,100%),1fr))}
.summary-top{grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);margin-top:0}
.facts2{display:grid;grid-template-columns:1fr auto;gap:0;margin:8px 0 0;font-size:13.5px}
.facts2 dt,.facts2 dd{padding:7px 0;border-top:1px solid var(--grid);margin:0}.facts2 dt{color:var(--ink2)}
.facts2 dd{font:600 13px var(--mono);text-align:right}.facts2 dt:first-of-type,.facts2 dd:first-of-type{border-top:0}
.sub{margin-top:20px}
.hero .figure{font:600 68px/1 var(--body);letter-spacing:-.02em;margin:6px 0 2px}
.hero .figure small{font:500 17px var(--body);color:var(--muted);letter-spacing:0}
.hero .rating{display:flex;align-items:center;gap:8px;font-weight:600;margin-bottom:14px}
.meter{height:8px;border-radius:99px;background:color-mix(in srgb,var(--sev) 20%,var(--surface));overflow:hidden}
.meter i{display:block;height:100%;border-radius:99px;background:var(--sev)}
.hero p{font-size:12.5px;color:var(--muted);margin:12px 0 0}
.tiles{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.tile{display:flex;flex-direction:column;justify-content:center}
.tile .v{font:600 34px/1.1 var(--body);margin-top:4px}
.tile .k{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--ink2)}
.dot{width:10px;height:10px;display:inline-block;flex:none}.dot svg{width:10px;height:10px;display:block;fill:var(--c)}
.c-high{--c:var(--high)}.c-medium{--c:var(--medium)}.c-low{--c:var(--low)}.c-good{--c:var(--good)}.c-none{--c:var(--axis)}
.segbar{display:flex;gap:2px;height:28px;margin:12px 0 10px}
.segbar span{border-radius:4px;min-width:6px;display:flex;align-items:center;padding-left:9px;font:600 13px var(--body);color:#fff;background:var(--c);overflow:visible;white-space:nowrap}
.segbar .c-low,.segbar .c-medium{color:#0b0b0b}
.legend{display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px;color:var(--ink2)}.legend span{display:flex;align-items:center;gap:6px}
.bars{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:8px 12px;align-items:center;margin-top:12px;font-size:13.5px}
.bars .track{display:flex;align-items:center;gap:8px}
.bars .bar{height:12px;border-radius:0 4px 4px 0;background:var(--accent);min-width:3px}
.bars .n{font:600 13px var(--mono);color:var(--ink)}
.prio{margin:10px 0 0;padding:0;list-style:none}
.prio li{display:flex;gap:10px;align-items:baseline;padding:8px 0;border-top:1px solid var(--grid);font-size:14px}
.prio li:first-child{border-top:0}.prio .fid{min-width:30px}.prio .count{margin-left:auto;color:var(--muted);font-size:12.5px;white-space:nowrap}
.fid{font:600 12.5px var(--mono);color:var(--ink2)}
.chip{display:inline-flex;align-items:center;gap:5px;font:700 10.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;padding:3px 8px 3px 6px;border-radius:4px;background:var(--c);color:#fff;vertical-align:middle}
.chip svg{width:9px;height:9px;fill:currentColor}.chip.c-low,.chip.c-medium{color:#0b0b0b}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.fbtn{font:13px var(--body);padding:6px 13px;border-radius:99px;border:1px solid var(--axis);background:var(--surface);color:var(--ink);cursor:pointer}
.fbtn[aria-pressed="true"]{background:var(--ink);color:var(--page);border-color:var(--ink)}
.search{font:14px var(--body);padding:8px 12px;border:1px solid var(--axis);border-radius:6px;background:var(--surface);color:var(--ink);min-width:260px}
.finding{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:8px;padding:18px 22px;margin-bottom:12px}
.finding header{display:flex;gap:11px;align-items:center;flex-wrap:wrap}
.tags{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 14px}
.tags span{font:11.5px var(--mono);color:var(--ink2);border:1px solid var(--grid);border-radius:4px;padding:2px 7px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(270px,100%),1fr));gap:18px}
.cols p{margin:0;font-size:14.5px}
details>summary{cursor:pointer;font-weight:600;font-size:13.5px;list-style:none;display:flex;align-items:center;gap:8px}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"";width:6px;height:6px;border-right:1.5px solid var(--ink2);border-bottom:1.5px solid var(--ink2);transform:rotate(-45deg);transition:transform .15s;flex:none}
details[open]>summary::before{transform:rotate(45deg)}
.evidence{margin-top:14px;border-top:1px solid var(--grid);padding-top:12px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:8px 12px 8px 0;border-bottom:1px solid var(--grid);vertical-align:top}
th{font:500 10.5px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted);white-space:nowrap}
tr:last-child td{border-bottom:0}
td.ip,td.num{font-family:var(--mono);font-size:12.5px;white-space:nowrap;font-variant-numeric:tabular-nums}
th[data-sort]{cursor:pointer}th[data-sort]:hover,th[data-sort]:focus-visible{color:var(--ink)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.legendnote{margin:0 0 14px}
.scroll{overflow-x:auto}
.evidence table{margin-top:8px}
.plan{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:14px}
.plan ol{margin:10px 0 0;padding:0;list-style:none}
.plan li{padding:9px 0;border-top:1px solid var(--grid);font-size:13.5px}
.plan li b{display:block;font-size:14px;font-weight:600}
.checks{list-style:none;margin:0;padding:0}.checks li{display:flex;gap:10px;padding:7px 0;border-top:1px solid var(--grid)}.checks li:first-child{border-top:0}
.checks svg{width:16px;height:16px;flex:none;margin-top:3px;fill:none;stroke:var(--good);stroke-width:2.2}
.limits{margin:0;padding-left:18px;color:var(--ink2)}.limits li{margin:6px 0}
.minibar{display:flex;align-items:center;gap:8px;white-space:nowrap}.minibar i{display:block;height:8px;border-radius:0 4px 4px 0;background:var(--accent);min-width:3px;flex:none}
.marks{display:inline-flex;gap:9px;font:12px var(--mono);color:var(--ink2);white-space:nowrap}.marks span{display:inline-flex;align-items:center;gap:4px}
.overview{font-size:17px;line-height:1.6;max-width:78ch;margin:0 0 20px}
.guide{margin-top:14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 22px}
.guide dl{margin:12px 0 2px;display:grid;grid-template-columns:minmax(120px,max-content) minmax(0,1fr);gap:10px 22px;font-size:14px}
.guide dt{font:10.5px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--muted);padding-top:3px}
.guide dd{margin:0}
.nowrap{white-space:nowrap}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.host{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:11px 16px;margin-bottom:6px}
.host summary .mono{min-width:112px}.host summary em{font-style:normal;color:var(--ink2);font-weight:400}
.host .facts{color:var(--ink2);font-size:13px;margin:10px 0 6px}
.note{color:var(--muted);font-size:13px}
.kv th{width:240px;text-transform:none;letter-spacing:0;font:500 13.5px var(--body);color:var(--ink2)}
footer{margin-top:54px;padding-top:14px;border-top:1px solid var(--ink);font:11px/1.7 var(--mono);color:var(--muted);letter-spacing:.04em}
[hidden]{display:none!important}
main{min-width:0}
@media (max-width:980px){.layout{grid-template-columns:minmax(0,1fr)}.spine{position:static;height:auto;padding:18px 20px;gap:12px}.spine nav,.spine .foot,.tally{display:none}main{padding:0 18px 40px}.summary-top{grid-template-columns:minmax(0,1fr)}.meta{grid-template-columns:repeat(2,minmax(0,1fr))}.search{min-width:0;width:100%}}
@media print{:root,:root[data-theme]{color-scheme:light;--page:#fff;--surface:#fff;--ink:#0b0b0b;--ink2:#52514e;--muted:#6b6a65;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.14);--accent:#2a78d6;--link:#0b0b0b;--wash:#eef3fb}
 .layout{display:block}.spine,.filters,.themebtn{display:none!important}main{padding:0;max-width:none}.scroll{overflow:visible}
 body{font-size:11.5px}.finding,.host,.panel{break-inside:avoid}h2{break-after:avoid;margin-top:34px}
 .segbar span,.chip,.meter i,.bars .bar,.minibar i,.dot svg{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

_JS = """
(function(){
 var root=document.documentElement,btn=document.getElementById('theme');
 if(btn){btn.addEventListener('click',function(){
  var dark=root.getAttribute('data-theme')?root.getAttribute('data-theme')==='dark':matchMedia('(prefers-color-scheme:dark)').matches;
  root.setAttribute('data-theme',dark?'light':'dark');});}
 var sevButtons=document.querySelectorAll('.fbtn[data-sev]');
 sevButtons.forEach(function(b){b.addEventListener('click',function(){
  sevButtons.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});
  var want=b.getAttribute('data-sev');
  document.querySelectorAll('.finding').forEach(function(f){f.hidden=want!=='ALL'&&f.getAttribute('data-sev')!==want;});});});
 var q=document.getElementById('q'),rows=[].slice.call(document.querySelectorAll('#inv tbody tr'));
 if(q){q.addEventListener('input',function(){var t=q.value.toLowerCase();var n=0;
  rows.forEach(function(r){var hit=r.textContent.toLowerCase().indexOf(t)>-1;r.hidden=!hit;if(hit)n++;});
  var c=document.getElementById('qn');if(c)c.textContent=n+' of '+rows.length+(rows.length===1?' host':' hosts');});}
 document.querySelectorAll('#inv th[data-sort]').forEach(function(th){var asc=true;
  var sort=function(){var body=document.querySelector('#inv tbody');
   var key=function(r){var c=r.children[th.cellIndex];return c.getAttribute('data-k')||c.textContent.trim().toLowerCase();};
   [].slice.call(body.rows).sort(function(a,b){var x=key(a),y=key(b);return (x<y?-1:x>y?1:0)*(asc?1:-1);})
    .forEach(function(r){body.appendChild(r);});
   th.setAttribute('aria-sort',asc?'ascending':'descending');asc=!asc;};
  th.addEventListener('click',sort);
  th.addEventListener('keydown',function(ev){if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();sort();}});});
 window.addEventListener('beforeprint',function(){[].forEach.call(document.querySelectorAll('details'),function(d){d.open=true;});});
 var all=document.getElementById('toggleHosts');
 if(all){all.addEventListener('click',function(){var d=document.querySelectorAll('details.host');
  var open=[].some.call(d,function(x){return !x.open;});[].forEach.call(d,function(x){x.open=open;});
  all.textContent=open?'Collapse all':'Expand all';});}
 var reveal=function(){var el=null;try{el=document.getElementById(decodeURIComponent(location.hash.slice(1)));}catch(err){}
  if(el&&el.tagName==='DETAILS'){el.open=true;el.scrollIntoView();}
  if(el&&el.classList.contains('finding')){el.hidden=false;}};
 window.addEventListener('hashchange',reveal);reveal();
})();
"""


def e(value) -> str:
    return html.escape("" if value is None else str(value))


def _dot(severity: str) -> str:
    return f"<span class='dot c-{SEV_CLASS[severity]}'>{SEV_ICON[severity]}</span>"


def _chip(severity: str) -> str:
    return f"<span class='chip c-{SEV_CLASS[severity]}'>{SEV_ICON[severity]}{SEV_LABEL[severity]}</span>"


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _header(*labels: str) -> str:
    return "<thead><tr>" + "".join(f"<th scope='col'>{label}</th>" for label in labels) + "</tr></thead>"


def _port_list(host: dict, limit: int = 40) -> str:
    records = host.get("ports", [])
    static = [rec["port"] for rec in records if not str(rec.get("service", "")).startswith("Dynamic RPC")]
    dynamic = len(records) - len(static)
    text = ", ".join(map(str, static[:limit]))
    if len(static) > limit:
        text += f" ... (+{len(static) - limit})"
    if dynamic:
        text += (" + " if text else "") + f"{dynamic} dynamic RPC"
    return text or "none"


def _ip_sort_key(ip: str) -> str:
    try:
        return "".join(f"{int(part):03d}" for part in ip.split("."))
    except ValueError:
        return ip


def _host_anchor(ip: str) -> str:
    return "host-" + "".join(ch if ch.isalnum() else "-" for ch in str(ip))


def _ip_link(ip: str, known) -> str:
    """The address, linked to its entry in the appendix when it is one of the audited hosts."""
    return f"<a href='#{_host_anchor(ip)}'>{e(ip)}</a>" if ip in known else e(ip)


def _finding_html(finding: dict, known=()) -> str:
    hosts = finding["hosts"]
    severity = finding["severity"]
    scope = "segment" if finding["key"] == "flat" else "host"
    rows = "".join(f"<tr><td class='ip'>{_ip_link(h['ip'], known)}</td><td>{e(h.get('name')) or '-'}</td>"
                   f"<td>{e(h.get('evidence'))}</td></tr>" for h in hosts)
    tags = [f"Affects {_plural(len({h['ip'] for h in hosts}), scope)}",
            "Fix: " + rules.WHEN_LABEL.get(finding["when"], finding["when"])]
    if finding.get("attack"):
        tags.append("MITRE ATT&CK " + finding["attack"])
    return (f"<article class='finding c-{SEV_CLASS[severity]}' id='{finding['id']}' data-sev='{severity}'>"
            f"<header>{_chip(severity)}<span class='fid'>{finding['id']}</span><h3>{e(finding['title'])}</h3></header>"
            f"<div class='tags'>{''.join(f'<span>{e(t)}</span>' for t in tags)}</div>"
            f"<div class='cols'><div><h4>Risk</h4><p>{e(finding['risk'])}</p></div>"
            f"<div><h4>Recommended action</h4><p>{e(finding['action'])}</p></div></div>"
            f"<details class='evidence'{' open' if len(hosts) <= 5 else ''}><summary>Evidence ({len(hosts)})</summary>"
            f"<div class='scroll'><table>{_header('Address', 'Host', 'Observed')}{rows}</table></div>"
            f"</details></article>")


def _overview(meta: dict, hosts: list, findings: list, counts: dict) -> str:
    """Two or three plain sentences for a reader who will read nothing else."""
    total = sum(counts.values())
    scope = ", ".join(meta.get("targets") or []) or "the network"
    parts = [f"This audit examined {e(scope)} and found {_plural(len(hosts), 'device')}."]
    if meta.get("interrupted"):
        parts.append("<b>It was interrupted before completion, so the picture below is partial.</b>")
    if not total:
        parts.append("The checks performed raised no findings. That is a good sign within the limits listed at "
                     "the end of this report; it is not proof that the network is secure.")
    else:
        split = ", ".join(f"{counts[s]} {SEV_LABEL[s].lower()}" for s in rules.SEVERITIES if counts[s])
        parts.append(f"It raised {_plural(total, 'finding')} ({split}).")
        high = [f for f in findings if f["severity"] == "HIGH"]
        if high:
            widest = max(high, key=lambda f: len({h["ip"] for h in f["hosts"]}))
            spread = len({h["ip"] for h in widest["hosts"]})
            where = "one network segment" if widest["key"] == "flat" else _plural(spread, "host")
            parts.append(f"The most widespread high finding is <a href='#{widest['id']}'>{e(widest['title'])}</a>, "
                         f"affecting {where}.")
            parts.append("Start with the items listed under <a href='#plan'>This week</a> in the remediation plan.")
        else:
            parts.append("None is rated high: work through the <a href='#plan'>remediation plan</a> in order.")
    return f"<p class='overview'>{' '.join(parts)}</p>"


_READING_GUIDE = (
    "<details class='guide'><summary>How to read this report</summary><dl>"
    "<dt>Severity</dt><dd><b>High</b>: on its own this can lead to the compromise of systems or the loss of data, "
    "or it removes a barrier attackers rely on being there. <b>Medium</b>: it makes an attack easier or wider but "
    "needs another weakness to be exploited. <b>Low</b>: a hygiene issue worth fixing when convenient.</dd>"
    "<dt>Timeframe</dt><dd>A suggestion based on risk against effort: <i>This week</i> for quick, high-value "
    "fixes, <i>Within 30 days</i> for work that needs planning, <i>Longer term</i> for changes to the network "
    "design.</dd>"
    "<dt>Exposure index</dt><dd>A figure from 0 (no findings) to 100 that grows with the number, severity and "
    "spread of the findings; higher is worse. The word beside it is only a band: Minimal below 25, Limited "
    "from 25, Elevated from 50, Severe from 75. It has meaning when compared with a previous audit of the same "
    "network. Findings about the scanning workstation do not count towards it.</dd>"
    "<dt>Weight</dt><dd>In <i>Most exposed hosts</i>, each high finding on a host counts 10, each medium 4 and "
    "each low 1: the table shows where fixing things pays off first.</dd>"
    "<dt>Evidence</dt><dd>Every finding lists where it was observed and what was seen. Evidence marked "
    "<i>by port number</i> means a port was open but the service behind it did not identify itself: confirm it "
    "on the device before acting.</dd>"
    "<dt>MITRE ATT&amp;CK</dt><dd>The code of the attacker technique the finding relates to, from the public "
    "ATT&amp;CK knowledge base. It helps security staff look up how the weakness is used in real attacks.</dd>"
    "<dt>What this audit is not</dt><dd>It looks at the network from one point inside it, without logging in to "
    "anything. It does not test passwords, measure patch levels or look at the Internet-facing side. See "
    "<a href='#limits'>Limitations</a>.</dd></dl></details>")


def _host_detail(host: dict) -> str:
    rows = []
    for rec in host.get("ports", []):
        details = []
        if rec.get("info"):
            details.append(rec["info"])
        http = rec.get("http") or {}
        if http.get("status"):
            details.append(f"HTTP {http['status']}")
        tls = rec.get("tls") or {}
        if tls.get("cn") or tls.get("version"):
            cert = f"{tls.get('version', '')} certificate '{tls.get('cn', '?')}'"
            if tls.get("issuer_cn"):
                cert += f" issued by '{tls['issuer_cn']}'"
            if tls.get("not_after"):
                cert += f", expires {tls['not_after']}"
            details.append(cert.strip())
        vnc = rec.get("vnc") or {}
        if vnc:
            details.append(f"VNC security types: {vnc.get('types')}")
        if rec.get("outdated"):
            details.append(rec["outdated"])
        rows.append(f"<tr><td class='num'>{rec['port']}</td><td>{e(rec.get('service'))}</td>"
                    f"<td>{e(rec.get('product'))}</td><td>{e('; '.join(dict.fromkeys(details)))}</td>"
                    f"<td class='mono'>{e(rec.get('source'))}</td></tr>")
    facts = []
    if host.get("mac"):
        facts.append(f"MAC {host['mac']} ({host.get('vendor') or 'unknown vendor'})")
    if host.get("alive_by"):
        facts.append("found via " + ", ".join(host["alive_by"]))
    ntlm = (host.get("smb") or {}).get("ntlm") or {}
    if ntlm:
        facts.append("SMB identity: " + ", ".join(f"{k}={v}" for k, v in ntlm.items()
                                                  if k in ("netbios_name", "dns_name", "dns_domain", "build")))
    nbns = host.get("nbns") or {}
    if nbns:
        facts.append("NetBIOS: " + ", ".join(f"{k}={v}" for k, v in nbns.items()))
    if host.get("snmp"):
        facts.append("SNMP sysDescr: " + host["snmp"])
    ssdp = host.get("ssdp") or {}
    if ssdp:
        facts.append("UPnP: " + (ssdp.get("server") or "device")
                     + f" ({_plural(len(ssdp.get('types', [])), 'service type')})")
    quality = {"partial": "scan interrupted, partial coverage",
               "intermittent": "answers intermittently under scan"}.get(host.get("scan_quality", ""))
    if quality:
        facts.append("note: " + quality)
    table = ("<div class='scroll'><table>" + _header("Port", "Service", "Product", "Details", "Source")
             + "".join(rows) + "</table></div>") if rows else \
        "<p class='note'>No open TCP port found.</p>"
    return (f"<details class='host' id='{_host_anchor(host['ip'])}'><summary><span class='mono'>{e(host['ip'])}</span>"
            f"<span>{e(rules.display_name(host) or '-')}</span><em>{e(host.get('type'))}</em></summary>"
            f"<p class='facts'>{e(' | '.join(facts))}</p>{table}</details>")


def render(audit: dict) -> str:
    meta, hosts, findings = audit["meta"], audit["hosts"], audit["findings"]
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in rules.SEVERITIES}
    exposure = rules.exposure(findings)
    scores = rules.host_scores(findings)
    refs: dict[str, list[dict]] = {}
    for finding in findings:
        for ip in dict.fromkeys(item["ip"] for item in finding["hosts"]):
            refs.setdefault(ip, []).append(finding)
    client = meta.get("client") or meta.get("cliente") or ""
    started = meta.get("started", "")
    known = {host["ip"] for host in hosts}
    sections: list[tuple[str, str]] = []
    body: list[str] = []

    def section(anchor: str, title: str) -> None:
        sections.append((anchor, title))
        body.append(f"<h2 id='{anchor}'><span class='num'>{len(sections):02d}</span>{e(title)}</h2>")

    # ---- cover
    cover = ["<header class='cover'><div class='strip'><span>Confidential &middot; Network security assessment</span>"
             f"<span>{e(started)}</span></div>",
             f"<h1>{e(client) or 'Network security audit'}</h1>",
             f"<p class='lede'>Network security audit of {e(', '.join(meta.get('targets', [])))}</p>",
             "<dl class='meta'>"]
    for label, value in (("Date", started), ("Operator", meta.get("operator") or meta.get("operatore")),
                         ("Vantage point", meta.get("source")), ("Profile", meta.get("profile")),
                         ("Duration", meta.get("duration")),
                         ("Method", "Identification only, no login attempts")):
        if value:
            cover.append(f"<div><dt>{label}</dt><dd>{e(value)}</dd></div>")
    cover.append("</dl></header>")
    for warning in meta.get("warnings") or []:
        cover.append(f"<div class='panel notice'><b>Attention:</b> {e(warning)}</div>")

    # ---- summary
    section("summary", "Executive summary")
    body.append(_overview(meta, hosts, findings, counts))
    rating_class = {"Severe": "high", "Elevated": "high", "Limited": "medium"}.get(exposure["rating"], "good")
    sev_var = {"high": "var(--high)", "medium": "var(--medium)", "good": "var(--good)"}[rating_class]
    hero = (f"<div class='panel hero' style='--sev:{sev_var}'><h4>Exposure index</h4>"
            f"<div class='figure'>{exposure['score']}<small> / 100</small></div>"
            f"<div class='rating'><span class='dot c-{rating_class}'>{SEV_ICON['LOW']}</span>{e(exposure['rating'])} exposure</div>"
            f"<div class='meter' role='img' aria-label='Exposure index {exposure['score']} of 100'>"
            f"<i style='width:{max(exposure['score'], 2)}%'></i></div>"
            "<p>0 means no findings; higher is worse. The figure grows with the severity and spread of the "
            "findings and is meant for tracking progress between audits of this network, not as an absolute "
            "measure.</p></div>")
    tiles = [f"<div class='panel tile'><div class='k'>Hosts found</div><div class='v'>{len(hosts)}</div></div>"]
    for severity in rules.SEVERITIES:
        tiles.append(f"<div class='panel tile'><div class='k'>{_dot(severity)}{SEV_LABEL[severity]} findings</div>"
                     f"<div class='v'>{counts[severity]}</div></div>")
    total = sum(counts.values())
    dist = ["<div class='panel'><h4>Findings by severity</h4>"]
    if total:
        dist.append("<div class='segbar' role='img' aria-label='" + ", ".join(
            f"{counts[s]} {SEV_LABEL[s].lower()}" for s in rules.SEVERITIES) + "'>")
        for severity in rules.SEVERITIES:
            if counts[severity]:
                share = counts[severity] / total * 100
                dist.append(f"<span class='c-{SEV_CLASS[severity]}' style='width:{share:.2f}%' "
                            f"title='{SEV_LABEL[severity]}: {counts[severity]} of {total}'>"
                            f"{counts[severity] if share >= 7 else ''}</span>")
        dist.append("</div><div class='legend'>" + "".join(
            f"<span>{_dot(s)}{SEV_LABEL[s]}</span>" for s in rules.SEVERITIES if counts[s]) + "</div>")
    else:
        dist.append("<p class='note'>No findings with the checks performed.</p>")
    dist.append("</div>")
    types: dict[str, int] = {}
    for host in hosts:
        label = rules.LABELS.get(host.get("category", "unknown"), "Unidentified")
        types[label] = types.get(label, 0) + 1
    top = max(types.values(), default=1)
    device = ["<div class='panel'><h4>Devices by type</h4><div class='bars'>"]
    for label, number in sorted(types.items(), key=lambda kv: (-kv[1], kv[0])):
        device.append(f"<span>{e(label)}</span><div class='track' title='{e(label)}: {number}'>"
                      f"<span class='bar' style='width:{number / top * 78:.1f}%'></span><span class='n'>{number}</span></div>")
    device.append("</div></div>")
    high = [f for f in findings if f["severity"] == "HIGH"] or findings[:5]
    dist.pop()  # the priorities continue inside the severity panel
    prio = dist + ["<h4 class='sub'>Top priorities</h4>"]
    if high:
        prio.append("<ul class='prio'>" + "".join(
            f"<li>{_dot(f['severity'])}<a class='fid' href='#{f['id']}'>{f['id']}</a><span>{e(f['title'])}</span>"
            f"<span class='count'>{_plural(len({h['ip'] for h in f['hosts']}), 'segment' if f['key'] == 'flat' else 'host')}</span></li>"
            for f in high[:7]) + "</ul>")
        if len(high) > 7:
            prio.append(f"<p class='note'>... and {_plural(len(high) - 7, 'more high finding')}: see "
                        "<a href='#findings'>Findings</a>.</p>")
    else:
        prio.append("<p class='note'>Nothing to prioritize.</p>")
    prio.append("</div>")
    by_ip = {h["ip"]: h for h in hosts}
    ranked = sorted(((ip, s) for ip, s in scores.items() if ip in by_ip), key=lambda kv: -kv[1]["score"])[:8]
    exposed = ["<div class='panel'><h4>Most exposed hosts</h4>"]
    if ranked:
        peak = ranked[0][1]["score"] or 1
        exposed.append("<div class='scroll'><table>" + _header("Address", "Host", "Findings", "Weight"))
        for ip, score in ranked:
            marks = "".join(f"<span title='{score[s]} {SEV_LABEL[s].lower()}'>{_dot(s)}{score[s]}"
                            f"<span class='sr'> {SEV_LABEL[s].lower()}</span></span>"
                            for s in rules.SEVERITIES if score[s])
            exposed.append(f"<tr><td class='ip'>{_ip_link(ip, known)}</td><td class='nowrap'>{e(rules.display_name(by_ip[ip]) or '-')}</td>"
                           f"<td><span class='marks'>{marks}</span></td>"
                           f"<td><div class='minibar' title='Weight {score['score']}'>"
                           f"<i style='width:{score['score'] / peak * 48:.1f}px'></i><span class='mono'>{score['score']}</span></div></td></tr>")
        exposed.append("</table></div>")
    else:
        exposed.append("<p class='note'>No host-level findings.</p>")
    exposed.append("</div>")
    records = [rec for host in hosts for rec in host.get("ports", [])]
    answered = sum(1 for rec in records if rec.get("source") not in ("", "port"))
    scan = meta.get("scan") or {}
    ports_checked = scan.get("ports_per_host")
    facts = [("Hosts found", len(hosts)), ("Open TCP ports", len(records)),
             ("Services that answered a probe", answered),
             ("Attributed by port number only", len(records) - answered),
             ("Hosts identified over SMB", sum(1 for h in hosts if (h.get("smb") or {}).get("ntlm"))),
             ("TCP ports checked per host", f"{ports_checked:,}" if isinstance(ports_checked, int) else "-")]
    coverage = ("<div class='panel'><h4>Coverage</h4><dl class='facts2'>" + "".join(
        f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in facts) + "</dl></div>")
    body.append(f"<div class='grid summary-top'>{hero}<div class='tiles'>{''.join(tiles)}</div></div>")
    body.append(f"<div class='grid g2'>{''.join(prio)}{''.join(exposed)}</div>")
    body.append(f"<div class='grid g2'>{''.join(device)}{coverage}</div>")
    body.append(_READING_GUIDE)

    # ---- findings
    if findings:
        section("findings", "Findings")
        body.append("<div class='filters' role='group' aria-label='Filter findings by severity'>"
                    "<button class='fbtn' type='button' data-sev='ALL' aria-pressed='true'>"
                    f"All ({total})</button>" + "".join(
                        f"<button class='fbtn' type='button' data-sev='{s}' aria-pressed='false'>{SEV_LABEL[s]} ({counts[s]})</button>"
                        for s in rules.SEVERITIES if counts[s]) + "</div>")
        body.extend(_finding_html(f, known) for f in findings)

    if audit.get("positives"):
        section("good", "What is working well")
        tick = "<svg viewBox='0 0 16 16' aria-hidden='true'><path d='M3 8.5 6.5 12 13 4.5'/></svg>"
        body.append("<div class='panel'><ul class='checks'>" + "".join(
            f"<li>{tick}<span>{e(p)}</span></li>" for p in audit["positives"]) + "</ul></div>")

    if findings:
        section("plan", "Remediation plan")
        body.append("<div class='plan'>")
        for when, label in rules.WHEN_LABEL.items():
            group = [f for f in findings if f["when"] == when]
            body.append(f"<div class='panel'><h4>{label}</h4>")
            if group:
                body.append("<ol>" + "".join(
                    f"<li><b>{_dot(f['severity'])} <a href='#{f['id']}'>{f['id']}</a> {e(f['title'])}</b>"
                    f"{e(f['action'])}</li>" for f in group) + "</ol>")
            else:
                body.append("<p class='note'>Nothing in this timeframe.</p>")
            body.append("</div>")
        body.append("</div>")

    diff = audit.get("diff")
    if diff:
        section("changes", "Changes since the previous audit")
        body.append(f"<div class='panel'><p class='note'>Compared with the audit of {e(diff.get('previous_date'))}.</p>")
        for note in diff.get("notes") or []:
            body.append(f"<p class='note'><b>Note:</b> {e(note)}</p>")

        def block(title, items, fmt):
            if items:
                body.append(f"<h4 style='margin-top:14px'>{title} ({len(items)})</h4><ul class='limits'>"
                            + "".join(f"<li>{fmt(i)}</li>" for i in items[:40]) + "</ul>")

        def host_line(item):
            return f"<span class='mono'>{e(item['ip'])}</span> {e(item['name'])} - {e(item['type'])}"

        def port_line(item):
            return f"<span class='mono'>{e(item['ip'])}</span> {e(item['name'])}: {e(', '.join(map(str, item['ports'])))}"

        block("New hosts", diff.get("new_hosts"), host_line)
        block("Hosts no longer present", diff.get("gone_hosts"), host_line)
        block("Newly open ports", diff.get("opened"), port_line)
        block("Closed ports", diff.get("closed"), port_line)
        block("New findings", diff.get("new_findings"), e)
        block("Resolved findings", diff.get("resolved"), e)
        if not any(diff.get(k) for k in ("new_hosts", "gone_hosts", "opened", "closed", "new_findings", "resolved")):
            body.append("<p>No difference from the previous audit.</p>")
        body.append("</div>")

    # ---- inventory
    section("inventory", "Host inventory")
    body.append("<div class='filters'><input id='q' class='search' type='search' placeholder='Filter by address, "
                f"name, type, port...' aria-label='Filter hosts'><span id='qn' class='note' aria-live='polite'>"
                f"{_plural(len(hosts), 'host')}</span></div>")
    sortable = "".join(f"<th data-sort scope='col' tabindex='0' title='Sort by {label.lower()}'>{label}</th>"
                       for label in ("Address", "Name", "Type", "System", "Vendor"))
    body.append(f"<div class='panel scroll'><table id='inv'><thead><tr>{sortable}<th scope='col'>Open ports</th>"
                "<th scope='col'>Findings</th></tr></thead><tbody>")
    for host in hosts:
        role = f" <span class='note'>({e(', '.join(host['roles']))})</span>" if host.get("roles") else ""
        links = " ".join(f"<a class='fid' href='#{f['id']}' title='{e(f['title'])}'>{f['id']}</a>"
                         for f in refs.get(host["ip"], [])) or "<span class='note'>-</span>"
        body.append(f"<tr><td class='ip' data-k='{e(_ip_sort_key(host['ip']))}'>{_ip_link(host['ip'], known)}</td>"
                    f"<td>{e(rules.display_name(host)) or '-'}</td>"
                    f"<td>{e(host.get('type'))}{role}</td><td>{e(host.get('os')) or '-'}</td>"
                    f"<td>{e(host.get('vendor')) or '-'}</td><td class='num' style='white-space:normal'>{e(_port_list(host))}</td>"
                    f"<td>{links}</td></tr>")
    body.append("</tbody></table></div>")

    local = audit.get("local")
    if local:
        section("workstation", "Scanning workstation")
        firewall = ", ".join(f"{p['name']}: {'on' if p.get('enabled') else 'OFF'}" for p in local.get("firewall", []))
        listening = ", ".join(f"{i['port']} ({i.get('process') or '?'})" for i in local.get("listening", [])[:40])
        shares = ", ".join(s["name"] for s in local.get("shares", [])) or "none"
        products = local.get("antivirus") or []
        if products:
            antivirus = ", ".join(f"{p.get('name')}: {'active' if p.get('active') else 'not active'}" for p in products)
        else:
            antivirus = {True: "Microsoft Defender active", False: "Microsoft Defender OFF"}.get(
                local.get("defender_realtime"), "not detected")
        state = local.get("bitlocker")
        bitlocker = {None: "not detected", 1: "on", 2: "OFF", 3: "encryption in progress",
                     4: "decryption in progress", 5: "suspended", 6: "on (locked)"}.get(
                         state, f"state {state} (not interpreted)")
        rows = [("Computer", f"{local.get('computer')} ({local.get('domain')})"),
                ("System", f"{local.get('os')} build {local.get('build')}"),
                ("Last update installed", local.get("last_update") or "not detected"),
                ("Firewall", firewall), ("Antivirus", antivirus), ("System drive encryption", bitlocker),
                ("User Account Control", "enabled" if local.get("uac_enabled", True) else "DISABLED"),
                ("Remote Desktop", ("enabled, NLA " + ("required" if local.get("rdp_nla") else "NOT required"))
                 if local.get("rdp_enabled") else "disabled"),
                ("SMB", "not detected" if local.get("smb_signing_required") is None else
                 f"SMBv1 {'ENABLED' if local.get('smb1') else 'disabled'}, signing "
                 f"{'required' if local.get('smb_signing_required') else 'NOT required'}"),
                ("Non-administrative shares", shares), ("Listening ports", listening)]
        body.append("<div class='panel scroll'><table class='kv'>" + "".join(
            f"<tr><th scope='row'>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows) + "</table></div>")

    section("limits", "Limitations of this audit")
    body.append("<div class='panel'><ul class='limits'>" + "".join(
        f"<li>{e(item)}</li>" for item in audit.get("limits", [])) + "</ul></div>")

    section("hosts", "Appendix: host details")
    body.append("<p class='note legendnote'>Source: <code>protocol</code>, <code>banner</code>, <code>http</code>, "
                "<code>tls</code>, <code>nmap</code> = the service answered; <code>port</code> = attributed from "
                "the port number alone, to be confirmed.</p>"
                "<div class='filters'><button class='fbtn' id='toggleHosts' type='button'>Expand all</button></div>")
    body.extend(_host_detail(host) for host in hosts)

    nav = "".join(f"<a href='#{a}'><span>{i:02d}</span>{e(t)}</a>" for i, (a, t) in enumerate(sections, 1))
    tally = "".join(f"<div>{_dot(s)}{SEV_LABEL[s]}<b>{counts[s]}</b></div>" for s in rules.SEVERITIES)
    spine = ("<aside class='spine'><div class='wordmark'>NET<i>AUDIT</i></div>"
             f"<div class='client'>{e(client) or 'Security audit'}<small>{e(started)}</small></div>"
             f"<nav aria-label='Sections'>{nav}</nav><div class='tally'>{tally}</div>"
             "<div class='foot'><button class='themebtn' id='theme' type='button'>Light / dark</button><br>"
             f"Confidential<br>NetAudit {__version__}</div></aside>")
    authorization = meta.get("authorization") or f"declared by {meta.get('operator') or meta.get('operatore') or '?'}"
    footer = (f"<footer>NetAudit {__version__} &middot; duration {e(meta.get('duration', ''))} &middot; authorization: "
              f"{e(authorization)} &middot; {e(started)}.<br>Confidential: this "
              "document describes the internal attack surface. Share it only with those who must act on it.</footer>")
    title = f"Security audit{' - ' + client if client else ''} - {started[:10]}"
    return ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{e(title)}</title><style>{_CSS}</style></head><body><div class='layout'>{spine}<main>"
            + "".join(cover) + "".join(body) + footer + f"</main></div><script>{_JS}</script></body></html>")


def summary_text(audit: dict) -> str:
    """Short plain-text summary for an e-mail or a ticket."""
    meta, findings = audit["meta"], audit["findings"]
    counts = {sev: sum(1 for f in findings if f["severity"] == sev) for sev in rules.SEVERITIES}
    exposure = rules.exposure(findings)
    targets = ", ".join(meta.get("targets") or [])
    client = meta.get("client") or meta.get("cliente") or targets or "network"
    lines = [f"# Security audit - {client} - {meta.get('started', '')}", ""]
    if meta.get("interrupted"):
        lines += ["**PARTIAL AUDIT: it was interrupted before completion. Absence of a finding means nothing.**", ""]
    if meta.get("warnings"):
        lines += [f"- {warning}" for warning in meta["warnings"]] + [""]
    lines += [f"Targets: {targets}",
              f"Hosts found: {len(audit['hosts'])}",
              f"Findings: {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low",
              f"Exposure index: {exposure['score']}/100 (higher is worse; {exposure['rating'].lower()})", ""]

    def where(finding):
        if finding["key"] == "flat":
            return "1 segment"
        addresses = list(dict.fromkeys(item["ip"] for item in finding["hosts"]))
        listed = ", ".join(addresses[:6]) + (f" and {len(addresses) - 6} more" if len(addresses) > 6 else "")
        # a ticket about a high finding needs to say where; for the rest the count is enough
        return f"{_plural(len(addresses), 'host')}: {listed}" if finding["severity"] == "HIGH" \
            else _plural(len(addresses), "host")

    for when, label in rules.WHEN_LABEL.items():
        group = [f for f in findings if f["when"] == when]
        if group:
            lines.append(f"## {label}")
            lines += [f"- [{SEV_LABEL[f['severity']]}] {f['id']} {f['title']} ({where(f)})" for f in group]
            lines.append("")
    if audit.get("positives"):
        lines.append("## Working well")
        lines += [f"- {item}" for item in audit["positives"]]
        lines.append("")
    lines.append("Full details in report.html. Confidential.")
    return "\n".join(lines) + "\n"


class _SafeCsv:
    """CSV writer that neutralizes spreadsheet formulas: device names, banners and SNMP strings
    come from the network and must never be executed when the file is opened in Excel."""

    def __init__(self, handle, delimiter: str = ","):
        self._writer = csv.writer(handle, delimiter=delimiter, quoting=csv.QUOTE_ALL)

    @staticmethod
    def clean(cell):
        if not isinstance(cell, str):
            return cell
        cell = "".join(ch if ch.isprintable() else " " for ch in cell)       # no control characters
        if cell[:1] in ("=", "+", "-", "@"):
            cell = "'" + cell
        # a spreadsheet that splits on ';' or tabs must not find a formula at the start of a piece
        return re.sub(r"([;\t])(\s*[=+\-@])", r"\1'\2", cell)

    def writerow(self, row):
        self._writer.writerow([self.clean(cell) for cell in row])


def write_outputs(audit: dict, outdir: str, delimiter: str = ",") -> dict:
    """Write report.html, audit.json, inventory.csv, findings.csv and summary.md. -> paths."""
    os.makedirs(outdir, exist_ok=True)
    paths = {name: os.path.join(outdir, name) for name in
             ("report.html", "audit.json", "inventory.csv", "findings.csv", "summary.md")}
    # the data first: a rendering problem must never cost the collected results
    with open(paths["audit.json"], "w", encoding="utf-8") as handle:
        json.dump(audit, handle, ensure_ascii=False, indent=1)
    with open(paths["report.html"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(audit))
    with open(paths["summary.md"], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(summary_text(audit))
    with open(paths["inventory.csv"], "w", encoding="utf-8-sig", newline="") as handle:
        writer = _SafeCsv(handle, delimiter)
        meta = audit.get("meta") or {}
        client, audit_date = meta.get("client") or meta.get("cliente") or "", str(meta.get("started", ""))[:10]
        writer.writerow(["Client", "Audit date", "Address", "Name", "Domain", "Type", "System", "MAC", "Vendor",
                         "Open ports", "Findings"])
        ids: dict[str, list[str]] = {}
        for finding in audit["findings"]:
            for ip in dict.fromkeys(item["ip"] for item in finding["hosts"]):
                ids.setdefault(ip, []).append(finding["id"])
        for host in audit["hosts"]:
            writer.writerow([client, audit_date, host["ip"], rules.display_name(host), host.get("domain", ""),
                             host.get("type", ""), host.get("os", ""), host.get("mac", ""), host.get("vendor", ""),
                             " ".join(str(rec["port"]) for rec in host.get("ports", [])),
                             " ".join(ids.get(host["ip"], []))])
    with open(paths["findings.csv"], "w", encoding="utf-8-sig", newline="") as handle:
        writer = _SafeCsv(handle, delimiter)
        # ID is the position in this report; Key is stable across audits and is what to match tickets on.
        # Severity rank sorts correctly in a spreadsheet (1 = high).
        writer.writerow(["Client", "Audit date", "ID", "Key", "Severity", "Severity rank", "Finding", "Address",
                         "Host", "Evidence", "Risk", "Action", "Timeframe", "MITRE ATT&CK"])
        for finding in audit["findings"]:
            rank = rules.SEVERITIES.index(finding["severity"]) + 1 if finding["severity"] in rules.SEVERITIES else ""
            for item in finding["hosts"]:
                writer.writerow([client, audit_date, finding["id"], finding["key"], SEV_LABEL.get(
                    finding["severity"], finding["severity"]), rank, finding["title"], item["ip"],
                    item.get("name", ""), item.get("evidence", ""), finding["risk"], finding["action"],
                    rules.WHEN_LABEL.get(finding["when"], finding["when"]), finding.get("attack", "")])
    return paths
