"""
CYPHEX — HTML scan report.

One fixed template, filled per scan. render_report_html(report, ...) returns a
self-contained HTML string (no external CSS/JS/fonts — opens offline, works
from a file:// link); write_report_html(...) writes it next to the run and
returns the absolute path the CLI prints as an openable link.

Design: a calm, minimalist, multi-page posture report styled to match the
CYPHEX dashboard (near-black violet, one purple accent, muted severity tones,
big numbers, //MONO// section headers). It reads top-to-bottom as a document —
executive summary, posture, findings summary, severity split, per-finding
detail with remediation, patches, methodology — and a "Download PDF" button
prints it (browser Save-as-PDF, colours preserved). Missing/empty sections
degrade to an explicit "none" state rather than vanishing.

Input is the dict cli_engine._print_report() returns:
    {scan_id, timestamp, score, target,
     summary: {critical, high, medium, low, total_vulns, duration_seconds},
     vulnerabilities: [{name, severity, endpoint, payload, confirmed}],
     attack_graph: {privilege_level, creds_harvested, tokens_harvested,
                    nodes_touched: [...], chains: [{seq, source, action,
                    target, priority}]} | None}
plus the before/after posture the patch phase records on the engine.
"""

import html
import os
from collections import Counter
from datetime import datetime, timezone

# ── palette (muted, self-contained hex — matches the dashboard, no neon) ─────
_BG = "#0a0611"        # near-black violet
_BG2 = "#0f0a1a"
_CARD = "#130d21"
_CARD2 = "#0e0819"
_TRACK = "#1c1430"     # empty bar / ring track
_TXT = "#ece7ff"
_DIM = "#8f84b3"
_FAINT = "#5f5680"
_LINE = "rgba(168,85,247,0.15)"
_PURPLE = "#a855f7"
_OK = "#4ade80"        # soft green (not neon)

# Severity — desaturated so nothing screams; label carries the meaning.
_SEV = {
    "Critical": "#d16b7f",   # dusty rose
    "High": "#d8a35e",       # muted amber
    "Medium": "#c7b45f",     # muted gold
    "Low": "#7fa8cc",        # muted steel blue
    "Info": "#8f84b3",       # dim
}

# Plain-language fix per finding class. Keyed on the normalised type; a generic
# boundary-hardening line covers anything not listed.
_REMEDIATION = {
    "SQL Injection": "Use parameterized queries or an ORM binding; never build SQL by concatenating user input.",
    "Command Injection": "Never pass user input to a shell. Use argument arrays with an allow-list of commands.",
    "Cross-Site Scripting": "Context-escape every value written to the page and enforce a strict Content-Security-Policy.",
    "XSS": "Context-escape every value written to the page and enforce a strict Content-Security-Policy.",
    "Sensitive Data Exposure": "Return only the fields a caller needs; redact passwords, keys and tokens from responses.",
    "Path Traversal": "Resolve and confine every file path to an allow-listed base directory before opening it.",
    "Local File Inclusion": "Resolve and confine every file path to an allow-listed base directory before opening it.",
    "Missing Security Headers": "Set HSTS, X-Content-Type-Options, X-Frame-Options and a Content-Security-Policy.",
    "HTTP Missing Security Headers": "Set HSTS, X-Content-Type-Options, X-Frame-Options and a Content-Security-Policy.",
    "Direct Response Write": "Encode data before writing it to the response; do not reflect raw user input.",
    "Raw Html Format": "Escape interpolated values and use an auto-escaping template engine.",
    "Insecure Direct Object Reference": "Enforce a per-object authorization check on every access.",
    "IDOR": "Enforce a per-object authorization check on every access.",
    "Broken Authentication": "Harden credential checks, rotate session tokens after login, and rate-limit attempts.",
    "Default Credentials": "Remove default/admin credentials and force a password change on first use.",
}
_REMEDIATION_FALLBACK = (
    "Validate and sanitize all untrusted input at this boundary and apply "
    "least-privilege access to whatever it reaches."
)

# The five phases every scan runs — shown verbatim in the Methodology section.
_PHASES = [
    ("Recon", "Fingerprint the stack, headers and exposed files to map what the target is built from."),
    ("Surface Map", "Crawl links, forms and API endpoints into an attack-surface index."),
    ("Oracle Swarm", "DeepAgents generate hypotheses, then fire real payloads — SQLi, command injection, XSS, path traversal, auth bypass, logic and supply-chain probes."),
    ("Council", "A multi-model debate filters false positives; static findings are carried through on their own evidence."),
    ("Self-Patch & Re-score", "Confirmed issues are patched in place, the target is re-scanned, and the posture is scored before and after."),
]


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _score_color(n: float) -> str:
    return _OK if n >= 70 else (_SEV["High"] if n >= 40 else _SEV["Critical"])


def _fmt_ts(ts) -> str:
    """ISO-8601 (usually UTC) -> 'YYYY-MM-DD HH:MM UTC'; pass through on any
    surprise so the report never fails to render over a date."""
    try:
        s = str(ts).replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return _esc(ts) or "—"


def _norm_type(name) -> str:
    """Collapse a finding name to its class for grouping / remediation lookup:
    drop a leading '[STATIC]'/'[DYNAMIC]' tag and the parenthetical detail.
    '[STATIC] SQL Injection (String Concat)' -> 'SQL Injection'."""
    n = str(name or "Finding").strip()
    if n.startswith("[") and "]" in n:
        n = n.split("]", 1)[1]
    n = n.split("(")[0].strip()
    return n or "Finding"


def _remediation_for(name) -> str:
    return _REMEDIATION.get(_norm_type(name), _REMEDIATION_FALLBACK)


# ── chart fragments (inline SVG — no JS) ─────────────────────────────────────
def _bar(label: str, score, width_px: int = 340) -> str:
    n = max(0, min(100, int(score if score is not None else 0)))
    col = _score_color(n)
    fill = int(width_px * n / 100)
    return f"""
    <div class="bar-row">
      <span class="bar-label">{_esc(label)}</span>
      <span class="bar-track" style="width:{width_px}px">
        <span class="bar-fill" style="width:{fill}px;background:{col}"></span>
      </span>
      <span class="bar-num" style="color:{col}">{n}<span class="bar-den">/100</span></span>
    </div>"""


def _donut(counts: dict) -> str:
    order = ["Critical", "High", "Medium", "Low"]
    total = sum(int(counts.get(k, 0)) for k in order)
    r, cx, cy, sw = 68, 90, 90, 14
    circ = 2 * 3.141592653589793 * r
    segs, offset = [], 0.0
    segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_TRACK}" stroke-width="{sw}"/>')
    if total:
        for k in order:
            c = int(counts.get(k, 0))
            if not c:
                continue
            length = circ * c / total
            segs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_SEV[k]}" stroke-width="{sw}" stroke-linecap="round" '
                f'stroke-dasharray="{max(0.1, length - 2):.2f} {circ - length + 2:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += length
    legend = "".join(
        f'<div class="lg"><span class="dot" style="background:{_SEV[k]}"></span>'
        f'{k}<span class="lg-n">{int(counts.get(k, 0))}</span></div>'
        for k in order
    )
    return f"""
    <div class="donut-wrap">
      <svg viewBox="0 0 180 180" width="164" height="164">
        {''.join(segs)}
        <text x="90" y="86" class="donut-total">{total}</text>
        <text x="90" y="106" class="donut-cap">FINDINGS</text>
      </svg>
      <div class="legend">{legend}</div>
    </div>"""


def _findings_by_type(vulns: list) -> str:
    """Horizontal bar list of findings grouped by class — always populated
    when there are findings, unlike the exploit-chain graph."""
    if not vulns:
        return '<div class="empty">No findings.</div>'
    counts = Counter(_norm_type(v.get("name")) for v in vulns).most_common(8)
    top = counts[0][1] if counts else 1
    rows = "".join(
        f'<div class="ft-row"><span class="ft-name" title="{_esc(name)}">{_esc(name)}</span>'
        f'<span class="ft-bar"><span class="ft-fill" '
        f'style="width:{max(6, round(100 * c / top))}%"></span></span>'
        f'<span class="ft-n">{c}</span></div>'
        for name, c in counts
    )
    return f'<div class="ft">{rows}</div>'


# ── sections ─────────────────────────────────────────────────────────────────
def _hero_tiles(after: int, total: int, patched_n: int, remaining_n: int) -> str:
    tiles = [
        ("SECURITY POSTURE", str(after), "/ 100", _score_color(after)),
        ("FINDINGS", str(total), "confirmed + static", _TXT),
        ("AUTO-PATCHED", str(patched_n), "by self-patch", _OK if patched_n else _DIM),
        ("STILL OPEN", str(remaining_n),
         "needs review", _SEV["High"] if remaining_n else _OK),
    ]
    return "".join(
        f'<div class="tile"><div class="tile-l">{lbl}</div>'
        f'<div class="tile-n" style="color:{col}">{val}'
        f'<span class="tile-u">{unit}</span></div></div>'
        for lbl, val, unit, col in tiles
    )


def _exec_summary(tgt, total, counts, before, after, delta,
                  patched_n, remaining_n) -> str:
    t = _esc(tgt)
    if total == 0:
        return (f"CYPHEX exercised the Oracle-guided DeepAgents swarm against "
                f"<b>{t}</b> and confirmed no exploitable findings. The security "
                f"posture holds at <b>{after}/100</b>.")
    crit = int(counts.get("Critical", 0))
    high = int(counts.get("High", 0))
    if delta > 0:
        moved = (f"lifted the security posture from <b>{before}/100</b> to "
                 f"<b>{after}/100</b> (Δ +{delta})")
    elif delta < 0:
        moved = (f"the posture moved from <b>{before}/100</b> to "
                 f"<b>{after}/100</b> (Δ {delta})")
    else:
        moved = f"held the security posture at <b>{after}/100</b>"
    return (
        f"CYPHEX ran its Oracle-guided DeepAgents swarm against <b>{t}</b> and "
        f"surfaced <b>{total}</b> finding(s) — {crit} critical, {high} high. "
        f"Automated self-patching remediated <b>{patched_n}</b> of them and {moved}. "
        f"<b>{remaining_n}</b> finding(s) remain open and are detailed below with "
        f"remediation guidance."
    )


def _stat_cards(s: dict) -> str:
    cards = [
        ("TOTAL", s.get("total_vulns", 0), _TXT),
        ("CRITICAL", s.get("critical", 0), _SEV["Critical"]),
        ("HIGH", s.get("high", 0), _SEV["High"]),
        ("MEDIUM", s.get("medium", 0), _SEV["Medium"]),
        ("LOW", s.get("low", 0), _SEV["Low"]),
    ]
    return "".join(
        f'<div class="stat"><div class="stat-n">{int(v)}</div>'
        f'<div class="stat-l"><span class="stat-dot" style="background:{col}"></span>{lbl}</div></div>'
        for lbl, v, col in cards
    )


def _finding_cards(vulns: list) -> str:
    if not vulns:
        return ('<div class="empty">No confirmed vulnerabilities — the target '
                'held.</div>')
    cards = []
    for v in vulns:
        sev = str(v.get("severity", "Info")).title()
        col = _SEV.get(sev, _SEV["Info"])
        payload = v.get("payload") or ""
        payload_html = (f'<div class="payload"><span class="pl-tag">payload</span>'
                        f'{_esc(payload)}</div>' if payload else "")
        confirmed = v.get("confirmed")
        status = ('<span class="conf conf-yes">✓ confirmed</span>' if confirmed
                  else '<span class="conf conf-no">static</span>')
        cards.append(f"""
        <div class="fcard" style="border-left:3px solid {col}">
          <div class="fcard-head">
            <span class="pill" style="color:{col};border-color:{col}55">{_esc(sev)}</span>
            <span class="fcard-name">{_esc(v.get("name", "Finding"))}</span>
            {status}
          </div>
          <div class="fcard-loc">{_esc(v.get("endpoint", "—"))}</div>
          {payload_html}
          <div class="fcard-fix"><span class="fix-tag">Remediation</span>{_esc(_remediation_for(v.get("name")))}</div>
        </div>""")
    return "".join(cards)


def _patches_section(patched: list, applied: int, remaining) -> str:
    patched = patched or []
    if patched:
        rows = "".join(
            f'<tr><td class="p-file">{_esc(p.get("file", "?"))}</td>'
            f'<td class="p-cwe">{_esc(p.get("cwe", ""))}</td>'
            f'<td class="p-type">{_esc(p.get("vuln_type", ""))}</td>'
            f'<td class="p-ok">&#10003; patched</td></tr>'
            for p in patched
        )
        body = ('<table class="ptab"><thead><tr><th>FILE</th><th>CWE</th>'
                f'<th>TYPE</th><th>STATUS</th></tr></thead><tbody>{rows}</tbody></table>')
    elif applied:
        body = f'<div class="empty">{int(applied)} patch(es) applied.</div>'
    else:
        body = '<div class="empty">No patches applied this scan.</div>'
    rem = (f'<div class="patch-rem">{int(remaining)} finding(s) still unpatched</div>'
           if remaining else '')
    return body + rem


def _attack_graph(ag) -> str:
    if not ag:
        return '<div class="empty">No exploit chains discovered.</div>'
    chains = ag.get("chains") or []
    meta = (f'<div class="ag-meta">privilege '
            f'<b>{_esc(ag.get("privilege_level", "none"))}</b> · creds '
            f'<b>{int(ag.get("creds_harvested", 0))}</b> · tokens '
            f'<b>{int(ag.get("tokens_harvested", 0))}</b> · nodes '
            f'<b>{len(ag.get("nodes_touched") or [])}</b></div>')
    if not chains:
        return meta + '<div class="empty">No exploit chains discovered.</div>'
    items = "".join(
        f'<li><span class="seq">{int(c.get("seq", i + 1))}</span>'
        f'<span class="node">{_esc(c.get("source", "?"))}</span>'
        f'<span class="act">──{_esc(c.get("action", ""))}──▶</span>'
        f'<span class="node">{_esc(c.get("target", "?"))}</span>'
        f'<span class="prio">[{_esc(c.get("priority", ""))}]</span></li>'
        for i, c in enumerate(chains)
    )
    return meta + f'<ul class="chains">{items}</ul>'


def _methodology() -> str:
    rows = "".join(
        f'<li><span class="mth-i">{i}</span>'
        f'<div><div class="mth-name">{_esc(name)}</div>'
        f'<div class="mth-desc">{_esc(desc)}</div></div></li>'
        for i, (name, desc) in enumerate(_PHASES, 1)
    )
    return f'<ol class="mth">{rows}</ol>'


def render_report_html(report: dict, *, score_before=None, score_after=None,
                       patches_applied=None, patched=None, remaining=None,
                       target=None) -> str:
    """Return the full self-contained HTML report for one scan."""
    report = report or {}
    summary = report.get("summary") or {}
    scan_id = report.get("scan_id", "—")
    tgt = target or report.get("target") or "—"
    ts = _fmt_ts(report.get("timestamp"))
    dur = summary.get("duration_seconds")
    dur_s = f"{float(dur):.0f}s" if dur is not None else "—"

    before = report.get("score") if score_before is None else score_before
    after = score_after if score_after is not None else before
    before = 0 if before is None else int(before)
    after = before if after is None else int(after)
    delta = after - before
    delta_col = _OK if delta > 0 else (_DIM if delta == 0 else _SEV["Critical"])
    patches = 0 if patches_applied is None else int(patches_applied)

    counts = {k: summary.get(k.lower(), 0) for k in ("Critical", "High", "Medium", "Low")}
    vulns = report.get("vulnerabilities") or []
    total = int(summary.get("total_vulns", len(vulns)) or 0)
    remaining_n = int(remaining or 0)

    patches_html = _patches_section(patched or [], patches, remaining_n)
    # The exploit-chain graph is empty on most scans, so only show it when
    # chains actually exist.
    ag = report.get("attack_graph") or {}
    chains = ag.get("chains") or []
    attack_section = (
        f'<section><h2>Attack Graph &middot; {len(chains)} chain(s)</h2>'
        f'<div class="card">{_attack_graph(ag)}</div></section>'
        if chains else ""
    )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CYPHEX Report · {_esc(scan_id)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0;
    -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  body {{
    background: radial-gradient(1100px 560px at 82% -12%, #180a2b 0%, {_BG} 58%) fixed, {_BG};
    color: {_TXT};
    font-family: ui-sans-serif, system-ui, "Segoe UI", sans-serif;
    line-height: 1.55; padding: 84px 22px 90px; -webkit-font-smoothing: antialiased;
  }}
  .mono {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; }}
  b {{ color: {_TXT}; font-weight: 650; }}

  /* download button — screen only */
  .dl-btn {{ position: fixed; top: 22px; right: 22px; z-index: 50;
    font-family: ui-monospace, monospace; font-size: .72rem; font-weight: 700;
    letter-spacing: 1px; color: #fff; cursor: pointer;
    background: linear-gradient(135deg, #7c3aed, {_PURPLE}); border: none;
    border-radius: 999px; padding: 11px 20px;
    box-shadow: 0 8px 26px rgba(124,58,237,.45); }}
  .dl-btn:hover {{ box-shadow: 0 8px 40px rgba(124,58,237,.65); }}

  header {{ display:flex; align-items:flex-end; justify-content:space-between;
    flex-wrap:wrap; gap:16px; border-bottom:1px solid {_LINE}; padding-bottom:24px; }}
  .brand {{ font-family: ui-monospace, monospace; font-size: 2.1rem; font-weight: 800;
    letter-spacing: 7px; text-shadow: 0 0 16px {_PURPLE}66; }}
  .brand small {{ display:block; font-size:.6rem; letter-spacing:4px; color:{_DIM};
    font-weight:600; margin-top:6px; }}
  .meta {{ font-family: ui-monospace, monospace; font-size:.72rem; color:{_DIM};
    text-align:right; line-height:2.0; }}
  .meta b {{ color:{_TXT}; font-weight:600; }}

  section {{ margin-top: 30px; }}
  h2 {{ font-family: ui-monospace, monospace; font-size:.7rem; letter-spacing:3px;
    color:{_PURPLE}; text-transform:uppercase; margin-bottom:15px; font-weight:700; }}
  h2::before {{ content:"// "; color:{_FAINT}; }}

  .card {{ background: {_CARD}; border:1px solid {_LINE}; border-radius:16px;
    padding:26px; }}
  .card + .card {{ margin-top:16px; }}

  /* hero big-number tiles */
  .tiles {{ display:grid; grid-template-columns: repeat(4,1fr); gap:14px; }}
  .tile {{ background:{_CARD}; border:1px solid {_LINE}; border-radius:16px; padding:22px 20px; }}
  .tile-l {{ font-family: ui-monospace, monospace; font-size:.56rem; letter-spacing:2px;
    color:{_DIM}; text-transform:uppercase; }}
  .tile-n {{ font-family: ui-monospace, monospace; font-size:3.1rem; font-weight:800;
    line-height:1.1; margin-top:10px; }}
  .tile-u {{ font-size:.72rem; font-weight:500; color:{_DIM}; margin-left:7px; letter-spacing:0; }}

  .lede {{ font-size:.94rem; color:#d7d0f0; line-height:1.75; }}

  /* posture */
  .posture {{ display:grid; grid-template-columns: 1fr auto; gap:26px; align-items:center; }}
  .bar-row {{ display:flex; align-items:center; gap:16px; margin:12px 0;
    font-family: ui-monospace, monospace; font-size:.8rem; }}
  .bar-label {{ width:130px; color:{_DIM}; }}
  .bar-track {{ height:12px; background:{_TRACK}; border-radius:8px; overflow:hidden;
    display:inline-block; }}
  .bar-fill {{ display:block; height:100%; border-radius:8px; }}
  .bar-num {{ font-weight:700; font-size:1rem; }}
  .bar-den {{ color:{_DIM}; font-size:.72rem; font-weight:400; }}
  .delta {{ text-align:center; padding-left:22px; border-left:1px solid {_LINE}; }}
  .delta-n {{ font-family: ui-monospace, monospace; font-size:2.6rem; font-weight:800; }}
  .delta-l {{ font-size:.6rem; letter-spacing:2px; color:{_DIM}; text-transform:uppercase; }}
  .patch-line {{ font-family: ui-monospace, monospace; font-size:.8rem; color:{_DIM}; margin-top:16px; }}
  .patch-line b {{ color:{_OK}; }}

  /* stats */
  .stats {{ display:grid; grid-template-columns: repeat(5,1fr); gap:12px; }}
  .stat {{ background:{_CARD2}; border:1px solid {_LINE}; border-radius:14px;
    padding:20px 14px; text-align:center; }}
  .stat-n {{ font-family: ui-monospace, monospace; font-size:2.4rem; font-weight:800; color:{_TXT}; }}
  .stat-l {{ font-size:.56rem; letter-spacing:2px; color:{_DIM}; margin-top:6px;
    display:flex; align-items:center; justify-content:center; gap:6px; }}
  .stat-dot {{ width:7px; height:7px; border-radius:50%; display:inline-block; }}

  /* split: donut + type bars */
  .split {{ display:grid; grid-template-columns: 300px 1fr; gap:16px; }}
  .donut-wrap {{ display:flex; align-items:center; gap:20px; }}
  .donut-total {{ fill:{_TXT}; font:800 32px ui-monospace,monospace; text-anchor:middle; }}
  .donut-cap {{ fill:{_DIM}; font:600 9px ui-monospace,monospace; letter-spacing:2px; text-anchor:middle; }}
  .legend {{ font-family: ui-monospace, monospace; font-size:.74rem; }}
  .lg {{ display:flex; align-items:center; gap:8px; margin:7px 0; color:{_DIM}; }}
  .lg-n {{ color:{_TXT}; margin-left:auto; font-weight:700; }}
  .dot {{ width:9px; height:9px; border-radius:3px; display:inline-block; }}
  .ft-title {{ font-family: ui-monospace, monospace; font-size:.56rem; letter-spacing:2px; color:{_DIM}; margin-bottom:16px; }}
  .ft-row {{ display:flex; align-items:center; gap:12px; margin:11px 0; font-family: ui-monospace, monospace; font-size:.72rem; }}
  .ft-name {{ width:150px; color:{_TXT}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .ft-bar {{ flex:1; height:8px; background:{_TRACK}; border-radius:6px; overflow:hidden; }}
  .ft-fill {{ display:block; height:100%; background:linear-gradient(90deg,{_PURPLE}bb,#c026d3aa); border-radius:6px; }}
  .ft-n {{ color:{_TXT}; font-weight:700; width:22px; text-align:right; }}

  /* finding detail cards */
  .fcard {{ background:{_CARD2}; border:1px solid {_LINE}; border-radius:12px;
    padding:16px 18px; margin-bottom:12px; }}
  .fcard-head {{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; }}
  .pill {{ font-family: ui-monospace, monospace; font-size:.6rem; font-weight:700;
    border:1px solid; border-radius:6px; padding:3px 9px; white-space:nowrap; text-transform:uppercase; }}
  .fcard-name {{ font-weight:650; font-size:.92rem; }}
  .conf {{ font-family: ui-monospace, monospace; font-size:.62rem; margin-left:auto; }}
  .conf-yes {{ color:{_OK}; }}
  .conf-no {{ color:{_FAINT}; }}
  .fcard-loc {{ font-family: ui-monospace, monospace; color:{_DIM}; font-size:.74rem;
    margin-top:9px; word-break:break-all; }}
  .payload {{ margin-top:10px; font-family: ui-monospace, monospace; color:#dcae55;
    background:{_BG2}; border:1px solid {_LINE}; border-radius:8px; padding:8px 10px;
    font-size:.72rem; word-break:break-all; }}
  .pl-tag, .fix-tag {{ font-size:.54rem; letter-spacing:1px; text-transform:uppercase;
    color:{_FAINT}; margin-right:9px; }}
  .fcard-fix {{ margin-top:11px; font-size:.82rem; color:#cfc7ea; line-height:1.6; }}

  .empty {{ color:{_DIM}; font-style:italic; padding:14px 4px; }}
  .patch-rem {{ font-family: ui-monospace, monospace; font-size:.72rem; color:{_DIM}; margin-top:14px; }}

  /* patches table */
  .ptab {{ width:100%; border-collapse:collapse; font-size:.76rem; }}
  .ptab th {{ text-align:left; font-family: ui-monospace, monospace; font-size:.56rem;
    letter-spacing:2px; color:{_DIM}; padding:0 10px 10px; border-bottom:1px solid {_LINE}; }}
  .ptab td {{ padding:10px; border-bottom:1px solid rgba(168,85,247,.08);
    font-family: ui-monospace, monospace; }}
  .p-file {{ color:{_TXT}; word-break:break-all; }}
  .p-cwe {{ color:{_PURPLE}; white-space:nowrap; }}
  .p-type {{ color:{_DIM}; }}
  .p-ok {{ color:{_OK}; white-space:nowrap; }}

  /* attack graph */
  .ag-meta {{ font-family: ui-monospace, monospace; font-size:.74rem; color:{_DIM}; margin-bottom:12px; }}
  .ag-meta b {{ color:{_TXT}; }}
  .chains {{ list-style:none; font-family: ui-monospace, monospace; font-size:.74rem; }}
  .chains li {{ display:flex; align-items:center; gap:8px; padding:7px 0;
    border-top:1px solid rgba(168,85,247,.1); flex-wrap:wrap; }}
  .seq {{ color:{_PURPLE}; font-weight:700; }}
  .node {{ color:{_TXT}; }} .act {{ color:{_PURPLE}; }} .prio {{ color:{_DIM}; margin-left:auto; }}

  /* methodology */
  .mth {{ list-style:none; }}
  .mth li {{ display:flex; gap:16px; padding:13px 0; border-top:1px solid rgba(168,85,247,.09); }}
  .mth li:first-child {{ border-top:0; }}
  .mth-i {{ font-family: ui-monospace, monospace; font-weight:800; color:{_PURPLE};
    font-size:.9rem; width:26px; flex:none; }}
  .mth-name {{ font-weight:650; font-size:.9rem; }}
  .mth-desc {{ color:{_DIM}; font-size:.82rem; margin-top:3px; line-height:1.6; }}

  footer {{ margin-top:44px; padding-top:22px; border-top:1px solid {_LINE};
    font-family: ui-monospace, monospace; font-size:.64rem; color:{_FAINT};
    display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }}

  @media (max-width:760px) {{
    .posture {{ grid-template-columns:1fr; }} .split {{ grid-template-columns:1fr; }}
    .tiles {{ grid-template-columns: repeat(2,1fr); }}
    .stats {{ grid-template-columns: repeat(2,1fr); }}
    .delta {{ border:0; padding:0; }} .bar-track {{ width:auto!important; flex:1; }}
  }}

  /* print / PDF — keep the dark theme, break into pages */
  @page {{ size: A4; margin: 13mm; }}
  @media print {{
    body {{ padding: 0; background: {_BG}; }}
    .dl-btn {{ display:none; }}
    .wrap {{ max-width:none; }}
    section, .card, .fcard, .tile {{ break-inside: avoid; }}
    .page-break {{ break-before: page; }}
  }}
</style></head>
<body>
  <button class="dl-btn" onclick="window.print()">&#8595; Download PDF</button>
  <div class="wrap">

  <header>
    <div class="brand mono">CYPHEX<small>SECURITY POSTURE REPORT</small></div>
    <div class="meta mono">
      <div>SCAN&nbsp; <b>{_esc(scan_id)}</b></div>
      <div>TARGET <b>{_esc(tgt)}</b></div>
      <div>{ts} &nbsp;·&nbsp; {dur_s}</div>
    </div>
  </header>

  <section>
    <h2>Executive Summary</h2>
    <div class="tiles">{_hero_tiles(after, total, patches, remaining_n)}</div>
    <div class="card" style="margin-top:16px"><p class="lede">{_exec_summary(tgt, total, counts, before, after, delta, patches, remaining_n)}</p></div>
  </section>

  <section>
    <h2>Security Posture</h2>
    <div class="card posture">
      <div>
        {_bar("Before Patching", before)}
        {_bar("After Patching", after)}
        <div class="patch-line"><b>{patches}</b> patch(es) applied &middot; <b style="color:{_SEV['High']}">{remaining_n}</b> still open</div>
      </div>
      <div class="delta">
        <div class="delta-n" style="color:{delta_col}">{'+' if delta > 0 else ''}{delta}</div>
        <div class="delta-l">posture Δ</div>
      </div>
    </div>
  </section>

  <section>
    <h2>Findings Summary</h2>
    <div class="stats">{_stat_cards(summary)}</div>
  </section>

  <section>
    <h2>Severity &amp; Findings by Type</h2>
    <div class="split">
      <div class="card">{_donut(counts)}</div>
      <div class="card"><div class="ft-title">Findings by type</div>{_findings_by_type(vulns)}</div>
    </div>
  </section>

  <section class="page-break">
    <h2>Findings — Detail</h2>
    <div class="card">{_finding_cards(vulns)}</div>
  </section>

  <section>
    <h2>Patches Applied</h2>
    <div class="card">{patches_html}</div>
  </section>

  {attack_section}

  <section class="page-break">
    <h2>Methodology</h2>
    <div class="card">{_methodology()}</div>
  </section>

  <footer>
    <span>CYPHEX · Oracle-Guided Cyber-Defense · RAG · Council · Reflexion · Genome</span>
    <span>generated {ts}</span>
  </footer>

  </div>
</body></html>"""


def write_report_html(report: dict, *, out_dir: str = None, **kw) -> str:
    """Render and write the report. Returns the absolute path (the CLI prints
    it as a file:// link). out_dir defaults to the current working directory so
    it lands where the user ran the scan, not inside the throwaway sandbox."""
    out_dir = out_dir or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    scan_id = (report or {}).get("scan_id", "scan")
    path = os.path.abspath(os.path.join(out_dir, f"cyphex_report_{scan_id}.html"))
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_report_html(report, **kw))
    return path


if __name__ == "__main__":
    # Smoke test: a synthetic report renders without raising and looks sane.
    demo = {
        "scan_id": "cli_demo123",
        "timestamp": "2026-01-01T12:00:00+00:00",
        "score": 17,
        "target": "https://github.com/acme/vibemart",
        "summary": {"critical": 2, "high": 3, "medium": 2, "low": 4,
                    "total_vulns": 11, "duration_seconds": 842.0},
        "vulnerabilities": [
            {"name": "[STATIC] SQL Injection (String Concatenation)", "severity": "Critical",
             "endpoint": "src/routes/orders.js:18", "payload": "' OR 1=1--", "confirmed": True},
            {"name": "Command Injection", "severity": "Critical",
             "endpoint": "/api/users/export", "payload": ";id", "confirmed": True},
            {"name": "Sensitive Data Exposure", "severity": "Medium",
             "endpoint": "/api/config", "payload": "", "confirmed": True},
        ],
        "attack_graph": {"privilege_level": "user", "creds_harvested": 1,
                         "tokens_harvested": 0, "nodes_touched": ["/login", "/api/orders"],
                         "chains": [{"seq": 1, "source": "/login", "action": "sqli",
                                     "target": "/api/orders", "priority": "high"}]},
    }
    demo_patched = [
        {"file": "src/orders.js", "cwe": "CWE-89", "vuln_type": "SQL Injection"},
        {"file": "src/users.js", "cwe": "CWE-78", "vuln_type": "Command Injection"},
    ]
    p = write_report_html(demo, out_dir="/tmp", score_before=17, score_after=42,
                          patches_applied=2, patched=demo_patched, remaining=4)
    assert os.path.exists(p) and os.path.getsize(p) > 2000
    html_text = render_report_html(demo, score_before=17, score_after=42,
                                   patches_applied=2, patched=demo_patched, remaining=4)
    assert "CYPHEX" in html_text and "42" in html_text and "SQL Injection" in html_text
    assert "Executive Summary" in html_text and "Methodology" in html_text
    assert "Findings by Type" in html_text and "Patches Applied" in html_text
    assert "Remediation" in html_text and "Download PDF" in html_text
    assert "src/orders.js" in html_text and "still open" in html_text
    print(f"[ok] wrote {p} ({os.path.getsize(p)} bytes)")
