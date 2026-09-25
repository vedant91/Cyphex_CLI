"""
CYPHEX — HTML scan report.

One fixed template, filled per scan. render_report_html(report, ...) returns a
self-contained HTML string (no external CSS/JS/fonts — opens offline, works
from a file:// link); write_report_html(...) writes it next to the run and
returns the absolute path the CLI prints as an openable link.

The template's structure is always the same — masthead, before/after posture,
severity stats, severity donut, attack-graph summary, findings table, footer —
so every scan produces a recognisable report; only the values differ. Missing
or empty sections degrade to an explicit "none" state rather than vanishing.

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
from datetime import datetime, timezone

# ── palette (CYPHEX BLOOD SIGNAL, as hex so the file is self-contained) ──────
_BG = "#080410"
_CARD = "#12091f"
_CARD2 = "#0d0618"
_TXT = "#ece7ff"
_DIM = "#8a7fb0"
_LINE = "rgba(168,85,247,0.22)"
_PURPLE = "#a855f7"
_OK = "#39ff14"

_SEV = {
    "Critical": "#ff3b3b",
    "High": "#ff8c1a",
    "Medium": "#e6c200",
    "Low": "#35c1ff",
    "Info": "#8a7fb0",
}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _score_color(n: float) -> str:
    return _OK if n >= 70 else ("#e6c200" if n >= 40 else "#ff3b3b")


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


# ── chart fragments (inline SVG — no JS) ─────────────────────────────────────
def _bar(label: str, score, width_px: int = 320) -> str:
    n = max(0, min(100, int(score if score is not None else 0)))
    col = _score_color(n)
    fill = int(width_px * n / 100)
    return f"""
    <div class="bar-row">
      <span class="bar-label">{_esc(label)}</span>
      <span class="bar-track" style="width:{width_px}px">
        <span class="bar-fill" style="width:{fill}px;background:{col};box-shadow:0 0 12px {col}66"></span>
      </span>
      <span class="bar-num" style="color:{col}">{n}<span class="bar-den">/100</span></span>
    </div>"""


def _donut(counts: dict) -> str:
    order = ["Critical", "High", "Medium", "Low"]
    total = sum(int(counts.get(k, 0)) for k in order)
    r, cx, cy = 70, 90, 90
    circ = 2 * 3.141592653589793 * r
    segs, offset = [], 0.0
    if total:
        for k in order:
            c = int(counts.get(k, 0))
            if not c:
                continue
            length = circ * c / total
            segs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_SEV[k]}" stroke-width="26" '
                f'stroke-dasharray="{length:.2f} {circ - length:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += length
    else:
        segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                    f'stroke="#241536" stroke-width="26"/>')
    legend = "".join(
        f'<div class="lg"><span class="dot" style="background:{_SEV[k]}"></span>'
        f'{k}<span class="lg-n">{int(counts.get(k, 0))}</span></div>'
        for k in order
    )
    return f"""
    <div class="donut-wrap">
      <svg viewBox="0 0 180 180" width="180" height="180">
        {''.join(segs)}
        <text x="90" y="84" class="donut-total">{total}</text>
        <text x="90" y="104" class="donut-cap">FINDINGS</text>
      </svg>
      <div class="legend">{legend}</div>
    </div>"""


# ── sections ─────────────────────────────────────────────────────────────────
def _stat_cards(s: dict) -> str:
    cards = [
        ("TOTAL", s.get("total_vulns", 0), _TXT),
        ("CRITICAL", s.get("critical", 0), _SEV["Critical"]),
        ("HIGH", s.get("high", 0), _SEV["High"]),
        ("MEDIUM", s.get("medium", 0), _SEV["Medium"]),
        ("LOW", s.get("low", 0), _SEV["Low"]),
    ]
    return "".join(
        f'<div class="stat"><div class="stat-n" style="color:{col}">{int(v)}</div>'
        f'<div class="stat-l">{lbl}</div></div>'
        for lbl, v, col in cards
    )


def _findings_rows(vulns: list) -> str:
    if not vulns:
        return ('<tr><td colspan="4" class="empty">No confirmed '
                'vulnerabilities — the target held.</td></tr>')
    rows = []
    for v in vulns:
        sev = str(v.get("severity", "Info")).title()
        col = _SEV.get(sev, _SEV["Info"])
        payload = v.get("payload") or ""
        payload_html = (f'<div class="payload">{_esc(payload)}</div>'
                        if payload else "")
        rows.append(f"""
        <tr>
          <td><span class="pill" style="color:{col};border-color:{col}55">{_esc(sev)}</span></td>
          <td class="f-name">{_esc(v.get("name", "Finding"))}</td>
          <td class="f-ep">{_esc(v.get("endpoint", "—"))}{payload_html}</td>
          <td class="f-ok">{'✓' if v.get("confirmed") else '·'}</td>
        </tr>""")
    return "".join(rows)


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


def _norm_type(name) -> str:
    """Collapse a finding name to its class for grouping — drop the
    parenthetical detail. 'SQL Injection (String Concat)' -> 'SQL Injection'."""
    n = str(name or "Finding").split("(")[0].strip()
    return n or "Finding"


def _findings_by_type(vulns: list) -> str:
    """Horizontal bar list of findings grouped by class — always populated
    when there are findings, unlike the exploit-chain graph."""
    if not vulns:
        return '<div class="empty">No findings.</div>'
    from collections import Counter
    counts = Counter(_norm_type(v.get("name")) for v in vulns).most_common(8)
    top = counts[0][1] if counts else 1
    rows = "".join(
        f'<div class="ft-row"><span class="ft-name">{_esc(name)}</span>'
        f'<span class="ft-bar"><span class="ft-fill" '
        f'style="width:{max(6, round(100 * c / top))}%"></span></span>'
        f'<span class="ft-n">{c}</span></div>'
        for name, c in counts
    )
    return f'<div class="ft">{rows}</div>'


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
    delta_col = _OK if delta > 0 else (_DIM if delta == 0 else "#ff3b3b")
    patches = 0 if patches_applied is None else int(patches_applied)

    counts = {k: summary.get(k.lower(), 0) for k in ("Critical", "High", "Medium", "Low")}
    vulns = report.get("vulnerabilities") or []

    remaining_n = int(remaining or 0)
    patches_html = _patches_section(patched or [], patches, remaining_n)
    # The exploit-chain graph is empty on most scans, so only show it when
    # chains actually exist — no more "No exploit chains discovered." panel.
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
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: radial-gradient(1200px 600px at 80% -10%, #1a0b2e 0%, {_BG} 55%) fixed, {_BG};
    color: {_TXT};
    font-family: ui-sans-serif, system-ui, "Segoe UI", sans-serif;
    line-height: 1.5; padding: 40px 20px 80px; -webkit-font-smoothing: antialiased;
  }}
  .mono {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}

  header {{ display:flex; align-items:flex-end; justify-content:space-between;
    flex-wrap:wrap; gap:16px; border-bottom:1px solid {_LINE}; padding-bottom:22px; }}
  .brand {{ font-family: ui-monospace, monospace; font-size: 2rem; font-weight: 800;
    letter-spacing: 6px; text-shadow: 0 0 14px {_PURPLE}88, 0 0 30px {_PURPLE}44; }}
  .brand small {{ display:block; font-size:.62rem; letter-spacing:4px; color:{_DIM};
    font-weight:600; margin-top:4px; }}
  .meta {{ font-family: ui-monospace, monospace; font-size:.72rem; color:{_DIM};
    text-align:right; line-height:1.9; }}
  .meta b {{ color:{_TXT}; font-weight:600; }}

  section {{ margin-top: 26px; }}
  h2 {{ font-family: ui-monospace, monospace; font-size:.72rem; letter-spacing:3px;
    color:{_PURPLE}; text-transform:uppercase; margin-bottom:14px; font-weight:700; }}

  .card {{ background: {_CARD}; border:1px solid {_LINE}; border-radius:14px;
    padding:24px; box-shadow: 0 10px 40px rgba(0,0,0,.5); }}
  .card + .card {{ margin-top:16px; }}

  /* posture */
  .posture {{ display:grid; grid-template-columns: 1fr auto; gap:24px; align-items:center; }}
  .bar-row {{ display:flex; align-items:center; gap:14px; margin:10px 0;
    font-family: ui-monospace, monospace; font-size:.8rem; }}
  .bar-label {{ width:130px; color:{_DIM}; }}
  .bar-track {{ height:12px; background:#241536; border-radius:8px; overflow:hidden;
    display:inline-block; }}
  .bar-fill {{ display:block; height:100%; border-radius:8px; transition:width .4s; }}
  .bar-num {{ font-weight:700; font-size:1rem; }}
  .bar-den {{ color:{_DIM}; font-size:.72rem; font-weight:400; }}
  .delta {{ text-align:center; padding-left:8px; border-left:1px solid {_LINE}; }}
  .delta-n {{ font-family: ui-monospace, monospace; font-size:2.4rem; font-weight:800; }}
  .delta-l {{ font-size:.62rem; letter-spacing:2px; color:{_DIM}; text-transform:uppercase; }}

  /* stats */
  .stats {{ display:grid; grid-template-columns: repeat(5,1fr); gap:12px; }}
  .stat {{ background:{_CARD2}; border:1px solid {_LINE}; border-radius:12px;
    padding:16px; text-align:center; }}
  .stat-n {{ font-family: ui-monospace, monospace; font-size:2rem; font-weight:800; }}
  .stat-l {{ font-size:.58rem; letter-spacing:2px; color:{_DIM}; margin-top:2px; }}

  /* split: donut + attack graph */
  .split {{ display:grid; grid-template-columns: 300px 1fr; gap:16px; }}
  .donut-wrap {{ display:flex; align-items:center; gap:18px; }}
  .donut-total {{ fill:{_TXT}; font:800 34px ui-monospace,monospace; text-anchor:middle; }}
  .donut-cap {{ fill:{_DIM}; font:600 9px ui-monospace,monospace; letter-spacing:2px; text-anchor:middle; }}
  .legend {{ font-family: ui-monospace, monospace; font-size:.74rem; }}
  .lg {{ display:flex; align-items:center; gap:8px; margin:6px 0; color:{_DIM}; }}
  .lg-n {{ color:{_TXT}; margin-left:auto; font-weight:700; }}
  .dot {{ width:10px; height:10px; border-radius:3px; display:inline-block; }}
  .ag-meta {{ font-family: ui-monospace, monospace; font-size:.74rem; color:{_DIM};
    margin-bottom:12px; }}
  .ag-meta b {{ color:{_TXT}; }}
  .chains {{ list-style:none; font-family: ui-monospace, monospace; font-size:.74rem; }}
  .chains li {{ display:flex; align-items:center; gap:8px; padding:6px 0;
    border-top:1px solid rgba(168,85,247,.1); flex-wrap:wrap; }}
  .seq {{ color:{_PURPLE}; font-weight:700; }}
  .node {{ color:{_TXT}; }}
  .act {{ color:{_PURPLE}; }}
  .prio {{ color:{_DIM}; margin-left:auto; }}

  /* findings */
  table {{ width:100%; border-collapse:collapse; font-size:.82rem; }}
  th {{ text-align:left; font-family: ui-monospace, monospace; font-size:.6rem;
    letter-spacing:2px; color:{_DIM}; padding:0 10px 10px; border-bottom:1px solid {_LINE}; }}
  td {{ padding:12px 10px; border-bottom:1px solid rgba(168,85,247,.09); vertical-align:top; }}
  .pill {{ font-family: ui-monospace, monospace; font-size:.62rem; font-weight:700;
    border:1px solid; border-radius:6px; padding:2px 8px; white-space:nowrap; }}
  .f-name {{ font-weight:600; }}
  .f-ep {{ font-family: ui-monospace, monospace; color:{_DIM}; font-size:.74rem; word-break:break-all; }}
  .payload {{ margin-top:6px; color:#e6c200; background:{_CARD2}; border-radius:6px;
    padding:6px 8px; font-size:.72rem; }}
  .f-ok {{ color:{_OK}; text-align:center; font-weight:700; }}
  .empty {{ color:{_DIM}; font-style:italic; padding:14px 4px; }}

  .patch-line {{ font-family: ui-monospace, monospace; font-size:.8rem; color:{_DIM};
    margin-top:14px; }}
  .patch-line b {{ color:{_OK}; }}
  .patch-rem {{ font-family: ui-monospace, monospace; font-size:.72rem; color:{_DIM}; margin-top:12px; }}

  /* findings by type */
  .ft-title {{ font-family: ui-monospace, monospace; font-size:.58rem; letter-spacing:2px; color:{_DIM}; margin-bottom:14px; }}
  .ft-row {{ display:flex; align-items:center; gap:10px; margin:9px 0; font-family: ui-monospace, monospace; font-size:.72rem; }}
  .ft-name {{ width:132px; color:{_TXT}; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .ft-bar {{ flex:1; height:9px; background:#241536; border-radius:6px; overflow:hidden; }}
  .ft-fill {{ display:block; height:100%; background:linear-gradient(90deg,{_PURPLE},#c026d3); border-radius:6px; }}
  .ft-n {{ color:{_TXT}; font-weight:700; width:24px; text-align:right; }}

  /* patches applied */
  .ptab {{ width:100%; border-collapse:collapse; font-size:.76rem; }}
  .ptab th {{ text-align:left; font-family: ui-monospace, monospace; font-size:.58rem;
    letter-spacing:2px; color:{_DIM}; padding:0 10px 8px; border-bottom:1px solid {_LINE}; }}
  .ptab td {{ padding:9px 10px; border-bottom:1px solid rgba(168,85,247,.08);
    font-family: ui-monospace, monospace; }}
  .p-file {{ color:{_TXT}; word-break:break-all; }}
  .p-cwe {{ color:{_PURPLE}; white-space:nowrap; }}
  .p-type {{ color:{_DIM}; }}
  .p-ok {{ color:{_OK}; white-space:nowrap; }}

  footer {{ margin-top:36px; padding-top:20px; border-top:1px solid {_LINE};
    font-family: ui-monospace, monospace; font-size:.66rem; color:{_DIM};
    display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }}

  @media (max-width:720px) {{
    .posture {{ grid-template-columns:1fr; }} .split {{ grid-template-columns:1fr; }}
    .stats {{ grid-template-columns: repeat(2,1fr); }} .delta {{ border:0; padding:0; }}
  }}
</style></head>
<body><div class="wrap">

  <header>
    <div class="brand mono">CYPHEX<small>SECURITY POSTURE REPORT</small></div>
    <div class="meta mono">
      <div>SCAN&nbsp; <b>{_esc(scan_id)}</b></div>
      <div>TARGET <b>{_esc(tgt)}</b></div>
      <div>{ts} &nbsp;·&nbsp; {dur_s}</div>
    </div>
  </header>

  <section>
    <h2>Security Posture</h2>
    <div class="card posture">
      <div>
        {_bar("Before Patching", before)}
        {_bar("After Patching", after)}
        <div class="patch-line"><b>{patches}</b> patch(es) applied &middot; <b style="color:#ff8c1a">{remaining_n}</b> still open</div>
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

  <section>
    <h2>Patches Applied</h2>
    <div class="card">{patches_html}</div>
  </section>

  <section>
    <h2>Confirmed Vulnerabilities</h2>
    <div class="card">
      <table>
        <thead><tr><th>SEVERITY</th><th>FINDING</th><th>ENDPOINT / PAYLOAD</th><th>✓</th></tr></thead>
        <tbody>{_findings_rows(vulns)}</tbody>
      </table>
    </div>
  </section>

  {attack_section}

  <footer>
    <span>CYPHEX · Oracle-Guided Cyber-Defense · RAG · Council · Reflexion · Genome</span>
    <span>generated {ts}</span>
  </footer>

</div></body></html>"""


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
            {"name": "SQL Injection (String Concatenation)", "severity": "Critical",
             "endpoint": "/api/orders", "payload": "' OR 1=1--", "confirmed": True},
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
    assert "Findings by Type" in html_text and "Patches Applied" in html_text
    assert "src/orders.js" in html_text and "still open" in html_text
    print(f"[ok] wrote {p} ({os.path.getsize(p)} bytes)")
