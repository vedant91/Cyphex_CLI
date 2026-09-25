"""The post-scan HTML report must render every fixed section from a report
dict, escape hostile finding text, and never raise on empty/missing data — a
report-render failure must not be able to spoil a scan that already finished.
"""
import report_html


_REPORT = {
    "scan_id": "cli_abc123",
    "timestamp": "2026-01-01T12:00:00+00:00",
    "score": 16,
    "target": "https://github.com/acme/vibemart",
    "summary": {"critical": 2, "high": 1, "medium": 0, "low": 3,
                "total_vulns": 6, "duration_seconds": 842.0},
    "vulnerabilities": [
        {"name": "SQL Injection", "severity": "Critical",
         "endpoint": "/api/orders", "payload": "' OR 1=1--", "confirmed": True},
    ],
    "attack_graph": {"privilege_level": "user", "creds_harvested": 1,
                     "tokens_harvested": 0, "nodes_touched": ["/login"],
                     "chains": [{"seq": 1, "source": "/login", "action": "sqli",
                                 "target": "/api/orders", "priority": "high"}]},
}


def test_renders_all_fixed_sections_with_before_after():
    patched = [{"file": "src/orders.js", "cwe": "CWE-89", "vuln_type": "SQL Injection"}]
    html = report_html.render_report_html(
        _REPORT, score_before=16, score_after=42, patches_applied=1,
        patched=patched, remaining=3)
    # masthead + every fixed section header is present
    for token in ("CYPHEX", "Security Posture", "Findings Summary",
                  "Findings by Type", "Patches Applied", "Confirmed Vulnerabilities"):
        assert token in html
    # before/after posture + delta are shown
    assert "Before Patching" in html and "After Patching" in html
    assert "+26" in html                       # delta 42 - 16
    assert "<b>1</b> patch(es) applied" in html
    assert "src/orders.js" in html             # the patched file is listed
    assert "3 finding(s) still unpatched" in html
    assert "SQL Injection" in html and "/api/orders" in html


def test_hostile_finding_text_is_escaped():
    r = dict(_REPORT, vulnerabilities=[
        {"name": "<script>alert(1)</script>", "severity": "High",
         "endpoint": "/x", "payload": "<img src=x onerror=alert(1)>", "confirmed": True}])
    html = report_html.render_report_html(r)
    assert "<script>alert(1)</script>" not in html      # raw tag must not survive
    assert "&lt;script&gt;" in html                       # escaped instead


def test_empty_report_does_not_raise():
    html = report_html.render_report_html({})
    assert "CYPHEX" in html
    assert "No confirmed vulnerabilities" in html         # explicit empty state
