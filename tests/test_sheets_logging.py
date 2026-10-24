"""BaseDeepAgent._log_hypothesis_row(): one row per tested hypothesis to
every connected Google Sheet — confirmed and not-found outcomes both log,
with a reason for the latter. No-op with nothing connected.
"""
from unittest.mock import patch

import pytest

from backend.deepagents.attack_graph import AttackGraph
from backend.deepagents.attack_surface_index import AttackSurfaceIndex
from backend.deepagents.base_deep_agent import BaseDeepAgent, HypothesisResult
from backend.deepagents.oracle_attack import HttpRequest, Hypothesis
from backend.backend.models.scan import ScanContext, Vuln


class _FakeAgent(BaseDeepAgent):
    PRIMARY_VULN_CLASS = "Test"


def _agent():
    return _FakeAgent(scan_id="s1", target_url="http://localhost:4001",
                      attack_graph=AttackGraph(), asi=AttackSurfaceIndex(), oracle=None)


def _hyp():
    req = HttpRequest(method="GET", path="/api/x", payload="' OR 1=1--", body="")
    return Hypothesis(id="h1", vuln_type="SQL Injection", cwe="CWE-89",
                      severity="High", test_request=req, reject_signal="", confirm_signal="")


def test_no_connection_builds_no_row_at_all():
    agent = _agent()
    with patch("cyphex.sheets.saved", return_value=[]), \
         patch("cyphex.sheets.log_row") as mock_log:
        agent._log_hypothesis_row(ScanContext(target_url=agent.target), _hyp(),
                                   HypothesisResult(False, reason="dead route (HTTP 404)"))
    mock_log.assert_not_called()


def test_confirmed_outcome_logs_the_vuln_fields():
    agent = _agent()
    vuln = Vuln(name="SQL Injection", cwe="CWE-89", severity="High",
               endpoint="/api/x", confirmed=True, description="Confirmed SQLi on /api/x.")
    with patch("cyphex.sheets.saved", return_value=[{"url": "u", "secret": "s"}]), \
         patch("cyphex.sheets.log_row") as mock_log:
        agent._log_hypothesis_row(ScanContext(target_url=agent.target), _hyp(),
                                   HypothesisResult(True, vuln, 92))
    row = mock_log.call_args.args[0]
    assert row["Outcome"] == "confirmed"
    assert row["Vulnerability"] == "SQL Injection"
    assert row["Endpoint"] == "/api/x"
    assert row["Payload"] == "' OR 1=1--"
    assert row["Confidence"] == 92
    assert "Confirmed SQLi" in row["Reason"]


def test_not_found_outcome_logs_the_reason():
    agent = _agent()
    with patch("cyphex.sheets.saved", return_value=[{"url": "u", "secret": "s"}]), \
         patch("cyphex.sheets.log_row") as mock_log:
        agent._log_hypothesis_row(ScanContext(target_url=agent.target), _hyp(),
                                   HypothesisResult(False, reason="dead route (HTTP 404)"))
    row = mock_log.call_args.args[0]
    assert row["Outcome"] == "not found"
    assert row["Reason"] == "dead route (HTTP 404)"
    assert row["Vulnerability"] == "SQL Injection"  # falls back to the hypothesis's own vuln_type


def test_row_has_exactly_the_sheet_columns():
    from cyphex import sheets
    agent = _agent()
    with patch("cyphex.sheets.saved", return_value=[{"url": "u", "secret": "s"}]), \
         patch("cyphex.sheets.log_row") as mock_log:
        agent._log_hypothesis_row(ScanContext(target_url=agent.target), _hyp(), HypothesisResult(False, reason="x"))
    assert set(mock_log.call_args.args[0]) == set(sheets.COLUMNS)


def test_never_raises_when_sheets_module_is_unimportable():
    agent = _agent()
    with patch("builtins.__import__", side_effect=ImportError("boom")):
        agent._log_hypothesis_row(ScanContext(target_url=agent.target), _hyp(),
                                   HypothesisResult(False, reason="x"))  # must not raise
