"""
CYPHEX — Cross-project patch memory (cognee) tests.

Skipped entirely when the optional `memory` extra isn't installed
(`pip install ".[memory]"`), so the base test suite stays green for
contributors who haven't opted into this feature.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

pytest.importorskip("cognee")

from backend.rag import cognee_memory as cm  # noqa: E402


def test_telemetry_disabled_on_import():
    assert os.environ.get("TELEMETRY_DISABLED") == "1"


def test_format_hint_empty():
    assert cm.format_hint([]) == ""
    assert cm.format_hint(None) == ""


def test_format_hint_nonempty():
    hint = cm.format_hint(["some prior fix"])
    assert hint != ""
    assert "MEMORY HINT" in hint


@pytest.mark.asyncio
async def test_cold_start_recall_returns_empty_list(tmp_path, monkeypatch):
    """
    A genuinely empty graph must return []. Uses an isolated temp directory
    rather than the shared default COGNEE_DATA_DIR — once any other test in
    this session has remembered something, a query against the *shared*
    graph would return that entry regardless of relevance (cognee's default
    vector top-k search has no similarity-score cutoff, so with only one or
    two entries in the graph it returns the nearest one even for an
    unrelated query — this isn't a bug in recall_similar_fixes, it's how a
    near-empty graph behaves; the discriminating case that matters is a
    graph with zero entries).
    """
    monkeypatch.setattr(cm, "COGNEE_DATA_DIR", str(tmp_path / "cognee_data"))
    monkeypatch.setattr(cm, "_configured", False)

    hits = await cm.recall_similar_fixes("CWE-999-NONEXISTENT", "some code that was never remembered")
    assert hits == []


def test_project_id_is_stable_and_distinct():
    """Cross-project memory only works if project identity is stable per repo
    and distinct between repos. Pure hashing — no models, no I/O."""
    a1 = cm.project_id_for("https://github.com/example/project-a.git", "")
    a2 = cm.project_id_for("https://github.com/example/project-a.git", "")
    b = cm.project_id_for("https://github.com/example/project-b.git", "")

    assert a1 == a2
    assert a1 != b


@pytest.mark.integration
@pytest.mark.asyncio
async def test_cross_project_recall(tmp_path, monkeypatch):
    """
    The actual value proposition: a fix remembered while working on one
    project should be recallable while working on a completely different
    project, for a semantically similar vulnerability.

    Marked `integration` — remember_fix() runs cognee's cognify, which drives a
    local LLM and can take minutes. Run with `pytest -m integration`.

    The monkeypatch is not optional: without it this writes into the repo's real
    .cognee_data/, permanently polluting cross-project memory with test
    fixtures and making later recalls return them.
    """
    monkeypatch.setattr(cm, "COGNEE_DATA_DIR", str(tmp_path / "cognee_data"))
    monkeypatch.setattr(cm, "_configured", False)

    project_a = cm.project_id_for("https://github.com/example/project-a.git", "")
    project_b = cm.project_id_for("https://github.com/example/project-b.git", "")
    assert project_a != project_b

    await cm.remember_fix(
        cwe="CWE-89",
        vulnerable_code="db.query('SELECT * FROM users WHERE id = ' + userId)",
        fixed_code="db.query('SELECT * FROM users WHERE id = ?', [userId])",
        project_id=project_a,
        framework="express",
    )

    hits = await cm.recall_similar_fixes(
        "CWE-89",
        "db.execute('SELECT * FROM orders WHERE id = ' + orderId)",
    )
    assert hits != []
