import pytest
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.council.debate_protocol import DebateProtocol


class TestDebateProtocol:

    @pytest.fixture
    def protocol(self):
        # Hermetic selector: avoid querying a live Ollama instance so these
        # tests are deterministic on any machine.
        fake_models = [
            SimpleNamespace(name="qwen2.5-coder:7b", param_size=7.0),
            SimpleNamespace(name="llama3.1:8b", param_size=8.0),
            SimpleNamespace(name="deepseek-coder:6.7b", param_size=6.7),
        ]
        fake_selector = MagicMock()
        fake_selector.models = fake_models
        fake_selector.get_validators.return_value = [m.name for m in fake_models]
        fake_selector.get_vram_costs.return_value = {}
        with patch(
            "backend.council.debate_protocol.get_selector",
            new_callable=AsyncMock,
            return_value=fake_selector,
        ):
            yield DebateProtocol()

    @pytest.mark.asyncio
    async def test_unanimous_confirm(self, protocol):
        """3/3 agree confirmed=true -> returns confirmed=True immediately"""
        confirmed_vote = {"confirmed": True, "confidence": 0.95, "reason": "SQL error in response"}

        with patch.object(protocol, '_call', new_callable=AsyncMock, return_value=confirmed_vote):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "SQL Injection",
                    "Request: POST /login\nPayload: 1' OR 1=1--\nResponse: SQL syntax error near 'OR 1=1'"
                )

        assert result is True
        assert conf == pytest.approx(0.95, rel=1e-3)
        assert len(votes) == 3
        # All round 1 — no round 2 needed
        assert all(v["round"] == 1 for v in votes)

    @pytest.mark.asyncio
    async def test_unanimous_reject(self, protocol):
        """3/3 agree confirmed=false -> returns confirmed=False, no round 2"""
        rejected_vote = {"confirmed": False, "confidence": 0.1, "reason": "No evidence of vulnerability"}

        with patch.object(protocol, '_call', new_callable=AsyncMock, return_value=rejected_vote):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "SQL Injection",
                    "Request: GET /search?q=laptop\nResponse: 200 OK - Normal search results"
                )

        assert result is False
        assert len(votes) == 3
        assert all(v["round"] == 1 for v in votes)

    @pytest.mark.asyncio
    async def test_majority_confirm_with_round2(self, protocol):
        """2/3 confirm -> dissenter re-prompted -> final 2/3 = CONFIRMED"""
        call_count = 0

        async def mock_call(model, system, prompt, task_name=""):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return {"confirmed": True, "confidence": 0.9, "reason": "XSS payload reflected"}
            elif call_count == 3:
                return {"confirmed": False, "confidence": 0.3, "reason": "Insufficient evidence"}
            else:
                # Round 2: dissenter re-prompted, still disagrees
                return {"confirmed": False, "confidence": 0.4, "reason": "Still not convinced"}

        with patch.object(protocol, '_call', side_effect=mock_call):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "XSS",
                    "Request: GET /search?q=<script>alert(1)</script>\nResponse: <h1><script>alert(1)</script></h1>"
                )

        # 2/3 still confirmed after round 2
        assert result is True
        assert len(votes) == 3

    @pytest.mark.asyncio
    async def test_split_vote_keeps_finding(self, protocol):
        """1/3 confirm on a split vote -> KEEP (conservative: never discard a
        finding any validator still confirms)."""
        call_count = 0

        async def mock_call(model, system, prompt, task_name=""):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"confirmed": True, "confidence": 0.6, "reason": "Suspicious pattern"}
            return {"confirmed": False, "confidence": 0.8, "reason": "No exploit evidence"}

        with patch.object(protocol, '_call', side_effect=mock_call):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "SSRF",
                    "Request: POST /fetch url=http://example.com\nResponse: 200 OK"
                )

        # Under the current single-round conservative logic:
        # 1/3 confirmed → KEEP the finding (safety-first, never silently discard).
        # The old two-round design where the confirmer got re-prompted no longer exists.
        assert result is True

    @pytest.mark.asyncio
    async def test_no_false_positive_on_benign_evidence(self, protocol):
        """Evidence='GET /search?q=laptop Response: 200 OK' must not confirm any vuln"""
        rejected_vote = {"confirmed": False, "confidence": 0.05, "reason": "Normal response, no exploit evidence"}

        with patch.object(protocol, '_call', new_callable=AsyncMock, return_value=rejected_vote):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "SQL Injection",
                    "Request: GET /search?q=laptop\nResponse: 200 OK - Search results for laptop"
                )

        assert result is False

    @pytest.mark.asyncio
    async def test_model_timeout_degrades_gracefully(self, protocol):
        """If one model times out, voting continues with 2 remaining models"""
        call_count = 0

        async def mock_call(model, system, prompt, task_name=""):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise Exception("Connection timeout")
            return {"confirmed": True, "confidence": 0.9, "reason": "SQL error in response body"}

        with patch.object(protocol, '_call', side_effect=mock_call):
            with patch.object(protocol.vram, 'ensure_loaded', new_callable=AsyncMock):
                result, conf, votes = await protocol.debate_finding(
                    "SQL Injection",
                    "Request: POST /login\nPayload: 1' OR 1=1--\nResponse: SQL syntax error"
                )

        # 2/3 confirmed (1 errored out as False), so result should be True
        assert result is True
        assert len(votes) == 3
