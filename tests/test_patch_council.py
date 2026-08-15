import pytest
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.council.patch_council import PatchCouncil
from backend.council.model_selector import ModelInfo


def _make_mock_selector():
    """Return a deterministic ModelSelector mock that doesn't call Ollama."""
    mock_sel = MagicMock()
    # Two fake models so get_reviewers(count=2) returns two distinct names
    mock_sel.models = [
        ModelInfo("cyphex-patch",        4.5, is_code=True,  vram_gb=4.5),
        ModelInfo("llama3.1:8b",         8.0, is_code=False, vram_gb=5.0),
        ModelInfo("deepseek-coder:6.7b", 6.7, is_code=True,  vram_gb=4.0),
    ]
    mock_sel.get.return_value            = "cyphex-patch"
    mock_sel.get_reviewers.return_value  = ["llama3.1:8b", "deepseek-coder:6.7b"]
    mock_sel.get_validators.return_value = ["llama3.1:8b", "deepseek-coder:6.7b", "cyphex-patch"]
    mock_sel.get_vram_costs.return_value = {
        "cyphex-patch": 4.5, "llama3.1:8b": 5.0, "deepseek-coder:6.7b": 4.0
    }
    return mock_sel


class TestPatchCouncil:

    @pytest.fixture
    def council(self):
        # Hermetic selector: fix the patcher/reviewer roster so these tests do
        # not depend on a live Ollama instance.
        fake_models = [
            SimpleNamespace(name="cyphex-patch", param_size=7.0),
            SimpleNamespace(name="deepseek-coder:1.3b", param_size=1.3),
            SimpleNamespace(name="llama3.1:8b", param_size=8.0),
        ]
        fake_selector = MagicMock()
        fake_selector.models = fake_models
        fake_selector.get.return_value = "cyphex-patch"
        fake_selector.get_reviewers.return_value = ["deepseek-coder:1.3b", "llama3.1:8b"]
        fake_selector.get_vram_costs.return_value = {}
        with patch(
            "backend.council.patch_council.get_selector",
            new_callable=AsyncMock,
            return_value=fake_selector,
        ):
            yield PatchCouncil()

    @pytest.mark.asyncio
    async def test_both_validators_approve(self, council):
        """Parameterised query patch approved by both validators -> safety=safe"""
        call_count = 0

        # **kwargs, not a fixed keyword list: the real _call has grown
        # `severity` and `cwe` since these were written, and a stub that
        # mirrors the signature exactly breaks again on the next addition.
        async def mock_call(model, system, prompt, **kwargs):
            nonlocal call_count
            call_count += 1
            if model == "cyphex-patch":
                return {
                    "unsafe_reason": "String concatenation into SQL query",
                    "fixed_code": "db.query('SELECT * FROM users WHERE id = ?', [req.params.id])",
                    "patch_safety": "safe"
                }
            else:
                return {"approved": True, "reason": "Parameterised query correctly fixes SQLi"}

        mock_selector = _make_mock_selector()
        with patch('backend.council.patch_council.get_selector', return_value=mock_selector):
            with patch.object(council, '_call', side_effect=mock_call):
                with patch.object(council.vram, 'ensure_loaded', new_callable=AsyncMock):
                    with patch.object(council.vram, 'unload', new_callable=AsyncMock):
                        result = await council.generate_and_validate_patch(
                            "SQL Injection", "CWE-89",
                            "const q = 'SELECT * FROM users WHERE id = ' + req.params.id",
                            "routes/users.js"
                        )

        assert result["patch_safety"] == "safe"
        assert result["fixed_code"] != ""
        assert len(result["dissent_reasons"]) == 0

    @pytest.mark.asyncio
    async def test_one_validator_rejects(self, council):
        """Incomplete patch rejected by one validator -> safety=review_needed"""
        call_count = 0

        # **kwargs, not a fixed keyword list: the real _call has grown
        # `severity` and `cwe` since these were written, and a stub that
        # mirrors the signature exactly breaks again on the next addition.
        async def mock_call(model, system, prompt, **kwargs):
            nonlocal call_count
            call_count += 1
            if model == "cyphex-patch":
                return {
                    "unsafe_reason": "innerHTML with user input",
                    "fixed_code": "element.textContent = userInput;",
                    "patch_safety": "safe"
                }
            elif model == "llama3.1:8b":
                return {"approved": True, "reason": "textContent prevents XSS"}
            else:
                return {"approved": False, "reason": "Missing DOMPurify for rich content"}

        mock_selector = _make_mock_selector()
        with patch('backend.council.patch_council.get_selector', return_value=mock_selector):
            with patch.object(council, '_call', side_effect=mock_call):
                with patch.object(council.vram, 'ensure_loaded', new_callable=AsyncMock):
                    with patch.object(council.vram, 'unload', new_callable=AsyncMock):
                        result = await council.generate_and_validate_patch(
                            "XSS", "CWE-79",
                            "element.innerHTML = userInput;",
                            "components/Profile.jsx"
                        )

        assert result["patch_safety"] == "review_needed"
        assert len(result["dissent_reasons"]) == 1

    @pytest.mark.asyncio
    async def test_both_validators_reject(self, council):
        """Bad patch rejected by both -> safety=rejected, fixed_code still returned"""
        # **kwargs, not a fixed keyword list: the real _call has grown
        # `severity` and `cwe` since these were written, and a stub that
        # mirrors the signature exactly breaks again on the next addition.
        async def mock_call(model, system, prompt, **kwargs):
            if model == "cyphex-patch":
                return {
                    "unsafe_reason": "eval with user input",
                    "fixed_code": "eval(sanitize(userInput))",  # still bad
                    "patch_safety": "safe"
                }
            else:
                return {"approved": False, "reason": "eval still present, vulnerability not fixed"}

        mock_selector = _make_mock_selector()
        with patch('backend.council.patch_council.get_selector', return_value=mock_selector):
            with patch.object(council, '_call', side_effect=mock_call):
                with patch.object(council.vram, 'ensure_loaded', new_callable=AsyncMock):
                    with patch.object(council.vram, 'unload', new_callable=AsyncMock):
                        result = await council.generate_and_validate_patch(
                            "Command Injection", "CWE-78",
                            "eval(req.body.code)",
                            "routes/debug.js"
                        )

        assert result["patch_safety"] == "rejected"
        assert result["fixed_code"] != ""  # still returned for user review
        assert len(result["dissent_reasons"]) == 2

    @pytest.mark.asyncio
    async def test_patch_does_not_invent_cve(self, council):
        """Patch output must not contain CVE- pattern"""
        import re
        CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}')

        # **kwargs, not a fixed keyword list: the real _call has grown
        # `severity` and `cwe` since these were written, and a stub that
        # mirrors the signature exactly breaks again on the next addition.
        async def mock_call(model, system, prompt, **kwargs):
            if model == "cyphex-patch":
                return {
                    "unsafe_reason": "Hardcoded secret in source code (CWE-798)",
                    "fixed_code": "const SECRET = process.env.JWT_SECRET;",
                    "patch_safety": "safe"
                }
            else:
                return {"approved": True, "reason": "Environment variable is correct fix"}

        mock_selector = _make_mock_selector()
        with patch('backend.council.patch_council.get_selector', return_value=mock_selector):
            with patch.object(council, '_call', side_effect=mock_call):
                with patch.object(council.vram, 'ensure_loaded', new_callable=AsyncMock):
                    with patch.object(council.vram, 'unload', new_callable=AsyncMock):
                        result = await council.generate_and_validate_patch(
                            "Hardcoded Secret", "CWE-798",
                            "const SECRET = 'mysupersecret123'",
                            "config.js"
                        )

        assert not CVE_PATTERN.search(result["fixed_code"])
        assert not CVE_PATTERN.search(result["unsafe_reason"])

    @pytest.mark.asyncio
    async def test_vram_unloads_before_qwen(self, council):
        """VRAMManager must unload all models before loading cyphex-patch"""
        council.vram.loaded = {"deepseek-coder:1.3b": 1.0, "phi3:mini": 2.2}
        unloaded_models = []

        async def mock_unload(model):
            unloaded_models.append(model)
            council.vram.loaded.pop(model, None)

        # **kwargs, not a fixed keyword list: the real _call has grown
        # `severity` and `cwe` since these were written, and a stub that
        # mirrors the signature exactly breaks again on the next addition.
        async def mock_call(model, system, prompt, **kwargs):
            if model == "cyphex-patch":
                return {"unsafe_reason": "test", "fixed_code": "test", "patch_safety": "safe"}
            return {"approved": True, "reason": "ok"}

        mock_selector = _make_mock_selector()
        with patch('backend.council.patch_council.get_selector', return_value=mock_selector):
            with patch.object(council, '_call', side_effect=mock_call):
                with patch.object(council.vram, 'unload', side_effect=mock_unload):
                    with patch.object(council.vram, 'ensure_loaded', new_callable=AsyncMock):
                        result = await council.generate_and_validate_patch(
                            "SQLi", "CWE-89", "test code", "test.js"
                        )

        # Both models should have been unloaded before Qwen loaded
        assert "deepseek-coder:1.3b" in unloaded_models
        assert "phi3:mini" in unloaded_models
