import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.council.council_orchestrator import VRAMManager


class TestVRAMManager:

    @pytest.fixture
    def vram(self, monkeypatch):
        v = VRAMManager()
        # Pin to 5.5 GB (the no-GPU fallback) so tests are deterministic
        # regardless of the host machine's physical GPU memory.
        v.VRAM_LIMIT = 5.5
        # live_budget() also caps on actually-free system RAM (see
        # test_live_ram_budget.py) — pin that to "plenty free" here so every
        # pre-existing test in this file keeps testing VRAM_LIMIT alone,
        # deterministic regardless of how much RAM is free on the machine
        # actually running the suite.
        monkeypatch.setattr(
            "backend.council.council_orchestrator.VRAMManager.live_budget",
            lambda self: self.VRAM_LIMIT,
        )
        return v

    @pytest.mark.asyncio
    async def test_deepseek_and_phi3_fit_together(self, vram):
        """Deepseek (1.0) + Phi-3 (2.2) = 3.2 GB — must fit within 5.5 GB budget"""
        assert vram.can_load("deepseek-coder:1.3b") is True
        # Simulate loaded
        vram.loaded["deepseek-coder:1.3b"] = 1.0
        assert vram.can_load("phi3:mini") is True
        vram.loaded["phi3:mini"] = 2.2
        # Total = 3.2, still under 5.5
        assert sum(vram.loaded.values()) == 3.2
        assert sum(vram.loaded.values()) <= vram.VRAM_LIMIT

    @pytest.mark.asyncio
    async def test_cannot_exceed_budget(self, vram):
        """Loading Qwen-7B (4.5 GB) when Phi-3 (2.2 GB) is loaded must exceed budget"""
        vram.loaded["phi3:mini"] = 2.2
        # 2.2 + 4.5 = 6.7 > 5.5
        assert vram.can_load("cyphex-patch") is False

    @pytest.mark.asyncio
    async def test_qwen_cannot_load_with_others(self, vram):
        """Qwen (4.5) + any other model exceeds 5.5 GB — must evict others first"""
        vram.loaded["deepseek-coder:1.3b"] = 1.0
        vram.loaded["phi3:mini"] = 2.2
        # 1.0 + 2.2 + 4.5 = 7.7 > 5.5
        assert vram.can_load("cyphex-patch") is False

    @pytest.mark.asyncio
    async def test_unload_releases_vram(self, vram):
        """After unload(), model no longer counted in VRAM budget"""
        vram.loaded["phi3:mini"] = 2.2
        assert sum(vram.loaded.values()) == 2.2

        with patch.object(vram, '_raw_call', new_callable=AsyncMock):
            await vram.unload("phi3:mini")

        assert "phi3:mini" not in vram.loaded
        assert sum(vram.loaded.values()) == 0.0
        assert vram.can_load("cyphex-patch") is True

    @pytest.mark.asyncio
    async def test_ensure_loaded_evicts_lru(self, vram):
        """ensure_loaded must evict models when needed to fit new model"""
        vram.loaded["deepseek-coder:1.3b"] = 1.0
        vram.loaded["phi3:mini"] = 2.2

        with patch.object(vram, '_raw_call', new_callable=AsyncMock):
            # Internal eviction calls _unload_locked directly (not the public,
            # lock-acquiring unload()) since the caller already holds self._lock.
            with patch.object(vram, '_unload_locked', new_callable=AsyncMock) as mock_unload:
                async def side_effect(model):
                    vram.loaded.pop(model, None)
                mock_unload.side_effect = side_effect

                await vram.ensure_loaded("cyphex-patch")
                # Both should have been evicted to make room for 4.5 GB
                assert mock_unload.call_count >= 1
                assert "cyphex-patch" in vram.loaded

    @pytest.mark.asyncio
    async def test_concurrent_ensure_loaded_does_not_corrupt_dict(self, vram):
        """Reproduces the real 'dictionary changed size during iteration' crash:
        up to 6 DeepAgents call ensure_loaded() truly concurrently via
        asyncio.gather, each with a real await inside the critical section.
        Without the lock, two coroutines racing on self.loaded raised that
        RuntimeError live during a /deep scan (DeepCMDiAgent, DeepSSTIAgent,
        DeepPathTraversalAgent). The lock must serialize them instead."""
        vram.VRAM_LIMIT = 3.0  # force eviction pressure across concurrent callers

        async def fake_raw_call(model, prompt, stream=False):
            await asyncio.sleep(0.01)  # real await point inside the critical section
            return "ok"

        with patch.object(vram, '_raw_call', side_effect=fake_raw_call):
            with patch.object(VRAMManager, '_unload_locked', autospec=True) as mock_unload:
                async def side_effect(self, model):
                    await asyncio.sleep(0.01)
                    self.loaded.pop(model, None)
                mock_unload.side_effect = side_effect

                models = ["cyphex-patch", "deepseek-coder:1.3b", "phi3:mini",
                          "qwen2.5-coder:7b", "llama3.1:8b", "cyphex-sqli"]
                await asyncio.gather(*(vram.ensure_loaded(m) for m in models))

        # No RuntimeError raised means the lock held; dict must be internally consistent
        assert sum(vram.loaded.values()) <= vram.VRAM_LIMIT
