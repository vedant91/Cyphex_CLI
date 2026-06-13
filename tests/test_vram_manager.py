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
    def vram(self):
        v = VRAMManager()
        # Pin to 5.5 GB (the no-GPU fallback) so tests are deterministic
        # regardless of the host machine's physical GPU memory.
        v.VRAM_LIMIT = 5.5
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
            with patch.object(vram, 'unload', new_callable=AsyncMock) as mock_unload:
                # Force the unload to actually remove from dict
                async def side_effect(model):
                    vram.loaded.pop(model, None)
                mock_unload.side_effect = side_effect

                await vram.ensure_loaded("cyphex-patch")
                # Both should have been evicted to make room for 4.5 GB
                assert mock_unload.call_count >= 1
                assert "cyphex-patch" in vram.loaded
