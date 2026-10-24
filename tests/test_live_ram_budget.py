"""VRAMManager.live_budget() — the fix for a real incident: CYPHEX detected a
"good" total-RAM budget once at startup, then loaded 2 parallel 7B+ Ollama
models while Docker was already running several GB, with nothing re-checking
actual free memory at the moment of that load. The machine hung. live_budget()
re-reads real free RAM on every load decision and keeps MIN_FREE_RAM_HEADROOM_GB
untouched; ensure_loaded_together() degrades to loading models one at a time
when the live-RAM-capped budget can't hold them all simultaneously.
"""
from unittest.mock import patch

import pytest

from backend.council.council_orchestrator import (
    VRAMManager, MIN_FREE_RAM_HEADROOM_GB,
)


@pytest.fixture
def vram():
    v = VRAMManager()
    v.VRAM_LIMIT = 20.0  # static ceiling generous; live RAM is the real cap here
    return v


def _patch_available(gb):
    return patch(
        "cyphex.hardware.get_available_memory_gb", return_value=gb
    )


class TestLiveBudget:

    def test_live_budget_caps_below_static_limit_when_ram_is_tight(self, vram):
        with _patch_available(3.0):
            # 3GB free, nothing loaded yet, 2.5GB must stay free -> 0.5GB usable
            assert vram.live_budget() == pytest.approx(0.5, abs=0.01)

    def test_live_budget_adds_back_already_loaded_models(self, vram):
        vram.loaded["phi3:mini"] = 2.2
        with _patch_available(3.0):
            # Ollama already holds 2.2GB of that "3GB free" reading, so it's
            # not double-penalized: 3.0 + 2.2 - 2.5 = 2.7 usable for the budget.
            assert vram.live_budget() == pytest.approx(2.7, abs=0.01)

    def test_live_budget_falls_back_to_static_limit_when_unreadable(self, vram):
        with patch("cyphex.hardware.get_available_memory_gb", return_value=None):
            assert vram.live_budget() == vram.VRAM_LIMIT

    def test_live_budget_never_exceeds_static_limit_even_with_lots_of_ram(self, vram):
        with _patch_available(500.0):
            assert vram.live_budget() == vram.VRAM_LIMIT

    def test_live_budget_never_goes_negative(self, vram):
        with _patch_available(0.1):
            assert vram.live_budget() == 0.0

    @pytest.mark.asyncio
    async def test_can_load_respects_live_ram_not_just_static_limit(self, vram):
        with _patch_available(3.0):  # only 0.5GB usable after headroom
            assert vram.can_load("cyphex-patch") is False  # needs 4.5GB

    @pytest.mark.asyncio
    async def test_ensure_loaded_together_falls_back_to_serial_when_ram_tight(self, vram):
        """Two 4.5GB models together need 9GB — fits the static VRAM_LIMIT
        (20) but not 3GB of live free RAM. Must load them one at a time,
        not raise and not silently try to hold both simultaneously."""
        warmed_at_once = []

        async def fake_raw_call(model, prompt, stream=False):
            warmed_at_once.append((model, dict(vram.loaded)))
            return "ok"

        with _patch_available(3.0):
            with patch.object(vram, "_raw_call", side_effect=fake_raw_call):
                await vram.ensure_loaded_together(["cyphex-patch", "mistral:7b"])

        # Serial fallback: by the time the SECOND model warms up, the first
        # one must already have been evicted (never both resident together).
        assert len(warmed_at_once) == 2
        _, loaded_during_second = warmed_at_once[1]
        assert "cyphex-patch" not in loaded_during_second

    @pytest.mark.asyncio
    async def test_ensure_loaded_together_stays_parallel_when_ram_is_plentiful(self, vram):
        async def fake_raw_call(model, prompt, stream=False):
            return "ok"

        with _patch_available(100.0):
            with patch.object(vram, "_raw_call", side_effect=fake_raw_call):
                await vram.ensure_loaded_together(["cyphex-patch", "mistral:7b"])

        assert "cyphex-patch" in vram.loaded and "mistral:7b" in vram.loaded

    def test_min_free_ram_headroom_is_within_the_user_requested_2_to_3gb_range(self):
        assert 2.0 <= MIN_FREE_RAM_HEADROOM_GB <= 3.0
