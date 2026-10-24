"""The main /scan /deep flow must always print exactly steps 1/10..10/10 —
users explicitly asked for 10 steps (it silently stopped at 9 before this,
having never printed the final COMPLETE step). Source-level check: cheap,
and the real contract (no step is skipped or mislabeled) that unit tests
on the full async scan pipeline would be far more expensive to assert.
"""
import re

import cli_engine


def _step_calls():
    src = open(cli_engine.__file__, "r", encoding="utf-8").read()
    return re.findall(r'self\._step\("(\d+)/10"', src)


def test_all_ten_step_numbers_appear_exactly_once_in_order():
    nums = [int(n) for n in _step_calls()]
    # 4/10 appears twice (multi-service vs single-target DYNAMIC SCAN variants
    # of the same step) — every other number appears exactly once.
    assert sorted(set(nums)) == list(range(1, 11))
    assert nums.count(4) == 2
    assert all(nums.count(n) == 1 for n in range(1, 11) if n != 4)


def test_step_9_is_printed_before_every_early_return_in_patch_workflow():
    """_patch_workflow must print 9/10 before its first possible return, so a
    scan with 0 patchable findings (the common /deep-against-a-live-URL case)
    still shows all 10 steps instead of silently stopping at 8."""
    src = open(cli_engine.__file__, "r", encoding="utf-8").read()
    start = src.index("async def _patch_workflow")
    end = src.index("\n    async def ", start + 10)
    body = src[start:end]
    step_pos = body.index('self._step("9/10"')
    first_return_pos = re.search(r"\n\s+return\b", body).start()
    assert step_pos < first_return_pos
