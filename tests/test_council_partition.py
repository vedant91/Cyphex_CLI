"""The council's false-positive debate must never discard STATIC findings.

STATIC findings ([STATIC] prefix) are deterministic Semgrep/scanner source
matches — the ones the patch phase repairs. If a local-model vote could delete
them, patching has nothing to fix and the after-patch score never improves
(the 16->16 symptom). _partition_for_council keeps them out of the vote.
"""
import cli_engine


class _V:
    def __init__(self, name):
        self.name = name


def test_static_findings_bypass_the_debate_dynamic_ones_are_validated():
    vulns = [
        _V("[STATIC] SQL Injection (String Concatenation)"),   # patchable source
        _V("[STATIC] Command Injection (child_process)"),      # patchable source
        _V("[DYNAMIC] Sensitive Data Exposure"),               # probe-inferred
        _V("[NETWORK] SMB exposed on port 445"),               # network
        _V("Reflected XSS"),                                   # untagged → treated dynamic
    ]
    static_keep, to_validate = cli_engine._partition_for_council(vulns)

    names = lambda xs: [v.name for v in xs]
    # every [STATIC] finding is kept, unconditionally — never sent to the vote
    assert names(static_keep) == [
        "[STATIC] SQL Injection (String Concatenation)",
        "[STATIC] Command Injection (child_process)",
    ]
    # everything else is what the council may debate/discard
    assert "[DYNAMIC] Sensitive Data Exposure" in names(to_validate)
    assert "[NETWORK] SMB exposed on port 445" in names(to_validate)
    assert "Reflected XSS" in names(to_validate)
    assert len(static_keep) + len(to_validate) == len(vulns)   # nothing lost


def test_partition_handles_empty_and_all_static():
    assert cli_engine._partition_for_council([]) == ([], [])
    allstatic = [_V("[STATIC] a"), _V("[STATIC] b")]
    keep, debate = cli_engine._partition_for_council(allstatic)
    assert len(keep) == 2 and debate == []      # nothing to debate → council is skipped
