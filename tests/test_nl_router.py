"""
CYPHEX — Natural-language router guardrail tests.

Ollama itself is mocked out (httpx.post is patched) — these tests exercise
the guardrail logic in nl_router.py: only a whitelisted slash command ever
survives translate(); everything else — chit-chat, an unlisted command,
shell metacharacters, a hallucinated target, Ollama being unreachable —
comes back as None. Tool-calling turns are simulated via side_effect lists
of mocked /api/chat responses, exercising the same multi-turn loop
translate() runs against the real model.
"""
import json
import os
import sys
from unittest.mock import patch, MagicMock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import nl_router  # noqa: E402


def _chat_response(content: str = "", tool_calls=None):
    """Build a fake httpx.Response-like object mirroring Ollama's /api/chat
    JSON shape: {"message": {"role": "assistant", "content": ..., "tool_calls": [...]}}"""
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "message": {"role": "assistant", "content": content, "tool_calls": tool_calls or []}
    }
    return resp


def _tool_call(tool_name: str, **arguments):
    return {"function": {"name": tool_name, "arguments": arguments}}


class TestGuardrailRefusesNonCommands:
    """The router must never leak chat, identity, or off-topic answers."""

    def test_refuses_name_question(self):
        with patch("httpx.post", return_value=_chat_response("REFUSE")):
            assert nl_router.translate("what is your name") is None

    def test_refuses_model_going_off_script(self):
        # Even if the model ignores its system prompt and starts chatting,
        # the allowlist regex — not the model — is what decides.
        with patch("httpx.post", return_value=_chat_response(
            "My name is Ollama and I'm happy to help with anything!"
        )):
            assert nl_router.translate("what is your name") is None

    def test_refuses_unlisted_command(self):
        with patch("httpx.post", return_value=_chat_response("/rm -rf /")):
            assert nl_router.translate("delete everything") is None

    def test_refuses_empty_response(self):
        with patch("httpx.post", return_value=_chat_response("")):
            assert nl_router.translate("hello") is None

    def test_refuses_shell_metacharacters_in_args(self):
        with patch("httpx.post", return_value=_chat_response("/scan ./app; rm -rf /")):
            assert nl_router.translate("scan my app") is None


class TestGuardrailMapsValidRequests:
    """Legitimate scan requests translate to the right slash command."""

    def test_repo_link_maps_to_full_scan(self):
        with patch("httpx.post", return_value=_chat_response(
            "/scan https://github.com/octocat/hello --full"
        )):
            out = nl_router.translate("run my repo https://github.com/octocat/hello")
        assert out == "/scan https://github.com/octocat/hello --full"

    def test_strips_surrounding_quotes_and_takes_first_line(self, tmp_path):
        # Real dir (not "./app") since /scan now requires the target to
        # actually exist — this test is specifically about the quote/
        # multi-line stripping, independent of that gate.
        with patch("httpx.post", return_value=_chat_response(
            f'"/scan {tmp_path}"\nHope that helps!'
        )):
            out = nl_router.translate(f"scan {tmp_path}")
        assert out == f"/scan {tmp_path}"

    def test_status_request(self):
        with patch("httpx.post", return_value=_chat_response("/status")):
            assert nl_router.translate("show me the health dashboard") == "/status"


class TestToolCalling:
    """The model grounds itself via check_path/list_cwd instead of this
    module pattern-matching a fix onto whatever it said. translate() is
    two-stage now: a tool-free classify() call decides "/scan" needs
    grounding, THEN the tool-calling loop runs — so every scenario here
    mocks the classify response first, followed by the grounding turns."""

    def _bare_scan_classify(self):
        """Stage 1's response when it correctly defers target resolution."""
        return _chat_response("/scan")

    def test_check_path_tool_grounds_a_local_target(self, tmp_path):
        real_dir = tmp_path / "vibemart"
        real_dir.mkdir()
        classify = self._bare_scan_classify()
        # Ground turn 1: model calls check_path with the raw phrase (sloppy
        # — includes extra words, same as observed against the live model).
        ground1 = _chat_response(tool_calls=[_tool_call("check_path", name=f"my repo {real_dir}")])
        # Ground turn 2: after seeing the tool result, commits to a command.
        ground2 = _chat_response(f"/scan {real_dir} --full")
        with patch("httpx.post", side_effect=[classify, ground1, ground2]) as mock_post:
            out = nl_router.translate(f"scan my repo {real_dir}")
        assert out == f"/scan {real_dir} --full"
        assert mock_post.call_count == 3
        # The tool result fed back to the model must reflect a real
        # filesystem check, not a canned answer.
        ground2_messages = mock_post.call_args_list[2].kwargs["json"]["messages"]
        tool_result = json.loads(ground2_messages[-1]["content"])
        assert tool_result == {"exists": True, "type": "directory", "matched": str(real_dir)}

    def test_list_cwd_tool_round_trip(self, tmp_path):
        (tmp_path / "auth.py").write_text("# auth")
        classify = self._bare_scan_classify()
        ground1 = _chat_response(tool_calls=[_tool_call("list_cwd", subdir=str(tmp_path))])
        ground2 = _chat_response(f"/scan {tmp_path / 'auth.py'} --full")
        with patch("httpx.post", side_effect=[classify, ground1, ground2]):
            out = nl_router.translate("scan the auth stuff")
        assert out == f"/scan {tmp_path / 'auth.py'} --full"

    def test_unknown_tool_name_does_not_crash(self):
        classify = self._bare_scan_classify()
        ground1 = _chat_response(tool_calls=[_tool_call("delete_everything", path="/")])
        ground2 = _chat_response("REFUSE")
        with patch("httpx.post", side_effect=[classify, ground1, ground2]):
            assert nl_router.translate("scan something") is None

    def test_exhausting_tool_turns_fails_closed(self):
        # Model keeps calling tools forever and never commits — must not hang
        # or trust a half-finished exploration.
        classify = self._bare_scan_classify()
        looping = _chat_response(tool_calls=[_tool_call("check_path", name="x")])
        with patch("httpx.post", side_effect=[classify] + [looping] * nl_router.MAX_TOOL_TURNS) as mock_post:
            assert nl_router.translate("scan x") is None
        assert mock_post.call_count == 1 + nl_router.MAX_TOOL_TURNS

    def test_model_ignoring_its_own_negative_check_is_still_refused(self):
        # Live-observed regression: model correctly calls check_path, gets
        # exists:False back, then answers with the target anyway. The
        # allowlist alone wouldn't catch this — /scan is a real command and
        # the argument has no shell metacharacters. _require_real_scan_target
        # is what closes this specific gap.
        classify = self._bare_scan_classify()
        ground1 = _chat_response(tool_calls=[_tool_call("check_path", name="totally-fake-xyz")])
        ground2 = _chat_response("/scan totally-fake-xyz --full")
        with patch("httpx.post", side_effect=[classify, ground1, ground2]):
            assert nl_router.translate("scan my repo totally-fake-xyz") is None

    def test_extracts_command_when_model_explains_itself_first(self, tmp_path):
        # Live-observed regression: model correctly calls check_path, gets
        # exists:True back, then still prefixes its answer with reasoning
        # on the same line instead of outputting only the command as
        # instructed. The right, grounded answer is still in there — pull
        # it out instead of refusing a request that was actually correct.
        classify = self._bare_scan_classify()
        ground1 = _chat_response(tool_calls=[_tool_call("check_path", name=str(tmp_path))])
        ground2 = _chat_response(
            f"check_path returned true, so we can proceed with the scan. /scan {tmp_path} --full"
        )
        with patch("httpx.post", side_effect=[classify, ground1, ground2]):
            out = nl_router.translate(f"run this full scan {tmp_path}")
        assert out == f"/scan {tmp_path} --full"

    def test_well_formed_line_is_not_touched_by_extraction(self):
        # _extract_trailing_command must no-op on the common, correct case.
        assert nl_router._extract_trailing_command("/scan ./app --full") is None

    def test_command_only_classification_skips_grounding_entirely(self):
        # The whole point of the two-stage split: a target-less command
        # must never trigger the tool-calling stage at all — regression
        # test for "install the missing tools" answering "/scan . --full"
        # after speculatively calling list_cwd.
        with patch("httpx.post", return_value=_chat_response("/setup")) as mock_post:
            out = nl_router.translate("install the missing tools")
        assert out == "/setup"
        assert mock_post.call_count == 1
        assert "tools" not in mock_post.call_args.kwargs["json"]


class TestToolImplementations:
    """The tools themselves — read-only filesystem grounding."""

    def test_check_path_resolves_whole_phrase_first(self, tmp_path):
        d = tmp_path / "myrepo"
        d.mkdir()
        result = nl_router._tool_check_path(str(d))
        assert result == {"exists": True, "type": "directory", "matched": str(d)}

    def test_check_path_falls_back_to_individual_words(self, tmp_path):
        d = tmp_path / "vibemart"
        d.mkdir()
        result = nl_router._tool_check_path(f"my repo {d}")
        assert result["exists"] is True
        assert result["matched"] == str(d)

    def test_check_path_not_found(self):
        result = nl_router._tool_check_path("totally-fake-nonexistent-xyz")
        assert result == {"exists": False, "type": "not_found"}

    def test_list_cwd_lists_real_entries(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        (tmp_path / "b.txt").write_text("y")
        result = nl_router._tool_list_cwd(str(tmp_path))
        assert result["entries"] == ["a.txt", "b.txt"]

    def test_list_cwd_bad_dir_returns_error_not_crash(self):
        result = nl_router._tool_list_cwd("/no/such/directory/at/all")
        assert "error" in result


class TestAntiHallucinationOnUrls:
    """Local-path hallucination is now the model's job to avoid (via
    check_path) — this only still guards URLs, which are exact strings a
    model can subtly mangle in transcription."""

    def test_prefers_users_own_url_over_models_rewrite(self):
        text = "please scan https://github.com/real/repo thanks"
        with patch("httpx.post", return_value=_chat_response(
            "/scan https://github.com/real/repo/ --full"  # model added a trailing slash
        )):
            out = nl_router.translate(text)
        assert out == "/scan https://github.com/real/repo --full"

    def test_command_only_response_untouched(self):
        with patch("httpx.post", return_value=_chat_response("/doctor")):
            assert nl_router.translate("check dependencies") == "/doctor"


class TestFailsClosed:
    """Ollama being absent/slow/broken must never crash or block the REPL."""

    def test_connection_error_returns_none(self):
        with patch("httpx.post", side_effect=ConnectionError("no ollama")):
            assert nl_router.translate("scan ./app") is None

    def test_timeout_returns_none(self):
        with patch("httpx.post", side_effect=TimeoutError("slow")):
            assert nl_router.translate("scan ./app") is None

    def test_empty_input_short_circuits_without_a_call(self):
        with patch("httpx.post") as mock_post:
            assert nl_router.translate("   ") is None
            mock_post.assert_not_called()
