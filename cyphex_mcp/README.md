# cyphex_mcp

A thin MCP server over the Cyphex engine. It **hosts no model and runs no
target**. It hands the host coding agent (Claude Code, Codex, Cursor) playbooks,
grades what the agents report back, runs the few steps that must be deterministic,
and writes an interactive report. Design: `docs/mcp-blueprint/architecture.html`.
A real example output: `docs/mcp-blueprint/sample-report.html`.

## What runs where

| Concern | Runs on | Why |
|---|---|---|
| Deep SAST, deep DAST, council, patch crew | the host agent's own model | better reasoning, already paid for, no inference cost to us |
| The target app (sandbox) | the user's own Docker | big apps eat RAM; keeps their source off our servers |
| Grading of every agent's output | this MCP (plain Python) | must be a fact, not an opinion, and an injection in scanned code cannot talk past it |
| Verify Gate | this MCP, plus the agent's exploit replay | a patch is fixed only if the exploit stops firing |
| Genome build + eval | this MCP (needs scikit-learn) | trains from the recon inventory, scored on attacks it never saw |
| Runtime `decide()` | the user's edge (Docker sidecar, Cloudflare, AWS) | blocks unseen attack shapes next to the app |

## One scan, step by step

1. `start_scan(repo_path=...)` **stops and asks the person three questions** (GitHub webhook? where do tests run: their own environment, a Docker sandbox, or none? deploy the agent team, and on one model or mixed models?) and does nothing until it gets their answers in their own words, which the report prints. Call it again with `human_answers={"webhook","sandbox","sandbox_url","agents","human_words"}` to get a `job_id`, how to get a running app, and the role order. Answering yes to the webhook returns the setup steps and a secret. CI sets `CYPHEX_UNATTENDED=1` to skip the questions, and the report says the run was unattended.
2. Build the sandbox from the recipe (`docker compose ... up -d --build`). The target has no internet route and no published ports; probe it from the `attacker` service at `http://target:3000`. If the app dies with a read-only error, pass the directory in `writable_paths`.
3. **Deploy the agents.** `deploy_agents(project_path, models, human_words)` writes 20 subagent files into `<project>/.claude/agents/` after the person says yes. `get_orchestration_plan(job_id)` returns 8 stages; launch each with the Agent tool, the parallel stages in one message. Each agent reads the code alone, in its own context, and calls `submit_result` under its own name. If Claude Code has not loaded the new files (it reads them at session start), run `/agents` or restart, or use `get_agent_prompt(name)` with a general-purpose subagent.
   Without deployed agents, play each role yourself (`get_playbook(role)`), but the reviewers are then not independent and the report says so.
4. `verify_patch(job_id, finding_id, replay={"fired": false, "evidence": "..."})` after applying the diff in your sandbox, rebuilding and re-running the exploit.
5. `build_genome(job_id)`, then `get_report(job_id, out_path="report.html")`.

## Tools

`start_scan` · `get_playbook` · `submit_result` · `get_finding` · `verify_patch` · `sandbox_recipe` ·
`build_genome` · `get_report` · `get_job` · `get_progress` · `get_history` · `publish_genome`

Agents: `deploy_agents` · `remove_agents` · `get_orchestration_plan` · `get_agent_prompt`

Agent security: `audit_agent_config` (reads `.mcp.json`, `.claude/settings*.json`, agent files and `CLAUDE.md` for risky setups) ·
`plant_canary` (a planted instruction that tests whether agents obey text they only read) · `guard_decide` (call gate, logged into the report)

## Live narration

The MCP cannot talk to the person; the host agent can. So the server sends instructions at connect time, every
stage in the plan carries a `say_before` sentence, and every `submit_result`, `verify_patch` and `build_genome`
returns a `say` line. The host prints them as the scan runs, for example: "Step 2 of 8, reading the code. 10 agents
start together and work separately. The SQL injection agent checks where user input ends up inside a database
query..." then "The SQL injection agent finished reading the code and reported 6 problems. Still working: the
cross-site scripting agent, the command injection agent and 7 more." `get_progress(job_id)` returns the same story
so far and who is pending. The report replays it under "What happened, in order".

## The agent team

20 agents, modelled on the CLI's pipeline: route mapper; ten bug-class specialists (sqli, xss, cmdi, path, auth,
ssrf, config, supply, logic, ai); a scanner runner for the live-attack stage; four independent reviewers (skeptic, exploiter, data-flow, defender);
a patcher with two fix reviewers; an agent-security auditor. Each is a Claude Code subagent with its own system
prompt, its own **tool allowlist** (the read-only specialists have no shell and no network), the guardrail rules,
and optionally its own model. With `models="mixed"` the reviewers run on Opus, Sonnet and Haiku, so the board is
not one model voting three times. Files carry a marker, so Cyphex never overwrites an agent file you wrote, and
`remove_agents` deletes only its own.

Reviewers each cast one ballot over every finding without seeing the others. The MCP tallies once three
ballots are in. A patcher proposes a diff and two reviewers add their verdicts separately; the Verify Gate
needs both. Two agents reporting the same bug are merged, and both are credited.

## The live-attack stage and Anthropic's cyber safeguards

The live-attack (deep DAST) stage is **deterministic**: `dast_recipe(job_id)` returns a Nuclei command, the
host runs that standard scanner against the sandbox target, and `submit_dast(job_id, jsonl)` lets the MCP parse
the output and mark proof itself (measured by Cyphex, not reported by a model). No Claude model authors attack
requests, so the stage is a plain tool run and is never gated by a safety classifier. Findings a scanner cannot
reach stay "confirmed by code reading"; the report says which is which.

A Claude model authoring *adaptive* attacks in real time is a different thing, and Anthropic's real-time cyber
safeguards correctly gate it — the sandbox cannot turn that off, because the safeguard judges the content of the
work, not where the traffic goes. The sanctioned route for a legitimate security vendor is Anthropic's Cyber
Verification Program (https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude). See
`docs/mcp-blueprint/cyber-verification.html` for the readiness packet. Until verified, Cyphex runs the
deterministic stage; it does not try to get a model past the safeguard.

## The local security folder

Everything lives under `CYPHEX_DATA_DIR` on the user's machine: `jobs/<id>.json` (the full record),
`jobs/<id>/report.html`, `jobs/<id>/genome/` (the `.pkl`, its signature, the `.cxgenome` bundle and
`thresholds.json`), and `SECURITY_LOG.md`, one readable entry per run. `get_history` lists past runs.

## How the MCP knows what each agent did

Agents report; the MCP grades with deterministic checks (`ledger.py`). No model
judges another model.

| Role | Checks |
|---|---|
| deep_sast | schema valid, cited file and line really exist, the quoted snippet is near that line, ids unique. Invented findings are dropped. |
| deep_dast | ids match SAST findings; a "proven" claim with no evidence is downgraded |
| council | at least 3 votes, distinct personas, the MCP recounts the votes and flags a verdict that disagrees |
| patch_crew | diff is a unified diff, touches the cited file, two reviewers approved and none rejected |
| verify_patch | applies cleanly, compiles, no suppression comments, inside the severity blast radius, not mostly deleted, the exploit was proven on the original code, and the agent reports it no longer fires. Without a proven "before" the answer is never PASS. |
| coverage | Cyphex counts the repo's source files itself and compares with the files the agent says it read. A partial route list is never high trust. |

Every check also says who produced it: `mcp` (Cyphex measured it) or `agent` (the agent reports it and Cyphex could not check it). The report shows the difference.

Each check is True, False, or None (could not be measured). None is never a pass.
Trust is `high` if all passed, `medium` if some were unmeasured, `low` if any failed.
`UNVERIFIABLE` is the Verify Gate's answer when nothing failed but something could not run.

## GitHub trigger

`python -m cyphex_mcp.webhook` listens on `127.0.0.1:3005` (`CYPHEX_WEBHOOK_SECRET`
required). It verifies `X-Hub-Signature-256`, turns a push to the default branch or
a merged pull request into a queued job, and serves finished reports at
`GET /report/<job_id>`. A webhook cannot scan by itself because the MCP has no
model, so `webhook.workflow_yaml()` writes a GitHub Actions workflow that runs a
headless agent (`claude -p`) against the Cyphex MCP on the same events.

**Not verified:** the workflow template and the headless run were never executed
against GitHub. The webhook receiver itself is tested.

## Run

```bash
pip install "cyphex[mcp]"                  # or: pip install "mcp>=1.2,<2"
claude mcp add cyphex -- cyphex-mcp        # local stdio, can see your Docker and gVisor
python -m cyphex_mcp.tests.test_core       # 9 checks, stdlib only
python -m cyphex_mcp.tests.test_pipeline   # 28 checks, stdlib only
# launches the server from a real mcp.json and runs a whole scan through it (36 checks):
~/.cyphex_mcp/venv/bin/python cyphex_mcp/tests/smoke_stdio.py cyphex_mcp/examples/mcp.json
```

Try it in a container (no Docker socket inside, so no gVisor detection, and no
scikit-learn, so `build_genome` reports `unavailable`):

```bash
docker compose -f cyphex_mcp/docker-compose.demo.yml up --build
# MCP endpoint: http://localhost:8765/mcp   reports: docker compose cp ...:/data/jobs/<id>/report.html .
```

Job data lives in `CYPHEX_DATA_DIR` (default `~/.cyphex_mcp`).

## Status

Built and tested: playbooks, guardrail gate, sandbox recipe (hardened-docker and gVisor tiers),
grading, Verify Gate, genome build and eval, report, webhook receiver, demo container.

Not done: the CI workflow run, browser-side proof for XSS (currently proven by unescaped reflection, not by
script execution), public benchmarks, agent red-team evals, a gVisor run (not installed on the test machine),
Nuclei installed in the attacker sandbox image, and the adaptive Claude live-attack stage (needs Anthropic's
Cyber Verification Program — see the live-attack section).
