<h1 align="center">CYPHEX Dockerization &amp; Containerization</h1>

<p align="center">
  <b>How CYPHEX builds, deploys, and isolates target applications<br/>
  inside a hardened, auto-synthesized Docker sandbox.</b>
</p>

> **The core philosophy:** the code you are scanning is untrusted. CYPHEX copies it out of your
> working tree, wraps it in an aggressively restricted container, and attacks *that* — so a target
> that tries to escape, fork-bomb, or phone home hits a wall rather than your machine.

> [!NOTE]
> Every constraint, flag and filename on this page was read out of the source, not from a design
> doc. Where a capability is designed but **not yet in the tree**, it is marked
> **`PLANNED`** rather than described in the present tense. See
> [What isn't built yet](#what-isnt-built-yet).

---

## Table of Contents

| | |
|---|---|
| **[Sandbox Architecture](#sandbox-architecture)** | How CYPHEX isolates untrusted code |
| **[Security Constraints](#security-constraints--hardening)** | The six layers of container defence |
| **[The Generated Dockerfile](#the-generated-dockerfile)** | What gets synthesized, and where it goes |
| **[Native Fallback](#native-fallback-no-docker)** | What happens without Docker |
| **[Cleanup & State](#cleanup--state-management)** | Teardown and orphan sweeping |
| **[What isn't built yet](#what-isnt-built-yet)** | Multi-container, service detection, agent routing |

---

## Sandbox Architecture

CYPHEX uses a deterministic fallback chain to deploy a target:

1. **Docker, single container** — auto-generates a `Dockerfile` if the target lacks one, builds
   it, and runs it under the constraint set below. → `cyphex/docker_sandbox.py`
2. **Native subprocess** — a genuinely resource-capped process if Docker is unavailable.
   → `backend/backend/sandbox_manager.py`
3. **Static analysis only** — if execution is impossible, the scan degrades to SAST rather than
   pretending it ran the app.

When you run `cyphex scan <path>`, the engine copies your working tree into a temporary sandbox
directory (`.cyphex_sandbox/`). **Your actual source is never executed and never patched** — the
sandbox operates exclusively on that clone. Only the opt-in `/watch` auto-heal daemon writes to
real source.

---

## Security Constraints & Hardening

Even inside Docker, a container can be dangerous. `cyphex/docker_sandbox.py` applies a strict
profile to every container it spins up.

> [!WARNING]
> These are hardcoded into the `docker run` invocation. The target application's own
> configuration cannot relax them.

| Constraint | Flag | Purpose |
|---|---|---|
| **Capability drop** | `--cap-drop ALL` | Revokes every Linux capability from container root — no raw sockets, no `chown`/`setuid` tricks, no packet spoofing. |
| **Privilege-escalation block** | `--security-opt no-new-privileges` | A `setuid`/`setgid` binary inside the container cannot gain privileges it was not started with. |
| **PID limit** | `--pids-limit 200` | Caps fork-bombs and runaway process spawning. |
| **Memory cap** | `--memory 512m` | Stops the target starving the host of RAM — which matters more than usual here, because the local models need it. |
| **CPU cap** | `--cpus 1` | Keeps a spinning target from stalling the scan that is attacking it. |
| **Unprivileged user** | `USER sandboxuser` | The generated Dockerfile creates uid `10001` with `--no-create-home` and a `nologin` shell, then `chown`s `/app` to it. The app never runs as root, even inside the already-restricted container. |
| **Loopback-only port** | `-p 127.0.0.1:<host>:<app>` | The published port binds to loopback. The target is unreachable from your LAN while it is being attacked. |

The unprivileged-user layer is deliberate redundancy: it exists so that *if* the runtime
constraints above were somehow bypassed, the process on the other side is still not root.

---

## The Generated Dockerfile

If the target already ships a `Dockerfile`, CYPHEX builds that. If it does not,
`_generate_dockerfile()` synthesizes one from a detected app type (`_detect_app_type()` inspects
the tree for the framework and its port).

Two details worth knowing:

- The generated file is written as **`Dockerfile`, into the sandbox copy** — not into your
  repository, and not under a `.cyphex` name. Your tree is untouched.
- It is **removed after the build**, so a generated Dockerfile never lingers to be mistaken for
  one the project owns.

Base images are the slim/alpine variants for the detected runtime, so the image stays small
enough to rebuild on every scan.

---

## Native Fallback (no Docker)

Without Docker, CYPHEX does not silently run the target unconstrained. `deploy_sandbox()` spawns
it through a `preexec_fn` that applies POSIX resource limits before the process image is
replaced:

| Limit | Effect |
|---|---|
| `RLIMIT_AS` | Caps total address space — the native analogue of `--memory`. |
| `RLIMIT_CPU` | Caps CPU seconds, so a spinning target dies instead of hanging the scan. |

> [!IMPORTANT]
> `resource.setrlimit` is POSIX-only — the `resource` module does not exist on Windows. On
> Windows without Docker, the native fallback runs **without** these caps. Use Docker there.

This tier is weaker than the container: it has no capability dropping, no PID limit, and no
network namespace. It exists so a scan degrades rather than fails, not as an equivalent.

---

## Cleanup & State Management

Containers leave state, so teardown is explicit:

- A single sandbox is removed with `docker rm -f cyphex-<id>` (`stop_docker_sandbox()`).
- `cleanup_all_sandboxes()` sweeps globally on exit — it removes every container matching
  `name=cyphex-` **and** every image matching `reference=cyphex-*`, so repeated scans do not
  accumulate dead images.
- The sweep is wrapped in a bare `except` on purpose: cleanup failing must never take down the
  scan that called it.

---

## What Isn't Built Yet

The following are designed and intended, but **not in the tree today**. They are listed here so
this page can be trusted as a description of what actually runs.

| Capability | Status | What exists instead |
|---|---|---|
| **Multi-container orchestration** — parsing a target's `docker-compose.yml` and synthesizing an isolated `docker-compose.sandbox.yml` network | `PLANNED` | Single-container only. `docker_sandbox.py` has no Compose path. A multi-service target is deployed as one container. |
| **Port-collision resolution** across synthesized services | `PLANNED` | `_find_free_port()` picks a free host port for the one container. |
| **Service & datastore detection** — `detect_services()`, `ServiceSignatures`, `services.json`, tagging Postgres/Redis as `attacked: false` | `PLANNED` | `_detect_app_type()` identifies a single app's framework and port. |
| **Agent routing by service role** — pointing `DeepXSSAgent` at a frontend and `DeepSQLiAgent` at a backend | `PLANNED` | The 13 DeepAgents all target the single deployed app. The agent classes themselves are real — see [backend/README.md](../backend/README.md). |
| **Compose teardown** — `docker compose -p <project> down -v` | `PLANNED` | `docker rm -f` plus the image sweep above. |

Once any of these lands, move its row into the body of this page and delete it from this table.

---

## See Also

- [README.md](../README.md) — the Verify Gate and the Maintainability Panel, the two deliverables
  everything here feeds.
- [backend/README.md](../backend/README.md) — the 13 DeepAgents that attack whatever this sandbox
  deploys.
- [cyphex/README.md](../cyphex/README.md) — the package that owns `docker_sandbox.py`.
