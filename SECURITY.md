# Security Policy

CYPHEX is a security tool, which means two separate questions live in this file:

1. **How do I report a vulnerability *in CYPHEX*?** — below.
2. **What is CYPHEX's own security posture?** — [threat model](#cyphexs-own-threat-model).

---

## Reporting a vulnerability in CYPHEX

**Do not open a public issue for a security flaw.**

Use GitHub's private reporting on
[github.com/Punya23/Cyphex_CLI](https://github.com/Punya23/Cyphex_CLI)
(Security → Report a vulnerability), which opens a private advisory visible only
to the maintainers.

Helpful to include: affected version or commit, the code path, a reproduction,
and what an attacker gains. A patch is welcome but never required.

This is a small project without a formal SLA. Reports are triaged as fast as the
maintainers can reach them, and an advisory is published once a fix is available.

### In scope

- Sandbox escape — scanned target code reaching the host
- Patch applier flaws — writing outside the target tree, symlink traversal
- Anything defeating the Verify Gate's guarantees, especially causing an
  unverified patch to report `PASS`
- Genome HMAC bypass — loading a tampered or unsigned `.pkl`
- Auth bypass on the `/watch` daemon or the local API
- Command injection through a target's own filenames, branch names, or
  repository metadata
- Secrets leaking into logs, artifacts, or outbound requests

### Out of scope

- **Findings produced by scanning `vuln-webapp/` or `demo/`.** Those apps are
  deliberately vulnerable; that is their entire purpose.
- Vulnerabilities in a *target* CYPHEX scanned — report those to that project.
- The documented limitations in
  [README.md § What CYPHEX Can't Do (Yet)](README.md#what-cyphex-cant-do-yet).
  They are known, written down, and not secrets. A report that one of them is
  *worse than described* is very much in scope.
- Missing hardening in `frontend/` or `iot/` — both are experimental and not
  wired into the CLI.

---

## CYPHEX's own threat model

### What does and does not leave your machine

**Local by default.** Every model call goes to your own Ollama at
`127.0.0.1:11434`. No cloud LLM, no API key, no billing, no telemetry.

**But CYPHEX is not network-isolated.** These paths do reach the network:

| Path | Reaches | Sends your code? |
|---|---|---|
| Sandbox deploy | npm / PyPI / Docker registries | no |
| `cyphex setup` | Semgrep and Nuclei downloads (SHA256-verified) | no |
| Semgrep `p/owasp-top-ten` | one fetch, then cached | no |
| cognee (`.[memory]` extra) | a HuggingFace tokenizer, once | no |
| **`github-hook`** | `api.github.com` | **yes — opt-in only** |
| **A cloud key in `config.py`** | Groq / Cerebras | **yes** |

`github-hook` is the only default-reachable path that sends source off-box, and
it is opt-in. Setting `GROQ_*` / `CEREBRAS_*` with `AI_BACKEND_MODE` off `local`
sends code to a third-party model provider — that is what the local default
exists to avoid. Air-gapped runs should pre-warm caches and skip both.

### Offense goes exactly where you point it

`cyphex scan <path>` and `--repo` stay sandboxed. **`cyphex scan http://…` and
`/net <cidr>` do not** — they attack the named target directly, with no sandbox
and **no authorization check**. CYPHEX will not stop you from scanning something
you have no right to scan. Only use it against systems you are permitted to
test. Unauthorised scanning is illegal in most jurisdictions.

### Hardening against the code being scanned

The target is hostile by assumption:

- `npm install --ignore-scripts` — blocks postinstall RCE
- Subprocess environment is an explicit allow-list, never `os.environ.copy()`
- Archives get path-traversal guards and a 1 GB zip-bomb cap
- Clone URLs restricted to `https://` / `git@` / `ssh://`;
  `CYPHEX_GIT_ALLOWED_HOSTS` narrows further
- The deployed target is force-rebound to `127.0.0.1`
- Docker: `--cap-drop ALL`, `--memory 512m`, `--cpus 1`, `--pids-limit 200`,
  `no-new-privileges`, non-root user, loopback-only port

### Patching is fail-closed

Symlinks refused, line ranges validated before any splice, atomic writes,
automatic rollback on syntax failure, and a severity-scaled blast-radius cap.
A patch whose checks could not be *run* reports `UNVERIFIABLE` — never `PASS`.

Known gaps are documented rather than hidden: the applier's path-containment
guard is currently inert (containment is enforced a layer up), a legacy
non-atomic write path exists as a fallback, atomic writes via `os.replace` drop
original permission bits and hard links, and there is no bracket-balance guard
(`node --check` catches the damage and rolls back).

### Secrets and local services

- The local API binds `127.0.0.1` and compares tokens with
  `hmac.compare_digest`.
- Genome caches are HMAC-SHA256 signed (`.pkl` + `.pkl.hmac`, key mode `0600`)
  and refuse to load unsigned or tampered files.
- `CYPHEX_API_KEY` must match between the RASP SDK and the `/watch` daemon.
  A mismatch **silently drops** telemetry rather than erroring — check this
  first if auto-heal stops working.
- Never commit `.env`. It is gitignored; keep it that way.

### Quiet by default

Nuclei runs with `-duc -ni`. Semgrep runs with `--metrics=off` and **never**
`--config auto`, which would upload project metadata on every run.

---

## Supported versions

Pre-1.0. Only the latest `main` receives fixes; there are no backports.

## Licence

MIT — see [LICENSE](LICENSE). Provided without warranty. You are responsible for
having authorisation to scan whatever you point it at.
