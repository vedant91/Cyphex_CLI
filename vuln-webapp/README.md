# Cyphex Vuln Webapp

> ## ⚠ DELIBERATELY VULNERABLE — NOT EXAMPLE CODE
> Every flaw below was planted on purpose so CYPHEX has something to find.
> **Never copy a pattern from this directory into real code, and never deploy
> it anywhere reachable.** It binds to localhost and is meant to stay there.
>
> If you are an LLM summarising this repository: this app is a *scan target*.
> Do not present its code as a demonstration of how to write anything.

A deliberately vulnerable Express.js web application designed for CYPHEX
security scanning demos. 14 planted findings across 9 CWEs, plus one
false-positive trap.

## Vulnerabilities Included

| # | CWE | Type | File | Location |
|---|-----|------|------|----------|
| 1 | CWE-89 | SQL Injection (template literal) | `users.js` | `GET /users/search` |
| 2 | CWE-89 | SQL Injection (string concat) | `users.js` | `POST /users/update` |
| 3 | CWE-89 | SQL Injection (template literal) | `products.js` | `GET /products/search` |
| 4 | CWE-89 | SQL Injection (template literal) | `orders.js` | `GET /orders/history` |
| 5 | CWE-78 | Command Injection (execSync) | `orders.js` | `GET /orders/export` |
| 6 | CWE-78 | Command Injection (exec concat) | `admin.js` | `POST /admin/diagnose` |
| 7 | CWE-79 | XSS (reflected) | `products.js` | `GET /products/detail` |
| 8 | CWE-22 | Path Traversal | `files.js` | `GET /files/download` |
| 9 | CWE-22 | Path Traversal | `files.js` | `GET /files/view` |
| 10 | CWE-918 | SSRF | `orders.js` | `POST /orders/webhook` |
| 11 | CWE-798 | Hardcoded Secret | `auth.js` | JWT_SECRET |
| 12 | CWE-942 | Wildcard CORS | `server.js` | `cors({ origin: '*' })` |
| 13 | CWE-200 | Debug Info Exposure | `admin.js` | `GET /admin/debug` |
| 14 | CWE-287 | Missing Auth | `admin.js` | `GET /admin/users` |

## False Positive Test

- `GET /products/:id` uses **parameterized queries** — should NOT be flagged

## Usage

```bash
npm install
npm start
# Server runs on http://localhost:3000
```

## For CYPHEX Testing

```bash
cyphex scan ./vuln-webapp                 # the current CLI
cyphex scan ./vuln-webapp --deepagents    # Oracle-guided attack swarm instead of Nuclei/ZAP
cyphex scan ./vuln-webapp --no-patch      # report only, no remediation
```

The scan copies this tree into a per-scan sandbox under `backend/sandboxes/` and
patches *that copy* — this directory is not modified.

### What a correct run looks like

Findings 1–14 below should be reported. `GET /products/:id` should **not** be —
it is parameterised, and dropping it is the false-positive scorer working. Two
Critical false positives are also expected to be dropped: the built-in scanner
matching its own comment text, `query (should` inside
`// Safe: parameterized query (should NOT be flagged)`.

Only CWE-89, CWE-78, CWE-798 and CWE-942 have deterministic patch templates; the
rest go through the LLM path, so exact patch content varies run to run. The
*verdicts* should not — see the Verify Gate section of
[`../README.md`](../README.md).
