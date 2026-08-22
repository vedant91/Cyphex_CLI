# `cyphex-rasp` — the runtime shield

Zero-dependency Express middleware. Inspects query strings, JSON bodies, and
cookie/referer/user-agent headers; blocks what it judges to be an attack; and
reports it back to the CYPHEX auto-heal daemon, which can patch your real source.

Node ≥ 16. MIT. Single file — `cyphex-rasp.js`, no `npm install` required.

---

## Install

Copy the file in, or let the onboarder do it:

```bash
python3 cyphex_cli.py onboard --path ./my-app
```

## Use

```js
const cyphexRasp = require('./cyphex-rasp');

// Global — simplest, but see the stack-trace caveat below.
app.use(cyphexRasp({ apiKey: process.env.CYPHEX_API_KEY }));

// Per-route — what you actually want.
app.get('/search', cyphexRasp(opts), searchHandler);
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `daemonUrl` | `http://127.0.0.1:3004` | Where attack telemetry is POSTed (`/api/telemetry/attack`) |
| `blockMode` | `true` | `true` → respond **403**. `false` → detect-only: log and pass through |
| `confidenceThreshold` | `0.7` | Minimum confidence before the middleware acts |
| `apiKey` | `process.env.CYPHEX_API_KEY` | Sent as `X-API-Key` |

Also exported for direct use: `analyzePayload`, `extractInputs`.

---

## Two things that bite people

**1. `CYPHEX_API_KEY` must match on both sides.** The `/watch` daemon enforces
API-key auth. If the key is missing or different, telemetry is **silently
dropped** — the shield still blocks, but nothing reaches the healer and there is
no error to notice. Set the same value in the app's environment and the
daemon's.

Older vendored copies of this file predate daemon auth entirely and send no
`X-API-Key` header at all. If auto-heal "just stopped working", check you are on
the current file before debugging anything else.

**2. Mounted globally, there is no `file:line`.** `app.use()` fires the
middleware *before* any route handler runs, so no application frame is on the
stack and the daemon cannot resolve which line is vulnerable. **Mount per-route**
to get one.

---

## Staged rollout

Start in detect-only mode and watch what it would have blocked:

```js
app.use(cyphexRasp({ blockMode: false, apiKey: process.env.CYPHEX_API_KEY }));
```

Raise `confidenceThreshold` if legitimate traffic trips it; the daemon applies
its own 70% floor before the AI council is allowed to patch anything, so a lower
threshold here means more *reports*, not more automatic edits.

The RASP shield is **Express-only** today. `GET /api/status` and
`GET /api/heal-log` on the daemon expose the healing history.
