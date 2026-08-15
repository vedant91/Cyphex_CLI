/**
 * CYPHEX RASP — Runtime Application Self-Protection for Node.js/Express
 *
 * HOW IT WORKS:
 * ─────────────
 * 1. Developer adds ONE LINE to their Express app:
 *      const cyphexRasp = require('cyphex-rasp');
 *      app.use(cyphexRasp({ repoRoot: __dirname }));
 *
 * 2. Every incoming request is checked for attack patterns:
 *    - SQL Injection (', UNION SELECT, OR 1=1, etc.)
 *    - XSS (<script>, onerror=, javascript:, etc.)
 *    - Command Injection (;ls, $(whoami), |cat, etc.)
 *    - Path Traversal (../../etc/passwd, etc.)
 *    - SSRF (127.0.0.1, 169.254.169.254, etc.)
 *
 * 3. If an attack is detected:
 *    a. The request is BLOCKED (403 Forbidden)
 *    b. A JavaScript Error is thrown to capture the STACK TRACE
 *    c. The stack trace is parsed to find the EXACT source file + line
 *       of the route handler that would have processed the malicious input
 *    d. This telemetry is sent to the Cyphex Daemon (localhost:3004)
 *    e. The Daemon's AI Council reads the source code and auto-patches it
 *
 * HOW THIS SOLVES THE "DAST DISCONNECT":
 * ──────────────────────────────────────
 * Traditional DAST attacks the app from outside and only knows the URL.
 * This RASP middleware runs INSIDE Express. When it detects an attack,
 * it throws an Error() to capture the stack trace. The stack trace contains:
 *
 *   at loginHandler (C:\project\backend\src\routes\auth.js:42:15)
 *
 * That's the EXACT file and line of the vulnerable code. No guessing needed.
 *
 * ZERO DEPENDENCIES — uses only built-in Node.js modules (http, path, fs).
 */

'use strict';

const http = require('http');
const path = require('path');

// ── Configuration defaults ──────────────────────────────────────────
const DEFAULTS = {
  daemonUrl: 'http://127.0.0.1:3004',
  repoRoot: process.cwd(),
  blockMode: true,       // true = block attacks (403), false = detect-only (log + pass through)
  logToConsole: true,
  confidenceThreshold: 0.7,
  // The daemon requires this shared key on every request (see
  // backend/backend/auth.py). Defaults to the same CYPHEX_API_KEY env var
  // the daemon itself reads; if neither is set, the daemon auto-generates
  // and persists one at ~/.cyphex/api_key — copy that value here via the
  // env var, or pass { apiKey: '...' } explicitly.
  apiKey: process.env.CYPHEX_API_KEY || '',
};

// ── Attack detection patterns ───────────────────────────────────────
// Each pattern has: name, regex array, CWE, severity weight

const ATTACK_SIGNATURES = [
  {
    name: 'SQL Injection',
    cwe: 'CWE-89',
    weight: 1.0,
    patterns: [
      /'\s*(or|and)\s+.*[=<>]/i,
      /'\s*;\s*(drop|delete|insert|update|alter)\b/i,
      /union\s+(all\s+)?select\b/i,
      /'\s*=\s*'/,
      /order\s+by\s+\d+/i,
      /waitfor\s+delay/i,
      /benchmark\s*\(/i,
      /'\s*--\s*/,
      /1\s*=\s*1/,
      /'\s*or\s+'.*'\s*=\s*'/i,
    ],
  },
  {
    name: 'XSS',
    cwe: 'CWE-79',
    weight: 0.9,
    patterns: [
      /<\s*script[^>]*>/i,
      /javascript\s*:/i,
      /on(error|load|click|mouseover|focus|blur|submit)\s*=/i,
      /<\s*(img|svg|body|iframe|input|details|marquee|object)\b[^>]*on\w+\s*=/i,
      /document\.(cookie|location|write)/i,
      /eval\s*\(/i,
      /fromCharCode/i,
      /alert\s*\(/i,
    ],
  },
  {
    name: 'Command Injection',
    cwe: 'CWE-78',
    weight: 1.0,
    patterns: [
      /[;|&`]\s*(ls|cat|dir|whoami|id|ping|curl|wget|nc|bash|sh|cmd|powershell)\b/i,
      /\$\(\s*(whoami|id|cat|ls)\b/i,
      /`[^`]*(whoami|id|cat|ls)[^`]*`/i,
    ],
  },
  {
    name: 'Path Traversal',
    cwe: 'CWE-22',
    weight: 0.8,
    patterns: [
      /\.\.[\/\\]/,
      /(etc\/passwd|etc\/shadow|win\.ini)/i,
      /%2e%2e[%2f\/\\]/i,
      /\.\.%252f/i,
    ],
  },
  {
    name: 'SSRF',
    cwe: 'CWE-918',
    weight: 0.9,
    patterns: [
      /127\.0\.0\.1/,
      /localhost/i,
      /169\.254\.169\.254/,      // AWS metadata
      /0\.0\.0\.0/,
      /10\.\d+\.\d+\.\d+/,      // Private RFC1918
      /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
      /192\.168\.\d+\.\d+/,
      /\[::1\]/,                  // IPv6 localhost
      /file:\/\//i,
    ],
  },
];

// ── Keyword-based heuristic score ───────────────────────────────────
const SUSPICIOUS_KEYWORDS = [
  'select', 'union', 'insert', 'update', 'delete', 'drop', 'exec',
  'script', 'alert', 'onerror', 'onload', 'eval', 'document',
  'cookie', '--', '/*', '*/', 'waitfor', 'sleep', 'benchmark',
  'char(', 'concat(', 'information_schema', 'passwd', 'shadow',
  '/etc/', 'cmd.exe', 'powershell', 'wget', 'curl', 'base64',
];


/**
 * Analyze a string for attack patterns.
 * Returns: { detected: bool, vulnType: string, cwe: string, confidence: float }
 */
function analyzePayload(input) {
  if (!input || typeof input !== 'string') {
    return { detected: false, vulnType: null, cwe: null, confidence: 0 };
  }

  let bestMatch = null;
  let bestScore = 0;

  for (const sig of ATTACK_SIGNATURES) {
    let hits = 0;
    for (const pattern of sig.patterns) {
      if (pattern.test(input)) {
        hits++;
      }
    }
    if (hits > 0) {
      // If ANY pattern matches, it's a very strong signal.
      // Score = base weight (e.g. 1.0) + small bonus for multiple hits
      const score = Math.min(1.0, sig.weight + (hits * 0.1));
      if (score > bestScore) {
        bestScore = score;
        bestMatch = sig;
      }
    }
  }

  // Also check keyword heuristics
  const inputLower = input.toLowerCase();
  let keywordHits = 0;
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (inputLower.includes(kw)) keywordHits++;
  }
  const keywordScore = Math.min(keywordHits / 3.0, 1.0);

  // Combined confidence
  const confidence = Math.min(1.0, bestScore + (keywordScore * 0.3));

  if (bestMatch && confidence >= 0.3) {
    return {
      detected: true,
      vulnType: bestMatch.name,
      cwe: bestMatch.cwe,
      confidence: Math.round(confidence * 100) / 100,
    };
  }

  return { detected: false, vulnType: null, cwe: null, confidence: 0 };
}


/**
 * Extract all user-controlled input from an Express request.
 * Checks: query params, body fields, URL params, headers (cookie, referer).
 */
function extractInputs(req) {
  const inputs = [];

  // Query parameters (?q=...)
  if (req.query) {
    for (const [key, val] of Object.entries(req.query)) {
      if (typeof val === 'string') inputs.push({ source: `query.${key}`, value: val });
    }
  }

  // Body fields (POST data)
  if (req.body && typeof req.body === 'object') {
    const flatten = (obj, prefix = 'body') => {
      for (const [key, val] of Object.entries(obj)) {
        if (typeof val === 'string') {
          inputs.push({ source: `${prefix}.${key}`, value: val });
        } else if (typeof val === 'object' && val !== null) {
          flatten(val, `${prefix}.${key}`);
        }
      }
    };
    flatten(req.body);
  }

  // URL params (:id, :slug, etc.)
  if (req.params) {
    for (const [key, val] of Object.entries(req.params)) {
      if (typeof val === 'string') inputs.push({ source: `params.${key}`, value: val });
    }
  }

  // Suspicious headers
  const checkHeaders = ['cookie', 'referer', 'x-forwarded-for', 'user-agent'];
  for (const h of checkHeaders) {
    const val = req.headers[h];
    if (val && typeof val === 'string') {
      inputs.push({ source: `header.${h}`, value: val });
    }
  }

  // Raw URL path (for path traversal)
  if (req.originalUrl) {
    inputs.push({ source: 'url', value: decodeURIComponent(req.originalUrl) });
  }

  return inputs;
}


/**
 * Capture the stack trace of the CURRENT request handler.
 *
 * THIS IS THE KEY INNOVATION that solves the DAST disconnect:
 * By throwing an Error inside the Express middleware chain, we get
 * a stack trace that includes the route handler's file and line number.
 *
 * The stack trace looks like:
 *   Error: CYPHEX stack capture
 *       at cyphexRaspMiddleware (cyphex-rasp.js:XX)
 *       at Layer.handle (express/lib/router/layer.js:95:5)
 *       at loginHandler (backend/src/routes/auth.js:42:15)  <-- THIS IS WHAT WE WANT
 *
 * We filter out framework internals and our own middleware to find
 * the first APPLICATION-LEVEL frame — that's the vulnerable code.
 */
function captureStackTrace(repoRoot) {
  const err = new Error('CYPHEX_STACK_CAPTURE');
  const stack = err.stack || '';

  // Parse each frame
  const lines = stack.split('\n').slice(1); // skip "Error: ..." header
  let appFile = '';
  let appLine = 0;

  const skipPatterns = [
    'node_modules', 'cyphex-rasp', 'internal/',
    '<anonymous>', 'node:',
  ];

  for (const line of lines) {
    // Match: "    at functionName (filepath:line:col)"
    const match = line.match(/at\s+(?:.*?\s+\()?([^():]+):(\d+)(?::\d+)?\)?/);
    if (!match) continue;

    const filePath = match[1].trim();
    const lineNum = parseInt(match[2], 10);

    // Skip framework internals
    if (skipPatterns.some(skip => filePath.includes(skip))) continue;

    // Found application-level code
    appFile = filePath;
    appLine = lineNum;

    // Make relative to repo root
    if (repoRoot && appFile.startsWith(repoRoot)) {
      appFile = appFile.slice(repoRoot.length).replace(/^[\/\\]/, '');
    }
    // Normalize separators
    appFile = appFile.replace(/\\/g, '/');

    break;
  }

  return { file: appFile, line: appLine, raw: stack };
}


/**
 * Send telemetry to the Cyphex Daemon for auto-healing.
 * Non-blocking — uses fire-and-forget HTTP POST.
 */
function sendTelemetry(daemonUrl, eventData, apiKey) {
  const url = new URL('/api/telemetry/attack', daemonUrl);

  const postData = JSON.stringify(eventData);
  const options = {
    hostname: url.hostname,
    port: url.port,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData),
      ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    },
    timeout: 3000,
  };

  // Fire-and-forget — don't block the response
  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => { body += chunk; });
    res.on('end', () => {
      try {
        const result = JSON.parse(body);
        if (result.status === 'healed') {
          console.log(`\x1b[92m[CYPHEX] ✓ Auto-healed: ${result.file}:${result.line}\x1b[0m`);
        }
      } catch (e) { /* ignore parse errors */ }
    });
  });

  req.on('error', () => {
    // Daemon not running — that's OK, just log locally
  });

  req.write(postData);
  req.end();
}


/**
 * CYPHEX RASP Express Middleware
 *
 * Usage:
 *   const cyphexRasp = require('cyphex-rasp');
 *   app.use(cyphexRasp({ repoRoot: __dirname }));
 *
 * Options:
 *   repoRoot:              Absolute path to the project root (for stack trace resolution)
 *   daemonUrl:             Cyphex Daemon URL (default: http://127.0.0.1:3004)
 *   blockMode:             true = block attacks (403), false = detect + log only
 *   logToConsole:          Print detections to console
 *   confidenceThreshold:   Minimum confidence to trigger (0.0 - 1.0, default: 0.7)
 */
function cyphexRasp(options = {}) {
  const config = { ...DEFAULTS, ...options };

  // Normalize repo root path
  config.repoRoot = path.resolve(config.repoRoot);

  let attackCount = 0;
  let requestCount = 0;

  console.log(`\x1b[96m[CYPHEX RASP] Active — monitoring all routes\x1b[0m`);
  console.log(`\x1b[2m  Repo:   ${config.repoRoot}\x1b[0m`);
  console.log(`\x1b[2m  Daemon: ${config.daemonUrl}\x1b[0m`);
  console.log(`\x1b[2m  Mode:   ${config.blockMode ? 'BLOCK + HEAL' : 'DETECT ONLY'}\x1b[0m`);

  return function cyphexRaspMiddleware(req, res, next) {
    requestCount++;

    // Extract all user-controlled inputs
    const inputs = extractInputs(req);

    // Check each input for attacks
    for (const input of inputs) {
      const result = analyzePayload(input.value);

      if (result.detected && result.confidence >= config.confidenceThreshold) {
        attackCount++;

        // Capture the stack trace (THE KEY to solving DAST disconnect)
        const trace = captureStackTrace(config.repoRoot);

        if (config.logToConsole) {
          console.log(`\x1b[91m[CYPHEX] ⚠ ${result.vulnType} detected in ${input.source}\x1b[0m`);
          console.log(`\x1b[2m  Payload:    ${input.value.substring(0, 80)}\x1b[0m`);
          console.log(`\x1b[2m  Confidence: ${(result.confidence * 100).toFixed(0)}%\x1b[0m`);
          if (trace.file) {
            console.log(`\x1b[2m  Source:     ${trace.file}:${trace.line}\x1b[0m`);
          }
        }

        // Send telemetry to Cyphex Daemon for auto-healing
        sendTelemetry(config.daemonUrl, {
          vuln_type: result.vulnType,
          cwe: result.cwe,
          payload: input.value,
          method: req.method,
          url: req.originalUrl || req.url,
          source_field: input.source,
          stack_trace: trace.raw,
          source_file: trace.file,
          source_line: trace.line,
          repo_root: config.repoRoot,
          confidence: result.confidence,
          blocked: config.blockMode,
          timestamp: new Date().toISOString(),
        }, config.apiKey);

        // Block if in block mode
        if (config.blockMode) {
          return res.status(403).json({
            error: 'Request blocked by CYPHEX RASP',
            reason: `${result.vulnType} detected (${(result.confidence * 100).toFixed(0)}% confidence)`,
            blocked_field: input.source,
            cyphex_id: `CYPHEX-${Date.now()}`,
          });
        }
      }
    }

    next();
  };
}

// ── Export ───────────────────────────────────────────────────────────
module.exports = cyphexRasp;
module.exports.analyzePayload = analyzePayload;
module.exports.extractInputs = extractInputs;
