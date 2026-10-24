#!/usr/bin/env node
/**
 * Self-check for the genome decision gate wiring (askGenome + its fail-open behaviour).
 * Zero dependencies, matching cyphex-rasp.js itself — run with `node test-genome-gate.js`.
 * No Python daemon needed: this stands up a tiny fake HTTP server playing its part.
 */
'use strict';
const http = require('http');
const assert = require('assert');
const { askGenome } = require('./cyphex-rasp.js');

let passed = 0;
function ok(name) { passed++; console.log(`  \x1b[92m✓\x1b[0m ${name}`); }

function withFakeDaemon(handler, fn) {
  return new Promise((resolve, reject) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', async () => {
      const port = srv.address().port;
      try {
        await fn(`http://127.0.0.1:${port}`);
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        srv.close();
      }
    });
  });
}

async function main() {
  // 1. A BLOCK verdict from the daemon passes through unchanged.
  await withFakeDaemon((req, res) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const parsed = JSON.parse(body);
      assert.deepStrictEqual(parsed.inputs, [{ source: 'query.q', value: "' OR 1=1--" }]);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ verdict: 'BLOCK', score: 0.9, field: 'query.q' }));
    });
  }, async (daemonUrl) => {
    const r = await askGenome({ genomeGate: true, daemonUrl, targetUrl: 'http://x', genomeTimeoutMs: 1000 },
      '/search', [{ source: 'query.q', value: "' OR 1=1--" }]);
    assert.strictEqual(r.verdict, 'BLOCK');
    ok('BLOCK verdict from daemon passes through, and the batched body is correct');
  });

  // 2. genomeGate: false never calls the network at all.
  {
    let called = false;
    const srv = http.createServer(() => { called = true; });
    await new Promise(res => srv.listen(0, '127.0.0.1', res));
    const port = srv.address().port;
    const r = await askGenome({ genomeGate: false, daemonUrl: `http://127.0.0.1:${port}` }, '/x', []);
    assert.strictEqual(r.verdict, 'ALLOW');
    assert.strictEqual(called, false);
    srv.close();
    ok('genomeGate:false short-circuits with no network call');
  }

  // 3. Fail OPEN when the daemon is unreachable (nothing listening on this port).
  {
    const r = await askGenome({ genomeGate: true, daemonUrl: 'http://127.0.0.1:1', genomeTimeoutMs: 500 }, '/x', []);
    assert.strictEqual(r.verdict, 'ALLOW');
    ok('unreachable daemon fails OPEN (ALLOW), never hangs or throws');
  }

  // 4. Fail OPEN on timeout (daemon never responds).
  await withFakeDaemon((req, res) => { /* never respond */ }, async (daemonUrl) => {
    const start = Date.now();
    const r = await askGenome({ genomeGate: true, daemonUrl, genomeTimeoutMs: 150 }, '/x', [{ source: 'q', value: 'x' }]);
    const elapsed = Date.now() - start;
    assert.strictEqual(r.verdict, 'ALLOW');
    assert.ok(elapsed < 1000, `took ${elapsed}ms, expected to bail near the 150ms timeout`);
    ok('slow daemon fails OPEN at genomeTimeoutMs, does not hang the request');
  });

  // 5. Fail OPEN on a malformed daemon response.
  await withFakeDaemon((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('not json');
  }, async (daemonUrl) => {
    const r = await askGenome({ genomeGate: true, daemonUrl, genomeTimeoutMs: 1000 }, '/x', [{ source: 'q', value: 'x' }]);
    assert.strictEqual(r.verdict, 'ALLOW');
    ok('unparseable daemon response fails OPEN');
  });

  console.log(`\n${passed}/5 genome gate checks passed`);
}

main().catch((e) => {
  console.error('\x1b[91mFAILED:\x1b[0m', e.message);
  process.exit(1);
});
