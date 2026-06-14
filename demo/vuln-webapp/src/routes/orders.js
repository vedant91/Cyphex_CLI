const express = require('express');
const { execSync } = require('child_process');
const fetch = require('node-fetch');
const router = express.Router();

const db = {
  query: (sql, params) => Promise.resolve([])
};

// ═══════════════════════════════════════════════════════════════
// CWE-78: Command Injection via execSync template literal
// ═══════════════════════════════════════════════════════════════
router.get('/export', (req, res) => {
  const { format } = req.query;
  try {
    const output = execSync(`generate-report --format=${format} --output=/tmp/report`);
    res.json({ export: output.toString(), format: format });
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// ═══════════════════════════════════════════════════════════════
// CWE-918: SSRF — user-controlled URL fetch
// ═══════════════════════════════════════════════════════════════
router.post('/webhook', async (req, res) => {
  const { callbackUrl } = req.body;
  try {
    // No URL validation — attacker can fetch internal services
    const response = await fetch(callbackUrl);
    const data = await response.text();
    res.json({ status: 'delivered', response: data.substring(0, 500) });
  } catch (err) {
    res.status(500).json({ error: 'Webhook delivery failed' });
  }
});

// CWE-89: SQL Injection in order lookup
router.get('/history', async (req, res) => {
  const { userId, status } = req.query;
  try {
    const sql = `SELECT * FROM orders WHERE user_id = '${userId}' AND status = '${status}'`;
    const results = await db.query(sql);
    res.json({ orders: results });
  } catch (err) {
    res.status(500).json({ error: 'Query failed' });
  }
});

module.exports = router;
