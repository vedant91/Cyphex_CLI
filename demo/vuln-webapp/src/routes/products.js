const express = require('express');
const router = express.Router();

const db = require('../db');

// ═══════════════════════════════════════════════════════════════
// CWE-89: SQL Injection via template literal in search
// ═══════════════════════════════════════════════════════════════
router.get('/search', async (req, res) => {
  const { category, minPrice, maxPrice } = req.query;
  try {
    // CWE-89: SQL Injection via template literal — params not sanitized
    const min = minPrice || 0;
    const max = maxPrice || 99999;
    const cat = category || '%';
    const sql = `SELECT * FROM products WHERE category LIKE '${cat}' AND price BETWEEN ${min} AND ${max}`;
    const results = await db.queryUnsafe(sql);
    res.json({ products: results });
  } catch (err) {
    res.status(500).json({ error: 'Search failed', detail: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// CWE-79: XSS via reflected user input in response
// ═══════════════════════════════════════════════════════════════
router.get('/detail', (req, res) => {
  const { name } = req.query;
  // Reflected XSS — user input rendered directly in HTML
  res.send(`
    <html>
    <body>
      <h1>Product: ${name}</h1>
      <p>You searched for: ${name}</p>
    </body>
    </html>
  `);
});

// Safe: parameterized query (should NOT be flagged)
router.get('/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  
  const results = await db.query('SELECT * FROM products WHERE id = ?', [id]);
  res.json({ product: results[0] });
});

module.exports = router;
