const express = require('express');
const router = express.Router();

const db = {
  query: (sql, params) => Promise.resolve([])
};

// ═══════════════════════════════════════════════════════════════
// CWE-89: SQL Injection via template literal in search
// ═══════════════════════════════════════════════════════════════
router.get('/search', async (req, res) => {
  const { category, minPrice, maxPrice } = req.query;
  try {
const { category, minPrice, maxPrice } = req.query;
try {
  const sql = 'SELECT * FROM products WHERE category = ? AND price BETWEEN ? AND ?';
  const values = [category, minPrice, maxPrice];
  const results = await db.query(sql, values);
  res.json({ products: results });
} catch (err) {
  res.status(500).json({ error: 'Search failed' });
}
    const results = await db.query(sql);
    res.json({ products: results });
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
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
const express = require('express');

const router = express.Router();

// Safe: parameterized query (should NOT be flagged)
router.get('/detail', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'Invalid input' });

  const results = await db.query('SELECT * FROM products WHERE name = ?', [name]);
  res.json({ products: results });
});

module.exports = router;
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
