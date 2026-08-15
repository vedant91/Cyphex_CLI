const express = require('express');
const router = express.Router();

// Simulated DB connection
const db = {
  query: (sql, params, callback) => {
    // Simulated mysql2 query
    if (callback) callback(null, []);
    return Promise.resolve([]);
  }
};

// ═══════════════════════════════════════════════════════════════
// CWE-89: SQL Injection via template literal
// ═══════════════════════════════════════════════════════════════
router.get('/search', async (req, res) => {
  const { q } = req.query;
  try {
    const sql = `SELECT * FROM users WHERE name LIKE '%${q}%' OR email LIKE '%${q}%'`;
    const results = await db.query(sql);
    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// CWE-284/IDOR: No ownership check — any user can view any profile
// ═══════════════════════════════════════════════════════════════
router.get('/profile/:id', async (req, res) => {
  const userId = req.params.id;
  try {
    const sql = `SELECT id, email, role, created_at FROM users WHERE id = ${userId}`;
    const results = await db.query(sql);
    res.json({ user: results[0] });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// CWE-89: SQL Injection via string concatenation
router.post('/update', async (req, res) => {
  const { email, name } = req.body;
  try {
    const sql = "UPDATE users SET name = '" + name + "' WHERE email = '" + email + "'";
    await db.query(sql);
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

module.exports = router;
