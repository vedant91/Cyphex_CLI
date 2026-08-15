/**
 * CYPHEX vuln-webapp — Database module
 *
 * When running inside Docker (DB_HOST env set), connects to real MySQL.
 * Falls back to a mock DB for native/native-npm sandbox mode.
 * This lets the DAST scanner actually trigger real SQL execution so
 * SQL injection vulnerabilities are genuinely exploitable in Docker mode.
 */

let db;

if (process.env.DB_HOST) {
  // ── Docker mode: real MySQL via mysql2 ────────────────────────────
  try {
    const mysql = require('mysql2/promise');
    const pool = mysql.createPool({
      host:     process.env.DB_HOST     || 'db',
      port:     process.env.DB_PORT     || 3306,
      user:     process.env.DB_USER     || 'root',
      password: process.env.DB_PASS     || 'rootpass',
      database: process.env.DB_NAME     || 'vulndb',
      waitForConnections: true,
      connectionLimit: 10,
    });

    db = {
      query: async (sql, params) => {
        const [rows] = await pool.execute(sql, params || []);
        return rows;
      },
      queryUnsafe: async (sql) => {
        // Used by vulnerable routes that pass raw SQL (no params)
        const [rows] = await pool.query(sql);
        return rows;
      },
    };

    console.log(`[DB] Connected to MySQL at ${process.env.DB_HOST}:${process.env.DB_PORT || 3306}`);
  } catch (e) {
    console.warn('[DB] mysql2 not available, falling back to mock DB:', e.message);
    db = _mockDb();
  }
} else {
  // ── Native mode: mock DB (returns empty results) ──────────────────
  db = _mockDb();
}

function _mockDb() {
  return {
    query: (_sql, _params) => Promise.resolve([]),
    queryUnsafe: (_sql) => Promise.resolve([]),
  };
}

module.exports = db;
