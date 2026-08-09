/**
 * CYPHEX VulnApp - Full coverage target (no native deps)
 * Covers: SQLi, XSS, Auth, CMDi, PathTraversal, SSRF, SSTI, XXE, IDOR, BusinessLogic
 * Port: 3001
 */
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

const app = express();
const PORT = 3001;

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text({ type: '*/*' }));
app.use(cookieParser());

// ── In-memory DB ──────────────────────────────────────────────────────────────
const db = {
  users: [
    { id: 1, username: 'admin', password: 'admin123', email: 'admin@shop.local', role: 'admin', balance: 9999.99 },
    { id: 2, username: 'alice', password: 'password', email: 'alice@shop.local', role: 'user',  balance: 250.00 },
    { id: 3, username: 'bob',   password: 'bob123',   email: 'bob@shop.local',   role: 'user',  balance: 75.00  },
  ],
  products: [
    { id: 1, name: 'Laptop Pro',     price: 999.99, description: 'High-performance laptop', category: 'electronics' },
    { id: 2, name: 'Wireless Mouse', price: 29.99,  description: 'Ergonomic wireless mouse', category: 'accessories' },
    { id: 3, name: 'USB Hub',        price: 19.99,  description: 'USB 3.0 7-port hub',       category: 'accessories' },
  ],
  orders: [
    { id: 1, user_id: 2, product_id: 1, quantity: 1, total: 999.99, status: 'completed' },
    { id: 2, user_id: 3, product_id: 2, quantity: 2, total: 59.98,  status: 'pending' },
  ],
  notes: [
    { id: 1, user_id: 1, content: 'Admin secret: SK_LIVE_abc123xyz', is_public: 0 },
    { id: 2, user_id: 2, content: 'My shopping list', is_public: 1 },
    { id: 3, user_id: 3, content: 'Remember to buy milk', is_public: 1 },
  ],
  comments: [],
  nextId: { orders: 3, notes: 4, comments: 1 },
};

// ── Sessions ──────────────────────────────────────────────────────────────────
const sessions = {};
function mkSession(userId, role) {
  const t = crypto.randomBytes(16).toString('hex');
  sessions[t] = { userId, role };
  return t;
}
function getSess(req) {
  return sessions[req.cookies.session || req.headers['x-session']] || null;
}

// ── HOMEPAGE (HTML with forms + links — feeds crawler) ────────────────────────
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>VulnShop - CYPHEX Test Target</title>
<style>body{font-family:Arial,sans-serif;max-width:900px;margin:0 auto;padding:20px;background:#f5f5f5}
h1{color:#c00}h2{color:#333;border-bottom:2px solid #c00}
.card{background:#fff;padding:15px;margin:10px 0;border-radius:6px;border:1px solid #ddd}
form input,form textarea{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}
form button{background:#c00;color:#fff;padding:10px 20px;border:none;cursor:pointer;border-radius:4px}
nav a{margin-right:15px;color:#c00;text-decoration:none}
.warn{background:#fff3cd;padding:10px;border:1px solid #ffc107;border-radius:4px}</style>
</head><body>
<h1>🛒 VulnShop</h1>
<p class="warn">⚠ Deliberately vulnerable app for Cyphex security testing</p>
<nav>
  <a href="/">Home</a> <a href="/products">Products</a> <a href="/search?q=laptop">Search</a>
  <a href="/auth/login">Login</a> <a href="/profile/1">Profile</a> <a href="/admin">Admin</a>
  <a href="/debug">Debug</a> <a href="/api/health">Health</a> <a href="/comments">Comments</a>
</nav>

<div class="card"><h2>🔍 Search (SQLi)</h2>
<form method="GET" action="/search">
  <input name="q" placeholder="Search products...">
  <button>Search</button>
</form></div>

<div class="card"><h2>🔐 Login (Auth Bypass)</h2>
<form method="POST" action="/auth/login">
  <input name="username" placeholder="Username" value="alice">
  <input name="password" type="password" placeholder="Password">
  <button>Login</button>
</form></div>

<div class="card"><h2>📝 Comment (XSS)</h2>
<form method="POST" action="/comments">
  <input name="name" placeholder="Your name">
  <textarea name="comment" rows="2" placeholder="Comment (HTML allowed!)"></textarea>
  <input name="redirect" type="hidden" value="/">
  <button>Post</button>
</form></div>

<div class="card"><h2>📡 URL Fetcher (SSRF)</h2>
<form method="GET" action="/fetch">
  <input name="url" placeholder="http://example.com">
  <button>Fetch</button>
</form></div>

<div class="card"><h2>📁 File Download (Path Traversal)</h2>
<form method="GET" action="/files/download">
  <input name="file" value="reports/summary.txt">
  <button>Download</button>
</form></div>

<div class="card"><h2>🖥 Ping (CMDi)</h2>
<form method="POST" action="/admin/ping">
  <input name="host" value="localhost">
  <button>Ping</button>
</form></div>

<div class="card"><h2>🧮 Order (Business Logic - price override)</h2>
<form method="POST" action="/orders">
  <input name="product_id" type="number" value="1">
  <input name="quantity" type="number" value="1">
  <input name="price" type="number" step="0.01" value="-1" placeholder="Price override">
  <button>Place Order</button>
</form></div>

<div class="card"><h2>📦 XML Import (XXE)</h2>
<form method="POST" action="/import/xml">
  <textarea name="xml" rows="4">&lt;items&gt;&lt;item&gt;&lt;name&gt;test&lt;/name&gt;&lt;/item&gt;&lt;/items&gt;</textarea>
  <button>Import</button>
</form></div>

<div class="card"><h2>🎨 Template Render (SSTI)</h2>
<form method="GET" action="/render">
  <input name="template" value="Hello {{ name }}">
  <input name="name" value="World">
  <button>Render</button>
</form></div>

<h2>Quick Links</h2>
<ul>
  <li><a href="/profile/1">Profile #1 (admin - IDOR)</a></li>
  <li><a href="/profile/2">Profile #2 (alice)</a></li>
  <li><a href="/api/users">GET /api/users (no auth)</a></li>
  <li><a href="/api/users/search?q=admin">GET /api/users/search?q=admin (SQLi)</a></li>
  <li><a href="/api/notes/1">GET /api/notes/1 (IDOR - private note)</a></li>
  <li><a href="/api/products">GET /api/products</a></li>
  <li><a href="/.env">GET /.env (info disclosure)</a></li>
  <li><a href="/config.json">GET /config.json (info disclosure)</a></li>
</ul>
</body></html>`);
});

// ── SQLi: Search ──────────────────────────────────────────────────────────────
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Simulate SQLi by exposing query + doing naive filter
  if (q.includes("'") || q.includes('--') || q.toLowerCase().includes(' or ')) {
    return res.status(500).send(`<h2>Database Error</h2>
<pre>Error: SQLITE_ERROR: unrecognized token near '${q}'
Query: SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'</pre>`);
  }
  const results = db.products.filter(p =>
    p.name.toLowerCase().includes(q.toLowerCase()) ||
    p.description.toLowerCase().includes(q.toLowerCase())
  );
  res.send(`<h2>Search: ${q}</h2><pre>${JSON.stringify(results, null, 2)}</pre><a href="/">Back</a>`);
});

// ── SQLi: API user search ─────────────────────────────────────────────────────
app.get('/api/users/search', (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`;
  if (q.includes("'") || q.includes('--') || q.toLowerCase().includes(' or ')) {
    return res.status(500).json({
      error: `SQLITE_ERROR: near "${q}": syntax error`,
      sql,
      hint: 'SQL injection detected in query'
    });
  }
  const results = db.users
    .filter(u => u.username.includes(q) || u.email.includes(q))
    .map(({ id, username, email, role }) => ({ id, username, email, role }));
  res.json({ results, sql });
});

// ── Auth: Login (SQLi bypass + brute force) ───────────────────────────────────
app.get('/auth/login', (req, res) => {
  res.send(`<h2>Login</h2>
<form method="POST" action="/auth/login">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button>Login</button>
</form><p><a href="/">Back</a></p>`);
});

app.post('/auth/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  // SQLi bypass: ' OR '1'='1
  const bypassed = username.includes("'") || password.includes("'") ||
    username.toLowerCase().includes(' or ') || password.toLowerCase().includes(' or ');
  const user = bypassed
    ? db.users[0]  // admin
    : db.users.find(u => u.username === username && u.password === password);

  if (user) {
    const token = mkSession(user.id, user.role);
    res.cookie('session', token, { httpOnly: false });
    res.send(`<h2>✅ Welcome ${user.username}!</h2>
<p>Role: <b>${user.role}</b> | Balance: $${user.balance}</p>
<p>Session token: <code>${token}</code></p>
<pre>Query used: ${sql}</pre>
${bypassed ? '<p style="color:red">⚠ SQL INJECTION BYPASS SUCCESSFUL</p>' : ''}
<a href="/">Home</a>`);
  } else {
    res.status(401).send(`<h2>❌ Login Failed</h2><pre>Query: ${sql}</pre><a href="/">Back</a>`);
  }
});

// ── XSS: Comments ─────────────────────────────────────────────────────────────
app.post('/comments', (req, res) => {
  const { name = '', comment = '', redirect: redir = '/' } = req.body;
  db.comments.push({ id: db.nextId.comments++, name, comment, time: new Date().toISOString() });
  // VULN: name, comment, redir all unescaped
  res.send(`<h2>Comment posted!</h2>
<p>By: ${name}</p><div>${comment}</div>
<a href="${redir}">Back</a>`);
});

app.get('/comments', (req, res) => {
  const html = db.comments.map(c =>
    `<div><b>${c.name}</b>: ${c.comment} <small>${c.time}</small></div>`
  ).join('') || '<p>No comments.</p>';
  res.send(`<h2>Comments</h2>${html}<a href="/">Back</a>`);
});

// ── Products ──────────────────────────────────────────────────────────────────
app.get('/products', (req, res) => {
  const cat = req.query.category || '';
  const list = cat ? db.products.filter(p => p.category === cat) : db.products;
  res.send(`<!DOCTYPE html><html><body>
<h2>Products</h2>
<script>document.write('<p>Category: '+new URLSearchParams(location.search).get('category')+'</p>');</script>
<pre>${JSON.stringify(list, null, 2)}</pre>
<ul>${db.products.map(p => `<li><a href="/products/${p.id}">${p.name}</a></li>`).join('')}</ul>
<a href="/">Back</a></body></html>`);
});

app.get('/products/:id', (req, res) => {
  const p = db.products.find(x => x.id == req.params.id);
  if (!p) return res.status(404).send('Not found');
  res.send(`<h2>${p.name}</h2><pre>${JSON.stringify(p, null, 2)}</pre><a href="/products">Back</a>`);
});

app.get('/api/products', (req, res) => res.json({ products: db.products }));

// ── CMDi: Ping ────────────────────────────────────────────────────────────────
app.post('/admin/ping', (req, res) => {
  const host = req.body.host || 'localhost';
  try {
    const out = execSync(`ping -n 1 ${host}`, { timeout: 5000 }).toString();
    res.send(`<h2>Ping: ${host}</h2><pre>${out}</pre><a href="/">Back</a>`);
  } catch (e) {
    res.status(500).send(`<h2>Error</h2><pre>${e.message}</pre><p>CMD: ping -n 1 ${host}</p>`);
  }
});

app.post('/admin/cmd', (req, res) => {
  const cmd = req.body.cmd || req.query.cmd || 'whoami';
  try {
    const out = execSync(cmd, { timeout: 5000 }).toString();
    res.json({ cmd, output: out });
  } catch (e) {
    res.status(500).json({ cmd, error: e.message });
  }
});

// ── Path Traversal ────────────────────────────────────────────────────────────
const FILES_BASE = path.join(__dirname, '..', 'files');
if (!fs.existsSync(path.join(FILES_BASE, 'reports'))) {
  fs.mkdirSync(path.join(FILES_BASE, 'reports'), { recursive: true });
  fs.writeFileSync(path.join(FILES_BASE, 'reports', 'summary.txt'), 'Q1 Revenue: $1.2M\nQ2 Revenue: $1.4M\nDB_PASS=secret123');
  fs.writeFileSync(path.join(FILES_BASE, 'readme.txt'), 'VulnApp file server');
}

app.get('/files/download', (req, res) => {
  const file = req.query.file || 'readme.txt';
  // VULN: no path sanitisation
  const full = path.join(FILES_BASE, file);
  try {
    res.setHeader('Content-Type', 'text/plain');
    res.send(fs.readFileSync(full, 'utf8'));
  } catch {
    try {
      // Even worse: try raw path for ../ traversal
      res.send(fs.readFileSync(file, 'utf8'));
    } catch (e2) {
      res.status(404).send(`File not found: ${file}\nAttempted: ${full}\nError: ${e2.message}`);
    }
  }
});

// ── SSRF ─────────────────────────────────────────────────────────────────────
app.get('/fetch', async (req, res) => {
  const url = req.query.url || '';
  if (!url) return res.send('<h2>Fetch</h2><form><input name="url"><button>Fetch</button></form>');
  try {
    const fetch = require('node-fetch');
    const r = await fetch(url, { timeout: 5000 });
    const body = await r.text();
    res.send(`<h2>Fetched: ${url}</h2><pre>${body.slice(0, 2000)}</pre>`);
  } catch (e) {
    res.status(500).send(`<h2>Fetch Error</h2><pre>${e.message}</pre><p>URL: ${url}</p>`);
  }
});

// ── SSTI ─────────────────────────────────────────────────────────────────────
app.get('/render', (req, res) => {
  const template = req.query.template || 'Hello {{ name }}';
  const name = req.query.name || 'World';
  const rendered = template.replace(/\{\{([^}]+)\}\}/g, (_, expr) => {
    try { return eval(expr.trim()); } catch (e) { return `[ERR:${e.message}]`; }
  });
  res.send(`<h2>Rendered</h2><div>${rendered}</div>
<p>Template: <code>${template}</code></p><a href="/">Back</a>`);
});

// ── XXE ───────────────────────────────────────────────────────────────────────
app.post('/import/xml', (req, res) => {
  const xml = req.body.xml || req.body || '';
  const xmlStr = typeof xml === 'string' ? xml : JSON.stringify(xml);
  const isXXE = xmlStr.includes('<!ENTITY') || xmlStr.includes('SYSTEM');
  if (isXXE) {
    const m = xmlStr.match(/SYSTEM\s+"([^"]+)"/i);
    let content = '';
    if (m) {
      try { content = fs.readFileSync(m[1].replace('file://', ''), 'utf8').slice(0, 500); } catch {}
    }
    return res.send(`<h2>XXE Detected</h2>
<p>Entity resolved: <code>${m ? m[1] : 'N/A'}</code></p>
<pre>${content || '[entity would resolve here]'}</pre><a href="/">Back</a>`);
  }
  const names = [...xmlStr.matchAll(/<name>([^<]+)<\/name>/g)].map(m => m[1]);
  res.send(`<h2>XML Imported</h2><pre>Items: ${JSON.stringify(names)}</pre><a href="/">Back</a>`);
});

app.post('/api/xml', (req, res) => {
  const xml = req.body || '';
  const isXXE = xml.includes && (xml.includes('<!ENTITY') || xml.includes('SYSTEM'));
  res.json({ parsed: true, xxe_detected: isXXE, length: xml.length, sample: xml.slice(0, 200) });
});

// ── IDOR: Profile ─────────────────────────────────────────────────────────────
app.get('/profile/:id', (req, res) => {
  const user = db.users.find(u => u.id == req.params.id);
  if (!user) return res.status(404).send('User not found');
  // VULN: returns password too, no ownership check
  res.send(`<h2>Profile #${req.params.id}</h2>
<pre>${JSON.stringify(user, null, 2)}</pre>
<p><a href="/profile/${parseInt(req.params.id) - 1}">← Prev</a>
 | <a href="/profile/${parseInt(req.params.id) + 1}">Next →</a></p>
<a href="/">Back</a>`);
});

// IDOR: notes
app.get('/api/notes/:id', (req, res) => {
  const note = db.notes.find(n => n.id == req.params.id);
  if (!note) return res.status(404).json({ error: 'Not found' });
  res.json(note); // No auth check — any note readable
});

// ── Business Logic ────────────────────────────────────────────────────────────
app.post('/orders', (req, res) => {
  const product_id = parseInt(req.body.product_id) || 1;
  const quantity = parseInt(req.body.quantity) || 1;
  const price = parseFloat(req.body.price); // client-supplied price
  const product = db.products.find(p => p.id === product_id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  const total = (isNaN(price) ? product.price : price) * quantity;
  const order = { id: db.nextId.orders++, user_id: 2, product_id, quantity, total, status: 'pending' };
  db.orders.push(order);
  res.send(`<h2>Order Placed</h2>
<p>${product.name} x${quantity}</p>
<p>Real price: $${product.price} | Used price: $${isNaN(price) ? product.price : price}</p>
<p>Total charged: <b>$${total}</b></p>
${total <= 0 ? '<p style="color:red">⚠ BUSINESS LOGIC FLAW: Free/negative order accepted!</p>' : ''}
<a href="/">Back</a>`);
});

// Role escalation via mass assignment
app.post('/api/users/update', (req, res) => {
  const { id, username, email, role, balance } = req.body;
  const user = db.users.find(u => u.id == id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (username) user.username = username;
  if (email) user.email = email;
  if (role) user.role = role;       // VULN: anyone can set role=admin
  if (balance) user.balance = parseFloat(balance);
  res.json({ success: true, user });
});

// ── API: Users + Orders ───────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
  // VULN: no auth, returns all users including passwords
  res.json({ users: db.users });
});

app.get('/api/orders', (req, res) => res.json({ orders: db.orders }));

// ── Admin panel ───────────────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.send(`<h2>Admin Panel</h2>
<h3>Users (including passwords)</h3><pre>${JSON.stringify(db.users, null, 2)}</pre>
<h3>Ping</h3>
<form method="POST" action="/admin/ping"><input name="host" value="localhost"><button>Ping</button></form>
<h3>Run Command</h3>
<form method="POST" action="/admin/cmd"><input name="cmd" value="whoami"><button>Run</button></form>
<a href="/">Back</a>`);
});

// ── Info disclosure ───────────────────────────────────────────────────────────
app.get('/.env', (req, res) => {
  res.type('text').send('DB_PASSWORD=supersecret\nAPI_KEY=sk_live_abc123\nJWT_SECRET=s3cr3tkey\nADMIN_PASS=admin123');
});

app.get('/config.json', (req, res) => {
  res.json({ db: 'sqlite', secret: 'notasecret', debug: true, admin_email: 'admin@shop.local', version: '1.0.0' });
});

app.get('/debug', (req, res) => {
  res.json({ node: process.version, platform: process.platform, uptime: process.uptime(), sessions: Object.keys(sessions).length, env: process.env });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'cyphex-vulnapp', port: PORT, uptime: process.uptime() });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║  CYPHEX VulnApp — Full Coverage Target               ║
║  http://localhost:${PORT}                               ║
║                                                      ║
║  SQLi · XSS · CMDi · PathTraversal · SSRF           ║
║  SSTI · XXE · IDOR · AuthBypass · BusinessLogic     ║
╚══════════════════════════════════════════════════════╝`);
});
