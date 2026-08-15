const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// ═══════════════════════════════════════════════════════════════
// CWE-942: Permissive CORS — allows any origin
// ═══════════════════════════════════════════════════════════════
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ═══════════════════════════════════════════════════════════════
// Routes
// ═══════════════════════════════════════════════════════════════
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const adminRoutes = require('./routes/admin');
const fileRoutes = require('./routes/files');

app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/products', productRoutes);
app.use('/orders', orderRoutes);
app.use('/admin', adminRoutes);
app.use('/files', fileRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/', (req, res) => {
  res.send(`
    <html>
      <body>
        <h1>VulnCorp API</h1>
        <ul>
          <li><a href="/users/search?q=test">Search Users (SQLi)</a></li>
          <li><a href="/users/profile/1">User Profile (IDOR)</a></li>
          <li><a href="/orders/export?format=json">Export Orders (CMDi)</a></li>
          <li><a href="/orders/history?userId=1&status=paid">Order History (SQLi)</a></li>
          <li><a href="/admin/debug">Admin Debug (SDE)</a></li>
        </ul>
      </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
