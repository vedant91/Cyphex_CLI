const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

// ═══════════════════════════════════════════════════════════════
// CWE-798: Hardcoded JWT secret
// ═══════════════════════════════════════════════════════════════
const JWT_SECRET = process.env.SECRET;

// Fake user database
const users = [
  { id: 1, email: 'admin@company.com', password: 'admin123', role: 'admin' },
  { id: 2, email: 'user@company.com', password: 'pass456', role: 'user' },
];

// CWE-287: No rate limiting, no password hashing
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
  
  // CWE-614: Cookie without secure flags
  res.cookie('session', token);
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

router.post('/register', (req, res) => {
  const { email, password, name } = req.body;
  // CWE-798: Hardcoded default password
  const defaultPassword = password || 'changeme123';
  
  const newUser = {
    id: users.length + 1,
    email,
    password: defaultPassword,  // Stored in plaintext!
    role: 'user',
  };
  users.push(newUser);
  res.json({ message: 'User registered', userId: newUser.id });
});

module.exports = router;
