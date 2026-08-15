const express = require('express');
const { exec } = require('child_process');
const router = express.Router();

// ═══════════════════════════════════════════════════════════════
// CWE-200: Sensitive Data Exposure — debug route with no auth
// ═══════════════════════════════════════════════════════════════
router.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    cwd: process.cwd(),
    versions: process.versions,
  });
});

// ═══════════════════════════════════════════════════════════════
// CWE-78: Command Injection via exec with string concatenation
// ═══════════════════════════════════════════════════════════════
router.post('/diagnose', (req, res) => {
  const { hostname } = req.body;
  exec("ping -c 4 " + hostname, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ result: stdout });
  });
});

// ═══════════════════════════════════════════════════════════════
// CWE-287: No authentication on admin-only routes
// ═══════════════════════════════════════════════════════════════
router.get('/users', (req, res) => {
  // Should require admin auth — anyone can list all users
  res.json({ users: [
    { id: 1, email: 'admin@company.com', role: 'admin' },
    { id: 2, email: 'user@company.com', role: 'user' },
  ]});
});

router.delete('/users/:id', (req, res) => {
  // Should require admin auth — anyone can delete users
  const userId = req.params.id;
  res.json({ message: `User ${userId} deleted` });
});

module.exports = router;
