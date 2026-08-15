const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const router = express.Router();

// ═══════════════════════════════════════════════════════════════
// CWE-22: Path Traversal — user-controlled file path
// ═══════════════════════════════════════════════════════════════
router.get('/download', (req, res) => {
  const { filename } = req.query;
  // CWE-22: No path traversal check — attacker can read any file on system
  if (!filename) {
    return res.status(400).json({ error: 'filename parameter required' });
  }
  const filePath = path.join(__dirname, '../../uploads', filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// CWE-22: Path Traversal in file read
router.get('/view', (req, res) => {
  const { file } = req.query;
  try {
    const content = fs.readFileSync(path.join('/data/reports', file), 'utf-8');
    res.json({ content });
  } catch (err) {
    res.status(404).json({ error: 'File not found' });
  }
});

// Upload with multer — safe (included to test false positive suppression)
const upload = multer({ dest: 'uploads/' });
router.post('/upload', upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({ 
    message: 'File uploaded',
    filename: req.file.filename,
    size: req.file.size,
  });
});

module.exports = router;
