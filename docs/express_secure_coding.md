# Express.js Security Best Practices

## CWE-942: Overly Permissive Cross-origin Resource Sharing (CORS)
By default, CORS should be restricted to trusted domains. Do not use `cors({ origin: '*' })` or reflect the `Origin` header blindly.
**Secure Pattern**:
```javascript
const cors = require('cors');
const allowedOrigins = ['https://trusted.com', 'https://api.trusted.com'];
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
```

## CWE-89: SQL Injection in Express (mysql2 / pg)
Never concatenate user input (e.g., `req.body.id`, `req.query.name`) directly into SQL strings.
**Vulnerable Pattern**:
```javascript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query, (err, results) => { ... });
```
**Secure Pattern**:
```javascript
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [req.params.id], (err, results) => { ... });
```

## CWE-22: Path Traversal in Express
When serving files based on user input, you must ensure the resolved path stays within the intended directory.
**Vulnerable Pattern**:
```javascript
const filePath = path.join(__dirname, 'public', req.query.file);
res.sendFile(filePath);
```
**Secure Pattern**:
```javascript
const baseDir = path.join(__dirname, 'public');
const filePath = path.resolve(baseDir, req.query.file);
if (!filePath.startsWith(baseDir)) {
  return res.status(403).send('Forbidden');
}
res.sendFile(filePath);
```
