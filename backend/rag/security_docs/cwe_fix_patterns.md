# Common CWE Fix Patterns Reference

## CWE-78: OS Command Injection
**Vulnerability**: Using `child_process.exec()` or `child_process.spawn()` with concatenated user input allows attackers to execute arbitrary shell commands.
**Fix Pattern**:
1. Never use `exec()`. Use `execFile()` or `spawn()`.
2. Do not use `shell: true`.
3. Pass arguments as an array, not a single string.

**Example (Node.js)**:
```javascript
// BAD
const { exec } = require('child_process');
exec(`ping -c 4 ${req.body.ip}`, (err, stdout) => { ... });

// GOOD
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', req.body.ip], (err, stdout) => { ... });
```

## CWE-798: Use of Hard-coded Credentials
**Vulnerability**: Storing passwords, API keys, or JWT secrets directly in source code allows anyone with read access to compromise the system.
**Fix Pattern**:
1. Remove the hardcoded secret from the code.
2. Load the secret from environment variables using `process.env`.
3. Provide a safe default or throw an error if the environment variable is missing.

**Example (Node.js)**:
```javascript
// BAD
const JWT_SECRET = "super_secret_key_12345";

// GOOD
const JWT_SECRET = process.env.JWT_SECRET || "default_dev_key";
// OR
if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required");
```

## CWE-79: Cross-Site Scripting (XSS)
**Vulnerability**: Reflecting user input directly into HTML responses allows attackers to execute arbitrary JavaScript in the victim's browser.
**Fix Pattern**:
1. Sanitize user input before rendering it.
2. Use libraries like DOMPurify or sanitize-html.
3. Use context-aware encoding.

**Example (Node.js)**:
```javascript
// BAD
res.send(`<h1>Welcome, ${req.query.name}</h1>`);

// GOOD
const sanitizeHtml = require('sanitize-html');
const safeName = sanitizeHtml(req.query.name);
res.send(`<h1>Welcome, ${safeName}</h1>`);
```
