# Cyphex Vuln Webapp

A deliberately vulnerable Express.js web application designed for CYPHEX security scanning demos.

## Vulnerabilities Included

| # | CWE | Type | File | Location |
|---|-----|------|------|----------|
| 1 | CWE-89 | SQL Injection (template literal) | `users.js` | `GET /users/search` |
| 2 | CWE-89 | SQL Injection (string concat) | `users.js` | `POST /users/update` |
| 3 | CWE-89 | SQL Injection (template literal) | `products.js` | `GET /products/search` |
| 4 | CWE-89 | SQL Injection (template literal) | `orders.js` | `GET /orders/history` |
| 5 | CWE-78 | Command Injection (execSync) | `orders.js` | `GET /orders/export` |
| 6 | CWE-78 | Command Injection (exec concat) | `admin.js` | `POST /admin/diagnose` |
| 7 | CWE-79 | XSS (reflected) | `products.js` | `GET /products/detail` |
| 8 | CWE-22 | Path Traversal | `files.js` | `GET /files/download` |
| 9 | CWE-22 | Path Traversal | `files.js` | `GET /files/view` |
| 10 | CWE-918 | SSRF | `orders.js` | `POST /orders/webhook` |
| 11 | CWE-798 | Hardcoded Secret | `auth.js` | JWT_SECRET |
| 12 | CWE-942 | Wildcard CORS | `server.js` | `cors({ origin: '*' })` |
| 13 | CWE-200 | Debug Info Exposure | `admin.js` | `GET /admin/debug` |
| 14 | CWE-287 | Missing Auth | `admin.js` | `GET /admin/users` |

## False Positive Test

- `GET /products/:id` uses **parameterized queries** — should NOT be flagged

## Usage

```bash
npm install
npm start
# Server runs on http://localhost:3000
```

## For CYPHEX Testing

```bash
python cyphex_cli.py scan --local ./demo/vuln-webapp
```
