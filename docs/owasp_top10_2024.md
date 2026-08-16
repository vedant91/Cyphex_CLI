# OWASP Top 10 Security Risks (2024 Edition)

## A01:2021-Broken Access Control (CWE-284, CWE-287)
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.
**Prevention**: Except for public resources, deny by default. Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage. 
**Related CWEs**: CWE-284, CWE-287.

## A03:2021-Injection (CWE-89, CWE-78)
Injection flaws, such as SQL, NoSQL, OS command, Object Relational Mapping (ORM), LDAP, and Expression Language (EL) or Object Graph Navigation Library (OGNL) injection, occur when untrusted data is sent to an interpreter as part of a command or query.
**Prevention**: Use a safe API, which avoids using the interpreter entirely, provides a parameterized interface, or migrates to Object Relational Mapping Tools (ORMs). Use positive or "whitelist" server-side input validation. For any residual dynamic queries, escape special characters using the specific escape syntax for that interpreter.
**Related CWEs**: CWE-89 (SQL Injection), CWE-78 (OS Command Injection).

## A07:2021-Identification and Authentication Failures (CWE-798, CWE-306)
Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.
**Prevention**: Where possible, implement multi-factor authentication to prevent automated, credential stuffing, brute force, and stolen credential reuse attacks. Do not ship or deploy with any default credentials, particularly for admin users. Never hardcode passwords or API keys (CWE-798) in source code.
**Related CWEs**: CWE-798 (Use of Hard-coded Credentials), CWE-306 (Missing Authentication for Critical Function).

## A08:2021-Software and Data Integrity Failures (CWE-502)
Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).
**Prevention**: Ensure that there is a review process for code and configuration changes. Ensure that libraries and dependencies, such as npm, Maven, or PyPI, are consuming trusted repositories.
**Related CWEs**: CWE-502 (Deserialization of Untrusted Data).
