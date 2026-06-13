# Secure Coding Review — Flask Authentication Module

A secure coding review of a small Python/Flask web application, performed as
part of an internship secure-development exercise. The review covers manual
code inspection and static analysis (Bandit), and documents 6 findings with
remediation.

## Repository Structure

```
secure-coding-review/
├── README.md
├── vulnerable_app/
│   └── app.py              # original code with intentional vulnerabilities
├── fixed_app/
│   ├── app.py               # remediated code
│   └── templates/
│       └── profile.html     # auto-escaped Jinja2 template (fixes XSS)
├── reports/
│   ├── bandit_vulnerable.txt  # Bandit scan of vulnerable_app/app.py
│   └── bandit_fixed.txt       # Bandit scan of fixed_app/app.py
├── secure-coding-review.html  # visual / interactive audit report
└── requirements.txt
```

## How to run

```bash
pip install -r requirements.txt

# Run the vulnerable version (do not expose publicly)
cd vulnerable_app && python app.py

# Run the fixed version
cd fixed_app && python app.py

# Run Bandit static analysis
bandit -r vulnerable_app/app.py
bandit -r fixed_app/app.py
```

## Methodology

1. **Manual inspection** — traced every route from user input (`request.form`
   / `request.args`) to its sink (SQL query, template render, file open) to
   find untrusted data reaching dangerous operations.
2. **Static analysis (Bandit)** — ran Bandit against both versions of the app
   to confirm findings automatically. Results in `reports/`.

## Findings Summary

| ID | Vulnerability | Route | Severity | CWE |
|----|----------------|----------|----------|---------|
| F1 | SQL Injection | `/login` | Critical | CWE-89 |
| F2 | Plaintext password storage | `/register` | Critical | CWE-256 |
| F3 | Reflected XSS | `/profile` | High | CWE-79 |
| F4 | Path traversal / arbitrary file read | `/download` | High | CWE-22 |
| F5 | Debug mode enabled | `app.run()` | High | CWE-489 |
| F6 | Missing input validation | all routes | Medium | CWE-20 |

## Findings & Remediation

### F1 — SQL Injection (Critical, CWE-89)
**Issue:** `username` and `password` are concatenated directly into a SQL
string, allowing authentication bypass with input like `' OR '1'='1`.

**Fix:** Use a parameterized query:
```python
cur.execute("SELECT password FROM users WHERE username = ?", (username,))
```

### F2 — Plaintext Password Storage (Critical, CWE-256)
**Issue:** Passwords are stored as-is. A database leak exposes every user's
real password.

**Fix:** Hash with `werkzeug.security.generate_password_hash` on register,
and verify with `check_password_hash` on login.

### F3 — Reflected XSS (High, CWE-79)
**Issue:** The `name` query parameter is concatenated into raw HTML via
`render_template_string`, allowing script injection.

**Fix:** Render through a Jinja2 template (`profile.html`) using
`render_template`, which auto-escapes `{{ name }}`.

### F4 — Path Traversal (High, CWE-22)
**Issue:** `file` query parameter is joined to the uploads path without
sanitization, allowing `../../etc/passwd`-style traversal.

**Fix:** Sanitize with `secure_filename()` and verify the resolved absolute
path stays inside the uploads directory before opening it.

### F5 — Debug Mode Enabled (High, CWE-489)
**Issue:** `app.run(debug=True, host="0.0.0.0")` exposes the Werkzeug
debugger, which can lead to remote code execution if reachable externally.

**Fix:** Default `debug=False`; control via an environment variable
(`FLASK_DEBUG`) that defaults to off.

### F6 — Missing Input Validation (Medium, CWE-20)
**Issue:** No checks on presence, length, or format of form fields.

**Fix:** Reject empty fields and enforce a maximum username length before
processing.

## Static Analysis Results

**Vulnerable app** — 3 issues found:
- `B608` SQL injection via string-based query construction (Medium)
- `B201` Flask debug mode enabled (High)
- `B104` Binding to all interfaces (Medium)

**Fixed app** — 0 issues found.

Full output in [`reports/bandit_vulnerable.txt`](reports/bandit_vulnerable.txt)
and [`reports/bandit_fixed.txt`](reports/bandit_fixed.txt).

## Secure Coding Best Practices

1. Use parameterized queries / an ORM — never build SQL via string concatenation.
2. Hash passwords with bcrypt, Argon2, or PBKDF2 — never store plaintext.
3. Use template auto-escaping (Jinja2 `render_template`) instead of raw HTML strings.
4. Sanitize and confine file paths with `secure_filename()` plus a directory check.
5. Disable debug mode in production; drive it from environment configuration.
6. Validate all input — length, type, and format — before use.
7. Set secure cookie flags: `HttpOnly`, `Secure`, `SameSite`.
8. Run SAST (Bandit/Semgrep) in CI on every pull request.
9. Rate-limit authentication endpoints to mitigate brute-force attacks.
10. Keep dependencies up to date; scan with `pip-audit` or `safety`.

## Conclusion

The audit identified 6 vulnerabilities (2 critical, 3 high, 1 medium) in the
original application. All were remediated in `fixed_app/` via parameterized
queries, password hashing, template auto-escaping, path sanitization, and
disabled debug mode. A follow-up Bandit scan of the fixed code reports zero
issues.
