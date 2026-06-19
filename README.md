# Secure Coding Review — Mini Notes (Flask)

A manual + automated security audit of a small Python/Flask web application, performed as a secure coding review exercise.

## 📌 What's in this repo

| File | Purpose |
|---|---|
| `vulnerable_app.py` | The audited application — a small Flask app (`Mini Notes`) with 9 intentionally realistic vulnerabilities |
| `security_review_report.html` | **Interactive visual report** — open in any browser. Filter findings by severity, view annotated code, and toggle recommended fixes |
| `findings.md` | Plain-text version of every finding with code, explanation, and remediation |
| `bandit_report.json` | Raw output from the Bandit static analyzer, used to cross-check manual findings |

## 🖥️ How to view the report
Just open `security_review_report.html` in any browser (double-click it, or use GitHub Pages / "Download raw file"). No server or build step needed — it's a single self-contained file.

Inside the report you can:
- Filter findings by severity (Critical / High / Medium / Low)
- See the exact vulnerable line highlighted inside its code context
- Click **"Show recommended fix"** on any finding to reveal the corrected code

## 🛠️ Methodology
1. **Manual inspection** — every route handler reviewed line by line, tracing untrusted input from request to sink.
2. **Static analysis** — [Bandit](https://bandit.readthedocs.io/) (a Python-specific security linter) run against the same file to cross-check findings.
3. **Threat framing** — each issue mapped to a [CWE](https://cwe.mitre.org/) identifier and the relevant OWASP Top 10 category.
4. **Remediation** — a corrected code snippet written and reviewed for every finding.

To reproduce the static analysis step yourself:
```bash
pip install bandit
bandit -r vulnerable_app.py
```

## 📊 Summary of findings

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| **Total** | **9** |

Vulnerability classes covered: SQL injection (CWE-89), OS command injection (CWE-78), reflected XSS (CWE-79), path traversal (CWE-22), hardcoded secrets (CWE-798), weak password hashing (CWE-327), sensitive data exposure (CWE-209), and insecure debug configuration (CWE-489).

## 📚 What I learned
- How small, realistic coding mistakes (a `%` format string, a missing parameter binding) turn into full-blown injection vulnerabilities
- The difference between what manual review catches vs. what static analyzers catch — and why both matter
- How to map a vulnerability to its CWE and write a concrete, testable remediation rather than a vague "be careful" note

## ⚠️ Disclaimer
`vulnerable_app.py` is **intentionally insecure** and built purely for this training exercise. Do not deploy it, expose it to a network, or use any of its patterns as a starting point for real code.
