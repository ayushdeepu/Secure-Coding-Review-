# Secure Coding Review — Findings Report

**Application audited:** Mini Notes (`vulnerable_app.py`)
**Language / framework:** Python 3.12, Flask
**Methodology:** Manual line-by-line review + Bandit static analysis (v1.9)
**Lines reviewed:** 68
**Total findings:** 9 (4 Critical · 3 High · 2 Medium)

---

## Summary table

| # | Finding | Severity | CWE | Location |
|---|---------|----------|-----|----------|
| 1 | Hardcoded secret key in source | Critical | CWE-798 | app.py:17 |
| 2 | SQL injection in login (string formatting) | Critical | CWE-89 | app.py:40 |
| 3 | Weak, unsalted password hashing (MD5) | High | CWE-327 | app.py:57 |
| 4 | SQL injection in note lookup (f-string) | Critical | CWE-89 | app.py:71 |
| 5 | Reflected XSS in note rendering | High | CWE-79 | app.py:77 |
| 6 | Path traversal in file export | High | CWE-22 | app.py:85 |
| 7 | OS command injection in /ping | Critical | CWE-78 | app.py:93 |
| 8 | Sensitive environment data exposed | Medium | CWE-209 | app.py:100 |
| 9 | Debug mode enabled, bound to all interfaces | Medium | CWE-489 | app.py:105 |

---

## Detailed findings

### 1. Hardcoded secret key in source — Critical (CWE-798)
**Code:**
```python
app.secret_key = "super-secret-key-123"
```
**Issue:** The session-signing key lives in source control. Anyone with repo access — including git history — can forge session cookies and impersonate users.

**Fix:**
```python
app.secret_key = os.environ["SECRET_KEY"]  # set in deployment env, never committed
```

### 2. SQL injection in login — Critical (CWE-89)
**Code:**
```python
query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
user = conn.execute(query).fetchone()
```
**Issue:** User input is interpolated directly into SQL. A username of `' OR '1'='1` bypasses authentication; worse payloads can read/modify the entire database.

**Fix:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
user = conn.execute(query, (username, password)).fetchone()
```

### 3. Weak, unsalted password hashing — High (CWE-327)
**Code:**
```python
hashed = hashlib.md5(password.encode()).hexdigest()
```
**Issue:** MD5 is fast and unsalted — trivially crackable with rainbow tables or commodity GPUs.

**Fix:**
```python
from werkzeug.security import generate_password_hash
hashed = generate_password_hash(password)
```

### 4. SQL injection in note lookup — Critical (CWE-89)
**Code:**
```python
row = conn.execute(f"SELECT content FROM notes WHERE id = {note_id}").fetchone()
```
**Issue:** `note_id` is dropped straight into the query string, allowing UNION-based data exfiltration.

**Fix:**
```python
row = conn.execute("SELECT content FROM notes WHERE id = ?", (note_id,)).fetchone()
```

### 5. Reflected XSS in note rendering — High (CWE-79)
**Code:**
```python
template = "<h1>Note</h1><p>" + content + "</p>"
return render_template_string(template)
```
**Issue:** Note content is concatenated into raw HTML with no escaping, enabling stored/reflected XSS via `<script>` payloads.

**Fix:**
```python
return render_template("note.html", content=content)  # Jinja2 autoescapes {{ }}
```

### 6. Path traversal in file export — High (CWE-22)
**Code:**
```python
filepath = os.path.join("/var/data/exports", filename)
return send_file(filepath)
```
**Issue:** `filename` is unvalidated. A request like `/export?file=../../../../etc/passwd` reads arbitrary files.

**Fix:**
```python
from werkzeug.utils import secure_filename
filename = secure_filename(request.args.get("file", "notes.txt"))
filepath = os.path.join("/var/data/exports", filename)
```

### 7. OS command injection in /ping — Critical (CWE-78)
**Code:**
```python
result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
```
**Issue:** `host` is interpolated into a shell command with `shell=True`. A value like `127.0.0.1; rm -rf /` executes arbitrary shell commands.

**Fix:**
```python
import re
if not re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host):
    abort(400)
result = subprocess.run(["ping", "-c", "1", host], shell=False, capture_output=True)
```

### 8. Sensitive environment data exposed — Medium (CWE-209)
**Code:**
```python
return {"env": dict(os.environ)}
```
**Issue:** Dumps every environment variable — often including API keys and DB credentials — to any unauthenticated visitor.

**Fix:** Remove the endpoint from production builds entirely; if diagnostics are needed, gate behind authentication and return only an explicit allow-list of non-sensitive fields.

### 9. Debug mode enabled, bound to all interfaces — Medium (CWE-489)
**Code:**
```python
app.run(host="0.0.0.0", port=5000, debug=True)
```
**Issue:** `debug=True` exposes the interactive Werkzeug debugger (arbitrary code execution on exception), and `host="0.0.0.0"` makes it reachable from the whole network.

**Fix:**
```python
app.run(host="127.0.0.1", port=5000, debug=False)  # use a real WSGI server (gunicorn/uwsgi) in prod
```

---

## General best practices

1. **Never build queries with string formatting** — use parameterized queries or an ORM for every database call.
2. **Treat all request data as hostile** — validate type, length, and format of every form field, query param, and header.
3. **Keep secrets out of source control** — load credentials from environment variables or a secrets manager.
4. **Hash passwords with a slow, salted algorithm** — bcrypt, scrypt, or Argon2, never MD5/SHA alone.
5. **Let the template engine escape output** — use Jinja2 autoescaping instead of manual string concatenation.
6. **Run static analysis on every commit** — wire Bandit (or similar) into CI so vulnerable patterns fail the build.

---

*This review was performed against an intentionally vulnerable sample application built for training purposes. Do not deploy `vulnerable_app.py` anywhere.*
