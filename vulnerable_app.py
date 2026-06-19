"""
Mini Notes - a tiny Flask app used as the SUBJECT of Task 3's security review.

This app intentionally contains common, realistic vulnerabilities so the
review has real findings to report on. Do not deploy this code anywhere.
"""

import os
import sqlite3
import hashlib
import subprocess
from flask import Flask, request, redirect, render_template_string, send_file

app = Flask(__name__)

# Finding 1 (CWE-798): hardcoded secret key checked into source control
app.secret_key = "super-secret-key-123"

DB_PATH = "notes.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, content TEXT)"
    )
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    # Finding 2 (CWE-89): SQL Injection via string-formatted query
    conn = get_db()
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    user = conn.execute(query).fetchone()

    if user:
        return redirect("/dashboard")
    return "Invalid credentials", 401


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # Finding 3 (CWE-327): weak, fast hash (MD5) used for password storage, no salt
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed)
    )
    conn.commit()
    return "Registered"


@app.route("/notes/<note_id>")
def view_note(note_id):
    conn = get_db()
    # Finding 4 (CWE-89): SQL Injection via f-string interpolation
    row = conn.execute(f"SELECT content FROM notes WHERE id = {note_id}").fetchone()
    content = row[0] if row else "Not found"

    # Finding 5 (CWE-79): Reflected XSS - user-controlled content rendered
    # directly into an HTML template without escaping
    template = "<h1>Note</h1><p>" + content + "</p>"
    return render_template_string(template)


@app.route("/export")
def export_notes():
    filename = request.args.get("file", "notes.txt")
    # Finding 6 (CWE-22): Path Traversal - filename is not validated, so a
    # request like /export?file=../../etc/passwd can read arbitrary files
    filepath = os.path.join("/var/data/exports", filename)
    return send_file(filepath)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Finding 7 (CWE-78): OS Command Injection - host is concatenated
    # straight into a shell command
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout


@app.route("/debug-info")
def debug_info():
    # Finding 8 (CWE-209): verbose error/debug info exposed to clients
    return {"env": dict(os.environ)}


if __name__ == "__main__":
    # Finding 9 (CWE-489): debug mode enabled, binds to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
