"""
VULNERABLE VERSION - for educational security review purposes only.
Do NOT deploy this code. See ../reports and ../fixed_app for the audit
findings and the corrected implementation.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, password TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = get_db()
    cur = conn.cursor()

    # F1: SQL Injection - user input concatenated directly into the query
    query = "SELECT * FROM users WHERE username = '" + username + \
            "' AND password = '" + password + "'"
    cur.execute(query)
    user = cur.fetchone()
    conn.close()

    if user:
        return "Welcome " + username
    else:
        return "Invalid credentials"


@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']

    conn = get_db()
    cur = conn.cursor()

    # F2: Plaintext password storage
    cur.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password)
    )
    conn.commit()
    conn.close()
    return "Registered successfully"


@app.route("/profile")
def profile():
    name = request.args.get("name")

    # F3: Reflected XSS - raw string concatenation into HTML
    template = "<h1>Welcome, " + name + "</h1>"
    return render_template_string(template)


@app.route("/download")
def download():
    filename = request.args.get("file")

    # F4: Path Traversal - no sanitization of filename
    with open(os.path.join("uploads", filename), "r") as f:
        return f.read()


if __name__ == "__main__":
    init_db()
    # F5: Debug mode enabled, bound to all interfaces
    app.run(debug=True, host="0.0.0.0")
