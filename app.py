"""
Secure REST API — Work 1 (HDU IS)
==================================
A deliberately-secure Flask API demonstrating:
  * Parameterized queries (SQL Injection protection)
  * Output escaping (XSS protection)
  * JWT-based authentication + bcrypt password hashing
  * Access control (protected endpoints reject requests without a valid token)

Endpoints:
  POST /auth/login   - authenticate, returns a JWT
  GET  /api/data     - returns stored records (JWT required, optional ?username= filter)
  POST /api/posts    - create a post (JWT required); content is escaped on output
  GET  /api/posts    - list posts (JWT required); content is escaped on output
  GET  /api/profile  - return the current authenticated user (JWT required)
"""
import html
import os
import sqlite3
import sys
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "users.db"))
# Secret key for JWT signing. In a real deployment this MUST come from an
# environment variable / secret manager, never be committed to the repo.
# The dev default is >= 32 bytes to satisfy RFC 7518 (HMAC-SHA256 key size).
SECRET_KEY = os.environ.get(
    "SECRET_KEY", "dev-only-secret-key-please-override-in-production-0123456789"
)
JWT_ALGO = "HS256"
JWT_EXPIRES_MINUTES = 60

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


# ---------------------------------------------------------------------------
# Database helpers (parameterized queries => SQLi protection)
# ---------------------------------------------------------------------------
def get_db():
    """Return a per-request sqlite3 connection. All queries MUST use `?`
    placeholders (never string concatenation) to prevent SQL injection."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed a demo user (only if empty)."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        # demo account: testuser / Test@1234
        pw_hash = bcrypt.hashpw(b"Test@1234", bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("testuser", pw_hash),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Authentication: JWT issue + verification middleware
# ---------------------------------------------------------------------------
def _token_for(username):
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=JWT_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)


def _decode_token(token):
    """Decode and validate a JWT. Raises jwt exceptions on any invalid token."""
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])


def login_required(f):
    """Middleware: require a valid Bearer JWT on protected endpoints."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing or malformed token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            payload = _decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401
        g.current_user = payload["sub"]
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Endpoint 1: authentication
# ---------------------------------------------------------------------------
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # Parameterized query — protects against SQL injection.
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None:
        return jsonify({"error": "invalid credentials"}), 401

    # Constant-time hash comparison (bcrypt.checkpw) prevents timing attacks
    # and verifies the password without ever storing/transmitting plaintext.
    if not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"token": _token_for(row["username"])}), 200


# ---------------------------------------------------------------------------
# Endpoint 2: get data (protected, optional username filter)
# ---------------------------------------------------------------------------
@app.route("/api/data", methods=["GET"])
@login_required
def api_data():
    conn = get_db()
    username = (request.args.get("username") or "").strip()
    if username:
        # Parameterized query again — user input only ever enters as a value.
        rows = conn.execute(
            "SELECT id, username, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, username, created_at FROM users ORDER BY id"
        ).fetchall()
    return jsonify({"data": [dict(r) for r in rows]}), 200


# ---------------------------------------------------------------------------
# Endpoint 3 (self-designed): create a post (protected)
# ---------------------------------------------------------------------------
@app.route("/api/posts", methods=["POST"])
@login_required
def create_post():
    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if not content or not isinstance(content, str) or len(content) > 500:
        return jsonify({"error": "content is required (max 500 chars)"}), 400

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO posts (username, content) VALUES (?, ?)",
        (g.current_user, content),
    )
    conn.commit()
    # Never return the raw content: escape it so any markup is inert.
    return (
        jsonify(
            {
                "id": cur.lastrowid,
                "username": g.current_user,
                "content": html.escape(content),
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# Endpoint 3b: list posts (protected) — XSS protection on output
# ---------------------------------------------------------------------------
@app.route("/api/posts", methods=["GET"])
@login_required
def list_posts():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, content, created_at FROM posts ORDER BY id DESC"
    ).fetchall()
    # Escape every content field before it reaches the client (XSS protection).
    payload = [
        {"id": r["id"], "username": r["username"],
         "content": html.escape(r["content"]), "created_at": r["created_at"]}
        for r in rows
    ]
    return jsonify({"posts": payload}), 200


# ---------------------------------------------------------------------------
# Endpoint 4: profile of the authenticated user (protected)
# ---------------------------------------------------------------------------
@app.route("/api/profile", methods=["GET"])
@login_required
def profile():
    return jsonify({"username": g.current_user}), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    print(f"Starting secure API on http://127.0.0.1:{port}", flush=True)
    app.run(host="127.0.0.1", port=port)
