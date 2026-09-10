"""
MPC_CIPHER_TERMINAL v8.0 — PostgreSQL Edition
- Admin-controlled access
- Argon2id password hashing
- Server-side sessions
- Rate limiting on login
- Force password change on first login
- Persistent data on Neon PostgreSQL (survives Render sleep)
- Server NEVER sees plaintext messages
"""

import os
import secrets
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template,
    make_response, g, redirect, url_for
)
from flask_cors import CORS
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# ---------------- Config ----------------

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

SESSION_TTL_HOURS = 24
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

INITIAL_ADMIN_USERNAME = "Mpc"
INITIAL_ADMIN_PASSWORD = "08800Mpc!"
INITIAL_ADMIN_EMAIL = "admin@mpcipher.local"

app = Flask(__name__)
CORS(app, supports_credentials=True)

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# ---------------- Database ----------------

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, sslmode="require")
        g.db.autocommit = False
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        if exc:
            db.rollback()
        db.close()

def db_execute(query, params=None, fetch=None):
    """Helper: run query, commit, optionally return rows."""
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(query, params or ())
        if fetch == "one":
            row = cur.fetchone()
            db.commit()
            return row
        if fetch == "all":
            rows = cur.fetchall()
            db.commit()
            return rows
        db.commit()
        return None
    except Exception:
        db.rollback()
        raise
    finally:
        cur.close()

def init_db():
    """Create tables if they don't exist, seed admin on first run."""
    db = psycopg2.connect(DATABASE_URL, sslmode="require")
    cur = db.cursor()
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            is_active     INTEGER NOT NULL DEFAULT 1,
            must_change   INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL,
            created_by    TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            username     TEXT NOT NULL,
            ip           TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            success      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS message_meta (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            algorithm  TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_time ON login_attempts(attempted_at);
        """)

        # Seed admin if not present
        cur.execute("SELECT id FROM users WHERE username = %s",
                    (INITIAL_ADMIN_USERNAME,))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users (username, email, password_hash, is_admin,
                                   is_active, must_change, created_at, created_by)
                VALUES (%s, %s, %s, 1, 1, 0, %s, 'system')
            """, (INITIAL_ADMIN_USERNAME, INITIAL_ADMIN_EMAIL,
                  ph.hash(INITIAL_ADMIN_PASSWORD),
                  datetime.utcnow().isoformat()))
        db.commit()
    finally:
        cur.close()
        db.close()

# ---------------- Helpers ----------------

def now_iso():
    return datetime.utcnow().isoformat()

def client_ip():
    return request.headers.get("X-Forwarded-For",
                               request.remote_addr or "unknown").split(",")[0].strip()

def recent_failed_attempts(username, ip):
    cutoff = (datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    row = db_execute("""
        SELECT COUNT(*) AS c FROM login_attempts
        WHERE success = 0 AND attempted_at > %s AND (username = %s OR ip = %s)
    """, (cutoff, username, ip), fetch="one")
    return row["c"] if row else 0

def record_attempt(username, ip, success):
    db_execute(
        "INSERT INTO login_attempts (username, ip, attempted_at, success) VALUES (%s, %s, %s, %s)",
        (username, ip, now_iso(), 1 if success else 0),
    )

def create_session(user_id):
    token = secrets.token_urlsafe(48)
    expires = (datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    db_execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (%s, %s, %s, %s)",
        (token, user_id, now_iso(), expires),
    )
    return token

def get_session_user(token):
    if not token:
        return None
    row = db_execute("""
        SELECT u.id, u.username, u.email, u.is_admin, u.is_active, u.must_change, s.expires_at
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = %s
    """, (token,), fetch="one")
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        db_execute("DELETE FROM sessions WHERE token = %s", (token,))
        return None
    if not row["is_active"]:
        return None
    return dict(row)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("mpc_session") or request.headers.get("X-MPC-Token")
        user = get_session_user(token)
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        g.user = user
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("mpc_session") or request.headers.get("X-MPC-Token")
        user = get_session_user(token)
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        if not user["is_admin"]:
            return jsonify({"error": "forbidden"}), 403
        g.user = user
        return f(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------

@app.route("/")
def home():
    token = request.cookies.get("mpc_session")
    user = get_session_user(token)
    if not user:
        return redirect(url_for("login_page"))
    if user["must_change"]:
        return redirect(url_for("change_pw_page"))
    if user["is_admin"]:
        return redirect(url_for("admin_page"))
    return render_template("index.html", username=user["username"])

@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/guide")
def guide_page():
    return render_template("guide.html")

@app.route("/change-password")
def change_pw_page():
    token = request.cookies.get("mpc_session")
    user = get_session_user(token)
    if not user:
        return redirect(url_for("login_page"))
    return render_template("change_password.html", username=user["username"],
                           forced=bool(user["must_change"]))

@app.route("/admin")
def admin_page():
    token = request.cookies.get("mpc_session")
    user = get_session_user(token)
    if not user:
        return redirect(url_for("login_page"))
    if not user["is_admin"]:
        return redirect(url_for("home"))
    return render_template("admin.html", username=user["username"])

# ---------------- Auth API ----------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    ip = client_ip()

    if recent_failed_attempts(username, ip) >= MAX_LOGIN_ATTEMPTS:
        return jsonify({"error": f"Too many attempts. Try again in {LOCKOUT_MINUTES} minutes."}), 429

    row = db_execute("SELECT * FROM users WHERE username = %s", (username,), fetch="one")

    if not row:
        try:
            ph.verify(
                "$argon2id$v=19$m=65536,t=3,p=4$"
                "AAAAAAAAAAAAAAAAAAAAAA$"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                password,
            )
        except Exception:
            pass
        record_attempt(username, ip, False)
        return jsonify({"error": "Invalid credentials"}), 401

    if not row["is_active"]:
        record_attempt(username, ip, False)
        return jsonify({"error": "Account disabled. Contact admin."}), 403

    try:
        ph.verify(row["password_hash"], password)
        if ph.check_needs_rehash(row["password_hash"]):
            db_execute("UPDATE users SET password_hash = %s WHERE id = %s",
                       (ph.hash(password), row["id"]))
    except (VerifyMismatchError, VerificationError):
        record_attempt(username, ip, False)
        return jsonify({"error": "Invalid credentials"}), 401

    record_attempt(username, ip, True)
    token = create_session(row["id"])

    resp = make_response(jsonify({
        "ok": True,
        "username": row["username"],
        "must_change": bool(row["must_change"]),
        "is_admin": bool(row["is_admin"]),
    }))
    resp.set_cookie("mpc_session", token, httponly=True, secure=True,
                    samesite="Lax", max_age=SESSION_TTL_HOURS * 3600)
    return resp

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("mpc_session")
    if token:
        db_execute("DELETE FROM sessions WHERE token = %s", (token,))
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("mpc_session")
    return resp

@app.route("/api/me")
@require_auth
def api_me():
    return jsonify({
        "username": g.user["username"],
        "email": g.user["email"],
        "is_admin": bool(g.user["is_admin"]),
        "must_change": bool(g.user["must_change"]),
    })

@app.route("/api/change-password", methods=["POST"])
@require_auth
def api_change_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current") or ""
    new = data.get("new") or ""

    if len(new) < 12:
        return jsonify({"error": "New password must be 12+ characters"}), 400

    row = db_execute("SELECT * FROM users WHERE id = %s", (g.user["id"],), fetch="one")
    try:
        ph.verify(row["password_hash"], current)
    except (VerifyMismatchError, VerificationError):
        return jsonify({"error": "Current password incorrect"}), 401

    db_execute("UPDATE users SET password_hash = %s, must_change = 0 WHERE id = %s",
               (ph.hash(new), g.user["id"]))
    return jsonify({"ok": True})

# ---------------- Admin API ----------------

@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_list_users():
    rows = db_execute("""
        SELECT id, username, email, is_admin, is_active, must_change, created_at, created_by
        FROM users ORDER BY id ASC
    """, fetch="all")
    return jsonify({"users": [dict(r) for r in rows]})

@app.route("/api/admin/create-user", methods=["POST"])
@require_admin
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be 3–32 characters"}), 400
    if "@" not in email or len(email) > 120:
        return jsonify({"error": "Invalid email"}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    try:
        db_execute("""
            INSERT INTO users (username, email, password_hash, is_admin, is_active,
                               must_change, created_at, created_by)
            VALUES (%s, %s, %s, 0, 1, 1, %s, %s)
        """, (username, email, ph.hash(password), now_iso(), g.user["username"]))
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username or email already exists"}), 409

    return jsonify({"ok": True}), 201

@app.route("/api/admin/toggle-user/<int:user_id>", methods=["POST"])
@require_admin
def admin_toggle_user(user_id):
    if user_id == g.user["id"]:
        return jsonify({"error": "Cannot disable yourself"}), 400
    row = db_execute("SELECT is_active, is_admin FROM users WHERE id = %s", (user_id,), fetch="one")
    if not row:
        return jsonify({"error": "User not found"}), 404
    if row["is_admin"]:
        return jsonify({"error": "Cannot disable another admin"}), 400
    new_state = 0 if row["is_active"] else 1
    db_execute("UPDATE users SET is_active = %s WHERE id = %s", (new_state, user_id))
    if new_state == 0:
        db_execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    return jsonify({"ok": True, "is_active": bool(new_state)})

@app.route("/api/admin/delete-user/<int:user_id>", methods=["POST"])
@require_admin
def admin_delete_user(user_id):
    if user_id == g.user["id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    row = db_execute("SELECT is_admin FROM users WHERE id = %s", (user_id,), fetch="one")
    if not row:
        return jsonify({"error": "User not found"}), 404
    if row["is_admin"]:
        return jsonify({"error": "Cannot delete another admin"}), 400
    db_execute("DELETE FROM users WHERE id = %s", (user_id,))
    return jsonify({"ok": True})

@app.route("/api/admin/reset-password/<int:user_id>", methods=["POST"])
@require_admin
def admin_reset_password(user_id):
    data = request.get_json(silent=True) or {}
    new = data.get("new") or ""
    if len(new) < 12:
        return jsonify({"error": "Password must be 12+ characters"}), 400
    row = db_execute("SELECT id FROM users WHERE id = %s", (user_id,), fetch="one")
    if not row:
        return jsonify({"error": "User not found"}), 404
    db_execute("UPDATE users SET password_hash = %s, must_change = 1 WHERE id = %s",
               (ph.hash(new), user_id))
    db_execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    return jsonify({"ok": True})

# ---------------- Message metadata ----------------

@app.route("/api/message-log", methods=["POST"])
@require_auth
def api_message_log():
    data = request.get_json(silent=True) or {}
    algorithm = (data.get("algorithm") or "AES-256-GCM")[:40]
    size = int(data.get("size") or 0)
    db_execute(
        "INSERT INTO message_meta (user_id, algorithm, size_bytes, created_at) VALUES (%s, %s, %s, %s)",
        (g.user["id"], algorithm, size, now_iso()),
    )
    return jsonify({"ok": True})

# ---------------- Startup ----------------

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
