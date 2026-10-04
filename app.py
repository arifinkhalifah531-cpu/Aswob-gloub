#!/usr/bin/env python3
import os, sqlite3, hashlib, secrets
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template, g
from werkzeug.utils import secure_filename

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "aswob.db")
UPLOAD = os.path.join(BASE, "static", "uploads")
os.makedirs(UPLOAD, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        bio TEXT DEFAULT '',
        created TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        image TEXT DEFAULT '',
        created TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS likes (
        user_id INTEGER, post_id INTEGER,
        PRIMARY KEY(user_id, post_id)
    );
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER, post_id INTEGER,
        content TEXT NOT NULL,
        created TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS follows (
        follower INTEGER, following INTEGER,
        PRIMARY KEY(follower, following)
    );
    """)
    db.commit()
    db.close()

init_db()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

TOKENS = {}

def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return None
    return TOKENS.get(auth[7:])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/api/register", methods=["POST"])
def register():
    d = request.json
    u, p = d.get("username", "").strip(), d.get("password", "")
    if not u or not p or len(p) < 4:
        return jsonify({"ok": False, "msg": "Username minimal 3, password minimal 4"}), 400
    if len(u) < 3:
        return jsonify({"ok": False, "msg": "Username minimal 3 karakter"}), 400
    db = get_db()
    try:
        cur = db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                         (u, hash_pw(p)))
        db.commit()
        uid = cur.lastrowid
        token = secrets.token_hex(16)
        TOKENS[token] = uid
        return jsonify({"ok": True, "token": token, "username": u})
    except sqlite3.IntegrityError:
        return jsonify({"ok": False, "msg": "Username sudah dipakai"}), 400

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    u, p = d.get("username", ""), d.get("password", "")
    db = get_db()
    row = db.execute("SELECT id, password FROM users WHERE username=?", (u,)).fetchone()
    if not row or row["password"] != hash_pw(p):
        return jsonify({"ok": False, "msg": "Username atau password salah"}), 401
    token = secrets.token_hex(16)
    TOKENS[token] = row["id"]
    return jsonify({"ok": True, "token": token, "username": u})

@app.route("/api/me")
def me():
    uid = current_user()
    if not uid: return jsonify({"ok": False}), 401
    db = get_db()
    u = db.execute("SELECT id, username, bio FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify(dict(u))

@app.route("/api/posts")
def posts():
    db = get_db()
    uid = current_user() or 0
    rows = db.execute("""
        SELECT p.id, p.content, p.image, p.created,
               u.username, u.id as user_id,
               (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as likes,
               (SELECT COUNT(*) FROM likes WHERE post_id=p.id AND user_id=?) as liked,
               (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comments
        FROM posts p JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 100
    """, (uid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/post", methods=["POST"])
def create_post():
    uid = current_user()
    if not uid: return jsonify({"ok": False}), 401
    content = request.form.get("content", "").strip()
    image = ""
    if "image" in request.files:
        f = request.files["image"]
        if f.filename:
            name = f"{secrets.token_hex(8)}_{secure_filename(f.filename)}"
            f.save(os.path.join(UPLOAD, name))
            image = name
    if not content and not image:
        return jsonify({"ok": False, "msg": "Kosong"}), 400
    db = get_db()
    db.execute("INSERT INTO posts (user_id, content, image) VALUES (?, ?, ?)",
               (uid, content, image))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/like/<int:pid>", methods=["POST"])
def like(pid):
    uid = current_user()
    if not uid: return jsonify({"ok": False}), 401
    db = get_db()
    row = db.execute("SELECT 1 FROM likes WHERE user_id=? AND post_id=?",
                     (uid, pid)).fetchone()
    if row:
        db.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (uid, pid))
    else:
        db.execute("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", (uid, pid))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/comment/<int:pid>", methods=["POST"])
def comment(pid):
    uid = current_user()
    if not uid: return jsonify({"ok": False}), 401
    d = request.json
    c = d.get("content", "").strip()
    if not c: return jsonify({"ok": False}), 400
    db = get_db()
    db.execute("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)",
               (uid, pid, c))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/comments/<int:pid>")
def get_comments(pid):
    db = get_db()
    rows = db.execute("""
        SELECT c.content, c.created, u.username
        FROM comments c JOIN users u ON c.user_id=u.id
        WHERE c.post_id=? ORDER BY c.id ASC
    """, (pid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/user/<username>")
def user_profile(username):
    db = get_db()
    u = db.execute("SELECT id, username, bio, created FROM users WHERE username=?",
                   (username,)).fetchone()
    if not u: return jsonify({"ok": False}), 404
    uid = current_user() or 0
    posts = db.execute("""
        SELECT p.id, p.content, p.image, p.created,
               (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as likes,
               (SELECT COUNT(*) FROM likes WHERE post_id=p.id AND user_id=?) as liked,
               (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comments
        FROM posts p WHERE user_id=? ORDER BY id DESC
    """, (uid, u["id"])).fetchall()
    return jsonify({"user": dict(u), "posts": [dict(p) for p in posts]})

@app.route("/api/bio", methods=["POST"])
def set_bio():
    uid = current_user()
    if not uid: return jsonify({"ok": False}), 401
    d = request.json
    db = get_db()
    db.execute("UPDATE users SET bio=? WHERE id=?", (d.get("bio", ""), uid))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/search")
def search():
    q = request.args.get("q", "").strip()
    if not q: return jsonify([])
    db = get_db()
    rows = db.execute("SELECT username, bio FROM users WHERE username LIKE ? LIMIT 20",
                      (f"%{q}%",)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/uploads/<name>")
def uploaded(name):
    return send_from_directory(UPLOAD, name)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
