import os
import sqlite3
import secrets
from functools import wraps
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DATABASE = os.environ.get("DATABASE_PATH", "min_rp.db")
PORT = int(os.environ.get("PORT", "10000"))

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            money INTEGER NOT NULL DEFAULT 5000,
            token TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

def current_player():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    return db().execute(
        "SELECT id, username, money FROM players WHERE token = ?", (token,)
    ).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        player = current_player()
        if player is None:
            return jsonify({"error": "Нужен вход. Передай токен в Authorization: Bearer <token>"}), 401
        request.player = player
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def index():
    return jsonify({
        "server": "MIN RP",
        "status": "online",
        "message": "Сервер работает. Это стартовый API-прототип, не 3D-игра.",
        "endpoints": ["/health", "/register", "/login", "/me", "/players", "/work"]
    })

@app.get("/health")
def health():
    return jsonify({"ok": True, "server": "MIN RP"})

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
        return jsonify({"error": "Логин: 3–20 символов, только буквы, цифры и _"}), 400
    if len(password) < 8:
        return jsonify({"error": "Пароль должен быть не короче 8 символов"}), 400

    token = secrets.token_urlsafe(32)
    try:
        conn = db()
        conn.execute(
            "INSERT INTO players (username, password_hash, money, token) VALUES (?, ?, 5000, ?)",
            (username, generate_password_hash(password), token)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Такой логин уже занят"}), 409

    return jsonify({
        "message": "Аккаунт создан",
        "username": username,
        "money": 5000,
        "token": token
    }), 201

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    conn = db()
    player = conn.execute(
        "SELECT id, username, password_hash FROM players WHERE username = ?", (username,)
    ).fetchone()
    if player is None or not check_password_hash(player["password_hash"], password):
        return jsonify({"error": "Неверный логин или пароль"}), 401

    token = secrets.token_urlsafe(32)
    conn.execute("UPDATE players SET token = ? WHERE id = ?", (token, player["id"]))
    conn.commit()
    return jsonify({"message": "Вход выполнен", "username": username, "token": token})

@app.get("/me")
@login_required
def me():
    return jsonify({
        "username": request.player["username"],
        "money": request.player["money"]
    })

@app.get("/players")
def players():
    rows = db().execute("SELECT username, money FROM players ORDER BY username LIMIT 100").fetchall()
    return jsonify({"players": [dict(row) for row in rows]})

@app.post("/work")
@login_required
def work():
    # Simple demo job: server awards a fixed amount.
    conn = db()
    conn.execute("UPDATE players SET money = money + 250 WHERE id = ?", (request.player["id"],))
    conn.commit()
    row = conn.execute("SELECT money FROM players WHERE id = ?", (request.player["id"],)).fetchone()
    return jsonify({"message": "Ты заработал 250 игровых долларов", "money": row["money"]})

@app.post("/logout")
@login_required
def logout():
    conn = db()
    conn.execute("UPDATE players SET token = NULL WHERE id = ?", (request.player["id"],))
    conn.commit()
    return jsonify({"message": "Вы вышли из аккаунта"})

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT)
else:
    init_db()
