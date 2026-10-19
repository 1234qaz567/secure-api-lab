import os
import sqlite3
from datetime import timedelta

import bcrypt
from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from markupsafe import escape

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-only-change-me")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
jwt = JWTManager(app)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row      # 让 row 支持 r["username"] 这种访问
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- 1. 登录 ----------
@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"msg": "Invalid credentials"}), 401

    db = get_db()
    row = db.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    password_bytes = password.encode("utf-8")
    if row is None or not bcrypt.checkpw(password_bytes, row["password_hash"]):
        return jsonify({"msg": "Invalid credentials"}), 401

    token = create_access_token(identity=str(row["id"]))
    return jsonify({"token": token})


# ---------- 2. 受保护的数据接口 ----------
@app.route("/api/data")
@jwt_required()
def get_data():
    db = get_db()
    rows = db.execute("SELECT id, username FROM users").fetchall()
    return jsonify([
        {"id": r["id"], "username": str(escape(r["username"]))}
        for r in rows
    ])


# ---------- 3. 自选端点：创建笔记 ----------
@app.route("/api/notes", methods=["POST"])
@jwt_required()
def create_note():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    safe_content = str(escape(content))

    db = get_db()
    db.execute("INSERT INTO notes (content) VALUES (?)", (safe_content,))
    db.commit()
    return jsonify({"msg": "created"}), 201


if __name__ == "__main__":
    app.run(debug=True)