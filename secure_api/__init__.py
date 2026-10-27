"""Small authenticated notes API for Information Security Lab 1."""

from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import os
import sqlite3

import bcrypt
from flask import Flask, g, jsonify, request
import jwt
from markupsafe import escape

# These strings identify the issuer and audience publicly; they are not secrets.
TOKEN_ISSUER = "hdu-information-security-lab1"  # nosec B105
TOKEN_AUDIENCE = "notes-api"  # nosec B105
TOKEN_SECONDS = 1800


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.app_database)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def initialize_database(database, login, password):
    """Create a demo account, storing only a salted bcrypt hash."""
    if not login or not 12 <= len(password.encode("utf-8")) <= 72:
        raise ValueError("Use a nonempty login and a password of 12 to 72 bytes.")
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.executescript(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS notes ("
            "id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL "
            "REFERENCES users(id), content TEXT NOT NULL);"
        )
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("ascii")
        db.execute(
            "INSERT INTO users(login, password_hash) VALUES (?, ?)",
            (login, password_hash),
        )


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("LAB_DATABASE", "instance/lab1.sqlite3"),
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        raise ValueError("JWT_SECRET must contain at least 32 bytes.")

    @app.before_request
    def set_database():
        g.app_database = app.config["DATABASE"]

    @app.teardown_appcontext
    def close_database(_error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    def authenticated(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                return jsonify(error="A Bearer token is required."), 401
            token = authorization[7:].strip()
            try:
                claims = jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    issuer=TOKEN_ISSUER,
                    audience=TOKEN_AUDIENCE,
                    options={"require": ["sub", "iat", "exp", "iss", "aud"]},
                )
                user_id = int(claims["sub"])
            except (jwt.InvalidTokenError, ValueError, TypeError):
                return jsonify(error="Invalid or expired token."), 401
            if get_db().execute(
                "SELECT id FROM users WHERE id = ?", (user_id,)
            ).fetchone() is None:
                return jsonify(error="Invalid or expired token."), 401
            g.user_id = user_id
            return view(*args, **kwargs)
        return wrapped

    @app.post("/auth/login")
    def login():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="A JSON object is required."), 400
        username = body.get("login")
        password = body.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="Login and password must be strings."), 400
        password_bytes = password.encode("utf-8")
        if not username or not 1 <= len(password_bytes) <= 72:
            return jsonify(error="Invalid credentials."), 401
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE login = ?", (username,)
        ).fetchone()
        if user is None or not bcrypt.checkpw(
            password_bytes, user["password_hash"].encode("ascii")
        ):
            return jsonify(error="Invalid credentials."), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(user["id"]), "iat": now,
             "exp": now + timedelta(seconds=TOKEN_SECONDS),
             "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE},
            secret,
            algorithm="HS256",
        )
        # Bearer is the public authentication scheme, not a credential.
        return jsonify(access_token=token, token_type="Bearer", expires_in=TOKEN_SECONDS)  # nosec B106

    @app.get("/api/data")
    @authenticated
    def list_notes():
        notes = get_db().execute(
            "SELECT id, content FROM notes WHERE owner_id = ? ORDER BY id", (g.user_id,)
        ).fetchall()
        return jsonify(notes=[{"id": n["id"], "content": str(escape(n["content"]))}
                              for n in notes])

    @app.post("/api/data")
    @authenticated
    def create_note():
        body = request.get_json(silent=True)
        content = body.get("content") if isinstance(body, dict) else None
        if not isinstance(content, str) or not 1 <= len(content) <= 2000:
            return jsonify(error="Content must be a string of 1 to 2000 characters."), 400
        db = get_db()
        cursor = db.execute(
            "INSERT INTO notes(owner_id, content) VALUES (?, ?)", (g.user_id, content)
        )
        db.commit()
        return jsonify(id=cursor.lastrowid, content=str(escape(content))), 201

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Request body is too large."), 413

    return app
