from datetime import datetime, timedelta, timezone
import secrets
import sqlite3

import bcrypt
import jwt
import pytest

from secure_api import TOKEN_AUDIENCE, TOKEN_ISSUER, create_app, initialize_database


@pytest.fixture()
def api(tmp_path):
    database = str(tmp_path / "test.sqlite3")
    password = secrets.token_urlsafe(18)
    secret = secrets.token_urlsafe(40)
    initialize_database(database, "cheng", password)
    initialize_database(database, "other", secrets.token_urlsafe(18))
    app = create_app({"TESTING": True, "DATABASE": database, "JWT_SECRET": secret})
    return app.test_client(), secret, database, password


def token(api):
    client, _, _, password = api
    response = client.post("/auth/login", json={"login": "cheng", "password": password})
    assert response.status_code == 200
    return response.json["access_token"]


def authorization(api):
    return {"Authorization": f"Bearer {token(api)}"}


@pytest.mark.parametrize("method", ["get", "post"])
def test_protected_endpoints_require_token(api, method):
    assert getattr(api[0], method)("/api/data").status_code == 401


@pytest.mark.parametrize("username", ["cheng' OR '1'='1' --", "' OR 1=1 --", "missing"])
def test_login_sql_injection_cannot_bypass_authentication(api, username):
    response = api[0].post("/auth/login", json={"login": username, "password": api[3]})
    assert response.status_code == 401


def test_password_is_salted_bcrypt_hash(api):
    with sqlite3.connect(api[2]) as db:
        value = db.execute("SELECT password_hash FROM users WHERE login = ?", ("cheng",)).fetchone()[0]
    assert value.startswith("$2b$12$")
    assert value != api[3]
    assert bcrypt.checkpw(api[3].encode(), value.encode())


def test_login_claims_and_lifetime(api):
    claims = jwt.decode(token(api), api[1], algorithms=["HS256"],
                        issuer=TOKEN_ISSUER, audience=TOKEN_AUDIENCE)
    assert claims["sub"] == "1"
    assert claims["exp"] - claims["iat"] == 1800


@pytest.mark.parametrize("case", ["expired", "unsigned", "wrong_signature", "missing_exp", "wrong_audience"])
def test_invalid_tokens_are_rejected(api, case):
    now = datetime.now(timezone.utc)
    claims = {"sub": "1", "iat": now, "exp": now + timedelta(minutes=30),
              "iss": TOKEN_ISSUER, "aud": TOKEN_AUDIENCE}
    key = api[1]
    algorithm = "HS256"
    if case == "expired":
        claims["iat"] = now - timedelta(hours=2)
        claims["exp"] = now - timedelta(hours=1)
    elif case == "unsigned":
        key, algorithm = "", "none"
    elif case == "wrong_signature":
        key = secrets.token_urlsafe(40)
    elif case == "missing_exp":
        del claims["exp"]
    elif case == "wrong_audience":
        claims["aud"] = "another-api"
    value = jwt.encode(claims, key, algorithm=algorithm)
    assert api[0].get("/api/data", headers={"Authorization": f"Bearer {value}"}).status_code == 401


def test_xss_is_escaped_in_create_and_read_responses(api):
    headers = authorization(api)
    value = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    response = api[0].post("/api/data", json={"content": value}, headers=headers)
    assert response.status_code == 201
    assert "<script>" not in response.json["content"]
    assert "&lt;script&gt;" in response.json["content"]
    read = api[0].get("/api/data", headers=headers)
    assert read.json["notes"][0]["content"] == response.json["content"]
    assert read.content_type == "application/json"
    assert read.headers["X-Content-Type-Options"] == "nosniff"


def test_notes_sql_injection_is_stored_as_data(api):
    headers = authorization(api)
    value = "'); DROP TABLE users; --"
    assert api[0].post("/api/data", json={"content": value}, headers=headers).status_code == 201
    with sqlite3.connect(api[2]) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
        assert db.execute("SELECT content FROM notes").fetchone()[0] == value


def test_user_cannot_read_another_users_notes(api):
    with sqlite3.connect(api[2]) as db:
        db.execute("INSERT INTO notes(owner_id, content) VALUES (?, ?)", (2, "other user's note"))
    response = api[0].get("/api/data?owner_id=2", headers=authorization(api))
    assert response.json == {"notes": []}


@pytest.mark.parametrize("body", [{}, {"content": 17}, {"content": ""}, {"content": "x" * 2001}])
def test_invalid_note_input_is_rejected(api, body):
    assert api[0].post("/api/data", json=body, headers=authorization(api)).status_code == 400


def test_short_signing_key_fails_at_startup():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        create_app({"JWT_SECRET": "short"})
