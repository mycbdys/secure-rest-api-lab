import os
import tempfile

# Use an isolated temp database for the whole test session.
_tmp_dir = tempfile.mkdtemp(prefix="secure_api_test_")
os.environ["DB_PATH"] = os.path.join(_tmp_dir, "test.db")

import app as app_module  # noqa: E402

app_module.init_db()
app = app_module.app


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def _login():
    resp = app.test_client().post(
        "/auth/login", json={"username": "testuser", "password": "Test@1234"}
    )
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


# ---------------------------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------------------------
def test_login_success_returns_jwt():
    token = _login()
    assert isinstance(token, str) and len(token) > 20


def test_login_wrong_password_returns_401():
    resp = app.test_client().post(
        "/auth/login", json={"username": "testuser", "password": "wrongpass"}
    )
    assert resp.status_code == 401


def test_login_unknown_user_returns_401():
    resp = app.test_client().post(
        "/auth/login", json={"username": "nosuchuser", "password": "whatever"}
    )
    assert resp.status_code == 401


def test_login_missing_fields_returns_400():
    resp = app.test_client().post("/auth/login", json={})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Access control tests (Broken Access Control / Broken Authentication)
# ---------------------------------------------------------------------------
def test_data_without_token_rejected():
    resp = app.test_client().get("/api/data")
    assert resp.status_code == 401


def test_data_with_valid_token_allowed():
    resp = app.test_client().get("/api/data", headers=_auth_headers(_login()))
    assert resp.status_code == 200
    assert "data" in resp.get_json()


def test_data_with_tampered_token_rejected():
    token = _login()[:-2] + "xx"  # corrupt the signature
    resp = app.test_client().get("/api/data", headers=_auth_headers(token))
    assert resp.status_code == 401


def test_posts_without_token_rejected():
    assert app.test_client().get("/api/posts").status_code == 401
    assert app.test_client().post(
        "/api/posts", json={"content": "hi"}
    ).status_code == 401


# ---------------------------------------------------------------------------
# SQL Injection protection tests
# ---------------------------------------------------------------------------
def test_sqli_filter_is_neutralized():
    token = _login()
    # Classic tautology payload. Because the query is parameterized, this is
    # treated as a literal username and matches no row -> empty result.
    evil = "' OR '1'='1' --"
    resp = app.test_client().get(
        "/api/data?username=" + evil, headers=_auth_headers(token)
    )
    assert resp.status_code == 200
    assert resp.get_json()["data"] == []


def test_sqli_in_login_is_neutralized():
    # SQLi payload as a username must not log us in.
    resp = app.test_client().post(
        "/auth/login",
        json={"username": "' OR '1'='1' --", "password": "anything"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# XSS protection tests
# ---------------------------------------------------------------------------
def test_post_content_is_escaped_on_create():
    token = _login()
    payload = "<script>alert(1)</script>"
    resp = app.test_client().post(
        "/api/posts", json={"content": payload}, headers=_auth_headers(token)
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert "<script>" not in body["content"]
    assert "&lt;script&gt;" in body["content"]


def test_posts_list_escapes_all_content():
    token = _login()
    app.test_client().post(
        "/api/posts",
        json={"content": "<img src=x onerror=alert(1)>"},
        headers=_auth_headers(token),
    )
    resp = app.test_client().get("/api/posts", headers=_auth_headers(token))
    assert resp.status_code == 200
    for post in resp.get_json()["posts"]:
        assert "<" not in post["content"] or post["content"].startswith("&lt;")


# ---------------------------------------------------------------------------
# Profile endpoint
# ---------------------------------------------------------------------------
def test_profile_returns_current_user():
    resp = app.test_client().get("/api/profile", headers=_auth_headers(_login()))
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "testuser"
