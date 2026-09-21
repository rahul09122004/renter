"""Authentication: hashing, lockout, sessions, email verification, password reset."""
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

import pytest

from conftest import *  # noqa
from conftest import flask_app, get_token
import security as sec
from models import Admin, db, unscoped
from validators import check_password_strength

NEW_PW = "Another-Long-Passphrase-42"


def _admin(username):
    return unscoped(Admin.query).filter_by(username=username).first()


# ── passwords ────────────────────────────────────────────────────────────────
def test_passwords_are_hashed_with_scrypt_and_never_stored_plain():
    _, u = make_user()
    with flask_app.app_context():
        h = _admin(u).password_hash
    assert h.startswith("scrypt:") and PASSWORD not in h


@pytest.mark.parametrize("pw", ["short", "password123", "aaaaaaaaaaaa", "1234567890", "x" * 129])
def test_weak_passwords_rejected(pw):
    assert check_password_strength(pw)


def test_password_must_not_contain_username():
    assert check_password_strength("ramesh-kumar-2024!", username="ramesh-kumar")
    assert check_password_strength(PASSWORD, username="someone") is None


def test_default_admin_credentials_do_not_work(client):
    assert login(client, "admin", "admin123").status_code == 401
    assert login(client, "admin", "password").status_code == 401


def test_signup_rejects_weak_password_and_bad_username(client):
    for pw, un in (("password123", unique()), ("short1", unique()), (PASSWORD, "Bad Name!"), (PASSWORD, "x'); DROP")):
        r = post(client, "/signup", {"username": un, "password": pw, "confirm_password": pw,
                                     "email": f"{unique()}@t.com"})
        assert r.status_code == 400


# ── login, lockout, enumeration ──────────────────────────────────────────────
def test_unknown_user_and_wrong_password_get_identical_response(client):
    _, u = make_user()
    a = login(client, u, "wrong-password-1")
    b = login(client, "no-such-user-xyz", "wrong-password-1")
    assert a.status_code == b.status_code == 401
    assert re.search(r"Invalid credentials", a.get_data(as_text=True))
    assert re.search(r"Invalid credentials", b.get_data(as_text=True))


def test_account_locks_after_repeated_failures_then_recovers(client):
    _, u = make_user()
    for i in range(sec.MAX_FAILED_LOGINS):
        assert login(client, u, f"wrong-pass-{i}").status_code == 401
    assert login(client, u, PASSWORD).status_code == 401          # correct password, but locked
    with flask_app.app_context():
        a = _admin(u)
        assert a.locked_until and a.locked_until > datetime.utcnow()
        a.locked_until = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert login(client, u, PASSWORD).status_code == 302          # lock expired


def test_successful_login_resets_failure_counter(client):
    _, u = make_user()
    for i in range(3):
        login(client, u, f"nope-nope-{i}")
    assert login(client, u, PASSWORD).status_code == 302
    with flask_app.app_context():
        assert _admin(u).failed_logins == 0


def test_login_is_case_insensitive_on_username(client):
    _, u = make_user()
    assert login(client, u.upper()).status_code == 302


def test_honeypot_blocks_bots_even_with_valid_credentials(client):
    _, u = make_user()
    r = post(client, "/login", {"username": u, "password": PASSWORD, "website": "http://spam.example"})
    assert r.status_code == 401
    assert client.get("/renters").status_code == 302


def test_honeypot_blocks_signup_bots(client):
    u = unique("bot")
    post(client, "/signup", {"username": u, "password": PASSWORD, "confirm_password": PASSWORD,
                             "email": f"{u}@t.com", "website": "x"})
    with flask_app.app_context():
        assert _admin(u) is None


# ── sessions ─────────────────────────────────────────────────────────────────
def test_session_cookie_flags(client):
    _, u = make_user()
    r = login(client, u)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_logout_requires_post_and_csrf(client):
    c, _ = logged_in_client()
    assert c.get("/logout").status_code == 405                    # no CSRF-able logout link
    assert c.post("/logout").status_code == 400                   # missing token
    assert c.get("/renters").status_code == 200                   # still signed in
    assert post(c, "/logout").status_code == 302
    assert c.get("/renters").status_code == 302


def test_password_change_revokes_other_sessions_but_keeps_current():
    c1, u = logged_in_client()
    c2 = flask_app.test_client()
    assert login(c2, u).status_code == 302
    r = post(c1, "/change-password", {"current_password": PASSWORD, "new_password": NEW_PW,
                                      "confirm_password": NEW_PW})
    assert r.status_code == 302
    assert c1.get("/renters").status_code == 200
    assert c2.get("/renters").status_code == 302                  # stolen/other session is dead
    assert login(flask_app.test_client(), u, NEW_PW).status_code == 302


def test_change_password_requires_current_password_and_policy():
    c, u = logged_in_client()
    assert "incorrect" in post(c, "/change-password", {"current_password": "bad", "new_password": NEW_PW,
                               "confirm_password": NEW_PW}, follow_redirects=True).get_data(as_text=True)
    r = post(c, "/change-password", {"current_password": PASSWORD, "new_password": "password123",
                                     "confirm_password": "password123"})
    assert r.status_code == 200 and b"too common" in r.data


def test_disabled_account_session_stops_working_immediately():
    c, u = logged_in_client()
    assert c.get("/renters").status_code == 200
    with flask_app.app_context():
        _admin(u).is_active = False
        db.session.commit()
    assert c.get("/renters").status_code == 302


def test_idle_timeout_signs_user_out():
    c, _ = logged_in_client()
    with c.session_transaction() as s:
        s["last_seen"] = 1                                        # ages ago
    r = c.get("/renters")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    assert c.get("/renters").status_code == 302


def test_super_admin_role_is_checked_against_db_not_cookie():
    c, u = logged_in_client(role="superadmin")
    assert c.get("/users").status_code == 200
    with flask_app.app_context():
        _admin(u).role = "owner"                                  # demoted
        db.session.commit()
    r = c.get("/users")
    assert r.status_code == 302                                   # cookie still says superadmin


def test_regular_user_cannot_use_admin_endpoints():
    c, _ = logged_in_client()
    other, ou = make_user()
    assert c.get("/users").status_code == 302
    assert post(c, f"/users/delete/{other}", {"confirm_username": ou}).status_code == 302
    assert post(c, f"/users/reset-password/{other}", {"new_password": NEW_PW}).status_code == 302
    with flask_app.app_context():
        assert _admin(ou) is not None


def test_admin_created_users_must_change_temp_password():
    c, _ = logged_in_client(role="superadmin")
    u = unique("temp")
    r = post(c, "/users/create", {"username": u, "password": "Temporary-Pass-77", "email": f"{u}@t.com",
                                  "role": "owner"})
    assert r.status_code == 302
    c2 = flask_app.test_client()
    assert login(c2, u, "Temporary-Pass-77").status_code == 302
    r = c2.get("/renters")
    assert r.status_code == 302 and r.headers["Location"].endswith("/change-password")
    assert post(c2, "/change-password", {"current_password": "Temporary-Pass-77", "new_password": NEW_PW,
                                         "confirm_password": NEW_PW}).status_code == 302
    assert c2.get("/renters").status_code == 200


def test_admin_cannot_create_weak_or_invalid_role_user():
    c, _ = logged_in_client(role="superadmin")
    u = unique("weak")
    post(c, "/users/create", {"username": u, "password": "abc", "role": "owner"})
    post(c, "/users/create", {"username": unique("r"), "password": PASSWORD, "role": "god"})
    with flask_app.app_context():
        assert _admin(u) is None


def test_username_cannot_be_changed_to_script_breaking_string():
    c, u = logged_in_client()
    r = post(c, "/change-username", {"new_username": "x');alert(1);//", "confirm_password_username": PASSWORD})
    assert r.status_code == 302
    with flask_app.app_context():
        assert _admin(u) is not None                              # unchanged


# ── sign-up policy ───────────────────────────────────────────────────────────
def test_signup_closed_returns_404_and_hides_link(client, monkeypatch):
    monkeypatch.setenv("SIGNUP_MODE", "closed")
    assert client.get("/signup").status_code == 404
    assert b"Create an account" not in client.get("/login").data


def test_signup_invite_mode_requires_code(client, monkeypatch):
    monkeypatch.setenv("SIGNUP_MODE", "invite")
    monkeypatch.setenv("SIGNUP_INVITE_CODE", "letmein-please-42")
    u = unique("inv")
    base = {"username": u, "password": PASSWORD, "confirm_password": PASSWORD, "email": f"{u}@t.com"}
    assert post(client, "/signup", {**base, "invite_code": "wrong"}).status_code == 400
    assert post(client, "/signup", {**base, "invite_code": "letmein-please-42"}).status_code == 302


def test_signup_default_is_closed_in_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SIGNUP_MODE", raising=False)
    assert sec.signup_mode() == "closed"
    monkeypatch.setenv("APP_ENV", "development")
    assert sec.signup_mode() == "open"


# ── email verification ───────────────────────────────────────────────────────
def _link_path(body, marker):
    m = re.search(r"https?://\S+/" + marker + r"/\S+", body)
    assert m, body
    return urlparse(m.group(0)).path


def test_email_verification_required_then_link_activates_account(client, monkeypatch):
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
    u = unique("nv")
    em = f"{u}@example.com"
    r = post(client, "/signup", {"username": u, "email": em, "password": PASSWORD, "confirm_password": PASSWORD})
    assert r.status_code == 200 and b"Check your email" in r.data
    assert login(client, u).status_code == 403                    # cannot sign in yet
    outbox = flask_app.extensions["outbox"]
    assert len(outbox) == 1 and outbox[0]["to"] == em
    path = _link_path(outbox[0]["body"], "verify-email")
    assert client.get(path).status_code == 302
    assert login(client, u).status_code == 302


def test_verification_link_tampered_or_expired_is_rejected(client, monkeypatch):
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
    u = unique("nv")
    post(client, "/signup", {"username": u, "email": f"{u}@example.com", "password": PASSWORD,
                             "confirm_password": PASSWORD})
    path = _link_path(flask_app.extensions["outbox"][-1]["body"], "verify-email")
    assert client.get(path[:-3] + "abc").headers["Location"].endswith("/resend-verification")
    monkeypatch.setattr(sec, "VERIFY_TOKEN_MAX_AGE", -1)          # everything is "expired"
    assert client.get(path).headers["Location"].endswith("/resend-verification")
    assert login(client, u).status_code == 403


def test_duplicate_email_signup_does_not_reveal_or_create(client, monkeypatch):
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
    _, existing = make_user()
    u = unique("dup")
    r = post(client, "/signup", {"username": u, "email": f"{existing}@example.com", "password": PASSWORD,
                                 "confirm_password": PASSWORD})
    assert r.status_code == 200 and b"Check your email" in r.data
    with flask_app.app_context():
        assert _admin(u) is None


# ── password reset ───────────────────────────────────────────────────────────
def test_password_reset_full_flow_single_use_and_revokes_sessions(client):
    victim, u = logged_in_client()
    em = f"{u}@example.com"
    assert post(client, "/forgot-password", {"email": em}).status_code == 200
    out = flask_app.extensions["outbox"]
    assert len(out) == 1 and out[0]["to"] == em
    path = _link_path(out[0]["body"], "reset-password")

    assert client.get(path).status_code == 200
    weak = post(client, path, {"password": "password123", "confirm_password": "password123"})
    assert weak.status_code == 400
    mismatch = post(client, path, {"password": NEW_PW, "confirm_password": NEW_PW + "x"})
    assert mismatch.status_code == 400
    assert post(client, path, {"password": NEW_PW, "confirm_password": NEW_PW}).status_code == 302

    assert login(flask_app.test_client(), u, NEW_PW).status_code == 302
    assert login(flask_app.test_client(), u, PASSWORD).status_code == 401
    assert client.get(path).status_code == 302                    # token is single-use
    assert victim.get("/renters").status_code == 302              # attacker's live session revoked


def test_reset_token_expires(client, monkeypatch):
    _, u = make_user()
    post(client, "/forgot-password", {"email": f"{u}@example.com"})
    path = _link_path(flask_app.extensions["outbox"][-1]["body"], "reset-password")
    monkeypatch.setattr(sec, "RESET_TOKEN_MAX_AGE", -1)
    r = client.get(path)
    assert r.status_code == 302 and r.headers["Location"].endswith("/forgot-password")


def test_reset_token_for_one_user_is_useless_after_password_changed_elsewhere(client):
    _, u = make_user()
    post(client, "/forgot-password", {"email": f"{u}@example.com"})
    path = _link_path(flask_app.extensions["outbox"][-1]["body"], "reset-password")
    c, _ = flask_app.test_client(), None
    login(c, u)
    post(c, "/change-password", {"current_password": PASSWORD, "new_password": NEW_PW, "confirm_password": NEW_PW})
    assert client.get(path).status_code == 302                    # fingerprint no longer matches


def test_forgot_password_does_not_reveal_whether_email_exists(client):
    _, u = make_user()
    known = post(client, "/forgot-password", {"email": f"{u}@example.com"})
    n_after_known = len(flask_app.extensions["outbox"])
    unknown = post(client, "/forgot-password", {"email": "nobody-at-all@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert b"Check your email" in known.data and b"Check your email" in unknown.data
    assert len(flask_app.extensions["outbox"]) == n_after_known   # nothing sent for unknown


def test_forgot_password_ignores_disabled_and_unverified(client):
    _, u1 = make_user(active=False)
    _, u2 = make_user(verified=False)
    post(client, "/forgot-password", {"email": f"{u1}@example.com"})
    post(client, "/forgot-password", {"email": f"{u2}@example.com"})
    assert flask_app.extensions.get("outbox", []) == []


def test_reset_links_use_configured_public_url_not_host_header(client, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://app.example.com")
    _, u = make_user()
    evil = "http://evil.example"                                  # attacker-controlled Host header
    page = client.get("/forgot-password", base_url=evil).get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    r = client.post("/forgot-password", base_url=evil, data={"email": f"{u}@example.com", "csrf_token": token})
    assert r.status_code == 200
    body = flask_app.extensions["outbox"][-1]["body"]
    assert "https://app.example.com/reset-password/" in body and "evil.example" not in body
