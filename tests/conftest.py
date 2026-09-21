"""Shared test harness. Environment is configured BEFORE the app is imported so every
test run uses an isolated throw-away database and upload folder."""
import os
import re
import tempfile

_TMP = tempfile.mkdtemp(prefix="rm_tests_")
os.environ.update(
    APP_ENV="test",
    SECRET_KEY="test-secret-key-" + "x" * 40,
    DATABASE_URL=os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{_TMP}/test.db",
    UPLOAD_DIR=f"{_TMP}/uploads",
    SIGNUP_MODE="open",
    REQUIRE_EMAIL_VERIFICATION="false",
    ADMIN_PASSWORD="Str0ng-Initial-Admin-Pass!",
    SEED_DEMO_DATA="false",
)
os.environ.pop("SUPABASE_URL", None)
os.environ.pop("SUPABASE_KEY", None)

import pytest  # noqa: E402

from app import app as flask_app  # noqa: E402
from models import Admin, db  # noqa: E402
import security as sec  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"
_counter = {"n": 0}


@pytest.fixture(autouse=True)
def _reset_state():
    """Fresh limiter + traffic counters, limits OFF unless a test opts in."""
    sec.limiter.enabled = False
    sec.limiter.reset()
    sec.traffic_monitor._hits.clear()
    sec.traffic_monitor._alerted.clear()
    flask_app.extensions.get("outbox", []).clear()
    flask_app.config["FORCE_HTTPS"] = False
    yield
    sec.limiter.enabled = False


@pytest.fixture
def app():
    return flask_app


@pytest.fixture
def client():
    return flask_app.test_client()


def get_token(client):
    for page in ("/login", "/renters", "/change-password"):
        r = client.get(page)
        m = re.search(r'name="csrf-token" content="([^"]+)"', r.get_data(as_text=True))
        if m:
            return m.group(1)
    raise AssertionError("no CSRF token found on any page")


def post(client, path, data=None, **kw):
    """POST with a valid CSRF token (fetched from the client's own session)."""
    data = dict(data or {})
    data.setdefault("csrf_token", get_token(client))
    return client.post(path, data=data, **kw)


def unique(prefix="user"):
    _counter["n"] += 1
    return f"{prefix}{_counter['n']}{os.getpid() % 1000}"


def make_user(username=None, password=PASSWORD, email=None, role="owner",
              verified=True, active=True, must_change=False):
    username = username or unique()
    email = email or f"{username}@example.com"
    with flask_app.app_context():
        a = Admin(username=username, password_hash=sec.hash_password(password), email=email,
                  full_name=username.title(), role=role, is_active=active,
                  email_verified=verified, must_change_password=must_change, session_version=0)
        db.session.add(a)
        db.session.commit()
        return a.id, username


def login(client, username, password=PASSWORD):
    return post(client, "/login", {"username": username, "password": password})


def logged_in_client(**kw):
    c = flask_app.test_client()
    _, username = make_user(**kw)
    r = login(c, username)
    assert r.status_code == 302, r.get_data(as_text=True)[:300]
    return c, username


def add_tenant(client, name="Test Tenant", phone="919876500001", amount="12000", **extra):
    data = {"name": name, "phone": phone, "amount": amount, "due_day": "5", "unit": "Flat 1A"}
    data.update(extra)
    return post(client, "/renters/add", data, content_type="multipart/form-data")
