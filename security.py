"""
security.py — central security configuration for RentManager.

Everything cross-cutting lives here so it is reviewable in one place:

  * environment / production-safety checks (fail closed on unsafe config)
  * session + cookie hardening, idle timeout, HTTPS enforcement, HSTS
  * CSRF protection (Flask-WTF) and rate limiting / abuse control (Flask-Limiter)
  * security response headers (CSP, frame, sniffing, referrer …)
  * structured security-event logging + abnormal-traffic detection
  * password hashing, signed one-time tokens
  * generic error handlers that never leak internals

Nothing in here imports ``app`` or ``models`` at import time (no cycles).
"""
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from urllib.parse import urlparse

from flask import (current_app, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("security")


# ══════════════════════════════════════════════════════════════════════════════
# Environment
# ══════════════════════════════════════════════════════════════════════════════
def app_env():
    """'production' (default — secure by default), 'development' or 'test'."""
    v = (os.environ.get("APP_ENV") or os.environ.get("FLASK_ENV") or "production")
    v = v.strip().lower()
    return {"dev": "development", "develop": "development", "testing": "test"}.get(v, v)


def is_production():
    return app_env() not in ("development", "test")


def is_development():
    return app_env() == "development"


def is_test():
    return app_env() == "test"


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


# Secrets that must never be accepted as a real SECRET_KEY.
_WEAK_SECRETS = {
    "", "dev", "secret", "changeme", "change-me", "development", "test",
    "change-this-to-a-random-32-char-string", "any-random-string-xyz123abc",
    "your-secret-key", "supersecret", "super-secret", "yoursecretkey",
}


def load_secret_key():
    """SECRET_KEY from the environment.

    Production: MUST be set, ≥ 32 chars and not a known placeholder — otherwise
    we refuse to start (fail closed). A random per-process key would silently
    break sessions across gunicorn workers and restarts.
    Development/test: an ephemeral random key is fine.
    """
    key = os.environ.get("SECRET_KEY", "").strip()
    if is_production():
        if key.lower() in _WEAK_SECRETS or len(key) < 32:
            raise RuntimeError(
                "SECRET_KEY is missing, too short (<32 chars) or a known placeholder. "
                "Generate one with:  python -c \"import secrets; print(secrets.token_urlsafe(48))\"  "
                "and set it as an environment variable. Refusing to start in production without it.")
        return key
    if key and key.lower() not in _WEAK_SECRETS and len(key) >= 16:
        return key
    logger.warning("SECRET_KEY not set — using an ephemeral random key (development only).")
    return secrets.token_urlsafe(48)


# ══════════════════════════════════════════════════════════════════════════════
# Structured security logging
# ══════════════════════════════════════════════════════════════════════════════
def mask_phone(p):
    p = re.sub(r"\D", "", str(p or ""))
    return ("*" * max(0, len(p) - 4)) + p[-4:] if p else "-"


def client_ip():
    try:
        return request.remote_addr or "-"
    except RuntimeError:                       # outside a request
        return "-"


def security_log(event, level="info", **fields):
    """Emit one JSON line: ``SECURITY {"event": "...", "ip": "...", ...}``.

    JSON encoding neutralises newline/log-injection; values are truncated.
    Never pass passwords, tokens, cookies or full OCR text here.
    """
    rec = {"event": event, "ip": client_ip(), "rid": getattr(g, "request_id", "-")}
    try:
        rec["path"] = request.path
        rec["method"] = request.method
        oid = session.get("owner_id")
        if oid:
            rec["uid"] = oid
    except RuntimeError:
        pass
    for k, v in fields.items():
        rec[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:200]
    security_logger.log(getattr(logging, level.upper(), logging.INFO),
                        "SECURITY %s", json.dumps(rec, ensure_ascii=True, default=str))


# ══════════════════════════════════════════════════════════════════════════════
# Passwords, tokens
# ══════════════════════════════════════════════════════════════════════════════
_HASH_METHOD = "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256:600000"


def hash_password(password):
    return generate_password_hash(password, method=_HASH_METHOD)


def verify_password(stored_hash, password):
    try:
        return bool(stored_hash) and check_password_hash(stored_hash, password)
    except Exception:                          # malformed hash → treat as mismatch
        return False


def password_needs_rehash(stored_hash):
    return _HASH_METHOD == "scrypt" and not (stored_hash or "").startswith("scrypt:")


# Verified against when the username does not exist, so unknown-user and
# wrong-password responses take the same time (no user enumeration by timing).
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def burn_password_check(password):
    check_password_hash(_DUMMY_HASH, password or "")


# ══════════════════════════════════════════════════════════════════════════════
# Security question — used instead of email for account recovery
# ══════════════════════════════════════════════════════════════════════════════
SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your first school?",
    "What is your favourite childhood nickname?",
]


def _normalize_answer(answer):
    """Case/whitespace-insensitive so a genuine answer typed differently still matches."""
    return re.sub(r"\s+", " ", (answer or "").strip().lower())


def hash_security_answer(answer):
    return hash_password(_normalize_answer(answer))


def verify_security_answer(stored_hash, answer):
    try:
        return bool(stored_hash) and check_password_hash(stored_hash, _normalize_answer(answer))
    except Exception:                          # malformed hash → treat as mismatch
        return False


_DUMMY_ANSWER_HASH = hash_security_answer(secrets.token_hex(16))


def burn_security_answer_check(answer):
    """Equalises timing whether or not the account/question exists."""
    check_password_hash(_DUMMY_ANSWER_HASH, _normalize_answer(answer))


def dummy_security_question(username):
    """A question that's always the same for a given (unknown) username, so the
    forgot-password page looks identical whether or not the account exists."""
    idx = int(hashlib.sha256((username or "").encode()).hexdigest(), 16) % len(SECURITY_QUESTIONS)
    return SECURITY_QUESTIONS[idx]


def _serializer(purpose):
    return URLSafeTimedSerializer(current_app.secret_key, salt=f"rentmanager:{purpose}")


def make_token(purpose, payload):
    return _serializer(purpose).dumps(payload)


def read_token(purpose, token, max_age):
    """Return the payload, or ``None`` if invalid/expired/tampered."""
    try:
        return _serializer(purpose).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None
    except Exception:
        return None


RESET_TOKEN_MAX_AGE = 60 * 60            # 1 hour — binds forgot-password's step 1 to step 2


# ══════════════════════════════════════════════════════════════════════════════
# Abnormal-traffic detection (per process, in memory)
# ══════════════════════════════════════════════════════════════════════════════
class TrafficMonitor:
    """Flags IPs that produce bursts of 4xx responses (scanners, brute force)."""

    def __init__(self, window=60, threshold=30, cooldown=300, max_ips=5000):
        self.window, self.threshold, self.cooldown, self.max_ips = window, threshold, cooldown, max_ips
        self._hits = defaultdict(deque)
        self._alerted = {}
        self._lock = threading.Lock()

    def record(self, ip, status, now=None):
        """Record a response; return the hit count when an alert should fire."""
        if status < 400:
            return 0
        now = time.time() if now is None else now
        with self._lock:
            dq = self._hits[ip]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(self._hits) > self.max_ips:              # bound memory
                for k in list(self._hits)[: self.max_ips // 10]:
                    self._hits.pop(k, None)
                    self._alerted.pop(k, None)
            last = self._alerted.get(ip)
            if len(dq) >= self.threshold and (last is None or now - last > self.cooldown):
                self._alerted[ip] = now
                return len(dq)
        return 0


traffic_monitor = TrafficMonitor()

_PROBE_RE = re.compile(
    r"(?:^|/)(?:\.env|\.git|\.aws|wp-admin|wp-login|xmlrpc\.php|phpmyadmin|"
    r"cgi-bin|\.DS_Store|vendor/phpunit|actuator|server-status|id_rsa)"
    r"|\.\./|%2e%2e|\.(?:php|asp|aspx|jsp|bak|sql|sqlite|db)$", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════════════
# Rate limiting (Flask-Limiter)
# ══════════════════════════════════════════════════════════════════════════════
def user_or_ip():
    """Rate-limit key: the signed-in account if any, else the client IP."""
    oid = session.get("owner_id")
    return f"u:{oid}" if oid else f"ip:{get_remote_address()}"


def form_field_key(field):
    """Key by a submitted form field (e.g. email) to stop distributed floods
    against one victim regardless of source IP."""
    def _key():
        val = (request.form.get(field) or "").strip().lower()
        return f"{field}:{hashlib.sha256(val.encode()).hexdigest()[:16]}"
    return _key


limiter = Limiter(key_func=user_or_ip, headers_enabled=True)

# Central place for all abuse limits — tweak here, not scattered in routes.
LIMITS = {
    "login":        "10 per minute;40 per hour",
    "signup":       "5 per hour;15 per day",
    "email_flow":   "5 per hour;15 per day",      # forgot-password (per IP)
    "ocr":          "10 per minute;100 per hour", # paid third-party OCR call
    "reminder":     "20 per hour;60 per day",     # WhatsApp/SMS cost money & annoy tenants
    "excel_import": "10 per hour",
    "excel_export": "20 per hour",
    "api":          "60 per minute",
    "files":        "300 per minute",
    "danger":       "5 per hour",                 # delete-all-data / user admin
    "default":      "300 per minute;3000 per hour",
}

# Per-tenant cooldown (seconds) between manual reminders + per-account daily cap
REMINDER_COOLDOWN_SECONDS = 10 * 60
REMINDER_DAILY_CAP = 60

# Account lockout after repeated bad passwords (temporary, not permanent, so an
# attacker can't permanently lock a victim out).
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15


# ══════════════════════════════════════════════════════════════════════════════
# Headers
# ══════════════════════════════════════════════════════════════════════════════
def build_csp():
    """Content-Security-Policy.

    ``'unsafe-inline'`` is still required for script/style because the UI uses
    inline handlers and <style>/<script> blocks. Everything else is locked
    down: no plugins, no framing, no foreign form targets, same-origin XHR only,
    scripts only from ourselves + the one CDN we use.
    """
    img = ["'self'", "data:", "blob:"]
    sb = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    if sb.startswith("https://"):
        img.append(sb)
    directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com",
                      "https://cdn.jsdelivr.net"],
        "font-src": ["'self'", "data:", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
        "img-src": img,
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
    }
    if is_production():
        directives["upgrade-insecure-requests"] = []
    return "; ".join(f"{k} {' '.join(v)}".strip() for k, v in directives.items())


# ══════════════════════════════════════════════════════════════════════════════
# Redirect safety
# ══════════════════════════════════════════════════════════════════════════════
def safe_back(default_endpoint, **values):
    """Redirect target = same-site Referer path, otherwise ``default_endpoint``.

    Prevents open redirects via a forged Referer header.
    """
    ref = request.referrer
    if ref:
        p = urlparse(ref)
        if p.netloc == request.host and p.scheme in ("http", "https") and p.path.startswith("/") \
                and not p.path.startswith("//"):
            return p.path + (f"?{p.query}" if p.query else "")
    return url_for(default_endpoint, **values)


def honeypot_tripped():
    """Bots fill every field. Humans never see the hidden 'website' input."""
    return bool((request.form.get("website") or "").strip())


# ══════════════════════════════════════════════════════════════════════════════
# Wire everything into the Flask app
# ══════════════════════════════════════════════════════════════════════════════
csrf = CSRFProtect()


def configure_app(app):
    env = app_env()
    prod = is_production()

    # ── Core config ───────────────────────────────────────────────────────────
    app.secret_key = load_secret_key()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,                    # JS can't read the cookie
        SESSION_COOKIE_SAMESITE="Lax",                   # blocks cross-site POST cookies
        SESSION_COOKIE_SECURE=prod and env_bool("SESSION_COOKIE_SECURE", True),
        SESSION_COOKIE_NAME="rm_session",
        PERMANENT_SESSION_LIFETIME=env_int("SESSION_LIFETIME_HOURS", 8) * 3600,
        SESSION_REFRESH_EACH_REQUEST=False,              # absolute lifetime, not sliding
        MAX_CONTENT_LENGTH=env_int("MAX_UPLOAD_MB", 16) * 1024 * 1024,
        JSON_SORT_KEYS=False,
        WTF_CSRF_TIME_LIMIT=None,                        # token lives as long as the session
        WTF_CSRF_SSL_STRICT=prod,                        # HTTPS: require same-origin Referer
        RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI") or "memory://",
        RATELIMIT_STRATEGY="moving-window",
        RATELIMIT_DEFAULT=LIMITS["default"],
        RATELIMIT_HEADERS_ENABLED=True,
        RATELIMIT_ENABLED=env_bool("RATELIMIT_ENABLED", True),
        SESSION_IDLE_MINUTES=env_int("SESSION_IDLE_MINUTES", 60),
        FORCE_HTTPS=prod and env_bool("FORCE_HTTPS", True),
        TESTING=is_test(),
    )
    if env == "development":
        app.config["TEMPLATES_AUTO_RELOAD"] = True

    # ── Reverse-proxy awareness (Render/Heroku/nginx) ─────────────────────────
    # Needed for: the real client IP (rate limits, logs) and request.is_secure
    # (HTTPS redirect, Secure cookies). Only trust as many proxy hops as exist.
    hops = env_int("TRUSTED_PROXIES", 1 if prod else 0)
    if hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    # ── CSRF + rate limits ────────────────────────────────────────────────────
    csrf.init_app(app)
    limiter.init_app(app)

    @limiter.request_filter
    def _exempt():
        return request.endpoint in ("static", "health")

    _register_hooks(app)
    _register_error_handlers(app)
    _log_startup_warnings(app)


def _log_startup_warnings(app):
    if not is_production():
        return
    if (os.environ.get("RATELIMIT_STORAGE_URI") or "memory://").startswith("memory://"):
        logger.warning("Rate limits use per-process memory. With several gunicorn workers the "
                       "effective limit is multiplied — set RATELIMIT_STORAGE_URI=redis://… "
                       "for shared, accurate limits. (Account lockout is DB-backed and unaffected.)")
    if str(app.config["SQLALCHEMY_DATABASE_URI"]).startswith("sqlite"):
        logger.warning("Running production on SQLite. Data may be lost on redeploy and the "
                       "file offers no network access control — use PostgreSQL (DATABASE_URL).")


# ── request/response hooks ────────────────────────────────────────────────────
def _register_hooks(app):

    @app.before_request
    def _request_id_and_probes():
        rid = request.headers.get("X-Request-ID", "")
        g.request_id = rid if re.fullmatch(r"[A-Za-z0-9\-]{8,64}", rid) else uuid.uuid4().hex[:16]
        g.started = time.time()
        if _PROBE_RE.search(request.path):
            security_log("scanner_probe", level="warning")

    @app.before_request
    def _enforce_https():
        if not app.config.get("FORCE_HTTPS"):
            return None
        if request.is_secure or request.endpoint == "health":
            return None
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=308)                   # 308 keeps method + body

    @app.before_request
    def _session_idle_timeout():
        """Sign the user out after inactivity (in addition to the absolute lifetime)."""
        if "owner_id" not in session:
            return None
        now = int(time.time())
        last = session.get("last_seen", now)
        idle = app.config["SESSION_IDLE_MINUTES"] * 60
        if now - last > idle:
            security_log("session_idle_timeout", uid=session.get("owner_id"))
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify(error="session_expired"), 401
            flash("You were signed out after a period of inactivity.", "info")
            return redirect(url_for("login"))
        if now - last > 60:                              # avoid re-signing cookie every hit
            session["last_seen"] = now
        return None

    @app.after_request
    def _security_headers(resp):
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
        h.setdefault("Content-Security-Policy", build_csp())
        if request.is_secure or is_production():
            h.setdefault("Strict-Transport-Security", "max-age=31536000")
        # The password-reset URL carries a secret token: never leak it via Referer.
        if request.endpoint == "reset_password":
            h["Referrer-Policy"] = "no-referrer"
        h["X-Request-ID"] = getattr(g, "request_id", "-")
        return resp

    @app.after_request
    def _monitor(resp):
        ip = client_ip()
        hits = traffic_monitor.record(ip, resp.status_code)
        if hits:
            security_log("suspicious_traffic", level="warning", hits=hits,
                         window_s=traffic_monitor.window, last_status=resp.status_code)
        if resp.status_code >= 500:
            security_log("server_error", level="error", status=resp.status_code)
        return resp

    @app.context_processor
    def _security_context():
        return {"signup_open": signup_mode() != "closed"}


# ── error handlers ────────────────────────────────────────────────────────────
_ERROR_TEXT = {
    400: ("Bad request", "The request could not be processed."),
    401: ("Sign in required", "Please sign in to continue."),
    403: ("Not allowed", "You don't have permission to do that."),
    404: ("Not found", "We couldn't find that page."),
    405: ("Method not allowed", "That action isn't supported here."),
    413: ("File too large", "The upload is larger than the allowed size."),
    429: ("Too many requests", "You're doing that too often. Please wait a bit and try again."),
    500: ("Something went wrong", "An unexpected error occurred. It has been logged."),
}


def _render_error(status, message=None):
    title, default_msg = _ERROR_TEXT.get(status, ("Error", "Something went wrong."))
    if request.path.startswith("/api/"):
        return jsonify(error=title.lower().replace(" ", "_"), message=message or default_msg,
                       request_id=getattr(g, "request_id", "-")), status
    return render_template("error.html", status=status, title=title,
                           message=message or default_msg,
                           request_id=getattr(g, "request_id", "-")), status


def _register_error_handlers(app):
    from models import db  # local import: avoid cycle at module import time

    @app.errorhandler(CSRFError)
    def _csrf_error(e):
        security_log("csrf_failure", level="warning", reason=e.description,
                     origin=request.headers.get("Origin", "-"))
        return _render_error(400, "Your form session expired or was invalid. "
                                  "Please reload the page and try again.")

    @app.errorhandler(HTTPException)
    def _http_error(e):
        code = e.code or 500
        if code == 429:
            security_log("rate_limited", level="warning", limit=str(getattr(e, "description", "")))
        elif code in (403, 405, 413):
            security_log("request_rejected", level="warning", status=code)
        return _render_error(code)

    @app.errorhandler(Exception)
    def _unhandled(e):
        try:
            db.session.rollback()
        except Exception:                                # noqa: BLE001
            pass
        app.logger.exception("Unhandled exception rid=%s", getattr(g, "request_id", "-"))
        return _render_error(500)


# ══════════════════════════════════════════════════════════════════════════════
# Sign-up policy
# ══════════════════════════════════════════════════════════════════════════════
def signup_mode():
    """'open' | 'invite' | 'closed'.

    Default is *closed* in production. Every account shares the deployment's
    WhatsApp/SMS credentials, so open self-registration lets any stranger send
    messages from your business number. Opt in explicitly with SIGNUP_MODE.
    """
    mode = (os.environ.get("SIGNUP_MODE") or "").strip().lower()
    if mode in ("open", "invite", "closed"):
        return mode
    return "closed" if is_production() else "open"
