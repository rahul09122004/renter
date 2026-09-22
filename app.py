"""
app.py — RentManager — with month-wise rent history
"""
import os, logging, re, hmac, time
from datetime import date, datetime, timedelta
from flask import (Flask, render_template, request, redirect, g, abort, Response,
                   url_for, session, flash, jsonify, send_file)
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from sqlalchemy.orm import joinedload
from models import (db, Tenant, CommonExpense, BuildingExpense,
                    ReminderLog, Admin, RentRecord, VacateSettlement,
                    RentAmountHistory, DepositPayment, init_db, get_database_url,
                    enable_owner_scope, unscoped, current_owner_id)
from whatsapp import send_rent_reminder, send_payment_confirmation
from scheduler import init_scheduler
import security as sec
import uploads
from security import LIMITS
from validators import (ValidationError, clean_text, clean_phone, clean_email, clean_username,
                        parse_money, parse_int, parse_date, parse_month_year, choice,
                        check_password_strength, excel_safe)

load_dotenv()
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    db_url = get_database_url()
    app.config["SQLALCHEMY_DATABASE_URI"]    = db_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    engine_opts = {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 5,
        "pool_recycle": 120,
        "pool_timeout": 20,
    }
    if "postgresql" in db_url:
        engine_opts["connect_args"] = {"connect_timeout": 10}
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts
    db.init_app(app)
    # Secret key, cookies, CSRF, rate limits, headers, HTTPS, error handlers …
    sec.configure_app(app)
    uploads.migrate_legacy_uploads(app)     # take old uploads out of the public /static folder
    # ── Gzip compression: typically saves 60-75% on HTML page sizes ──
    try:
        from flask_compress import Compress
        app.config["COMPRESS_ALGORITHM"] = ["gzip"]
        app.config["COMPRESS_MIN_SIZE"]  = 500   # bytes – skip tiny responses
        Compress(app)
    except ImportError:
        pass  # falls back gracefully if package not yet installed
    enable_owner_scope(app)
    init_db(app)
    # Create rent_records table if it doesn't exist yet (safe migration)
    with app.app_context():
        db.create_all()
    if not sec.is_test():
        init_scheduler(app)
    return app

app = create_app()

# ── Performance: HTTP cache headers ──────────────────────────────────────────
@app.after_request
def add_cache_headers(response):
    """Static assets are cacheable; everything authenticated is never stored."""
    endpoint = request.endpoint or ""
    if endpoint == "static":
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    elif endpoint != "serve_upload":
        # Financial data + reset tokens must not sit in browser/proxy caches
        # (back-button after logout, shared computers).
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response

PAY_METHODS   = ("cash", "upi", "upi_screenshot", "bank_transfer", "cheque", "neft", "manual")
STATUSES      = ("Paid", "Pending")
OCCUPANCY     = ("Active", "Vacated")

def _rent_form_values(t=None, rec=None):
    """Validate the fields shared by add/edit rent record. Returns a dict."""
    status = choice(request.form.get("status"), STATUSES, "Status", default="Paid")
    base = (rec.rent_amount if rec else t.amount)
    v = {"status": status,
         "rent_amount": parse_money(request.form.get("rent_amount"), "Rent amount",
                                    allow_blank=True, default=base),
         "notes": clean_text(request.form.get("notes"), "Notes", 2000, multiline=True)}
    if status == "Paid":
        v["paid_amount"] = parse_money(request.form.get("paid_amount"), "Paid amount",
                                       allow_blank=True, default=v["rent_amount"])
        v["payment_method"] = choice(request.form.get("payment_method"), PAY_METHODS,
                                     "Payment method", default="cash")
        v["transaction_id"] = clean_text(request.form.get("transaction_id"), "Transaction ID", 100)
        v["payment_date"] = parse_date(request.form.get("payment_date"), "Payment date") or date.today()
    return v

# ── Helpers ───────────────────────────────────────────────────────────────────
def save_upload(field):
    """Validate + store an uploaded file for the signed-in account.

    Returns a storage key (never a user-supplied filename) or None when no file
    was chosen. Raises ValidationError for anything unsafe.
    """
    f = request.files.get(field)
    if not f or not f.filename:
        return None
    key, _ = uploads.store_upload(app, f, session["owner_id"],
                                  kinds="image" if field == "photo" else "doc")
    return key

def flash_error(user_message, exc=None):
    """Tell the user something failed WITHOUT leaking exception text; log details."""
    if exc is not None:
        app.logger.error("%s | rid=%s | %s: %s", user_message, getattr(g, "request_id", "-"),
                         type(exc).__name__, exc, exc_info=True)
    flash(f"{user_message} (ref {getattr(g, 'request_id', '-')})", "danger")

def _valid_screenshot_key(raw, current=None):
    """The screenshot reference comes back from a hidden form field, i.e. from the
    client. Only accept keys we issued to THIS account (or the value already stored)."""
    raw = clean_text(raw, "Screenshot reference", 255)
    if not raw or raw == current:
        return current
    if uploads.key_owner(raw) == session.get("owner_id"):
        return raw
    raise ValidationError("Invalid screenshot reference.")

def send_sms(phone, message):
    api_key = os.environ.get("FAST2SMS_KEY", "").strip()
    if not api_key:
        return {"error": "FAST2SMS_KEY not set", "success": False}
    num = re.sub(r'[^0-9]', '', phone)
    if num.startswith('91') and len(num) == 12: num = num[2:]
    if len(num) != 10: return {"error": f"Invalid phone: {phone}", "success": False}
    try:
        import requests as req
        resp = req.post("https://www.fast2sms.com/dev/bulkV2",
            headers={"authorization": api_key, "Content-Type": "application/x-www-form-urlencoded"},
            data={"variables_values": message, "route": "q", "numbers": num}, timeout=15)
        result = resp.json()
        result["success"] = result.get("return") is True
        return result
    except Exception as ex:
        return {"error": str(ex), "success": False}

def _get_or_create_record(tenant_id, month, year):
    """Get existing RentRecord or create a new pending one.
    Also resets tenant.status to Pending if this is a new month (no existing record).
    """
    rec = RentRecord.query.filter_by(tenant_id=tenant_id, month=month, year=year).first()
    if not rec:
        t = Tenant.query.get(tenant_id)
        if not t: return None
        rec = RentRecord(
            tenant_id=tenant_id, tenant_name=t.name,
            month=month, year=year,
            rent_amount=t.amount, status="Pending",
            owner_id=t.owner_id,          # always inherit from the renter
        )
        db.session.add(rec)
        # Reset tenant status for the new month so tracker stays in sync
        t.status = "Pending"
        t.payment_date = None
        t.payment_method = None
        t.transaction_id = None
        t.payment_screenshot = None
        db.session.commit()
    return rec


def _safe_month_year(args, today):
    """Parse month/year query args safely and clamp invalid values."""
    try:
        sel_year = int(args.get("year", today.year))
    except (TypeError, ValueError):
        sel_year = today.year
    try:
        sel_month = int(args.get("month", today.month))
    except (TypeError, ValueError):
        sel_month = today.month
    if sel_month < 1 or sel_month > 12:
        sel_month = today.month
    # Keep year in a practical range to avoid date() exceptions
    if sel_year < 2000 or sel_year > 2100:
        sel_year = today.year
    return sel_year, sel_month

def _cycle_label(year, month):
    """Display label for a rent month, shown as the span it's collected over.

    The stored value is still a single month; rent for September is simply
    collected during October, so it reads 'Sep–Oct 2026'.
    """
    by, bm = (year + 1, 1) if month == 12 else (year, month + 1)
    start = date(year, month, 1)
    end   = date(by, bm, 1)
    if by == year:
        return f"{start.strftime('%b')}–{end.strftime('%b %Y')}"
    return f"{start.strftime('%b %Y')}–{end.strftime('%b %Y')}"

def _billed_in_label(year, month):
    by, bm = (year + 1, 1) if month == 12 else (year, month + 1)
    return date(by, bm, 1).strftime("%B %Y")

def _overdue_records(today=None):
    """Unpaid rent records that are past their due date.

    Rent for month M is collected in M+1, so a record only becomes overdue
    after the tenant's due day in the FOLLOWING month.
    """
    today = today or date.today()
    recs = (RentRecord.query
            .options(joinedload(RentRecord.tenant))
            .join(Tenant, RentRecord.tenant_id == Tenant.id)
            .filter(RentRecord.status != "Paid",
                    Tenant.occupancy_status == "Active")
            .all())
    return [r for r in recs if r.is_overdue(today)]

def _month_bounds(year, month):
    """Return [month_start, next_month_start) for efficient date filtering."""
    start = date(year, month, 1)
    end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    return start, end

# ── AUTH (multi-account) ──────────────────────────────────────────────────────
def current_user():
    """The Admin row for the signed-in account, or None.

    Re-validated against the DB on EVERY request (cached per request), so a
    disabled account, a changed password or a "sign out everywhere" takes effect
    immediately even though the session cookie itself is stateless.
    """
    if "_current_user" in g:
        return g._current_user
    admin = None
    oid = session.get("owner_id")
    if oid and session.get("admin_logged_in"):
        a = unscoped(Admin.query).filter_by(id=oid).first()
        if a is not None and a.is_active and (a.session_version or 0) == session.get("sv", 0):
            admin = a
    if admin is None and oid:
        session.clear()
    g._current_user = admin
    return admin


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if user is None:
            if request.path.startswith("/api/"):
                return jsonify(error="unauthorized"), 401
            return redirect(url_for("login"))
        if user.must_change_password and request.endpoint not in ("change_password", "logout"):
            flash("Please set a new password before continuing.", "warning")
            return redirect(url_for("change_password"))
        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # Role comes from the DB, never from the (cached) session cookie.
        if not current_user().is_superadmin():
            sec.security_log("forbidden_admin_area", level="warning")
            flash("That area is restricted to the super admin.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return login_required(decorated)


@app.context_processor
def inject_current_user():
    return {"current_user": current_user()}


@app.template_global()
def file_url(key):
    """URL for a stored upload. Files are never served from /static."""
    if not key:
        return ""
    if key.startswith("https://"):          # legacy public Supabase object URL
        return key
    if uploads.is_valid_key(key):
        return url_for("serve_upload", key=key)
    return ""


def _now():
    return datetime.utcnow()


def _start_session(admin):
    session.clear()                          # new session id → no fixation
    session.permanent = True                 # bounded by PERMANENT_SESSION_LIFETIME
    session["admin_logged_in"] = True
    session["admin_username"]  = admin.username
    session["owner_id"]        = admin.id
    session["is_superadmin"]   = admin.is_superadmin()
    session["sv"]              = admin.session_version or 0
    session["last_seen"]       = int(time.time())
    admin.last_login = _now()
    admin.failed_logins = 0
    admin.locked_until = None
    db.session.commit()
    g._current_user = admin


def _set_password(admin, new_password, must_change=False):
    admin.password_hash = sec.hash_password(new_password)
    admin.must_change_password = must_change
    admin.password_changed_at = _now()
    admin.session_version = (admin.session_version or 0) + 1   # revoke every other session
    admin.failed_logins = 0
    admin.locked_until = None


@app.route("/login", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["login"], methods=["POST"], key_func=get_remote_address)
def login():
    if request.method == "GET":
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    generic = "Invalid credentials, or the account is temporarily locked. Try again shortly."
    if sec.honeypot_tripped():
        sec.security_log("honeypot_triggered", level="warning", form="login")
        flash(generic, "danger")
        return render_template("login.html"), 401

    username = (request.form.get("username") or "").strip().lower()[:80]
    password = (request.form.get("password") or "")[:1024]
    # Account lookup must bypass the per-account filter (no session yet).
    admin = unscoped(Admin.query).filter(db.func.lower(Admin.username) == username).first()
    now = _now()

    if admin and admin.locked_until and admin.locked_until > now:
        sec.burn_password_check(password)
        sec.security_log("login_blocked_locked", level="warning", user=username)
        flash(generic, "danger")
        return render_template("login.html"), 401

    ok = bool(admin) and sec.verify_password(admin.password_hash, password)
    if not admin:
        sec.burn_password_check(password)          # equalise timing for unknown users

    if not ok:
        if admin:
            admin.failed_logins = (admin.failed_logins or 0) + 1
            if admin.failed_logins >= sec.MAX_FAILED_LOGINS:
                admin.locked_until = now + timedelta(minutes=sec.LOCKOUT_MINUTES)
                admin.failed_logins = 0
                sec.security_log("account_locked", level="warning", user=username,
                                 minutes=sec.LOCKOUT_MINUTES)
            db.session.commit()
        sec.security_log("login_failed", level="warning", user=username,
                         reason="bad_password" if admin else "unknown_user")
        flash(generic, "danger")
        return render_template("login.html"), 401

    # Password is correct from here on, so it is safe to be specific.
    if not admin.is_active:
        sec.security_log("login_denied_disabled", level="warning", user=username)
        flash("This account has been disabled. Contact the administrator.", "danger")
        return render_template("login.html"), 403
    if sec.password_needs_rehash(admin.password_hash):   # transparently upgrade old hashes
        admin.password_hash = sec.hash_password(password)
    _start_session(admin)
    sec.security_log("login_success", user=admin.username)
    flash(f"Welcome back, {admin.display_name()}!", "success")
    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["signup"], methods=["POST"], key_func=get_remote_address)
def signup():
    """Create a brand-new account with its own separate set of data."""
    mode = sec.signup_mode()
    if mode == "closed":
        return sec._render_error(404, "Registration is closed on this server. "
                                      "Ask the administrator to create an account for you.")
    if request.method == "GET":
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("signup.html", form={}, invite=(mode == "invite"),
                               security_questions=sec.SECURITY_QUESTIONS)

    form = request.form
    if sec.honeypot_tripped():
        sec.security_log("honeypot_triggered", level="warning", form="signup")
        flash("Account created. You can sign in now.", "success")   # tell the bot nothing
        return redirect(url_for("login"))
    errors = []
    if mode == "invite":
        expected = os.environ.get("SIGNUP_INVITE_CODE", "")
        if not expected or not hmac.compare_digest(form.get("invite_code", ""), expected):
            sec.security_log("signup_bad_invite", level="warning")
            errors.append("Invalid invitation code.")
    username = email = ""
    try: username = clean_username(form.get("username"))
    except ValidationError as e: errors.append(str(e))
    try: email = clean_email(form.get("email"), required=True).lower()
    except ValidationError as e: errors.append(str(e))
    full_name = property_name = ""
    try:
        full_name = clean_text(form.get("full_name"), "Full name", 120)
        property_name = clean_text(form.get("property_name"), "Property name", 120)
    except ValidationError as e: errors.append(str(e))
    password = form.get("password", "")
    msg = check_password_strength(password, username, email)
    if msg: errors.append(msg)
    if password != form.get("confirm_password", ""):
        errors.append("Passwords do not match.")
    if username and unscoped(Admin.query).filter(db.func.lower(Admin.username) == username).first():
        errors.append("That username is already taken.")
    security_question = (form.get("security_question") or "").strip()
    security_answer = (form.get("security_answer") or "").strip()
    if security_question not in sec.SECURITY_QUESTIONS:
        errors.append("Choose a security question.")
    if len(security_answer) < 2:
        errors.append("Enter an answer to your security question — you'll need it if you "
                      "ever forget your password.")
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("signup.html", form=form, invite=(mode == "invite"),
                               security_questions=sec.SECURITY_QUESTIONS), 400

    # Same response whether or not the email is already registered (no enumeration).
    if unscoped(Admin.query).filter(db.func.lower(Admin.email) == email).first():
        sec.security_log("signup_duplicate_email", level="info")
        flash("Account created. You can sign in now.", "success")
        return redirect(url_for("login"))
    try:
        admin = Admin(username=username, password_hash=sec.hash_password(password),
                      full_name=full_name, email=email, property_name=property_name,
                      role="owner", is_active=True, email_verified=True,
                      security_question=security_question,
                      security_answer_hash=sec.hash_security_answer(security_answer),
                      password_changed_at=_now())
        db.session.add(admin)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("signup failed")
        flash("Could not create the account. Please try again.", "danger")
        return render_template("signup.html", form=form, invite=(mode == "invite"),
                               security_questions=sec.SECURITY_QUESTIONS), 500
    sec.security_log("signup", user=username)
    _start_session(admin)
    flash("Account created. This workspace starts empty — add your first renter to begin.", "success")
    return redirect(url_for("renters"))


def _security_reset_token(uid):
    return sec.make_token("security-reset", {"uid": uid})


@app.route("/forgot-password", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["email_flow"], methods=["POST"], key_func=get_remote_address)
@sec.limiter.limit(LIMITS["email_flow"], methods=["POST"], key_func=sec.form_field_key("username"))
def forgot_password():
    """Step 1: look up the account by username and show its security question.

    The page looks identical whether or not the account exists — an unknown
    username gets a deterministic decoy question, and the token it produces
    can never pass step 2 — so this doesn't reveal which usernames are real.
    """
    if request.method == "GET":
        return render_template("forgot_password.html")
    if sec.honeypot_tripped():
        sec.security_log("honeypot_triggered", level="warning", form="forgot_password")
        return render_template("forgot_password.html")
    username = (request.form.get("username") or "").strip().lower()[:80]
    admin = unscoped(Admin.query).filter(db.func.lower(Admin.username) == username).first()
    if admin and admin.is_active and admin.security_question and admin.security_answer_hash:
        question = admin.security_question
        token = _security_reset_token(admin.id)
        sec.security_log("forgot_password_started", user=username)
    else:
        question = sec.dummy_security_question(username)
        token = _security_reset_token(None)      # can never verify → dead end
        sec.security_log("forgot_password_no_match", level="info")
    return render_template("reset_password.html", token=token, question=question)


@app.route("/reset-password/<token>", methods=["POST"])
@sec.limiter.limit(LIMITS["login"], methods=["POST"], key_func=get_remote_address)
def reset_password(token):
    """Step 2: answer the security question and choose a new password."""
    data = sec.read_token("security-reset", token, sec.RESET_TOKEN_MAX_AGE)
    uid = data.get("uid") if data else None
    admin = unscoped(Admin.query).filter_by(id=uid).first() if uid else None
    answer = request.form.get("security_answer", "")
    pw, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")

    if not admin or not admin.is_active or not admin.security_answer_hash:
        sec.burn_security_answer_check(answer)          # equalise timing
        sec.security_log("reset_token_invalid", level="warning")
        flash("That didn't match, or the link has expired. Start over below.", "danger")
        return redirect(url_for("forgot_password"))

    if not sec.verify_security_answer(admin.security_answer_hash, answer):
        sec.security_log("reset_answer_wrong", level="warning", user=admin.username)
        flash("That answer doesn't match what we have on file. Try again.", "danger")
        return render_template("reset_password.html", token=token,
                               question=admin.security_question), 401

    msg = check_password_strength(pw, admin.username, admin.email or "")
    if msg or pw != confirm:
        flash(msg or "Passwords do not match.", "danger")
        return render_template("reset_password.html", token=token,
                               question=admin.security_question), 400

    _set_password(admin, pw)
    db.session.commit()
    sec.security_log("password_reset_completed", user=admin.username)
    flash("Password updated. Sign in with your new password.", "success")
    return redirect(url_for("login"))


# ── USER MANAGEMENT (super admin only) ───────────────────────────────────────
@app.route("/users")
@superadmin_required
def users():
    accounts = unscoped(Admin.query).order_by(Admin.id.asc()).all()
    stats = {}
    for a in accounts:
        stats[a.id] = {
            "renters": unscoped(Tenant.query).filter_by(owner_id=a.id).count(),
            "records": unscoped(RentRecord.query).filter_by(owner_id=a.id).count(),
        }
    return render_template("users.html", accounts=accounts, stats=stats,
                           me=session.get("owner_id"))

@app.route("/users/create", methods=["POST"])
@sec.limiter.limit(LIMITS["danger"] + ";60 per day")
@superadmin_required
def create_user():
    try:
        username = clean_username(request.form.get("username"))
        email = clean_email(request.form.get("email")).lower()
        password = request.form.get("password", "")
        msg = check_password_strength(password, username, email)
        if msg:
            raise ValidationError(msg)
        role = choice(request.form.get("role"), ("owner", "superadmin"), "Role", default="owner")
        full_name = clean_text(request.form.get("full_name"), "Full name", 120)
        property_name = clean_text(request.form.get("property_name"), "Property name", 120)
    except ValidationError as e:
        flash(str(e), "danger")
        return redirect(url_for("users"))
    if unscoped(Admin.query).filter(db.func.lower(Admin.username) == username).first():
        flash("That username already exists.", "danger")
        return redirect(url_for("users"))
    db.session.add(Admin(
        username=username, password_hash=sec.hash_password(password),
        full_name=full_name, email=email or None, property_name=property_name,
        role=role, is_active=True,
        email_verified=True,             # created by a trusted admin
        must_change_password=True,       # temp password must be replaced at first login
        password_changed_at=_now()))
    db.session.commit()
    sec.security_log("admin_user_created", user=username, role=role, by=session.get("admin_username"))
    flash(f"Account '{username}' created with its own empty workspace. "
          "They must change the password at first login.", "success")
    return redirect(url_for("users"))

@app.route("/users/toggle/<int:uid>", methods=["POST"])
@superadmin_required
def toggle_user(uid):
    a = unscoped(Admin.query).filter_by(id=uid).first_or_404()
    if a.id == session.get("owner_id"):
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("users"))
    a.is_active = not a.is_active
    a.session_version = (a.session_version or 0) + 1
    db.session.commit()
    sec.security_log("admin_user_toggled", target=a.username, active=bool(a.is_active))
    flash(f"Account '{a.username}' {'enabled' if a.is_active else 'disabled'}.", "info")
    return redirect(url_for("users"))

@app.route("/users/reset-password/<int:uid>", methods=["POST"])
@sec.limiter.limit(LIMITS["danger"] + ";30 per day")
@superadmin_required
def reset_user_password(uid):
    a = unscoped(Admin.query).filter_by(id=uid).first_or_404()
    new = request.form.get("new_password", "")
    msg = check_password_strength(new, a.username, a.email or "")
    if msg:
        flash(msg, "danger")
        return redirect(url_for("users"))
    _set_password(a, new, must_change=True)
    db.session.commit()
    sec.security_log("admin_password_reset", target=a.username, by=session.get("admin_username"))
    flash(f"Password reset for '{a.username}'. They must change it at next login.", "success")
    return redirect(url_for("users"))

@app.route("/users/delete/<int:uid>", methods=["POST"])
@sec.limiter.limit(LIMITS["danger"])
@superadmin_required
def delete_user(uid):
    a = unscoped(Admin.query).filter_by(id=uid).first_or_404()
    if a.id == session.get("owner_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users"))
    if request.form.get("confirm_username", "").strip().lower() != a.username.lower():
        flash("Type the username exactly to confirm deletion.", "danger")
        return redirect(url_for("users"))
    name = a.username
    _purge_owner_files(uid)
    for model in (RentRecord, DepositPayment, VacateSettlement, ReminderLog,
                  RentAmountHistory, Tenant, CommonExpense, BuildingExpense):
        unscoped(model.query).filter_by(owner_id=uid).delete(synchronize_session=False)
    db.session.delete(a)
    db.session.commit()
    sec.security_log("admin_user_deleted", target=name, by=session.get("admin_username"), level="warning")
    flash(f"Account '{name}' and all of its data were permanently deleted.", "warning")
    return redirect(url_for("users"))

@app.route("/logout", methods=["POST"])
def logout():
    if session.get("owner_id"):
        sec.security_log("logout", user=session.get("admin_username"))
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ── PRIVATE FILE DOWNLOADS ────────────────────────────────────────────────────
_SERVE_MIME = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
               ".webp": "image/webp", ".gif": "image/gif", ".pdf": "application/pdf"}

def _legacy_key_referenced(key):
    """Old flat filenames: only serve if one of THIS account's rows references it
    (queries are auto-scoped to the signed-in owner)."""
    return bool(
        Tenant.query.filter(db.or_(Tenant.photo_path == key, Tenant.agreement_path == key,
                                   Tenant.payment_screenshot == key)).first()
        or RentRecord.query.filter_by(payment_screenshot=key).first()
        or BuildingExpense.query.filter_by(receipt_path=key).first())

def _all_file_keys(owner_id):
    keys = set()
    for model, cols in ((Tenant, ("photo_path", "agreement_path", "payment_screenshot")),
                        (RentRecord, ("payment_screenshot",)),
                        (BuildingExpense, ("receipt_path",))):
        for row in unscoped(model.query).filter_by(owner_id=owner_id).all():
            keys.update(getattr(row, c) for c in cols if getattr(row, c))
    return keys

def _purge_owner_files(owner_id):
    for k in _all_file_keys(owner_id):
        uploads.delete_stored(app, k)

@app.route("/files/<path:key>")
@sec.limiter.limit(LIMITS["files"])
@login_required
def serve_upload(key):
    """Authenticated, ownership-checked file download (replaces public /static/uploads)."""
    if not uploads.is_valid_key(key):
        abort(404)
    owner = uploads.key_owner(key)
    if owner is not None:
        if owner != session.get("owner_id"):
            sec.security_log("file_access_denied", level="warning", key=key)
            abort(404)                                  # 404, not 403: don't confirm it exists
    elif not _legacy_key_referenced(key):
        abort(404)
    if key.startswith("sb:"):
        url = uploads.supabase_signed_url(key)
        if not url:
            abort(404)
        return redirect(url, code=302)
    ext = os.path.splitext(key)[1].lower()
    path = uploads.local_path(app, key)
    if ext not in _SERVE_MIME or not path or not os.path.isfile(path):
        abort(404)
    resp = send_file(path, mimetype=_SERVE_MIME[ext], conditional=True)
    resp.headers["Cache-Control"] = "private, max-age=300"
    resp.headers["Content-Disposition"] = "inline"
    if ext != ".pdf":
        resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return resp


@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")


# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    today = date.today()
    month_start, month_end = _month_bounds(today.year, today.month)

    # ── Single query: current month rent records + tenant in one join ──
    cur_records = (RentRecord.query
                   .options(joinedload(RentRecord.tenant))
                   .join(Tenant, RentRecord.tenant_id == Tenant.id)
                   .filter(
                       RentRecord.month == today.month,
                       RentRecord.year == today.year,
                       Tenant.occupancy_status == "Active",
                   )
                   .all())

    collected   = sum(r.paid_amount or r.rent_amount for r in cur_records if r.status == "Paid")
    pending_amt = sum(r.rent_amount for r in cur_records if r.status != "Paid")
    # Overdue = unpaid records past the due day of the FOLLOWING month
    # (rent for September is only late after e.g. the 10th of October).
    overdue_recs = _overdue_records(today)
    overdue      = []
    _seen        = set()
    for r in overdue_recs:
        if r.tenant and r.tenant.id not in _seen:
            _seen.add(r.tenant.id)
            overdue.append(r.tenant)
    all_tenants = [r.tenant for r in cur_records if r.tenant]

    # ── Combine both expense SUM queries into ONE round trip ──
    exp_row = db.session.query(
        db.func.coalesce(db.func.sum(
            db.case((CommonExpense.date >= month_start, CommonExpense.amount), else_=0)
        ), 0.0),
        db.func.coalesce(db.func.sum(
            db.case((CommonExpense.date < month_end, CommonExpense.amount), else_=0)
        ), 0.0),
    ).filter(CommonExpense.date >= month_start, CommonExpense.date < month_end).one()
    total_common = float(exp_row[0] or 0)

    total_building = db.session.query(
        db.func.coalesce(db.func.sum(BuildingExpense.amount), 0.0)
    ).filter(
        BuildingExpense.date >= month_start,
        BuildingExpense.date < month_end,
    ).scalar() or 0.0

    # ── Chart: 6 months paid records — targeted columns only ──
    chart_months = []
    monthly = {}
    for i in range(5, -1, -1):
        m = today.month - i; y = today.year
        while m <= 0: m += 12; y -= 1
        label = datetime(y, m, 1).strftime("%b")
        monthly[label] = 0
        chart_months.append((m, y))
    chart_start = date(chart_months[0][1], chart_months[0][0], 1)

    for r in (RentRecord.query
              .filter(RentRecord.status == "Paid",
                      RentRecord.payment_date >= chart_start)
              .with_entities(RentRecord.payment_date, RentRecord.paid_amount, RentRecord.rent_amount)
              .all()):
        if r.payment_date:
            k = r.payment_date.strftime("%b")
            if k in monthly:
                monthly[k] += (r.paid_amount or r.rent_amount)

    # ── Pie chart: aggregate expenses in DB (not Python loop) ──
    common_cats = {
        (row.description or row.category or "Other").strip(): float(row.total)
        for row in db.session.query(
            db.func.coalesce(CommonExpense.description, CommonExpense.category, "Other").label("description"),
            CommonExpense.category,
            db.func.sum(CommonExpense.amount).label("total")
        ).filter(CommonExpense.date >= month_start, CommonExpense.date < month_end
        ).group_by(CommonExpense.description, CommonExpense.category).all()
    }
    building_cats = {
        (row.description or row.category or "Other").strip(): float(row.total)
        for row in db.session.query(
            db.func.coalesce(BuildingExpense.description, BuildingExpense.category, "Other").label("description"),
            BuildingExpense.category,
            db.func.sum(BuildingExpense.amount).label("total")
        ).filter(BuildingExpense.date >= month_start, BuildingExpense.date < month_end
        ).group_by(BuildingExpense.description, BuildingExpense.category).all()
    }
    expense_categories = {f"{k} (Common)": v for k, v in common_cats.items()}
    expense_categories.update({f"{k} (Building)": v for k, v in building_cats.items()})

    import json
    chart_data = ({
        "total_tenants": len(cur_records),
        "paid_count": sum(1 for r in cur_records if r.status == "Paid"),
        "pending_count": sum(1 for r in cur_records if r.status != "Paid"),
        "collected": collected,
        "pending_amount": pending_amt,
        "monthly_income": monthly,
        "total_common": total_common,
        "total_building": total_building,
        "expense_categories": expense_categories,
    })

    return render_template("dashboard.html",
        tenants=all_tenants, total=len(cur_records),
        collected=collected, pending_amt=pending_amt, overdue=overdue,
        total_common=total_common, total_building=total_building,
        today=today, chart_data=chart_data)

# ── RENT TRACKER (current month) ──────────────────────────────────────────────
@app.route("/rent-tracker")
@login_required
def rent_tracker():
    today = date.today()

    # Check if any records exist for this month — single query
    existing_ids = {r.tenant_id for r in
        RentRecord.query
        .filter_by(month=today.month, year=today.year)
        .with_entities(RentRecord.tenant_id).all()}

    # Only create missing records (batch insert instead of N individual queries)
    active_tenants = Tenant.query.filter_by(occupancy_status="Active").all()
    new_records = []
    for t in active_tenants:
        if t.id not in existing_ids:
            new_records.append(RentRecord(
                tenant_id=t.id, tenant_name=t.name,
                month=today.month, year=today.year,
                rent_amount=t.amount, status="Pending",
                owner_id=t.owner_id,
            ))
    if new_records:
        db.session.bulk_save_objects(new_records)
        db.session.commit()

    # Load current-month records as the source of truth
    records = (RentRecord.query
               .options(joinedload(RentRecord.tenant))
               .filter_by(month=today.month, year=today.year)
               .join(Tenant, RentRecord.tenant_id == Tenant.id)
               .filter(Tenant.occupancy_status == "Active")
               .order_by(Tenant.unit)
               .all())

    # Sync tenant.status from RentRecord — only update changed ones
    changed = False
    for r in records:
        # Keep the amount shown in sync with the renter's current rent.
        # If the rent was revised (profile edit or a rent revision) an unpaid
        # record must pick it up, otherwise the tracker shows the stale figure.
        if r.tenant and r.status != "Paid" and r.rent_amount != r.tenant.amount:
            r.rent_amount = r.tenant.amount
            changed = True
        if r.tenant and r.tenant.status != r.status:
            r.tenant.status = r.status
            if r.status == "Paid":
                r.tenant.payment_date   = r.payment_date
                r.tenant.payment_method = r.payment_method
                r.tenant.transaction_id = r.transaction_id
            else:
                r.tenant.payment_date   = None
                r.tenant.payment_method = None
                r.tenant.transaction_id = None
            changed = True
    if changed:
        db.session.commit()

    tenants = [r.tenant for r in records if r.tenant]
    return render_template("rent_tracker.html", tenants=tenants, records=records, today=today)

# ── MONTHLY HISTORY ───────────────────────────────────────────────────────────
@app.route("/rent-history")
@login_required
def rent_history():
    today = date.today()
    # Build list of available months (last 24)
    months = []
    for i in range(24):
        m = today.month - i
        y = today.year
        while m <= 0: m += 12; y -= 1
        months.append((y, m, _cycle_label(y, m)))

    sel_year, sel_month = _safe_month_year(request.args, today)

    records = (RentRecord.query
               .options(joinedload(RentRecord.tenant))
               .filter_by(month=sel_month, year=sel_year)
               .order_by(RentRecord.tenant_name)
               .all())

    # Filter out records for tenants who hadn't joined yet in the selected month
    sel_month_start = date(sel_year, sel_month, 1)
    records = [
        r for r in records
        if r.tenant is None or r.tenant.join_date is None
        or date(r.tenant.join_date.year, r.tenant.join_date.month, 1) <= sel_month_start
    ]

    # For active tenants with no record this month, show them as pending
    # (only if they had already joined by that month)
    existing_ids = {r.tenant_id for r in records}
    for t in Tenant.query.filter_by(occupancy_status="Active").all():
        if t.id not in existing_ids:
            # Skip if renter hadn't joined yet
            if t.join_date and date(t.join_date.year, t.join_date.month, 1) > sel_month_start:
                continue
            records.append(RentRecord(
                tenant_id=t.id, tenant_name=t.name,
                month=sel_month, year=sel_year,
                rent_amount=t.amount, status="Pending",
                owner_id=t.owner_id,
            ))

    total_expected = sum(r.rent_amount for r in records)
    total_collected = sum(r.paid_amount or 0 for r in records if r.status == "Paid")
    paid_count   = sum(1 for r in records if r.status == "Paid")
    pending_count = sum(1 for r in records if r.status != "Paid")

    return render_template("rent_history.html",
        records=records, months=months,
        sel_year=sel_year, sel_month=sel_month,
        sel_label=_cycle_label(sel_year, sel_month),
        sel_rent_month=date(sel_year, sel_month, 1).strftime("%B %Y"),
        sel_billed_in=_billed_in_label(sel_year, sel_month),
        total_expected=total_expected, total_collected=total_collected,
        paid_count=paid_count, pending_count=pending_count,
        today=today)

# ── ADD / EDIT MONTHLY RECORD (backdated / manual) ───────────────────────────
@app.route("/rent-history/add", methods=["GET", "POST"])
@login_required
def add_rent_record():
    tenants = Tenant.query.order_by(Tenant.name).all()
    today   = date.today()
    if request.method == "POST":
        try:
            tid = parse_int(request.form.get("tenant_id"), "Renter", 1, 10**9)
            month, year = parse_month_year(request.form.get("month"), request.form.get("year"))
            t = Tenant.query.get_or_404(tid)
            v = _rent_form_values(t=t)
            rec = RentRecord.query.filter_by(tenant_id=tid, month=month, year=year).first()
            if not rec:
                rec = RentRecord(tenant_id=tid, tenant_name=t.name, month=month, year=year,
                                 rent_amount=t.amount, owner_id=t.owner_id)
                db.session.add(rec)
            rec.status, rec.rent_amount, rec.notes = v["status"], v["rent_amount"], v["notes"]
            if v["status"] == "Paid":
                rec.paid_amount, rec.payment_method = v["paid_amount"], v["payment_method"]
                rec.transaction_id, rec.payment_date = v["transaction_id"], v["payment_date"]
            else:
                rec.paid_amount = rec.payment_date = rec.payment_method = rec.transaction_id = None
            db.session.commit()
            flash(f"✅ Record saved for {t.name} — {date(year, month, 1).strftime('%B %Y')}.", "success")
            return redirect(url_for("rent_history", year=year, month=month))
        except ValidationError as ve:
            db.session.rollback(); flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback(); flash_error("Could not save the record.", e)

    # Pre-fill from query params (validated — bad values fall back to today)
    pre_year, pre_month = _safe_month_year(request.args, today)
    pre_tid = request.args.get("tenant_id", "")
    pre_tid = pre_tid if pre_tid.isdigit() else ""
    return render_template("add_rent_record.html",
        tenants=tenants, today=today,
        pre_tid=pre_tid, pre_month=pre_month, pre_year=pre_year)

@app.route("/rent-history/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
def edit_rent_record(record_id):
    rec     = RentRecord.query.get_or_404(record_id)
    tenants = Tenant.query.order_by(Tenant.name).all()
    if request.method == "POST":
        try:
            v = _rent_form_values(rec=rec)
            rec.status, rec.rent_amount, rec.notes = v["status"], v["rent_amount"], v["notes"]
            if v["status"] == "Paid":
                rec.paid_amount, rec.payment_method = v["paid_amount"], v["payment_method"]
                rec.transaction_id, rec.payment_date = v["transaction_id"], v["payment_date"]
            else:
                rec.paid_amount = rec.payment_date = rec.payment_method = rec.transaction_id = None
            db.session.commit()
            flash("✅ Record updated.", "success")
            return redirect(url_for("rent_history", year=rec.year, month=rec.month))
        except ValidationError as ve:
            db.session.rollback(); flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback(); flash_error("Could not update the record.", e)
    return render_template("add_rent_record.html",
        record=rec, tenants=tenants, today=date.today(),
        pre_tid=rec.tenant_id, pre_month=rec.month, pre_year=rec.year)

@app.route("/rent-history/mark-paid/<int:record_id>", methods=["POST"])
@login_required
def history_mark_paid(record_id):
    rec = RentRecord.query.get_or_404(record_id)
    today = date.today()
    rec.status         = "Paid"
    rec.paid_amount    = rec.rent_amount
    rec.payment_date   = today
    try:
        rec.payment_method = choice(request.form.get("method"), PAY_METHODS, "Payment method", default="cash")
        rec.transaction_id = clean_text(request.form.get("transaction_id"), "Transaction ID", 100)
    except ValidationError as ve:
        db.session.rollback(); flash(str(ve), "danger")
        return redirect(url_for("rent_history", year=rec.year, month=rec.month))
    # Sync Tenant if this is the current month
    if rec.tenant and rec.month == today.month and rec.year == today.year:
        rec.tenant.status         = "Paid"
        rec.tenant.payment_date   = today
        rec.tenant.payment_method = rec.payment_method
        rec.tenant.transaction_id = rec.transaction_id
    db.session.commit()
    flash(f"✅ {rec.tenant_name} marked Paid for {rec.month_label()}.", "success")
    return redirect(url_for("rent_history", year=rec.year, month=rec.month))

@app.route("/rent-history/mark-unpaid/<int:record_id>", methods=["POST"])
@login_required
def history_mark_unpaid(record_id):
    rec = RentRecord.query.get_or_404(record_id)
    today = date.today()
    rec.status = "Pending"; rec.paid_amount = None; rec.payment_date = None
    rec.payment_method = None; rec.transaction_id = None
    if rec.tenant and rec.month == today.month and rec.year == today.year:
        rec.tenant.status = "Pending"; rec.tenant.payment_date = None
        rec.tenant.payment_method = None; rec.tenant.transaction_id = None
    db.session.commit()
    flash(f"{rec.tenant_name} marked Unpaid for {rec.month_label()}.", "info")
    return redirect(url_for("rent_history", year=rec.year, month=rec.month))

@app.route("/rent-history/delete/<int:record_id>", methods=["POST"])
@login_required
def delete_rent_record(record_id):
    rec = RentRecord.query.get_or_404(record_id)
    y, m = rec.year, rec.month
    db.session.delete(rec)
    db.session.commit()
    flash("Record deleted.", "info")
    return redirect(url_for("rent_history", year=y, month=m))

# ── PAYMENT (current month — also writes to RentRecord) ──────────────────────
@app.route("/tenant/mark-paid/<int:tid>", methods=["POST", "GET"])
@login_required
def mark_paid(tid):
    return redirect(url_for("verify_payment", tid=tid))

@app.route("/tenant/verify-payment/<int:tid>", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["ocr"], methods=["POST"])
@login_required
def verify_payment(tid):
    t = Tenant.query.get_or_404(tid)
    if request.method == "GET":
        return render_template("payment_verify.html", tenant=t)

    try:
        method     = choice(request.form.get("method"), ("cash", "manual", "screenshot"), "Method", default="cash")
        manual_txn = clean_text(request.form.get("transaction_id"), "Transaction ID", 100)
        manual_amt = parse_money(request.form.get("manual_amount"), "Amount", allow_blank=True, default=t.amount)
    except ValidationError as ve:
        flash(str(ve), "danger")
        return render_template("payment_verify.html", tenant=t), 400

    def _commit_payment(paid_amount, txn_id, pay_method, screenshot_fn=None):
        today = date.today()
        t.status         = "Paid"
        t.payment_date   = today
        t.payment_method = pay_method
        t.transaction_id = txn_id or pay_method.title()
        if screenshot_fn:
            t.payment_screenshot = screenshot_fn
        db.session.commit()
        # Write to monthly history
        rec = _get_or_create_record(t.id, today.month, today.year)
        if rec:
            rec.status = "Paid"; rec.paid_amount = paid_amount
            rec.payment_date = today; rec.payment_method = pay_method
            rec.transaction_id = txn_id or ""; rec.payment_screenshot = screenshot_fn or ""
            db.session.commit()

    if method == "manual":
        _commit_payment(manual_amt, manual_txn, "manual")
        sec.security_log("payment_marked", tenant=t.id, method="manual")
        flash(f"✅ {t.name} marked as Paid.", "success")
        return redirect(url_for("rent_tracker"))

    if method == "screenshot":
        files = [f for f in request.files.getlist("screenshot") if f and f.filename]
        if not files:
            flash("Please upload at least one screenshot.", "danger")
            return render_template("payment_verify.html", tenant=t), 400
        if len(files) > uploads.MAX_FILES_PER_REQUEST:
            flash(f"Please upload at most {uploads.MAX_FILES_PER_REQUEST} screenshots at once.", "danger")
            return render_template("payment_verify.html", tenant=t), 400
        from ocr_parser import parse_payment_screenshot
        best_parsed = None
        saved_fns   = []
        try:
            for f in files:
                # validates type/size/content, re-encodes the image, stores privately
                key, local = uploads.store_upload(app, f, session["owner_id"],
                                                  kinds="image", keep_local=True)
                saved_fns.append(key)
                parsed = parse_payment_screenshot(local, t.amount, manual_txn)
                if best_parsed is None or (parsed.get("amount") or 0) > (best_parsed.get("amount") or 0):
                    best_parsed = parsed
        except ValidationError as ve:
            for k in saved_fns:
                uploads.delete_stored(app, k)
            flash(str(ve), "danger")
            return render_template("payment_verify.html", tenant=t), 400
        detected_txn = manual_txn or best_parsed.get("txn_id")
        ocr_result = {"raw_text": best_parsed.get("raw_text", ""),
                      "amount": best_parsed.get("amount"), "txn_id": detected_txn,
                      "method": best_parsed.get("method", "unknown"), "files": saved_fns}
        return render_template("payment_verify.html", tenant=t, ocr=ocr_result,
                               screenshot_fn=saved_fns[0] if saved_fns else "")

    # Cash
    _commit_payment(t.amount, manual_txn, "cash")
    sec.security_log("payment_marked", tenant=t.id, method="cash")
    flash(f"✅ {t.name} marked as Paid (Cash).", "success")
    return redirect(url_for("rent_tracker"))

@app.route("/tenant/force-paid/<int:tid>", methods=["POST"])
@login_required
def force_mark_paid(tid):
    t = Tenant.query.get_or_404(tid)
    today = date.today()
    try:
        method = choice(request.form.get("method"), PAY_METHODS, "Method", default="upi_screenshot")
        txn    = clean_text(request.form.get("transaction_id"), "Transaction ID", 100) or "—"
        shot   = _valid_screenshot_key(request.form.get("screenshot_fn"), t.payment_screenshot)
        paid_amount = parse_money(request.form.get("manual_amount"), "Amount",
                                  allow_blank=True, default=t.amount)
    except ValidationError as ve:
        flash(str(ve), "danger")
        return redirect(sec.safe_back("rent_tracker"))
    t.status             = "Paid"
    t.payment_date       = today
    t.payment_method     = method
    t.transaction_id     = txn
    t.payment_screenshot = shot
    db.session.commit()
    # Write to monthly history
    rec = _get_or_create_record(t.id, today.month, today.year)
    if rec:
        rec.status = "Paid"; rec.paid_amount = paid_amount
        rec.payment_date = today; rec.payment_method = t.payment_method
        rec.transaction_id = t.transaction_id
        rec.payment_screenshot = t.payment_screenshot or ""
        db.session.commit()
    sec.security_log("payment_marked", tenant=t.id, method=method)
    flash(f"✅ {t.name} confirmed as Paid.", "success")
    return redirect(url_for("rent_tracker"))

@app.route("/tenant/mark-unpaid/<int:tid>", methods=["POST"])
@login_required
def mark_unpaid(tid):
    t = Tenant.query.get_or_404(tid)
    today = date.today()
    t.status = "Pending"; t.payment_date = None
    t.payment_method = None; t.transaction_id = None; t.payment_screenshot = None
    db.session.commit()
    # Also revert this month's record
    rec = RentRecord.query.filter_by(tenant_id=t.id, month=today.month, year=today.year).first()
    if rec:
        rec.status = "Pending"; rec.paid_amount = None; rec.payment_date = None
        db.session.commit()
    flash(f"{t.name} marked as Unpaid.", "info")
    return redirect(sec.safe_back("rent_tracker"))

@app.route("/tenant/remind/<int:tid>", methods=["POST"])
@sec.limiter.limit(LIMITS["reminder"], methods=["POST"])
@login_required
def remind_tenant(tid):
    """Send a WhatsApp/SMS reminder. Costs money and messages a real person, so:
    rate-limited per account, per-tenant cooldown and a daily account cap."""
    t = Tenant.query.get_or_404(tid)
    try:
        channel = choice(request.form.get("channel"), ("whatsapp", "sms"), "Channel", default="whatsapp")
    except ValidationError as ve:
        flash(str(ve), "danger")
        return redirect(sec.safe_back("rent_tracker"))

    now = datetime.utcnow()
    recent = (ReminderLog.query.filter(ReminderLog.tenant_id == t.id,
              ReminderLog.sent_at > now - timedelta(seconds=sec.REMINDER_COOLDOWN_SECONDS)).first())
    today_count = ReminderLog.query.filter(ReminderLog.sent_at > now - timedelta(days=1)).count()
    if recent:
        flash(f"A reminder was already sent to {t.name} in the last "
              f"{sec.REMINDER_COOLDOWN_SECONDS // 60} minutes.", "warning")
        return redirect(sec.safe_back("rent_tracker"))
    if today_count >= sec.REMINDER_DAILY_CAP:
        sec.security_log("reminder_daily_cap", level="warning", count=today_count)
        flash("Daily reminder limit reached. Try again tomorrow.", "warning")
        return redirect(sec.safe_back("rent_tracker"))

    status  = "failed"
    log_msg = f"Reminder via {channel}"

    if channel == "whatsapp":
        result = send_rent_reminder(to_phone=t.phone, tenant_name=t.name,
            amount=t.amount, due_date=f"{t.get_due_day()}th of every month")
        if "error" not in result:
            status = "sent"
        else:
            log_msg = "WhatsApp failed"
            logger.error("[remind_tenant] WhatsApp FAILED tenant=%s phone=%s: %s",
                         t.id, sec.mask_phone(t.phone), result.get("error", "unknown"))

    else:
        msg = (f"Hi {t.name}, rent Rs.{t.amount:,.0f} due on "
               f"the {t.get_due_day()}th of every month. Please pay. -RentManager")
        result = send_sms(t.phone, msg)
        if result.get("success"):
            status = "sent"
        else:
            error_reason = result.get("error") or result.get("message") or "unknown"
            log_msg = "SMS failed"
            logger.error("[remind_tenant] SMS FAILED tenant=%s phone=%s reason=%s",
                         t.id, sec.mask_phone(t.phone), error_reason)

    db.session.add(ReminderLog(tenant_id=t.id, tenant_name=t.name,
        channel=channel, status=status, message=log_msg, owner_id=t.owner_id))
    db.session.commit()
    sec.security_log("reminder", tenant=t.id, channel=channel, status=status)

    if status == "sent":
        flash(f"Reminder sent to {t.name} via {channel}.", "success")
    else:
        flash(f"Reminder to {t.name} via {channel} failed. Check server logs.", "warning")
    return redirect(sec.safe_back("rent_tracker"))

# ── RENTER PROFILE (with monthly history) ────────────────────────────────────
@app.route("/renters")
@login_required
def renters():
    tenants = Tenant.query.order_by(Tenant.name).all()
    return render_template("renters.html", tenants=tenants)

@app.route("/renters/detail/<int:tid>")
@login_required
def renter_detail(tid):
    t    = Tenant.query.get_or_404(tid)
    logs = ReminderLog.query.filter_by(tenant_id=tid).order_by(ReminderLog.sent_at.desc()).all()
    # Ensure current month record exists for active tenants
    if t.occupancy_status == "Active":
        _get_or_create_record(t.id, date.today().month, date.today().year)
    # Monthly rent history — last 24 months from RentRecord
    records = (RentRecord.query.filter_by(tenant_id=tid)
               .order_by(RentRecord.year.desc(), RentRecord.month.desc())
               .limit(24).all())
    settlement = VacateSettlement.query.filter_by(tenant_id=tid).first()

    # ── Payment summary (shown for every renter, not just vacated ones) ──
    all_recs = RentRecord.query.filter_by(tenant_id=tid).all()
    paid_recs = [r for r in all_recs if r.status == "Paid"]
    today = date.today()
    summary = {
        "total_months":   len(all_recs),
        "months_paid":    len(paid_recs),
        "months_pending": len(all_recs) - len(paid_recs),
        "months_overdue": sum(1 for r in all_recs if r.is_overdue(today)),
        "total_billed":   sum(r.rent_amount or 0 for r in all_recs),
        "total_collected": sum(r.paid_amount or 0 for r in paid_recs),
        "last_payment":   max((r.payment_date for r in paid_recs if r.payment_date), default=None),
    }
    summary["outstanding"] = max(0.0, summary["total_billed"] - summary["total_collected"])
    summary["collection_rate"] = (
        round(summary["total_collected"] / summary["total_billed"] * 100)
        if summary["total_billed"] else 0
    )
    summary["avg_rent"] = (
        round(summary["total_billed"] / summary["total_months"]) if summary["total_months"] else 0
    )

    deposit_payments = (DepositPayment.query.filter_by(tenant_id=tid)
                        .order_by(DepositPayment.payment_date.asc(),
                                  DepositPayment.id.asc()).all())

    rent_revisions = (RentAmountHistory.query.filter_by(tenant_id=tid)
                      .order_by(RentAmountHistory.effective_from.desc()).all())

    return render_template("renter_detail.html", tenant=t, logs=logs, records=records,
                           settlement=settlement, summary=summary,
                           deposit_payments=deposit_payments, today=today,
                           rent_revisions=rent_revisions)

def _renter_fields():
    """Validate the renter form. Raises ValidationError."""
    f = request.form
    return dict(
        name=clean_text(f.get("name"), "Name", 120, required=True),
        phone=clean_phone(f.get("phone")),
        email=clean_email(f.get("email")),
        unit=clean_text(f.get("unit"), "Unit", 20),
        unit_number=clean_text(f.get("unit_number"), "Unit number", 30),
        amount=parse_money(f.get("amount"), "Monthly rent"),
        due_day=parse_int(f.get("due_day"), "Due day", 1, 31),
        deposit=parse_money(f.get("deposit"), "Deposit", allow_blank=True, default=0.0),
        join_date=parse_date(f.get("join_date"), "Join date"),
        notes=clean_text(f.get("notes"), "Notes", 2000, multiline=True),
    )

def _legacy_due_date(due_day):
    """Legacy NOT NULL due_date column: keep populated with a valid date."""
    import calendar as _cal
    _today = date.today()
    return date(_today.year, _today.month, min(due_day, _cal.monthrange(_today.year, _today.month)[1]))

@app.route("/renters/add", methods=["GET", "POST"])
@login_required
def add_renter():
    if request.method == "POST":
        saved = []
        try:
            v = _renter_fields()
            photo, agreement = save_upload("photo"), save_upload("agreement")
            saved = [k for k in (photo, agreement) if k]
            t = Tenant(
                name=v["name"], phone=v["phone"], email=v["email"], unit=v["unit"],
                unit_number=v["unit_number"], amount=v["amount"], due_day=v["due_day"],
                due_date=_legacy_due_date(v["due_day"]), deposit=v["deposit"],
                join_date=v["join_date"], vacated_date=None, occupancy_status="Active",
                notes=v["notes"], photo_path=photo, agreement_path=agreement, status="Pending",
            )
            db.session.add(t); db.session.commit()
            flash(f"Renter '{t.name}' added.", "success")
            return redirect(url_for("renters"))
        except ValidationError as ve:
            db.session.rollback(); [uploads.delete_stored(app, k) for k in saved]
            flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback(); [uploads.delete_stored(app, k) for k in saved]
            flash_error("Could not add the renter.", e)
    return render_template("renter_form.html", tenant=None, action="Add")

@app.route("/renters/edit/<int:tid>", methods=["GET", "POST"])
@login_required
def edit_renter(tid):
    t = Tenant.query.get_or_404(tid)
    if request.method == "POST":
        new_files, old_files = [], []
        try:
            # Quick file-only update from detail page (no full form fields present)
            if request.form.get("_photo_only"):
                pf = save_upload("photo")
                if pf:
                    old_files.append(t.photo_path); t.photo_path = pf
                db.session.commit(); [uploads.delete_stored(app, k) for k in old_files]
                flash("Photo updated.", "success")
                return redirect(url_for("renter_detail", tid=tid))
            if request.form.get("_agreement_only"):
                af = save_upload("agreement")
                if af:
                    old_files.append(t.agreement_path); t.agreement_path = af
                db.session.commit(); [uploads.delete_stored(app, k) for k in old_files]
                flash("Agreement updated.", "success")
                return redirect(url_for("renter_detail", tid=tid))
            # Full edit form
            v = _renter_fields()
            occupancy = choice(request.form.get("occupancy_status"), OCCUPANCY,
                               "Occupancy status", default=t.occupancy_status or "Active")
            vacated = parse_date(request.form.get("vacated_date"), "Vacated date")
            _old_amount = t.amount
            t.name, t.phone, t.email, t.unit = v["name"], v["phone"], v["email"], v["unit"]
            t.unit_number, t.amount, t.due_day = v["unit_number"], v["amount"], v["due_day"]
            t.due_date = _legacy_due_date(t.due_day)
            t.deposit, t.notes = v["deposit"], v["notes"]
            if v["join_date"]:
                t.join_date = v["join_date"]
            t.occupancy_status = occupancy
            if occupancy == "Vacated" and vacated:
                t.vacated_date = vacated
            elif occupancy == "Active":
                t.vacated_date = None
            pf = save_upload("photo"); af = save_upload("agreement")
            new_files = [k for k in (pf, af) if k]
            if pf: old_files.append(t.photo_path); t.photo_path = pf
            if af: old_files.append(t.agreement_path); t.agreement_path = af
            # Rent changed on the profile — roll it onto unpaid records so the
            # Rent Tracker and Rent History show the new figure straight away.
            if _old_amount != t.amount:
                today_ = date.today()
                n = 0
                for rec in RentRecord.query.filter_by(tenant_id=tid, status="Pending").all():
                    if date(rec.year, rec.month, 1) >= date(today_.year, today_.month, 1):
                        rec.rent_amount = t.amount
                        n += 1
                if n:
                    flash(f"Rent updated on {n} unpaid record(s).", "info")
            db.session.commit(); [uploads.delete_stored(app, k) for k in old_files]
            flash(f"Renter '{t.name}' updated.", "success")
            return redirect(url_for("renters"))
        except ValidationError as ve:
            db.session.rollback(); [uploads.delete_stored(app, k) for k in new_files]
            flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback(); [uploads.delete_stored(app, k) for k in new_files]
            flash_error("Could not update the renter.", e)
    return render_template("renter_form.html", tenant=t, action="Edit")

# ── UPDATE RENT AMOUNT & DEPOSIT (yearly revision) ───────────────────────────
@app.route("/renters/update-rent/<int:tid>", methods=["GET", "POST"])
@login_required
def update_rent_amount(tid):
    t = Tenant.query.get_or_404(tid)
    today = date.today()
    history = (RentAmountHistory.query
               .filter_by(tenant_id=tid)
               .order_by(RentAmountHistory.changed_at.desc())
               .all())

    if request.method == "POST":
        try:
            new_amount  = parse_money(request.form.get("new_amount"), "New rent")
            new_deposit = parse_money(request.form.get("new_deposit"), "New deposit",
                                      allow_blank=True, default=float(t.deposit or 0))
            effective_month, effective_year = parse_month_year(
                request.form.get("effective_month", today.month),
                request.form.get("effective_year", today.year))
            notes = clean_text(request.form.get("notes"), "Notes", 2000, multiline=True)

            # Log the change
            history_entry = RentAmountHistory(
                tenant_id=tid, tenant_name=t.name, owner_id=t.owner_id,
                old_amount=t.amount, new_amount=new_amount,
                old_deposit=t.deposit or 0, new_deposit=new_deposit,
                effective_from=date(effective_year, effective_month, 1),
                notes=notes,
            )
            db.session.add(history_entry)

            # Update tenant record
            t.amount  = new_amount
            t.deposit = new_deposit

            # Push the new amount onto UNPAID rent records from the effective
            # month onward, so the Rent Tracker and Rent History immediately
            # reflect the revision. Already-paid months keep what was charged.
            eff = date(effective_year, effective_month, 1)
            updated = 0
            for rec in RentRecord.query.filter_by(tenant_id=tid).all():
                rec_start = date(rec.year, rec.month, 1)
                if rec_start >= eff and rec.status != "Paid":
                    rec.rent_amount = new_amount
                    updated += 1
            db.session.commit()
            msg = (f"✅ Rent updated to ₹{new_amount:,.0f} and deposit to ₹{new_deposit:,.0f} "
                   f"effective {eff.strftime('%B %Y')}.")
            if updated:
                msg += f" {updated} unpaid rent record(s) updated."
            flash(msg, "success")
            return redirect(url_for("renter_detail", tid=tid))
        except ValidationError as ve:
            db.session.rollback(); flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback(); flash_error("Could not update the rent.", e)

    return render_template("update_rent_amount.html", tenant=t, today=today, history=history)

# ── DEPOSIT INSTALMENTS (half now / half later) ──────────────────────────────
@app.route("/renters/deposit/add/<int:tid>", methods=["POST"])
@login_required
def add_deposit_payment(tid):
    """Record one instalment of the security deposit ('half now, rest later')."""
    t = Tenant.query.get_or_404(tid)
    try:
        mode = choice(request.form.get("amount_mode"), ("custom", "half", "balance"),
                      "Amount mode", default="custom")
        agreed  = float(t.deposit or 0)
        already = t.deposit_paid()
        balance = max(0.0, agreed - already)

        if mode == "half":
            amount = round(agreed / 2, 2)
        elif mode == "balance":
            amount = balance
        else:
            amount = parse_money(request.form.get("amount"), "Amount", allow_blank=True, default=0.0)

        if amount <= 0:
            flash("Enter a deposit amount greater than zero.", "danger")
            return redirect(url_for("renter_detail", tid=tid))

        db.session.add(DepositPayment(
            tenant_id=t.id, tenant_name=t.name, owner_id=t.owner_id,
            amount=amount,
            payment_date=parse_date(request.form.get("payment_date"), "Payment date") or date.today(),
            method=choice(request.form.get("method"), PAY_METHODS, "Method", default="cash"),
            transaction_id=clean_text(request.form.get("transaction_id"), "Transaction ID", 100),
            notes=clean_text(request.form.get("notes"), "Notes", 2000, multiline=True),
        ))
        db.session.commit()

        new_balance = max(0.0, agreed - t.deposit_paid())
        if new_balance <= 0.01:
            flash(f"✅ Deposit fully collected for {t.name} — ₹{t.deposit_paid():,.0f}.", "success")
        else:
            flash(f"✅ ₹{amount:,.0f} deposit instalment recorded. "
                  f"Balance still due: ₹{new_balance:,.0f}.", "success")
    except ValidationError as ve:
        db.session.rollback(); flash(str(ve), "danger")
    except Exception as e:
        db.session.rollback(); flash_error("Could not record the deposit.", e)
    return redirect(url_for("renter_detail", tid=tid))

@app.route("/renters/deposit/delete/<int:pid>", methods=["POST"])
@login_required
def delete_deposit_payment(pid):
    p = DepositPayment.query.get_or_404(pid)
    tid = p.tenant_id
    db.session.delete(p)
    db.session.commit()
    flash("Deposit instalment removed.", "warning")
    return redirect(url_for("renter_detail", tid=tid))

@app.route("/renters/delete/<int:tid>", methods=["POST"])
@login_required
def delete_renter(tid):
    t = Tenant.query.get_or_404(tid)
    name = t.name
    # Remember stored files so they are erased too (a "delete" must really delete).
    keys = {t.photo_path, t.agreement_path, t.payment_screenshot}
    keys |= {r.payment_screenshot for r in RentRecord.query.filter_by(tenant_id=tid).all()}
    # Delete all child records first to avoid FK / NOT NULL violations
    RentRecord.query.filter_by(tenant_id=tid).delete()
    DepositPayment.query.filter_by(tenant_id=tid).delete()
    VacateSettlement.query.filter_by(tenant_id=tid).delete()
    ReminderLog.query.filter_by(tenant_id=tid).delete()
    db.session.delete(t)
    db.session.commit()
    for k in keys:
        uploads.delete_stored(app, k)
    sec.security_log("renter_deleted", tenant=tid, level="warning")
    flash(f"Renter '{name}' and all related records deleted.", "warning")
    return redirect(url_for("renters"))

@app.route("/renters/delete-file/<int:tid>/<field>", methods=["POST"])
@login_required
def delete_renter_file(tid, field):
    t = Tenant.query.get_or_404(tid)
    if field == "photo":
        old, t.photo_path = t.photo_path, None
    elif field == "agreement":
        old, t.agreement_path = t.agreement_path, None
    else:
        abort(404)
    db.session.commit()
    uploads.delete_stored(app, old)
    flash("File removed successfully.", "success")
    return redirect(url_for("renter_detail", tid=tid))


@app.route("/renters/vacate/<int:tid>", methods=["GET", "POST"])
@login_required
def vacate_renter(tid):
    t = Tenant.query.get_or_404(tid)
    existing = VacateSettlement.query.filter_by(tenant_id=tid).first()

    prev_recovered_ids = []
    if existing and existing.unpaid_rent_ids:
        prev_recovered_ids = [int(i) for i in existing.unpaid_rent_ids.split(",") if i.strip().isdigit()]

    # Unpaid rent months available to recover from the deposit — plus any
    # months already recovered by THIS settlement, so editing can un-recover
    # them (put them back to Pending) instead of silently losing the
    # deduction while the record stays marked Paid.
    unpaid_records = (RentRecord.query
                      .filter(RentRecord.tenant_id == tid,
                              db.or_(RentRecord.status != "Paid",
                                     RentRecord.id.in_(prev_recovered_ids or [-1])))
                      .order_by(RentRecord.year.asc(), RentRecord.month.asc())
                      .all())
    deposit_collected = t.deposit_paid()

    if request.method == "POST":
        try:
            # Repair margin: what the tenant is charged vs what was actually spent
            charged  = parse_money(request.form.get("repair_charged"), "Repair charged", allow_blank=True, default=0.0)
            actual   = parse_money(request.form.get("repair_actual"), "Repair actual", allow_blank=True, default=0.0)
            other    = parse_money(request.form.get("other_deduction"), "Other deduction", allow_blank=True, default=0.0)

            # Unpaid rent selected for recovery from the deposit
            sel_ids = [int(i) for i in request.form.getlist("unpaid_rent_ids") if str(i).strip().isdigit()]
            sel_recs = [r for r in unpaid_records if r.id in sel_ids]
            unpaid_total = sum(r.rent_amount or 0 for r in sel_recs)
            unpaid_note  = ", ".join(r.cycle_label() for r in sel_recs)

            returned = deposit_collected - charged - other - unpaid_total
            if returned < 0: returned = 0

            if existing:
                s = existing
            else:
                s = VacateSettlement(tenant_id=tid, owner_id=t.owner_id)
                db.session.add(s)
            s.deposit_held     = deposit_collected
            s.repair_charged   = charged
            s.repair_actual    = actual
            s.repair_cost      = charged        # keep legacy column in sync
            s.other_deduction  = other
            s.unpaid_rent      = unpaid_total
            s.unpaid_rent_ids  = ",".join(str(i) for i in sel_ids)
            s.unpaid_rent_note = unpaid_note
            s.deduction_notes  = clean_text(request.form.get("deduction_notes"), "Deduction notes", 2000, multiline=True)
            s.return_amount    = parse_money(request.form.get("return_amount"), "Return amount",
                                             allow_blank=True, default=returned)
            s.settlement_date  = parse_date(request.form.get("vacated_date"), "Vacated date") or date.today()

            # Settle the selected unpaid months out of the deposit so the
            # renter's ledger and the building accounts agree.
            for r in sel_recs:
                if r.payment_method == "deposit_adjustment":
                    continue  # already recovered by this settlement — leave as-is
                r.status         = "Paid"
                r.paid_amount    = r.rent_amount
                r.payment_date   = s.settlement_date
                r.payment_method = "deposit_adjustment"
                r.notes = ((r.notes or "") +
                           f" | Recovered from security deposit on vacate ({s.settlement_date}).").strip(" |")

            # Any month recovered by a PREVIOUS save of this settlement but
            # left unticked now — put it back to unpaid so it isn't both
            # marked Paid AND missing from the return-amount deduction.
            for r in unpaid_records:
                if (r.id in prev_recovered_ids and r.id not in sel_ids
                        and r.payment_method == "deposit_adjustment"):
                    r.status         = "Pending"
                    r.paid_amount    = None
                    r.payment_date   = None
                    r.payment_method = None
                    r.notes = (r.notes or "").split(" | Recovered from security deposit")[0].strip(" |")

            # Sync the vacate deductions into Building Expenses. These are
            # keyed off the tenant so re-saving the settlement UPDATES the
            # existing expense rows instead of appending duplicates each time.
            def _sync_expense(desc, amount, category, note):
                existing = (BuildingExpense.query
                            .filter_by(description=desc)
                            .order_by(BuildingExpense.id.asc())
                            .first())
                if amount and amount > 0:
                    if existing:
                        existing.amount   = amount
                        existing.category = category
                        existing.date     = s.settlement_date
                        existing.notes    = note
                    else:
                        db.session.add(BuildingExpense(
                            description=desc, amount=amount, category=category,
                            date=s.settlement_date, notes=note,
                            owner_id=t.owner_id))
                elif existing:
                    # Deduction was cleared — drop the auto-created expense too
                    db.session.delete(existing)

            # Log the ACTUAL money spent, not the amount charged to the
            # tenant, so the repair margin shows up as profit.
            _sync_expense(
                f"Vacate repair - {t.name}", actual, "Repairs",
                (f"Auto-synced from vacate settlement for tenant {t.name} (ID {t.id}). "
                 f"Charged to tenant ₹{charged:,.0f}; actual spend ₹{actual:,.0f}; "
                 f"margin ₹{charged - actual:,.0f}."),
            )
            _sync_expense(
                f"Vacate painting/cleaning - {t.name}", other, "Painting",
                f"Auto-synced from vacate settlement for tenant {t.name} (ID {t.id}).",
            )

            # Mark tenant as vacated
            t.occupancy_status = "Vacated"
            t.vacated_date     = s.settlement_date
            # Deposit is no longer held once settlement is completed.
            t.deposit          = 0
            db.session.commit()
            flash(f"✅ {t.name} vacated. Deposit settlement saved — ₹{s.return_amount:,.0f} to be returned.", "success")
            return redirect(url_for("renter_detail", tid=tid))
        except ValidationError as ve:
            db.session.rollback()
            flash(str(ve), "danger")
        except Exception as e:
            db.session.rollback()
            flash_error("Could not save the settlement.", e)
    selected_ids = []
    if existing and existing.unpaid_rent_ids:
        selected_ids = [int(i) for i in existing.unpaid_rent_ids.split(",") if i.strip().isdigit()]
    return render_template("vacate_renter.html", tenant=t, settlement=existing,
                           today=date.today(), unpaid_records=unpaid_records,
                           deposit_collected=deposit_collected, selected_ids=selected_ids,
                           deposit_payments=t.deposit_payments)

# ── EXPENSES ──────────────────────────────────────────────────────────────────
@app.route("/common-expenses")
@login_required
def common_expenses():
    return render_template("common_expenses.html",
        expenses=CommonExpense.query.order_by(CommonExpense.date.desc()).all())

@app.route("/common-expenses/add", methods=["POST"])
@login_required
def add_common_expense():
    try:
        db.session.add(CommonExpense(
            description=clean_text(request.form.get("description"), "Description", 200, required=True),
            amount=parse_money(request.form.get("amount"), "Amount"),
            category=clean_text(request.form.get("category"), "Category", 80) or "Other",
            split_units=parse_int(request.form.get("split_units"), "Split units", 1, 500,
                                  allow_blank=True, default=6),
            date=parse_date(request.form.get("date"), "Date", required=True),
            notes=clean_text(request.form.get("notes"), "Notes", 2000, multiline=True),
        ))
        db.session.commit(); flash("Common expense added.", "success")
    except ValidationError as ve:
        db.session.rollback(); flash(str(ve), "danger")
    except Exception as ex:
        db.session.rollback(); flash_error("Could not add the expense.", ex)
    return redirect(url_for("common_expenses"))

@app.route("/common-expenses/delete/<int:eid>", methods=["POST"])
@login_required
def delete_common_expense(eid):
    e=CommonExpense.query.get_or_404(eid); db.session.delete(e); db.session.commit()
    flash("Expense deleted.","warning"); return redirect(url_for("common_expenses"))

@app.route("/building-expenses")
@login_required
def building_expenses():
    return render_template("building_expenses.html",
        expenses=BuildingExpense.query.order_by(BuildingExpense.date.desc()).all())

@app.route("/building-expenses/add", methods=["POST"])
@login_required
def add_building_expense():
    receipt = None
    try:
        desc   = clean_text(request.form.get("description"), "Description", 200, required=True)
        amount = parse_money(request.form.get("amount"), "Amount")
        cat    = clean_text(request.form.get("category"), "Category", 80) or "Maintenance"
        dt     = parse_date(request.form.get("date"), "Date", required=True)
        notes  = clean_text(request.form.get("notes"), "Notes", 2000, multiline=True)
        receipt = save_upload("receipt")
        db.session.add(BuildingExpense(description=desc, amount=amount, category=cat,
                                       date=dt, notes=notes, receipt_path=receipt))
        db.session.commit(); flash("Building expense added.", "success")
    except ValidationError as ve:
        db.session.rollback(); uploads.delete_stored(app, receipt); flash(str(ve), "danger")
    except Exception as ex:
        db.session.rollback(); uploads.delete_stored(app, receipt)
        flash_error("Could not add the expense.", ex)
    return redirect(url_for("building_expenses"))

@app.route("/building-expenses/delete/<int:eid>", methods=["POST"])
@login_required
def delete_building_expense(eid):
    e=BuildingExpense.query.get_or_404(eid); db.session.delete(e); db.session.commit()
    flash("Expense deleted.","warning"); return redirect(url_for("building_expenses"))

@app.route("/income-expenses")
@login_required
def income_expenses():
    today = date.today()
    view_mode = "year" if request.args.get("view") == "year" else "month"
    sel_year, sel_month = _safe_month_year(request.args, today)

    # Build months list (last 24) and years list — pure Python, no DB
    months = []
    for i in range(24):
        m = today.month - i; y = today.year
        while m <= 0: m += 12; y -= 1
        months.append((y, m, date(y, m, 1).strftime("%B %Y")))
    years = list(range(today.year, today.year - 5, -1))

    # ── Build trend window (always 6 months ending at sel_month) ──
    trend_keys = []
    trend_labels = []
    for i in range(5, -1, -1):
        m = sel_month - i; y = sel_year
        while m <= 0: m += 12; y -= 1
        trend_keys.append(f"{y}-{m:02d}")
        trend_labels.append(datetime(y, m, 1).strftime("%b %y"))
    trend_start = date(int(trend_keys[0][:4]), int(trend_keys[0][5:7]), 1)

    if view_mode == "year":
        year_start = date(sel_year, 1, 1)
        year_end   = date(sel_year + 1, 1, 1)
        sel_label  = str(sel_year)
        month_start, month_end = year_start, year_end
        # Single query for all rent records in year
        rent_records = (RentRecord.query
                        .filter_by(year=sel_year)
                        .order_by(RentRecord.month, RentRecord.tenant_name).all())
    else:
        month_start, month_end = _month_bounds(sel_year, sel_month)
        sel_label = date(sel_year, sel_month, 1).strftime("%B %Y")
        rent_records = (RentRecord.query
                        .filter_by(month=sel_month, year=sel_year)
                        .order_by(RentRecord.tenant_name).all())

    # ── Fetch display expenses and trend expenses in ONE query each ──
    # Extend range to cover both display period and trend window
    fetch_start = min(month_start, trend_start)
    fetch_end   = month_end  # trend_end == month_end always

    all_common   = db.session.query(
        CommonExpense.date, CommonExpense.amount, CommonExpense.description,
        CommonExpense.category, CommonExpense.id
    ).filter(
        CommonExpense.date >= fetch_start,
        CommonExpense.date < fetch_end,
    ).order_by(CommonExpense.date.desc()).all()

    all_building = db.session.query(
        BuildingExpense.date, BuildingExpense.amount, BuildingExpense.description,
        BuildingExpense.category, BuildingExpense.id
    ).filter(
        BuildingExpense.date >= fetch_start,
        BuildingExpense.date < fetch_end,
    ).order_by(BuildingExpense.date.desc()).all()

    # ── Split into display vs trend in Python (no extra DB round-trips) ──
    common   = [r for r in all_common   if month_start <= r.date < month_end]
    building = [r for r in all_building if month_start <= r.date < month_end]

    # ── Also fetch paid RentRecords for trend in same window ──
    paid_rows = db.session.query(
        RentRecord.year, RentRecord.month,
        RentRecord.paid_amount, RentRecord.rent_amount,
    ).filter(
        RentRecord.status == "Paid",
        RentRecord.payment_date >= trend_start,
        RentRecord.payment_date < fetch_end,
    ).all()

    # ── Aggregate trend data in Python ──
    paid_by_month = {k: 0.0 for k in trend_keys}
    exp_by_month  = {k: 0.0 for k in trend_keys}
    for r in paid_rows:
        k = f"{r.year}-{int(r.month):02d}"
        if k in paid_by_month:
            paid_by_month[k] += float(r.paid_amount if r.paid_amount is not None else r.rent_amount or 0.0)
    for row in all_common:
        if row.date:
            k = row.date.strftime("%Y-%m")
            if k in exp_by_month:
                exp_by_month[k] += float(row.amount or 0.0)
    for row in all_building:
        if row.date:
            k = row.date.strftime("%Y-%m")
            if k in exp_by_month:
                exp_by_month[k] += float(row.amount or 0.0)
    trend_income   = [round(paid_by_month[k], 2) for k in trend_keys]
    trend_expenses = [round(exp_by_month[k],  2) for k in trend_keys]

    return render_template("income_expenses.html",
        rent_records=rent_records, common=common, building=building,
        trend_labels=trend_labels, trend_income=trend_income, trend_expenses=trend_expenses,
        months=months, years=years, sel_year=sel_year, sel_month=sel_month,
        sel_label=sel_label, view_mode=view_mode, today=today)

@app.route("/ca-audit")
@login_required
def ca_audit():
    today = date.today()
    view_mode = "year" if request.args.get("view") == "year" else "month"
    sel_year, sel_month = _safe_month_year(request.args, today)

    months = []
    for i in range(24):
        m = today.month - i; y = today.year
        while m <= 0: m += 12; y -= 1
        months.append((y, m, date(y, m, 1).strftime("%B %Y")))
    years = list(range(today.year, today.year - 5, -1))

    # FY bounds (Apr-Mar) computed once, shared between display & FY panels
    fy_start_year = sel_year if sel_month >= 4 else sel_year - 1
    fy_start = date(fy_start_year, 4, 1)
    fy_end   = date(fy_start_year + 1, 4, 1)

    if view_mode == "year":
        year_start  = date(sel_year, 1, 1)
        year_end    = date(sel_year + 1, 1, 1)
        sel_label   = str(sel_year)
        month_start, month_end = year_start, year_end
    else:
        sel_label = date(sel_year, sel_month, 1).strftime("%B %Y")
        month_start, month_end = _month_bounds(sel_year, sel_month)

    # Fetch the UNION window of [display + FY] in ONE query per table (3 total vs 10 before)
    fetch_start = min(month_start, fy_start)
    fetch_end   = max(month_end, fy_end)

    all_rr = (RentRecord.query
               .filter(
                   db.or_(
                       db.and_(RentRecord.year == fy_start_year, RentRecord.month >= 4),
                       db.and_(RentRecord.year == fy_start_year + 1, RentRecord.month < 4),
                   )
               ).order_by(RentRecord.month, RentRecord.tenant_name).all())

    # Fetch expenses and tenants in parallel-style (3 queries, all targeted)
    all_common   = (CommonExpense.query
                    .filter(CommonExpense.date >= fetch_start, CommonExpense.date < fetch_end)
                    .order_by(CommonExpense.date).all())
    all_building = (BuildingExpense.query
                    .filter(BuildingExpense.date >= fetch_start, BuildingExpense.date < fetch_end)
                    .order_by(BuildingExpense.date).all())
    tenants = Tenant.query.filter_by(occupancy_status="Active").all()

    # Split in Python - zero extra DB round-trips
    if view_mode == "year":
        rent_records = [r for r in all_rr if r.year == sel_year]
    else:
        rent_records = [r for r in all_rr if r.month == sel_month and r.year == sel_year]

    common      = [e for e in all_common   if month_start <= e.date < month_end]
    building    = [e for e in all_building if month_start <= e.date < month_end]
    fy_records  = all_rr
    fy_common   = [e for e in all_common   if fy_start <= e.date < fy_end]
    fy_building = [e for e in all_building if fy_start <= e.date < fy_end]

    fy_label = f"FY {fy_start_year}–{str(fy_start_year+1)[2:]}"
    return render_template("ca_audit.html",
        rent_records=rent_records, common=common, building=building,
        fy_records=fy_records, fy_common=fy_common, fy_building=fy_building,
        tenants=tenants, months=months, years=years,
        sel_year=sel_year, sel_month=sel_month, sel_label=sel_label,
        view_mode=view_mode, fy_label=fy_label, today=today)
# ── UNIT ANALYTICS ────────────────────────────────────────────────────────────
@app.route("/unit-analytics")
@login_required
def unit_analytics():
    """Per-unit performance: who lives there, what it earned, what it cost.

    Groups every tenant (current and past) by their unit so you can compare
    units rather than people — occupancy, collection rate, arrears and the
    margin kept from vacate repair settlements.
    """
    import json
    today = date.today()

    try:
        sel_year = int(request.args.get("year", 0))
    except (TypeError, ValueError):
        sel_year = 0            # 0 = all time
    if sel_year and (sel_year < 2000 or sel_year > 2100):
        sel_year = 0

    tenants = Tenant.query.order_by(Tenant.unit, Tenant.name).all()

    rec_q = RentRecord.query
    if sel_year:
        rec_q = rec_q.filter(RentRecord.year == sel_year)
    records = rec_q.all()

    recs_by_tenant = {}
    for r in records:
        recs_by_tenant.setdefault(r.tenant_id, []).append(r)

    settlements = {s.tenant_id: s for s in VacateSettlement.query.all()}

    units = {}
    for t in tenants:
        key = (t.unit or "").strip() or "Unassigned"
        u = units.setdefault(key, {
            "unit": key, "unit_numbers": set(),
            "current_tenant": None, "current_rent": 0.0,
            "occupied": False, "tenant_count": 0, "past_tenants": [],
            "billed": 0.0, "collected": 0.0, "outstanding": 0.0,
            "months_tracked": 0, "months_paid": 0, "months_overdue": 0,
            "deposit_agreed": 0.0, "deposit_collected": 0.0, "deposit_balance": 0.0,
            "repair_charged": 0.0, "repair_actual": 0.0, "repair_profit": 0.0,
            "rent_recovered": 0.0, "last_payment": None,
        })
        if t.unit_number:
            u["unit_numbers"].add(t.unit_number)
        u["tenant_count"] += 1

        if t.occupancy_status == "Active":
            u["occupied"] = True
            u["current_tenant"] = t
            u["current_rent"] += float(t.amount or 0)
            u["deposit_agreed"]    += float(t.deposit or 0)
            u["deposit_collected"] += t.deposit_paid()
            u["deposit_balance"]   += t.deposit_balance()
        else:
            u["past_tenants"].append(t)

        for r in recs_by_tenant.get(t.id, []):
            u["months_tracked"] += 1
            u["billed"] += float(r.rent_amount or 0)
            if r.status == "Paid":
                u["months_paid"] += 1
                u["collected"] += float(r.paid_amount or r.rent_amount or 0)
                if r.payment_date and (u["last_payment"] is None or r.payment_date > u["last_payment"]):
                    u["last_payment"] = r.payment_date
            else:
                u["outstanding"] += float(r.rent_amount or 0)
                if r.is_overdue(today):
                    u["months_overdue"] += 1

        s = settlements.get(t.id)
        if s and (not sel_year or (s.settlement_date and s.settlement_date.year == sel_year)):
            u["repair_charged"] += float(s.repair_charged or s.repair_cost or 0)
            u["repair_actual"]  += float(s.repair_actual or 0)
            u["repair_profit"]  += s.repair_profit()
            u["rent_recovered"] += float(s.unpaid_rent or 0)

    unit_list = []
    for u in units.values():
        u["unit_numbers"] = ", ".join(sorted(u["unit_numbers"]))
        u["collection_rate"] = round(u["collected"] / u["billed"] * 100) if u["billed"] else 0
        u["avg_monthly"] = round(u["collected"] / u["months_paid"]) if u["months_paid"] else 0
        u["total_earned"] = u["collected"] + u["repair_profit"]
        unit_list.append(u)
    unit_list.sort(key=lambda x: (-x["collected"], x["unit"]))

    totals = {
        "units": len(unit_list),
        "occupied": sum(1 for u in unit_list if u["occupied"]),
        "vacant": sum(1 for u in unit_list if not u["occupied"]),
        "billed": sum(u["billed"] for u in unit_list),
        "collected": sum(u["collected"] for u in unit_list),
        "outstanding": sum(u["outstanding"] for u in unit_list),
        "deposit_balance": sum(u["deposit_balance"] for u in unit_list),
        "repair_profit": sum(u["repair_profit"] for u in unit_list),
    }
    totals["collection_rate"] = (
        round(totals["collected"] / totals["billed"] * 100) if totals["billed"] else 0
    )
    totals["occupancy_rate"] = (
        round(totals["occupied"] / totals["units"] * 100) if totals["units"] else 0
    )

    years = sorted({r.year for r in RentRecord.query.with_entities(RentRecord.year).all()}
                   | {today.year}, reverse=True)

    chart_data = ({
        "labels":      [u["unit"] for u in unit_list],
        "collected":   [round(u["collected"]) for u in unit_list],
        "outstanding": [round(u["outstanding"]) for u in unit_list],
        "rates":       [u["collection_rate"] for u in unit_list],
        "occupancy":   [totals["occupied"], totals["vacant"]],
    })

    return render_template("unit_analytics.html",
        units=unit_list, totals=totals, years=years, sel_year=sel_year,
        chart_data=chart_data, today=today)

@app.route("/reminders")
@login_required
def reminders():
    pending_tenants = (Tenant.query
                       .filter_by(status="Pending", occupancy_status="Active")
                       .all())
    logs = (ReminderLog.query
            .order_by(ReminderLog.sent_at.desc())
            .limit(50).all())
    return render_template("reminders.html", tenants=pending_tenants, logs=logs)

@app.route("/change-password", methods=["GET", "POST"])
@sec.limiter.limit("10 per hour", methods=["POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        admin   = current_user()
        msg = check_password_strength(new_pw, admin.username, admin.email or "")
        if not sec.verify_password(admin.password_hash, current):
            sec.security_log("password_change_failed", level="warning", reason="bad_current")
            flash("Current password incorrect.", "danger")
        elif new_pw != confirm:
            flash("Passwords don't match.", "danger")
        elif msg:
            flash(msg, "danger")
        elif sec.verify_password(admin.password_hash, new_pw):
            flash("The new password must be different from the current one.", "danger")
        else:
            _set_password(admin, new_pw)
            db.session.commit()
            session["sv"] = admin.session_version      # keep THIS session; all others are revoked
            sec.security_log("password_changed", user=admin.username)
            flash("Password changed. Other devices have been signed out.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html", security_questions=sec.SECURITY_QUESTIONS)

@app.route("/change-username", methods=["POST"])
@sec.limiter.limit("10 per hour")
@login_required
def change_username():
    admin = current_user()
    try:
        new_username = clean_username(request.form.get("new_username"), "New username")
    except ValidationError as ve:
        flash(str(ve), "danger")
        return redirect(url_for("change_password"))
    taken = unscoped(Admin.query).filter(db.func.lower(Admin.username) == new_username).first()
    if not sec.verify_password(admin.password_hash, request.form.get("confirm_password_username", "")):
        sec.security_log("username_change_failed", level="warning", reason="bad_password")
        flash("Incorrect password — username not changed.", "danger")
    elif taken and taken.id != admin.id:
        flash("That username is already taken.", "danger")
    else:
        old = admin.username
        admin.username = new_username
        db.session.commit()
        session["admin_username"] = new_username
        sec.security_log("username_changed", old=old, new=new_username)
        flash(f"Username changed to '{new_username}'.", "success")
        return redirect(url_for("dashboard"))
    return redirect(url_for("change_password"))


@app.route("/change-security-question", methods=["POST"])
@sec.limiter.limit("10 per hour")
@login_required
def change_security_question():
    admin = current_user()
    question = (request.form.get("security_question") or "").strip()
    answer = (request.form.get("security_answer") or "").strip()
    current = request.form.get("confirm_password_secq", "")
    if not sec.verify_password(admin.password_hash, current):
        sec.security_log("security_question_change_failed", level="warning", reason="bad_password")
        flash("Incorrect password — security question not changed.", "danger")
    elif question not in sec.SECURITY_QUESTIONS:
        flash("Choose one of the listed security questions.", "danger")
    elif len(answer) < 2:
        flash("Enter an answer to your security question.", "danger")
    else:
        admin.security_question = question
        admin.security_answer_hash = sec.hash_security_answer(answer)
        db.session.commit()
        sec.security_log("security_question_changed", user=admin.username)
        flash("Security question updated.", "success")
        return redirect(url_for("dashboard"))
    return redirect(url_for("change_password"))

# ── REST API ──────────────────────────────────────────────────────────────────
# ── DANGER ZONE — DELETE ALL DATA ────────────────────────────────────────────
def _new_captcha():
    """Generate a simple arithmetic captcha and stash the answer in session."""
    import secrets
    a, b = 3 + secrets.randbelow(17), 2 + secrets.randbelow(8)
    op = secrets.choice(["+", "-"])
    if op == "-" and b > a:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    session["reset_captcha"] = str(answer)
    return f"{a} {op} {b}"

@app.route("/reset-data", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["danger"], methods=["POST"])
@login_required
def reset_data():
    """Permanently wipe this account's data. Other accounts are untouched."""
    oid = session.get("owner_id")
    counts = {
        "Renters":            Tenant.query.count(),
        "Rent records":       RentRecord.query.count(),
        "Deposit payments":   DepositPayment.query.count(),
        "Vacate settlements": VacateSettlement.query.count(),
        "Common expenses":    CommonExpense.query.count(),
        "Building expenses":  BuildingExpense.query.count(),
        "Reminder logs":      ReminderLog.query.count(),
        "Rent revisions":     RentAmountHistory.query.count(),
    }

    if request.method == "POST":
        admin       = current_user()
        password    = request.form.get("password", "")
        captcha_in  = request.form.get("captcha", "").strip()
        expected    = session.get("reset_captcha")
        phrase      = request.form.get("confirm_phrase", "").strip()

        errors = []
        if not admin or not sec.verify_password(admin.password_hash, password):
            errors.append("Password is incorrect.")
        if not expected or captcha_in != expected:
            errors.append("Captcha answer is incorrect.")
        if phrase != "DELETE ALL DATA":
            errors.append('You must type exactly: DELETE ALL DATA')

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("reset_data.html", counts=counts,
                                   captcha=_new_captcha(),
                                   scope=request.form.get("scope", "all"))

        scope = choice(request.form.get("scope"), ("all", "expenses", "rent"), "Scope", default="all")
        try:
            if scope == "expenses":
                targets = [CommonExpense, BuildingExpense]
                label = "All expense records"
            elif scope == "rent":
                targets = [RentRecord, RentAmountHistory]
                label = "All rent history"
            else:
                targets = [RentRecord, DepositPayment, VacateSettlement, ReminderLog,
                           RentAmountHistory, Tenant, CommonExpense, BuildingExpense]
                label = "All data"

            if scope not in ("expenses", "rent"):
                _purge_owner_files(oid)              # erase stored documents too
            sec.security_log("data_reset", scope=scope, level="warning")
            deleted = 0
            for model in targets:
                deleted += unscoped(model.query).filter_by(owner_id=oid).delete(
                    synchronize_session=False)
            db.session.commit()
            session.pop("reset_captcha", None)
            flash(f"{label} deleted — {deleted} record(s) removed. This cannot be undone.", "warning")
            return redirect(url_for("dashboard"))
        except Exception as e:
            db.session.rollback()
            flash_error("Delete failed.", e)

    return render_template("reset_data.html", counts=counts,
                           captcha=_new_captcha(), scope="all")

@app.route("/api/dashboard")
@sec.limiter.limit(LIMITS["api"])
@login_required
def api_dashboard():
    today = date.today()
    month_start, month_end = _month_bounds(today.year, today.month)
    cur_records = RentRecord.query.filter_by(month=today.month, year=today.year).all()
    paid_recs    = [r for r in cur_records if r.status == "Paid"]
    pending_recs = [r for r in cur_records if r.status != "Paid"]
    monthly = {}
    for i in range(5, -1, -1):
        m = today.month - i; y = today.year
        while m <= 0: m += 12; y -= 1
        monthly[datetime(y, m, 1).strftime("%b")] = 0
    for r in RentRecord.query.filter_by(status="Paid").all():
        if r.payment_date:
            k = r.payment_date.strftime("%b")
            if k in monthly: monthly[k] += (r.paid_amount or r.rent_amount)
    total_common = db.session.query(
        db.func.coalesce(db.func.sum(CommonExpense.amount), 0.0)
    ).filter(
        CommonExpense.date >= month_start,
        CommonExpense.date < month_end,
    ).scalar() or 0.0
    total_building = db.session.query(
        db.func.coalesce(db.func.sum(BuildingExpense.amount), 0.0)
    ).filter(
        BuildingExpense.date >= month_start,
        BuildingExpense.date < month_end,
    ).scalar() or 0.0

    return jsonify({"total_tenants": len(cur_records), "paid_count": len(paid_recs),
        "pending_count": len(pending_recs),
        "collected": sum(r.paid_amount or r.rent_amount for r in paid_recs),
        "pending_amount": sum(r.rent_amount for r in pending_recs),
        "monthly_income": monthly,
        "total_common": total_common,
        "total_building": total_building})

@app.route("/health")
def health():
    return jsonify({"status":"ok","time":datetime.utcnow().isoformat()})

# ── LEGACY COMPAT ─────────────────────────────────────────────────────────────
@app.route("/tenant/add", methods=["GET","POST"])
@login_required
def add_tenant(): return redirect(url_for("add_renter"))

@app.route("/tenant/edit/<int:tid>", methods=["GET","POST"])
@login_required
def edit_tenant(tid): return redirect(url_for("edit_renter", tid=tid))

@app.route("/tenant/delete/<int:tid>", methods=["POST"])
@login_required
def delete_tenant(tid): return redirect(url_for("delete_renter", tid=tid))

# ── EXCEL UPLOAD ─────────────────────────────────────────────────────────────
MAX_EXCEL_BYTES   = 8 * 1024 * 1024
MAX_IMPORT_ROWS   = 5000            # per sheet
MAX_UNZIPPED      = 80 * 1024 * 1024

@app.route("/upload/excel", methods=["GET", "POST"])
@sec.limiter.limit(LIMITS["excel_import"], methods=["POST"])
@login_required
def upload_excel():
    if request.method == "GET":
        return render_template("upload_excel.html")

    import io, zipfile, math
    from openpyxl import load_workbook

    f = request.files.get("excel_file")
    if not f or not (f.filename or "").lower().endswith(".xlsx"):
        flash("Please upload a valid .xlsx file.", "danger")
        return redirect(url_for("upload_excel"))
    data = f.stream.read(MAX_EXCEL_BYTES + 1)
    if len(data) > MAX_EXCEL_BYTES:
        flash(f"Spreadsheet is too large (max {MAX_EXCEL_BYTES // (1024*1024)} MB).", "danger")
        return redirect(url_for("upload_excel"))
    # .xlsx is a ZIP: check the magic bytes and defuse zip bombs BEFORE parsing.
    try:
        if data[:4] != b"PK\x03\x04":
            raise ValueError("not a zip")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > 300 or sum(i.file_size for i in infos) > MAX_UNZIPPED:
                raise ValueError("zip bomb")
    except Exception:
        sec.security_log("excel_rejected", level="warning")
        flash("That file is not a valid .xlsx workbook.", "danger")
        return redirect(url_for("upload_excel"))

    try:
        wb = load_workbook(io.BytesIO(data), data_only=True)   # cached values only; formulas never evaluated
    except Exception as ex:
        app.logger.warning("Excel load failed: %s", type(ex).__name__)
        flash("Could not read the workbook. Make sure it is a valid .xlsx file.", "danger")
        return redirect(url_for("upload_excel"))
    sec.security_log("excel_import_started", bytes=len(data))

    def _rows_of(ws):
        return list(ws.iter_rows(min_row=3, max_row=2 + MAX_IMPORT_ROWS))

    stats = {"tenants":0,"rent_records":0,"common_expenses":0,
             "building_expenses":0,"vacate_settlements":0,
             "deposit_payments":0,"skipped":0}
    errors = []

    def cell(row, idx):
        v = row[idx].value if idx < len(row) else None
        if isinstance(v, str):
            try:    # strip control/bidi chars, bound the length; markup is inert (output is escaped)
                return clean_text(v, "cell", 500, multiline=True, allow_markup=True) or None
            except ValidationError:
                return None
        return v

    def to_date(v):
        if v is None: return None
        if isinstance(v, (date, datetime)): return v.date() if isinstance(v, datetime) else v
        try:
            from datetime import datetime as dt
            for fmt in ("%Y-%m-%d","%d-%m-%Y","%d/%m/%Y","%d-%b-%Y","%d %b %Y"):
                try: return dt.strptime(str(v).strip(), fmt).date()
                except: pass
        except: pass
        return None

    def to_float(v):
        """Strict: finite, non-negative, bounded — else None (never NaN/inf/negative)."""
        if v is None or v == "" or isinstance(v, bool):
            return None
        try:
            if isinstance(v, (int, float)):
                if not math.isfinite(v):
                    return None
                v = f"{round(float(v), 2):.2f}"
            return parse_money(str(v), "value")
        except ValidationError:
            return None

    # ── Tenants sheet ──────────────────────────────────────────────────────
    if "Tenants" in wb.sheetnames:
        ws = wb["Tenants"]
        rows = _rows_of(ws)   # row1=title, row2=header
        for row in rows:
            name = cell(row, 1)
            if not name: continue
            try:
                phone       = str(cell(row, 2) or "")[:20]
                email       = str(cell(row, 3) or "")[:120]
                unit        = str(cell(row, 4) or "")[:20]
                unit_number = str(cell(row, 5) or "")[:30]
                occupancy   = "Vacated" if str(cell(row, 6) or "").lower() == "vacated" else "Active"
                amount      = to_float(cell(row, 7)) or 0.0
                due_day     = int(to_float(cell(row, 8)) or 5)
                deposit     = to_float(cell(row, 9)) or 0.0
                dep_paid    = to_float(cell(row,10))       # Deposit Collected
                join_date   = to_date(cell(row,13))
                vacated_date= to_date(cell(row,14))
                status      = "Paid" if str(cell(row,15) or "").lower() == "paid" else "Pending"
                pay_method  = str(cell(row,16) or "")[:20]
                notes       = str(cell(row,17) or "")
                if not (1 <= due_day <= 31): due_day = 5
                existing = Tenant.query.filter_by(name=name, phone=phone).first()
                if existing:
                    existing.email=email; existing.unit=unit
                    existing.unit_number=unit_number; existing.due_day=due_day
                    existing.occupancy_status=occupancy; existing.amount=amount
                    existing.deposit=deposit; existing.join_date=join_date
                    existing.vacated_date=vacated_date; existing.status=status
                    existing.payment_method=pay_method; existing.notes=notes
                    t_obj = existing
                else:
                    t_obj = Tenant(
                        name=name, phone=phone, email=email, unit=unit,
                        unit_number=unit_number,
                        amount=amount, deposit=deposit,
                        due_day=due_day, status=status,
                        join_date=join_date, vacated_date=vacated_date,
                        occupancy_status=occupancy,
                        payment_method=pay_method, notes=notes)
                    db.session.add(t_obj)
                    stats["tenants"] += 1
                # Record the collected deposit as an instalment when the
                # sheet has no separate Deposit Payments rows for them.
                db.session.flush()
                if dep_paid and dep_paid > 0 and not DepositPayment.query.filter_by(tenant_id=t_obj.id).first():
                    db.session.add(DepositPayment(
                        tenant_id=t_obj.id, tenant_name=t_obj.name, owner_id=t_obj.owner_id,
                        amount=dep_paid, payment_date=join_date, method="cash",
                        notes="Imported from spreadsheet."))
                    stats["deposit_payments"] += 1
            except Exception as ex:
                errors.append(f"Tenants row '{name}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    # ── Rent Records sheet ─────────────────────────────────────────────────
    if "Rent Records" in wb.sheetnames:
        ws = wb["Rent Records"]
        for row in _rows_of(ws):
            tenant_name = cell(row, 1)
            if not tenant_name: continue
            try:
                month       = int(cell(row, 3) or 0)
                year        = int(cell(row, 4) or 0)
                if not (1 <= month <= 12) or year < 2000: continue
                rent_amount = to_float(cell(row, 9)) or 0.0
                paid_amount = to_float(cell(row,10)) or 0.0
                status      = "Paid" if str(cell(row,11) or "").lower() == "paid" else "Pending"
                pay_date    = to_date(cell(row,12))
                pay_method  = str(cell(row,13) or "")[:30]
                txn_id      = str(cell(row,14) or "")[:100]
                cf_val      = cell(row,15)
                carried     = str(cf_val).lower() in ("yes","true","1") if cf_val else False
                notes_v     = str(cell(row,16) or "")
                tenant = Tenant.query.filter_by(name=tenant_name).first()
                tid    = tenant.id if tenant else None
                existing = RentRecord.query.filter_by(
                    tenant_name=tenant_name, month=month, year=year).first()
                if existing:
                    existing.rent_amount=rent_amount; existing.paid_amount=paid_amount
                    existing.status=status; existing.payment_date=pay_date
                    existing.payment_method=pay_method; existing.transaction_id=txn_id
                    existing.carried_forward=carried; existing.notes=notes_v
                elif tid:
                    db.session.add(RentRecord(
                        tenant_id=tid, tenant_name=tenant_name,
                        owner_id=(tenant.owner_id if tenant else None),
                        month=month, year=year,
                        rent_amount=rent_amount, paid_amount=paid_amount,
                        status=status, payment_date=pay_date,
                        payment_method=pay_method, transaction_id=txn_id,
                        carried_forward=carried, notes=notes_v))
                    stats["rent_records"] += 1
            except Exception as ex:
                errors.append(f"Rent Records row '{tenant_name}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    # ── Common Expenses sheet ──────────────────────────────────────────────
    if "Common Expenses" in wb.sheetnames:
        ws = wb["Common Expenses"]
        for row in _rows_of(ws):
            desc = cell(row, 1)
            if not desc or str(desc).upper() == "TOTAL": continue
            try:
                category    = str(cell(row, 2) or "Other")
                exp_date    = to_date(cell(row, 3)) or date.today()
                amount      = to_float(cell(row, 4)) or 0.0
                split_units = max(1, min(500, int(cell(row, 5) or 6)))
                notes_v     = str(cell(row, 7) or "")
                db.session.add(CommonExpense(
                    description=desc, category=category, date=exp_date,
                    amount=amount, split_units=split_units, notes=notes_v))
                stats["common_expenses"] += 1
            except Exception as ex:
                errors.append(f"Common Expenses row '{desc}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    # ── Building Expenses sheet ────────────────────────────────────────────
    if "Building Expenses" in wb.sheetnames:
        ws = wb["Building Expenses"]
        for row in _rows_of(ws):
            desc = cell(row, 1)
            if not desc or str(desc).upper() == "TOTAL": continue
            try:
                category = str(cell(row, 2) or "Maintenance")
                exp_date = to_date(cell(row, 3)) or date.today()
                amount   = to_float(cell(row, 4)) or 0.0
                notes_v  = str(cell(row, 6) or "")
                db.session.add(BuildingExpense(
                    description=desc, category=category, date=exp_date,
                    amount=amount, notes=notes_v))
                stats["building_expenses"] += 1
            except Exception as ex:
                errors.append(f"Building Expenses row '{desc}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    # ── Vacate Settlements sheet ───────────────────────────────────────────
    if "Vacate Settlements" in wb.sheetnames:
        ws = wb["Vacate Settlements"]
        for row in _rows_of(ws):
            tenant_name = cell(row, 1)
            if not tenant_name: continue
            try:
                settle_date   = to_date(cell(row, 3))
                deposit_held  = to_float(cell(row, 4)) or 0.0
                repair_charged= to_float(cell(row, 5)) or 0.0
                repair_actual = to_float(cell(row, 6)) or 0.0
                unpaid_rent   = to_float(cell(row, 8)) or 0.0
                unpaid_note   = str(cell(row, 9) or "")
                other_deduct  = to_float(cell(row,10)) or 0.0
                return_amount = to_float(cell(row,11)) or 0.0
                ded_notes     = str(cell(row,12) or "")
                tenant = Tenant.query.filter_by(name=tenant_name).first()
                if not tenant:
                    errors.append(f"Vacate Settlements: tenant '{tenant_name}' not found")
                    stats["skipped"] += 1
                    continue
                existing = VacateSettlement.query.filter_by(tenant_id=tenant.id).first()
                if existing:
                    s_obj = existing
                else:
                    s_obj = VacateSettlement(tenant_id=tenant.id, owner_id=tenant.owner_id)
                    db.session.add(s_obj)
                    stats["vacate_settlements"] += 1
                s_obj.deposit_held=deposit_held
                s_obj.repair_charged=repair_charged; s_obj.repair_actual=repair_actual
                s_obj.repair_cost=repair_charged
                s_obj.unpaid_rent=unpaid_rent; s_obj.unpaid_rent_note=unpaid_note
                s_obj.other_deduction=other_deduct; s_obj.return_amount=return_amount
                s_obj.settlement_date=settle_date; s_obj.deduction_notes=ded_notes
            except Exception as ex:
                errors.append(f"Vacate Settlements row '{tenant_name}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    # ── Deposit Payments sheet ─────────────────────────────────────────────
    if "Deposit Payments" in wb.sheetnames:
        ws = wb["Deposit Payments"]
        for row in _rows_of(ws):
            tenant_name = cell(row, 1)
            if not tenant_name or str(tenant_name).upper() == "TOTAL": continue
            try:
                pay_date = to_date(cell(row, 3))
                amount   = to_float(cell(row, 4)) or 0.0
                method   = str(cell(row, 5) or "cash")
                txn      = str(cell(row, 6) or "")
                notes_v  = str(cell(row, 7) or "")
                if amount <= 0: continue
                tenant = Tenant.query.filter_by(name=tenant_name).first()
                if not tenant:
                    errors.append(f"Deposit Payments: tenant '{tenant_name}' not found")
                    stats["skipped"] += 1
                    continue
                # Skip exact duplicates so re-importing the same file is safe
                dup = DepositPayment.query.filter_by(
                    tenant_id=tenant.id, amount=amount, payment_date=pay_date).first()
                if dup: continue
                db.session.add(DepositPayment(
                    tenant_id=tenant.id, tenant_name=tenant.name, owner_id=tenant.owner_id,
                    amount=amount, payment_date=pay_date,
                    method=method, transaction_id=txn, notes=notes_v))
                stats["deposit_payments"] += 1
            except Exception as ex:
                errors.append(f"Deposit Payments row '{tenant_name}': invalid or unsupported data")
                stats["skipped"] += 1
        db.session.commit()

    sec.security_log("excel_import_done", **{k: v for k, v in stats.items()})
    summary = (f"Import complete — "
               f"{stats['tenants']} tenants, "
               f"{stats['rent_records']} rent records, "
               f"{stats['common_expenses']} common expenses, "
               f"{stats['building_expenses']} building expenses, "
               f"{stats['vacate_settlements']} settlements, "
               f"{stats['deposit_payments']} deposit payments added.")
    flash(summary, "success")
    if errors:
        for e in errors[:5]:
            flash(e, "warning")
        if len(errors) > 5:
            flash(f"…and {len(errors)-5} more warnings.", "warning")
    return redirect(url_for("dashboard"))


# ── EXCEL EXPORT ─────────────────────────────────────────────────────────────
@app.route("/download/excel")
@sec.limiter.limit(LIMITS["excel_export"])
@login_required
def download_excel():
    import io
    from openpyxl import Workbook
    from openpyxl.styles import (Font, PatternFill, Alignment,
                                  Border, Side, GradientFill)
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    wb.remove(wb.active)

    # ── Colour palette ────────────────────────────────────────────────────────
    C_HEADER_FILL  = "1A1F35"   # dark navy  – header row bg
    C_HEADER_FONT  = "F5C842"   # gold       – header text
    C_ALT_ROW      = "F4F6FB"   # light grey – alternate rows
    C_GREEN_BG     = "D6F5E3"   # paid
    C_GREEN_FG     = "1A7A45"
    C_AMBER_BG     = "FFF3CD"   # pending
    C_AMBER_FG     = "7A5000"
    C_RED_BG       = "FFE0E0"   # vacated
    C_RED_FG       = "9B1C1C"
    C_TITLE_FILL   = "0F1117"   # deep dark  – sheet title
    C_TITLE_FONT   = "F5C842"

    thin = Side(style="thin", color="D0D4E0")
    bdr  = Border(left=thin, right=thin, top=thin, bottom=thin)

    def _header_fill(): return PatternFill("solid", fgColor=C_HEADER_FILL)
    def _alt_fill():    return PatternFill("solid", fgColor=C_ALT_ROW)
    def _fill(c):       return PatternFill("solid", fgColor=c)

    def make_sheet(name, columns):
        ws = wb.create_sheet(title=name)
        # Title row
        ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(columns))
        tc = ws.cell(1, 1, name)
        tc.font      = Font(name="Arial", bold=True, size=13, color=C_TITLE_FONT)
        tc.fill      = _fill(C_TITLE_FILL)
        tc.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 28
        # Header row
        for ci, col in enumerate(columns, 1):
            c = ws.cell(2, ci, col)
            c.font      = Font(name="Arial", bold=True, size=10, color=C_HEADER_FONT)
            c.fill      = _header_fill()
            c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            c.border    = bdr
        ws.row_dimensions[2].height = 22
        return ws

    def auto_width(ws, min_w=10, max_w=40):
        for col in ws.columns:
            best = min_w
            for cell in col:
                try:
                    v = len(str(cell.value)) if cell.value else 0
                    if v > best: best = v
                except: pass
            ws.column_dimensions[get_column_letter(col[0].column)].width = min(best + 3, max_w)

    def data_cell(ws, row, col, value, fill=None, bold=False, num_fmt=None, align="left"):
        c = ws.cell(row, col, excel_safe(value))   # neutralise =,+,-,@ formula injection
        c.font      = Font(name="Arial", size=9, bold=bold,
                           color="111827" if not fill or fill == C_ALT_ROW else "000000")
        c.alignment = Alignment(horizontal=align, vertical="center", wrap_text=False)
        c.border    = bdr
        if fill:  c.fill = _fill(fill)
        if num_fmt: c.number_format = num_fmt
        return c

    currency_fmt = '₹#,##0.00'
    date_fmt     = 'DD-MMM-YYYY'

    # ── 1. Tenants ────────────────────────────────────────────────────────────
    cols_t = ["#","Name","Phone","Email","Unit","Unit No","Occupancy",
              "Monthly Rent (₹)","Due Day","Deposit Agreed (₹)",
              "Deposit Collected (₹)","Deposit Balance (₹)","Deposit Status",
              "Join Date","Vacated Date",
              "Current Status","Payment Method","Notes"]
    ws1 = make_sheet("Tenants", cols_t)
    tenants = Tenant.query.order_by(Tenant.occupancy_status, Tenant.name).all()
    for ri, t in enumerate(tenants, 3):
        is_vacated = t.occupancy_status == "Vacated"
        row_fill   = C_RED_BG if is_vacated else (C_ALT_ROW if ri % 2 == 1 else None)
        row = [t.id, t.name, t.phone, t.email or "", t.unit or "", t.unit_number or "",
               t.occupancy_status, t.amount, t.get_due_day(), t.deposit or 0,
               t.deposit_paid(), t.deposit_balance(), t.deposit_status(),
               t.join_date, t.vacated_date,
               t.status, t.payment_method or "", t.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci in (8,10,11,12) else (date_fmt if ci in (14,15) else None)
            fg  = (C_RED_FG if is_vacated else None) if ci == 7 else None
            c   = data_cell(ws1, ri, ci, v, row_fill, num_fmt=fmt)
            if fg: c.font = Font(name="Arial", size=9, color=fg, bold=True)
        ws1.row_dimensions[ri].height = 18
    # Legend
    leg_row = len(tenants) + 4
    ws1.cell(leg_row,   1, "🔴 Red rows = Vacated tenants  ·  Due Day = day of the FOLLOWING month rent is collected").font = Font(name="Arial", size=8, italic=True, color="9B1C1C")
    auto_width(ws1)

    # ── 2. Rent Records ───────────────────────────────────────────────────────
    cols_r = ["#","Tenant","Unit","Month","Year","Rent Month","Billing Cycle",
              "Billed In","Due Date",
              "Rent (₹)","Paid (₹)","Status","Payment Date",
              "Method","Transaction ID","Carried Forward","Notes"]
    ws2 = make_sheet("Rent Records", cols_r)
    records = (RentRecord.query
               .options(joinedload(RentRecord.tenant))
               .order_by(RentRecord.year.desc(), RentRecord.month.desc(), RentRecord.tenant_name)
               .all())
    for ri, r in enumerate(records, 3):
        is_paid   = r.status == "Paid"
        row_fill  = C_GREEN_BG if is_paid else C_AMBER_BG
        unit      = r.tenant.unit if r.tenant else ""
        due_d  = r.due_date_obj() if r.tenant else None
        row = [r.id, r.tenant_name or "", unit, r.month, r.year,
               r.month_label(), r.cycle_label(), r.billed_in_label(), due_d,
               r.rent_amount, r.paid_amount or 0,
               r.status, r.payment_date,
               r.payment_method or "", r.transaction_id or "",
               "Yes" if r.carried_forward else "No", r.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci in (10,11) else (date_fmt if ci in (9,13) else None)
            c   = data_cell(ws2, ri, ci, v, row_fill, num_fmt=fmt)
            if ci == 12:
                c.font = Font(name="Arial", size=9, bold=True,
                              color=C_GREEN_FG if is_paid else C_AMBER_FG)
        ws2.row_dimensions[ri].height = 18
    # Legend
    leg_row = len(records) + 4
    ws2.cell(leg_row,   1, "🟢 Green = Paid   🟡 Amber = Pending").font = Font(name="Arial", size=8, italic=True)
    auto_width(ws2)

    # ── 3. Common Expenses ────────────────────────────────────────────────────
    cols_c = ["#","Description","Category","Date","Total Amount (₹)",
              "Split Units","Per Unit Cost (₹)","Notes"]
    ws3 = make_sheet("Common Expenses", cols_c)
    common = CommonExpense.query.order_by(CommonExpense.date.desc()).all()
    for ri, e in enumerate(common, 3):
        per_unit = round(e.amount / e.split_units, 2) if e.split_units else e.amount
        row_fill = C_ALT_ROW if ri % 2 == 1 else None
        row = [e.id, e.description, e.category, e.date,
               e.amount, e.split_units, per_unit, e.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci in (5,7) else (date_fmt if ci == 4 else None)
            align = "right" if ci in (5,6,7) else "left"
            data_cell(ws3, ri, ci, v, row_fill, num_fmt=fmt, align=align)
        ws3.row_dimensions[ri].height = 18
    # Totals row
    tot_row = len(common) + 3
    ws3.cell(tot_row, 1, "TOTAL").font = Font(name="Arial", bold=True, size=9)
    ws3.cell(tot_row, 5, f"=SUM(E3:E{tot_row-1})").number_format = currency_fmt
    ws3.cell(tot_row, 7, f"=SUM(G3:G{tot_row-1})").number_format = currency_fmt
    for ci in range(1, 9):
        ws3.cell(tot_row, ci).fill   = _fill("E8ECF8")
        ws3.cell(tot_row, ci).border = bdr
        ws3.cell(tot_row, ci).font   = Font(name="Arial", bold=True, size=9)
    auto_width(ws3)

    # ── 4. Building Expenses ──────────────────────────────────────────────────
    cols_b = ["#","Description","Category","Date","Amount (₹)","Receipt","Notes"]
    ws4 = make_sheet("Building Expenses", cols_b)
    building = BuildingExpense.query.order_by(BuildingExpense.date.desc()).all()
    for ri, e in enumerate(building, 3):
        row_fill = C_ALT_ROW if ri % 2 == 1 else None
        receipt  = "Yes" if e.receipt_path else "No"
        row = [e.id, e.description, e.category, e.date,
               e.amount, receipt, e.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci == 5 else (date_fmt if ci == 4 else None)
            data_cell(ws4, ri, ci, v, row_fill, num_fmt=fmt,
                      align="right" if ci == 5 else "left")
        ws4.row_dimensions[ri].height = 18
    tot_row = len(building) + 3
    ws4.cell(tot_row, 1, "TOTAL").font = Font(name="Arial", bold=True, size=9)
    ws4.cell(tot_row, 5, f"=SUM(E3:E{tot_row-1})").number_format = currency_fmt
    for ci in range(1, 8):
        ws4.cell(tot_row, ci).fill   = _fill("E8ECF8")
        ws4.cell(tot_row, ci).border = bdr
        ws4.cell(tot_row, ci).font   = Font(name="Arial", bold=True, size=9)
    auto_width(ws4)

    # ── 5. Vacate Settlements ─────────────────────────────────────────────────
    cols_v = ["#","Tenant","Unit","Settlement Date","Deposit Collected (₹)",
              "Repair Charged (₹)","Repair Actual (₹)","Repair Margin (₹)",
              "Unpaid Rent Recovered (₹)","Unpaid Rent Months",
              "Other Deduction (₹)","Amount Returned (₹)",
              "Deduction Notes"]
    ws5 = make_sheet("Vacate Settlements", cols_v)
    settlements = (VacateSettlement.query
                   .options(joinedload(VacateSettlement.tenant))
                   .order_by(VacateSettlement.settlement_date.desc())
                   .all())
    for ri, s in enumerate(settlements, 3):
        unit = s.tenant.unit if s.tenant else ""
        name = s.tenant.name if s.tenant else f"Tenant #{s.tenant_id}"
        row_fill = C_ALT_ROW if ri % 2 == 1 else None
        returned = s.return_amount or 0
        net_color = C_GREEN_BG if returned >= (s.deposit_held or 0) * 0.8 else C_AMBER_BG
        margin = s.repair_profit()
        row = [s.id, name, unit, s.settlement_date,
               s.deposit_held or 0,
               s.repair_charged or s.repair_cost or 0, s.repair_actual or 0, margin,
               s.unpaid_rent or 0, s.unpaid_rent_note or "",
               s.other_deduction or 0, returned,
               s.deduction_notes or ""]
        money_cols = (5,6,7,8,9,11,12)
        for ci, v in enumerate(row, 1):
            fmt   = currency_fmt if ci in money_cols else (date_fmt if ci == 4 else None)
            fill  = net_color if ci == 12 else (C_GREEN_BG if ci == 8 and margin > 0 else row_fill)
            c = data_cell(ws5, ri, ci, v, fill, num_fmt=fmt,
                          align="right" if ci in money_cols else "left")
            if ci == 8:
                c.font = Font(name="Arial", size=9, bold=True,
                              color=C_GREEN_FG if margin > 0 else (C_RED_FG if margin < 0 else "111827"))
        ws5.row_dimensions[ri].height = 18
    if not settlements:
        ws5.cell(3, 1, "No vacate settlements recorded yet.").font = Font(name="Arial", italic=True, size=9, color="888888")
    auto_width(ws5)

    # ── 6. Deposit Payments ───────────────────────────────────────────────────
    cols_d = ["#","Tenant","Unit","Date","Amount (₹)","Method",
              "Transaction ID","Notes"]
    ws6 = make_sheet("Deposit Payments", cols_d)
    dps = (DepositPayment.query
           .options(joinedload(DepositPayment.tenant))
           .order_by(DepositPayment.tenant_name, DepositPayment.payment_date)
           .all())
    for ri, d in enumerate(dps, 3):
        row_fill = C_ALT_ROW if ri % 2 == 1 else None
        unit = d.tenant.unit if d.tenant else ""
        row = [d.id, d.tenant_name or "", unit, d.payment_date,
               d.amount or 0, d.method or "", d.transaction_id or "", d.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci == 5 else (date_fmt if ci == 4 else None)
            data_cell(ws6, ri, ci, v, row_fill, num_fmt=fmt,
                      align="right" if ci == 5 else "left")
        ws6.row_dimensions[ri].height = 18
    if dps:
        tot_row = len(dps) + 3
        ws6.cell(tot_row, 1, "TOTAL").font = Font(name="Arial", bold=True, size=9)
        ws6.cell(tot_row, 5, f"=SUM(E3:E{tot_row-1})").number_format = currency_fmt
        for ci in range(1, 9):
            ws6.cell(tot_row, ci).fill   = _fill("E8ECF8")
            ws6.cell(tot_row, ci).border = bdr
            ws6.cell(tot_row, ci).font   = Font(name="Arial", bold=True, size=9)
    else:
        ws6.cell(3, 1, "No deposit instalments recorded yet.").font = Font(name="Arial", italic=True, size=9, color="888888")
    auto_width(ws6)

    # ── Stream workbook ───────────────────────────────────────────────────────
    sec.security_log("excel_export")
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = f"RentManager_Export_{date.today().strftime('%Y%m%d')}.xlsx"
    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ── CLI: recover a locked-out / forgotten super-admin account ────────────────
import click

@app.cli.command("set-password")
@click.argument("username")
def set_password_cmd(username):
    """Set a new password:  flask --app app set-password <username>"""
    import getpass
    a = unscoped(Admin.query).filter(db.func.lower(Admin.username) == username.lower()).first()
    if not a:
        raise click.ClickException("No such user.")
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat: "):
        raise click.ClickException("Passwords do not match.")
    msg = check_password_strength(pw, a.username, a.email or "")
    if msg:
        raise click.ClickException(msg)
    _set_password(a, pw)
    a.is_active = True
    db.session.commit()
    click.echo("Password updated; all existing sessions were revoked.")

if __name__ == "__main__":
    # Local development server only (production uses gunicorn — see Procfile).
    # The Werkzeug debugger allows remote code execution, so it is enabled only
    # in development AND only when bound to loopback.
    port  = int(os.environ.get("PORT") or 5000)
    host  = os.environ.get("HOST") or "127.0.0.1"
    debug = sec.is_development() and host in ("127.0.0.1", "localhost", "::1")
    app.run(host=host, port=port, debug=debug)
