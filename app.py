"""
app.py — RentManager — with month-wise rent history
"""
import os, logging, re
from datetime import date, datetime, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy.orm import joinedload
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import (db, Tenant, CommonExpense, BuildingExpense,
                    ReminderLog, Admin, RentRecord, VacateSettlement,
                    RentAmountHistory, init_db, get_database_url)
from whatsapp import send_rent_reminder, send_payment_confirmation
from scheduler import init_scheduler

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["300 per hour"])

load_dotenv()
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
ALLOWED_EXT   = {"png", "jpg", "jpeg", "gif", "pdf", "webp"}

def create_app():
    app = Flask(__name__)
    app.secret_key                           = os.environ.get("SECRET_KEY", os.urandom(32))
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
    app.config["MAX_CONTENT_LENGTH"]         = 32 * 1024 * 1024
    # Auto-reload templates only in development (saves ~50ms per request in prod)
    app.config["TEMPLATES_AUTO_RELOAD"]      = os.environ.get("FLASK_ENV") == "development"

    # ── Security: session cookie hardening ──
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    app.jinja_env.auto_reload = True
    # ── Gzip compression: typically saves 60-75% on HTML page sizes ──
    try:
        from flask_compress import Compress
        app.config["COMPRESS_ALGORITHM"] = ["gzip"]
        app.config["COMPRESS_MIN_SIZE"]  = 500   # bytes – skip tiny responses
        Compress(app)
    except ImportError:
        pass  # falls back gracefully if package not yet installed
    init_db(app)
    # Create rent_records table if it doesn't exist yet (safe migration)
    with app.app_context():
        db.create_all()
    init_scheduler(app)
    return app

app = create_app()

# ── Performance: HTTP cache headers ──────────────────────────────────────────
@app.after_request
def add_cache_headers(response):
    """Add caching headers to speed up repeat page loads."""
    endpoint = request.endpoint or ""
    # Static assets: cache 7 days
    if endpoint == "static":
        response.headers["Cache-Control"] = "public, max-age=604800, immutable"
    # Login page: no cache (always fresh)
    elif endpoint == "login":
        response.headers["Cache-Control"] = "no-store"
    # All other authenticated pages: revalidate (browser caches but checks freshness)
    elif response.status_code == 200 and response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "private, no-cache, must-revalidate"
    # ── Security headers ──
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"500 error: {e}")
    flash("Something went wrong. Please try again.", "danger")
    return redirect(url_for("dashboard") if session.get("admin_logged_in") else url_for("login")), 500

@app.errorhandler(413)
def too_large(e):
    flash("File too large.", "danger")
    return redirect(request.referrer or url_for("dashboard")), 413

# ── Helpers ───────────────────────────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def allowed_file(fn):
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXT

_FILE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif", b"GIF89a": "gif",
    b"RIFF": "webp",   # followed by WEBP at offset 8, good enough as a first check
    b"%PDF": "pdf",
}

def is_safe_upload(file_storage):
    """Reject files whose real content doesn't match a known-safe signature —
    blocks malicious files renamed with an image/pdf extension."""
    try:
        pos = file_storage.stream.tell()
    except Exception:
        pos = 0
    header = file_storage.stream.read(16)
    file_storage.stream.seek(pos)
    if not header:
        return False
    return any(header.startswith(sig) for sig in _FILE_SIGNATURES)

def save_upload(field):
    f = request.files.get(field)
    if f and f.filename and allowed_file(f.filename):
        if not is_safe_upload(f):
            logger.warning(f"[Upload] Rejected file with mismatched content: {f.filename}")
            flash("That file could not be verified as a valid image/PDF and was not uploaded.", "warning")
            return None
        fn = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{f.filename}")

        supabase_url = os.environ.get("SUPABASE_URL")
        supabase_key = os.environ.get("SUPABASE_KEY")
        bucket       = os.environ.get("SUPABASE_BUCKET", "uploads")

        if supabase_url and supabase_key:
            try:
                from storage3 import create_client
                headers = {"apiKey": supabase_key, "Authorization": f"Bearer {supabase_key}"}
                storage = create_client(f"{supabase_url}/storage/v1", headers, is_async=False)
                file_bytes = f.read()
                content_type = f.content_type or "application/octet-stream"
                storage.from_(bucket).upload(fn, file_bytes, {"content-type": content_type})
                return f"{supabase_url}/storage/v1/object/public/{bucket}/{fn}"
            except Exception as e:
                logger.error(f"Supabase upload failed: {e}")
                f.seek(0)
                f.save(os.path.join(UPLOAD_FOLDER, fn))
                return fn
        else:
            f.save(os.path.join(UPLOAD_FOLDER, fn))
            return fn
    return None

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
            rent_amount=t.amount, status="Pending"
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

def _month_bounds(year, month):
    """Return [month_start, next_month_start) for efficient date filtering."""
    start = date(year, month, 1)
    end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    return start, end

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.locked_until and admin.locked_until > datetime.utcnow():
            wait_min = max(1, int((admin.locked_until - datetime.utcnow()).total_seconds() // 60) + 1)
            flash(f"Account locked due to repeated failed attempts. Try again in ~{wait_min} min.", "danger")
            return render_template("login.html")

        if admin and check_password_hash(admin.password_hash, password):
            admin.failed_attempts = 0
            admin.locked_until = None
            db.session.commit()
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"]  = username
            session.permanent = True
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))

        if admin:
            admin.failed_attempts = (admin.failed_attempts or 0) + 1
            if admin.failed_attempts >= 5:
                admin.locked_until = datetime.utcnow() + timedelta(minutes=15)
                admin.failed_attempts = 0
                logger.warning(f"[Security] Account '{username}' locked after 5 failed login attempts.")
            db.session.commit()
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

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
    overdue     = [r.tenant for r in cur_records if r.is_overdue(today)]
    new_joins   = [r.tenant for r in cur_records
                   if r.status != "Paid" and r.tenant and r.is_new_join_month()]
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
    chart_data = json.dumps({
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

    record_by_tenant = {r.tenant_id: r for r in cur_records}
    return render_template("dashboard.html",
        tenants=all_tenants, total=len(cur_records),
        collected=collected, pending_amt=pending_amt, overdue=overdue, new_joins=new_joins,
        record_by_tenant=record_by_tenant,
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
                rent_amount=t.amount, status="Pending"
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
    record_by_tenant = {r.tenant_id: r for r in records}
    return render_template("rent_tracker.html", tenants=tenants, records=records,
                            record_by_tenant=record_by_tenant, today=today)

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
        months.append((y, m, date(y, m, 1).strftime("%B %Y")))

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
                rent_amount=t.amount, status="Pending"
            ))

    total_expected = sum(r.rent_amount for r in records)
    total_collected = sum(r.paid_amount or 0 for r in records if r.status == "Paid")
    paid_count   = sum(1 for r in records if r.status == "Paid")
    pending_count = sum(1 for r in records if r.status != "Paid")

    return render_template("rent_history.html",
        records=records, months=months,
        sel_year=sel_year, sel_month=sel_month,
        sel_label=date(sel_year, sel_month, 1).strftime("%B %Y"),
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
        tid    = int(request.form["tenant_id"])
        month  = int(request.form["month"])
        year   = int(request.form["year"])
        status = request.form.get("status", "Paid")
        t      = Tenant.query.get_or_404(tid)

        rec = RentRecord.query.filter_by(tenant_id=tid, month=month, year=year).first()
        if not rec:
            rec = RentRecord(tenant_id=tid, tenant_name=t.name,
                             month=month, year=year, rent_amount=t.amount)
            db.session.add(rec)

        rec.status      = status
        rec.rent_amount = float(request.form.get("rent_amount") or t.amount)
        if status == "Paid":
            rec.paid_amount      = float(request.form.get("paid_amount") or rec.rent_amount)
            rec.payment_method   = request.form.get("payment_method", "cash")
            rec.transaction_id   = request.form.get("transaction_id", "")
            rec.notes            = request.form.get("notes", "")
            pd = request.form.get("payment_date")
            rec.payment_date = datetime.strptime(pd, "%Y-%m-%d").date() if pd else date.today()
        else:
            rec.paid_amount = None
            rec.payment_date = None
            rec.payment_method = None
            rec.transaction_id = None
        db.session.commit()
        flash(f"✅ Record saved for {t.name} — {date(year, month, 1).strftime('%B %Y')}.", "success")
        return redirect(url_for("rent_history", year=year, month=month))

    # Pre-fill from query params
    pre_tid   = request.args.get("tenant_id", "")
    pre_month = int(request.args.get("month", today.month))
    pre_year  = int(request.args.get("year",  today.year))
    return render_template("add_rent_record.html",
        tenants=tenants, today=today,
        pre_tid=pre_tid, pre_month=pre_month, pre_year=pre_year)

@app.route("/rent-history/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
def edit_rent_record(record_id):
    rec     = RentRecord.query.get_or_404(record_id)
    tenants = Tenant.query.order_by(Tenant.name).all()
    if request.method == "POST":
        status = request.form.get("status", "Paid")
        rec.status      = status
        rec.rent_amount = float(request.form.get("rent_amount") or rec.rent_amount)
        rec.notes       = request.form.get("notes", "")
        if status == "Paid":
            rec.paid_amount    = float(request.form.get("paid_amount") or rec.rent_amount)
            rec.payment_method = request.form.get("payment_method", "cash")
            rec.transaction_id = request.form.get("transaction_id", "")
            pd = request.form.get("payment_date")
            rec.payment_date = datetime.strptime(pd, "%Y-%m-%d").date() if pd else date.today()
        else:
            rec.paid_amount = None
            rec.payment_date = None
            rec.payment_method = None
            rec.transaction_id = None
        db.session.commit()
        flash(f"✅ Record updated.", "success")
        return redirect(url_for("rent_history", year=rec.year, month=rec.month))
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
    rec.payment_method = request.form.get("method", "cash")
    rec.transaction_id = request.form.get("transaction_id", "")
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
@login_required
def verify_payment(tid):
    t = Tenant.query.get_or_404(tid)
    if request.method == "GET":
        return render_template("payment_verify.html", tenant=t)

    method     = request.form.get("method", "cash")
    manual_txn = request.form.get("transaction_id", "").strip()
    manual_amt = request.form.get("manual_amount", "").strip()

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
        try:
            paid_amount = float(manual_amt.replace(",", "")) if manual_amt else t.amount
        except ValueError:
            paid_amount = t.amount
        _commit_payment(paid_amount, manual_txn, "manual")
        flash(f"✅ {t.name} marked as Paid.", "success")
        return redirect(url_for("rent_tracker"))

    if method == "screenshot":
        files = request.files.getlist("screenshot")
        files = [f for f in files if f and f.filename and allowed_file(f.filename)]
        safe_files = [f for f in files if is_safe_upload(f)]
        if len(safe_files) < len(files):
            flash("One or more files were rejected as invalid image/PDF content.", "warning")
        files = safe_files
        if not files:
            flash("Please upload at least one screenshot.", "danger")
            return render_template("payment_verify.html", tenant=t)
        from ocr_parser import parse_payment_screenshot
        best_parsed = None
        saved_fns   = []
        for f in files:
            fn = secure_filename(f"pay_{t.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{f.filename}")
            local_path = os.path.join(UPLOAD_FOLDER, fn)
            file_bytes = f.read()
            # Save locally for OCR parsing
            with open(local_path, "wb") as lf:
                lf.write(file_bytes)
            # Upload to Supabase if configured
            supabase_url = os.environ.get("SUPABASE_URL")
            supabase_key = os.environ.get("SUPABASE_KEY")
            bucket = os.environ.get("SUPABASE_BUCKET", "uploads")
            stored_fn = fn
            if supabase_url and supabase_key:
                try:
                    from storage3 import create_client
                    headers = {"apiKey": supabase_key, "Authorization": f"Bearer {supabase_key}"}
                    storage = create_client(f"{supabase_url}/storage/v1", headers, is_async=False)
                    storage.from_(bucket).upload(fn, file_bytes, {"content-type": f.content_type or "image/jpeg"})
                    stored_fn = f"{supabase_url}/storage/v1/object/public/{bucket}/{fn}"
                except Exception as e:
                    logger.error(f"Supabase screenshot upload failed: {e}")
            saved_fns.append(stored_fn)
            parsed = parse_payment_screenshot(local_path, t.amount, manual_txn)
            if best_parsed is None or (parsed.get("amount") or 0) > (best_parsed.get("amount") or 0):
                best_parsed = parsed
        detected_txn = manual_txn or best_parsed.get("txn_id")
        ocr_result = {"raw_text": best_parsed.get("raw_text", ""),
                      "amount": best_parsed.get("amount"), "txn_id": detected_txn,
                      "method": best_parsed.get("method", "unknown"), "files": saved_fns}
        return render_template("payment_verify.html", tenant=t, ocr=ocr_result,
                               screenshot_fn=saved_fns[0] if saved_fns else "")

    # Cash
    _commit_payment(t.amount, manual_txn, "cash")
    flash(f"✅ {t.name} marked as Paid (Cash).", "success")
    return redirect(url_for("rent_tracker"))

@app.route("/tenant/force-paid/<int:tid>", methods=["POST"])
@login_required
def force_mark_paid(tid):
    t = Tenant.query.get_or_404(tid)
    today = date.today()
    t.status             = "Paid"
    t.payment_date       = today
    t.payment_method     = request.form.get("method", "upi_screenshot")
    t.transaction_id     = request.form.get("transaction_id", "—")
    t.payment_screenshot = request.form.get("screenshot_fn", "") or t.payment_screenshot
    manual_amt = request.form.get("manual_amount", "").strip()
    try:
        paid_amount = float(manual_amt.replace(",", "")) if manual_amt else t.amount
    except Exception:
        paid_amount = t.amount
    db.session.commit()
    # Write to monthly history
    rec = _get_or_create_record(t.id, today.month, today.year)
    if rec:
        rec.status = "Paid"; rec.paid_amount = paid_amount
        rec.payment_date = today; rec.payment_method = t.payment_method
        rec.transaction_id = t.transaction_id
        rec.payment_screenshot = t.payment_screenshot or ""
        db.session.commit()
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
    return redirect(request.referrer or url_for("rent_tracker"))

@app.route("/tenant/remind/<int:tid>", methods=["POST"])
@login_required
def remind_tenant(tid):
    t = Tenant.query.get_or_404(tid)
    channel = request.form.get("channel", "whatsapp")
    status  = "failed"
    log_msg = f"Reminder via {channel}"

    if channel == "whatsapp":
        result = send_rent_reminder(to_phone=t.phone, tenant_name=t.name,
            amount=t.amount, due_date=f"{t.get_due_day()}th of every month")
        if "error" not in result:
            status = "sent"
        else:
            status = "failed"
            log_msg = f"WhatsApp failed: {result.get('error', 'Unknown')}"
            logger.error("[remind_tenant] WhatsApp FAILED for %s (phone=%s): %s",
                         t.name, t.phone, result)

    elif channel == "sms":
        msg = (f"Hi {t.name}, rent Rs.{t.amount:,.0f} due on "
               f"the {t.get_due_day()}th of every month. Please pay. -RentManager")
        result = send_sms(t.phone, msg)
        if result.get("success"):
            status = "sent"
        else:
            status = "failed"
            error_reason = result.get("error") or result.get("message") or str(result)
            log_msg = f"SMS failed: {error_reason}"
            logger.error(
                "[remind_tenant] SMS FAILED for %s (phone=%s) | Reason: %s | Full response: %s",
                t.name, t.phone, error_reason, result
            )

    db.session.add(ReminderLog(tenant_id=t.id, tenant_name=t.name,
        channel=channel, status=status, message=log_msg))
    db.session.commit()

    if status == "sent":
        flash(f"Reminder sent to {t.name} via {channel}.", "success")
    else:
        flash(f"Reminder to {t.name} via {channel} failed. Check server logs.", "warning")
    return redirect(request.referrer or url_for("rent_tracker"))

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
    return render_template("renter_detail.html", tenant=t, logs=logs, records=records,
                            settlement=settlement, today=date.today())

@app.route("/renters/add", methods=["GET", "POST"])
@login_required
def add_renter():
    if request.method == "POST":
        try:
            _due_day = int(request.form["due_day"])
            from datetime import date as _date
            import calendar as _cal
            _today = _date.today()
            _max_day = _cal.monthrange(_today.year, _today.month)[1]
            _due_date_compat = _date(_today.year, _today.month, min(_due_day, _max_day))
            t = Tenant(
                name=request.form["name"].strip(), phone=request.form["phone"].strip(),
                email=request.form.get("email", "").strip(),
                unit=request.form.get("unit", "").strip(),
                unit_number=request.form.get("unit_number", "").strip(),
                amount=float(request.form["amount"]),
                due_day=_due_day,
                due_date=_due_date_compat,
                deposit=float(request.form.get("deposit", 0) or 0),
                join_date=datetime.strptime(request.form["join_date"], "%Y-%m-%d").date() if request.form.get("join_date") else None,
                vacated_date=None, occupancy_status="Active",
                notes=request.form.get("notes", ""),
                photo_path=save_upload("photo"), agreement_path=save_upload("agreement"),
                status="Pending",
            )
            db.session.add(t); db.session.commit()
            flash(f"Renter '{t.name}' added.", "success")
            return redirect(url_for("renters"))
        except Exception as e:
            db.session.rollback(); flash(f"Error: {e}", "danger")
    return render_template("renter_form.html", tenant=None, action="Add")

@app.route("/renters/edit/<int:tid>", methods=["GET", "POST"])
@login_required
def edit_renter(tid):
    t = Tenant.query.get_or_404(tid)
    if request.method == "POST":
        try:
            # Quick file-only update from detail page (no full form fields present)
            if request.form.get("_photo_only"):
                pf = save_upload("photo")
                if pf: t.photo_path = pf
                db.session.commit(); flash("Photo updated.", "success")
                return redirect(url_for("renter_detail", tid=tid))
            if request.form.get("_agreement_only"):
                af = save_upload("agreement")
                if af: t.agreement_path = af
                db.session.commit(); flash("Agreement updated.", "success")
                return redirect(url_for("renter_detail", tid=tid))
            # Full edit form
            t.name=request.form["name"].strip(); t.phone=request.form["phone"].strip()
            t.email=request.form.get("email","").strip(); t.unit=request.form.get("unit","").strip()
            t.unit_number=request.form.get("unit_number","").strip()
            t.amount=float(request.form["amount"])
            t.due_day=int(request.form["due_day"])
            # Keep legacy due_date in sync so NOT NULL constraint on old DB is satisfied
            from datetime import date as _date
            import calendar
            _today = _date.today()
            _max_day = calendar.monthrange(_today.year, _today.month)[1]
            t.due_date = _date(_today.year, _today.month, min(t.due_day, _max_day))
            t.deposit=float(request.form.get("deposit",0) or 0)
            t.notes=request.form.get("notes","")
            if request.form.get("join_date"):
                t.join_date=datetime.strptime(request.form["join_date"],"%Y-%m-%d").date()
            t.occupancy_status=request.form.get("occupancy_status",t.occupancy_status or "Active")
            if t.occupancy_status=="Vacated" and request.form.get("vacated_date"):
                t.vacated_date=datetime.strptime(request.form["vacated_date"],"%Y-%m-%d").date()
            elif t.occupancy_status=="Active": t.vacated_date=None
            pf=save_upload("photo"); af=save_upload("agreement")
            if pf: t.photo_path=pf
            if af: t.agreement_path=af
            db.session.commit(); flash(f"Renter '{t.name}' updated.","success")
            return redirect(url_for("renters"))
        except Exception as e:
            db.session.rollback(); flash(f"Error: {e}","danger")
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
            new_amount  = float(request.form["new_amount"])
            new_deposit = float(request.form.get("new_deposit") or t.deposit or 0)
            effective_month = int(request.form.get("effective_month", today.month))
            effective_year  = int(request.form.get("effective_year",  today.year))
            notes = request.form.get("notes", "").strip()

            # Log the change
            history_entry = RentAmountHistory(
                tenant_id=tid, tenant_name=t.name,
                old_amount=t.amount, new_amount=new_amount,
                old_deposit=t.deposit or 0, new_deposit=new_deposit,
                effective_from=date(effective_year, effective_month, 1),
                notes=notes,
            )
            db.session.add(history_entry)

            # Update tenant record
            t.amount  = new_amount
            t.deposit = new_deposit
            db.session.commit()
            flash(f"✅ Rent updated to ₹{new_amount:,.0f} and deposit to ₹{new_deposit:,.0f} "
                  f"effective {date(effective_year, effective_month, 1).strftime('%B %Y')}.", "success")
            return redirect(url_for("renter_detail", tid=tid))
        except Exception as e:
            db.session.rollback(); flash(f"Error: {e}", "danger")

    return render_template("update_rent_amount.html", tenant=t, today=today, history=history)

@app.route("/renters/delete/<int:tid>", methods=["POST"])
@login_required
def delete_renter(tid):
    t = Tenant.query.get_or_404(tid)
    name = t.name
    # Delete all child records first to avoid FK / NOT NULL violations
    RentRecord.query.filter_by(tenant_id=tid).delete()
    VacateSettlement.query.filter_by(tenant_id=tid).delete()
    ReminderLog.query.filter_by(tenant_id=tid).delete()
    db.session.delete(t)
    db.session.commit()
    flash(f"Renter '{name}' and all related records deleted.", "warning")
    return redirect(url_for("renters"))

@app.route("/renters/delete-file/<int:tid>/<field>", methods=["POST"])
@login_required
def delete_renter_file(tid, field):
    t = Tenant.query.get_or_404(tid)
    if field == "photo":
        t.photo_path = None
    elif field == "agreement":
        t.agreement_path = None
    db.session.commit()
    flash("File removed successfully.", "success")
    return redirect(url_for("renter_detail", tid=tid))


@app.route("/renters/vacate/<int:tid>", methods=["GET", "POST"])
@login_required
def vacate_renter(tid):
    t = Tenant.query.get_or_404(tid)
    existing = VacateSettlement.query.filter_by(tenant_id=tid).first()

    # Outstanding (unpaid) rent records for this tenant — shown to the owner
    outstanding_records = (RentRecord.query
                            .filter(RentRecord.tenant_id == tid, RentRecord.status != "Paid")
                            .order_by(RentRecord.year, RentRecord.month).all())
    outstanding_total = sum(r.rent_amount for r in outstanding_records)

    if request.method == "POST":
        try:
            repair        = float(request.form.get("repair_cost", 0) or 0)          # charged to tenant
            repair_actual = float(request.form.get("repair_actual_cost", 0) or 0)    # actually spent
            other         = float(request.form.get("other_deduction", 0) or 0)       # charged to tenant
            other_actual  = float(request.form.get("other_actual_cost", 0) or 0)     # actually spent
            rent_deduct   = float(request.form.get("pending_rent_deducted", 0) or 0)  # unpaid rent recovered

            # Actual spend can never exceed what was charged to the tenant
            repair_actual = min(repair_actual, repair)
            other_actual  = min(other_actual, other)
            # Rent recovered can't exceed actual outstanding rent
            rent_deduct   = max(0.0, min(rent_deduct, outstanding_total))

            total_deduction = repair + other + rent_deduct
            returned = max(0.0, (t.deposit or 0) - total_deduction)

            if existing:
                s = existing
            else:
                s = VacateSettlement(tenant_id=tid)
                db.session.add(s)

            s.deposit_held          = t.deposit
            s.repair_cost           = repair
            s.repair_actual_cost    = repair_actual
            s.other_deduction       = other
            s.other_actual_cost     = other_actual
            s.pending_rent_deducted = rent_deduct
            s.deduction_notes       = request.form.get("deduction_notes", "")
            return_amount_raw = (request.form.get("return_amount") or "").strip()
            s.return_amount = float(return_amount_raw) if return_amount_raw else returned
            vd = request.form.get("vacated_date")
            s.settlement_date = datetime.strptime(vd, "%Y-%m-%d").date() if vd else date.today()

            # Only the REAL spend goes into Building Expenses — not the amount charged to the tenant.
            if repair_actual > 0:
                db.session.add(BuildingExpense(
                    description=f"Vacate repair - {t.name}",
                    amount=repair_actual,
                    category="Repairs",
                    date=s.settlement_date,
                    notes=(f"Actual repair spend for tenant {t.name} (ID {t.id}). "
                           f"₹{repair:,.0f} deducted from deposit; ₹{repair_actual:,.0f} actually spent."),
                ))
            if other_actual > 0:
                db.session.add(BuildingExpense(
                    description=f"Vacate painting/cleaning - {t.name}",
                    amount=other_actual,
                    category="Painting",
                    date=s.settlement_date,
                    notes=(f"Actual painting/cleaning spend for tenant {t.name} (ID {t.id}). "
                           f"₹{other:,.0f} deducted from deposit; ₹{other_actual:,.0f} actually spent."),
                ))

            # Clear outstanding rent from the deposit, oldest month first.
            remaining = rent_deduct
            for r in outstanding_records:
                if remaining <= 0:
                    break
                if remaining >= r.rent_amount:
                    r.status         = "Paid"
                    r.paid_amount    = r.rent_amount
                    r.payment_date   = s.settlement_date
                    r.payment_method = "deposit_deduction"
                    r.notes          = (r.notes or "") + " | Settled from security deposit on vacate."
                    remaining -= r.rent_amount
                else:
                    r.notes = (r.notes or "") + f" | ₹{remaining:,.0f} covered from deposit on vacate; balance still pending."
                    remaining = 0

            # Mark tenant as vacated
            t.occupancy_status = "Vacated"
            t.vacated_date     = s.settlement_date
            t.deposit          = 0   # deposit no longer held once settlement is completed
            db.session.commit()

            profit_kept = s.profit_kept()
            msg = f"✅ {t.name} vacated. ₹{s.return_amount:,.0f} to be returned."
            if profit_kept > 0:
                msg += f" ₹{profit_kept:,.0f} kept over actual repair/cleaning spend."
            if rent_deduct > 0:
                msg += f" ₹{rent_deduct:,.0f} unpaid rent recovered from deposit."
            flash(msg, "success")
            return redirect(url_for("renter_detail", tid=tid))
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {e}", "danger")
    return render_template("vacate_renter.html", tenant=t, settlement=existing, today=date.today(),
                            outstanding_records=outstanding_records, outstanding_total=outstanding_total)

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
            description=request.form["description"].strip(), amount=float(request.form["amount"]),
            category=request.form.get("category","Other"),
            split_units=int(request.form.get("split_units",6)),
            date=datetime.strptime(request.form["date"],"%Y-%m-%d").date(),
            notes=request.form.get("notes",""),
        ))
        db.session.commit(); flash("Common expense added.","success")
    except Exception as ex:
        db.session.rollback(); flash(f"Error: {ex}","danger")
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
    try:
        db.session.add(BuildingExpense(
            description=request.form["description"].strip(), amount=float(request.form["amount"]),
            category=request.form.get("category","Maintenance"),
            date=datetime.strptime(request.form["date"],"%Y-%m-%d").date(),
            notes=request.form.get("notes",""), receipt_path=save_upload("receipt"),
        ))
        db.session.commit(); flash("Building expense added.","success")
    except Exception as ex:
        db.session.rollback(); flash(f"Error: {ex}","danger")
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
    view_mode = request.args.get("view", "month")  # "month" or "year"
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

    # ── Vacate settlements (deposit profit) in the same fetch window ──
    all_settlements = (VacateSettlement.query
                        .filter(VacateSettlement.settlement_date >= fetch_start,
                                VacateSettlement.settlement_date < fetch_end)
                        .all())
    settlements = [s for s in all_settlements
                   if s.settlement_date and month_start <= s.settlement_date < month_end]
    deposit_profit = sum(s.profit_kept() for s in settlements)

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
    paid_by_month   = {k: 0.0 for k in trend_keys}
    exp_by_month    = {k: 0.0 for k in trend_keys}
    profit_by_month = {k: 0.0 for k in trend_keys}
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
    for s in all_settlements:
        if s.settlement_date:
            k = s.settlement_date.strftime("%Y-%m")
            if k in profit_by_month:
                profit_by_month[k] += s.profit_kept()
    trend_income   = [round(paid_by_month[k] + profit_by_month[k], 2) for k in trend_keys]
    trend_expenses = [round(exp_by_month[k],  2) for k in trend_keys]

    return render_template("income_expenses.html",
        rent_records=rent_records, common=common, building=building,
        settlements=settlements, deposit_profit=deposit_profit,
        trend_labels=trend_labels, trend_income=trend_income, trend_expenses=trend_expenses,
        months=months, years=years, sel_year=sel_year, sel_month=sel_month,
        sel_label=sel_label, view_mode=view_mode, today=today)

@app.route("/ca-audit")
@login_required
def ca_audit():
    today = date.today()
    view_mode = request.args.get("view", "month")  # "month" or "year"
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

    # ── Vacate settlements (deposit profit) — same UNION window ──
    all_settlements = (VacateSettlement.query
                        .filter(VacateSettlement.settlement_date >= fetch_start,
                                VacateSettlement.settlement_date < fetch_end)
                        .all())

    # Split in Python - zero extra DB round-trips
    if view_mode == "year":
        rent_records = [r for r in all_rr if r.year == sel_year]
        settlements  = [s for s in all_settlements if s.settlement_date and s.settlement_date.year == sel_year]
    else:
        rent_records = [r for r in all_rr if r.month == sel_month and r.year == sel_year]
        settlements  = [s for s in all_settlements
                         if s.settlement_date and s.settlement_date.month == sel_month
                         and s.settlement_date.year == sel_year]

    common      = [e for e in all_common   if month_start <= e.date < month_end]
    building    = [e for e in all_building if month_start <= e.date < month_end]
    fy_records  = all_rr
    fy_common   = [e for e in all_common   if fy_start <= e.date < fy_end]
    fy_building = [e for e in all_building if fy_start <= e.date < fy_end]
    fy_settlements = [s for s in all_settlements if s.settlement_date and fy_start <= s.settlement_date < fy_end]

    deposit_profit    = sum(s.profit_kept() for s in settlements)
    fy_deposit_profit = sum(s.profit_kept() for s in fy_settlements)

    fy_label = f"FY {fy_start_year}–{str(fy_start_year+1)[2:]}"
    return render_template("ca_audit.html",
        rent_records=rent_records, common=common, building=building,
        fy_records=fy_records, fy_common=fy_common, fy_building=fy_building,
        settlements=settlements, fy_settlements=fy_settlements,
        deposit_profit=deposit_profit, fy_deposit_profit=fy_deposit_profit,
        tenants=tenants, months=months, years=years,
        sel_year=sel_year, sel_month=sel_month, sel_label=sel_label,
        view_mode=view_mode, fy_label=fy_label, today=today)
@app.route("/reminders")
@login_required
def reminders():
    pending_tenants = (Tenant.query
                       .filter_by(status="Pending", occupancy_status="Active")
                       .all())
    logs = (ReminderLog.query
            .order_by(ReminderLog.sent_at.desc())
            .limit(50).all())
    return render_template("reminders.html", tenants=pending_tenants, logs=logs, today=date.today())

@app.route("/change-password", methods=["GET","POST"])
@login_required
def change_password():
    if request.method == "POST":
        current=request.form.get("current_password",""); new_pw=request.form.get("new_password","")
        confirm=request.form.get("confirm_password","")
        admin=Admin.query.filter_by(username=session["admin_username"]).first()
        if not check_password_hash(admin.password_hash, current): flash("Current password incorrect.","danger")
        elif new_pw != confirm: flash("Passwords don't match.","danger")
        elif len(new_pw) < 6: flash("Min 6 characters.","danger")
        else:
            admin.password_hash=generate_password_hash(new_pw); db.session.commit()
            flash("Password changed.","success"); return redirect(url_for("dashboard"))
    return render_template("change_password.html")

@app.route("/change-username", methods=["POST"])
@login_required
def change_username():
    new_username = request.form.get("new_username","").strip()
    password     = request.form.get("confirm_password_username","")
    admin = Admin.query.filter_by(username=session["admin_username"]).first()
    if not admin:
        flash("Admin not found.","danger")
    elif not check_password_hash(admin.password_hash, password):
        flash("Incorrect password — username not changed.","danger")
    elif len(new_username) < 3:
        flash("Username must be at least 3 characters.","danger")
    elif (lambda ex: ex and ex.id != admin.id)(Admin.query.filter_by(username=new_username).first()):
        flash("That username is already taken.","danger")
    else:
        admin.username = new_username
        db.session.commit()
        session["admin_username"] = new_username
        flash(f"Username changed to '{new_username}'.", "success")
        return redirect(url_for("dashboard"))
    return redirect(url_for("change_password"))

# ── REST API ──────────────────────────────────────────────────────────────────
@app.route("/api/dashboard")
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
@app.route("/upload/excel", methods=["GET", "POST"])
@login_required
def upload_excel():
    if request.method == "GET":
        return render_template("upload_excel.html")

    f = request.files.get("excel_file")
    if not f or not f.filename.endswith((".xlsx", ".xls")):
        flash("Please upload a valid .xlsx or .xls file.", "error")
        return redirect(url_for("upload_excel"))

    import io
    from openpyxl import load_workbook

    try:
        buf = io.BytesIO(f.read())
        wb  = load_workbook(buf, data_only=True)
    except Exception as ex:
        flash(f"Could not read workbook: {ex}", "error")
        return redirect(url_for("upload_excel"))

    stats = {"tenants":0,"rent_records":0,"common_expenses":0,
             "building_expenses":0,"vacate_settlements":0,"skipped":0}
    errors = []

    def cell(row, idx):
        v = row[idx].value if idx < len(row) else None
        return v.strip() if isinstance(v, str) else v

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
        try: return float(str(v).replace("₹","").replace(",","").strip())
        except: return None

    # ── Tenants sheet ──────────────────────────────────────────────────────
    if "Tenants" in wb.sheetnames:
        ws = wb["Tenants"]
        rows = list(ws.iter_rows(min_row=3))   # row1=title, row2=header
        for row in rows:
            name = cell(row, 1)
            if not name: continue
            try:
                phone       = str(cell(row, 2) or "")
                email       = str(cell(row, 3) or "")
                unit        = str(cell(row, 4) or "")
                occupancy   = str(cell(row, 5) or "Active")
                amount      = to_float(cell(row, 6)) or 0.0
                deposit     = to_float(cell(row, 7)) or 0.0
                join_date   = to_date(cell(row, 8))
                vacated_date= to_date(cell(row, 9))
                status      = str(cell(row,10) or "Pending")
                pay_method  = str(cell(row,11) or "")
                notes       = str(cell(row,12) or "")
                existing = Tenant.query.filter_by(name=name, phone=phone).first()
                if existing:
                    existing.email=email; existing.unit=unit
                    existing.occupancy_status=occupancy; existing.amount=amount
                    existing.deposit=deposit; existing.join_date=join_date
                    existing.vacated_date=vacated_date; existing.status=status
                    existing.payment_method=pay_method; existing.notes=notes
                else:
                    db.session.add(Tenant(
                        name=name, phone=phone, email=email, unit=unit,
                        amount=amount, deposit=deposit,
                        due_day=5, status=status,
                        join_date=join_date, vacated_date=vacated_date,
                        occupancy_status=occupancy,
                        payment_method=pay_method, notes=notes))
                    stats["tenants"] += 1
            except Exception as ex:
                errors.append(f"Tenants row '{name}': {ex}")
                stats["skipped"] += 1
        db.session.commit()

    # ── Rent Records sheet ─────────────────────────────────────────────────
    if "Rent Records" in wb.sheetnames:
        ws = wb["Rent Records"]
        for row in list(ws.iter_rows(min_row=3)):
            tenant_name = cell(row, 1)
            if not tenant_name: continue
            try:
                month       = int(cell(row, 3) or 0)
                year        = int(cell(row, 4) or 0)
                if not (1 <= month <= 12) or year < 2000: continue
                rent_amount = to_float(cell(row, 6)) or 0.0
                paid_amount = to_float(cell(row, 7)) or 0.0
                status      = str(cell(row, 8) or "Pending")
                pay_date    = to_date(cell(row, 9))
                pay_method  = str(cell(row,10) or "")
                txn_id      = str(cell(row,11) or "")
                cf_val      = cell(row,12)
                carried     = str(cf_val).lower() in ("yes","true","1") if cf_val else False
                notes_v     = str(cell(row,13) or "")
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
                        month=month, year=year,
                        rent_amount=rent_amount, paid_amount=paid_amount,
                        status=status, payment_date=pay_date,
                        payment_method=pay_method, transaction_id=txn_id,
                        carried_forward=carried, notes=notes_v))
                    stats["rent_records"] += 1
            except Exception as ex:
                errors.append(f"Rent Records row '{tenant_name}': {ex}")
                stats["skipped"] += 1
        db.session.commit()

    # ── Common Expenses sheet ──────────────────────────────────────────────
    if "Common Expenses" in wb.sheetnames:
        ws = wb["Common Expenses"]
        for row in list(ws.iter_rows(min_row=3)):
            desc = cell(row, 1)
            if not desc or str(desc).upper() == "TOTAL": continue
            try:
                category    = str(cell(row, 2) or "Other")
                exp_date    = to_date(cell(row, 3)) or date.today()
                amount      = to_float(cell(row, 4)) or 0.0
                split_units = int(cell(row, 5) or 6)
                notes_v     = str(cell(row, 7) or "")
                db.session.add(CommonExpense(
                    description=desc, category=category, date=exp_date,
                    amount=amount, split_units=split_units, notes=notes_v))
                stats["common_expenses"] += 1
            except Exception as ex:
                errors.append(f"Common Expenses row '{desc}': {ex}")
                stats["skipped"] += 1
        db.session.commit()

    # ── Building Expenses sheet ────────────────────────────────────────────
    if "Building Expenses" in wb.sheetnames:
        ws = wb["Building Expenses"]
        for row in list(ws.iter_rows(min_row=3)):
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
                errors.append(f"Building Expenses row '{desc}': {ex}")
                stats["skipped"] += 1
        db.session.commit()

    # ── Vacate Settlements sheet ───────────────────────────────────────────
    if "Vacate Settlements" in wb.sheetnames:
        ws = wb["Vacate Settlements"]
        for row in list(ws.iter_rows(min_row=3)):
            tenant_name = cell(row, 1)
            if not tenant_name: continue
            try:
                settle_date   = to_date(cell(row, 3))
                deposit_held  = to_float(cell(row, 4)) or 0.0
                repair_cost   = to_float(cell(row, 5)) or 0.0
                other_deduct  = to_float(cell(row, 6)) or 0.0
                return_amount = to_float(cell(row, 7)) or 0.0
                ded_notes     = str(cell(row, 8) or "")
                tenant = Tenant.query.filter_by(name=tenant_name).first()
                if not tenant:
                    errors.append(f"Vacate Settlements: tenant '{tenant_name}' not found")
                    stats["skipped"] += 1
                    continue
                existing = VacateSettlement.query.filter_by(tenant_id=tenant.id).first()
                if existing:
                    existing.deposit_held=deposit_held; existing.repair_cost=repair_cost
                    existing.other_deduction=other_deduct; existing.return_amount=return_amount
                    existing.settlement_date=settle_date; existing.deduction_notes=ded_notes
                else:
                    db.session.add(VacateSettlement(
                        tenant_id=tenant.id, deposit_held=deposit_held,
                        repair_cost=repair_cost, other_deduction=other_deduct,
                        return_amount=return_amount, settlement_date=settle_date,
                        deduction_notes=ded_notes))
                    stats["vacate_settlements"] += 1
            except Exception as ex:
                errors.append(f"Vacate Settlements row '{tenant_name}': {ex}")
                stats["skipped"] += 1
        db.session.commit()

    summary = (f"Import complete — "
               f"{stats['tenants']} tenants, "
               f"{stats['rent_records']} rent records, "
               f"{stats['common_expenses']} common expenses, "
               f"{stats['building_expenses']} building expenses, "
               f"{stats['vacate_settlements']} settlements added.")
    flash(summary, "success")
    if errors:
        for e in errors[:5]:
            flash(e, "warning")
        if len(errors) > 5:
            flash(f"…and {len(errors)-5} more warnings.", "warning")
    return redirect(url_for("dashboard"))


# ── EXCEL EXPORT ─────────────────────────────────────────────────────────────
@app.route("/download/excel")
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
        c = ws.cell(row, col, value)
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
    cols_t = ["#","Name","Phone","Email","Unit","Occupancy",
              "Monthly Rent (₹)","Deposit (₹)","Join Date","Vacated Date",
              "Current Status","Payment Method","Notes"]
    ws1 = make_sheet("Tenants", cols_t)
    tenants = Tenant.query.order_by(Tenant.occupancy_status, Tenant.name).all()
    for ri, t in enumerate(tenants, 3):
        is_vacated = t.occupancy_status == "Vacated"
        row_fill   = C_RED_BG if is_vacated else (C_ALT_ROW if ri % 2 == 1 else None)
        row = [t.id, t.name, t.phone, t.email or "", t.unit or "",
               t.occupancy_status, t.amount, t.deposit or 0,
               t.join_date, t.vacated_date,
               t.status, t.payment_method or "", t.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci in (7,8) else (date_fmt if ci in (9,10) else None)
            fg  = (C_RED_FG if is_vacated else None) if ci == 6 else None
            c   = data_cell(ws1, ri, ci, v, row_fill, num_fmt=fmt)
            if fg: c.font = Font(name="Arial", size=9, color=fg, bold=True)
        ws1.row_dimensions[ri].height = 18
    # Legend
    leg_row = len(tenants) + 4
    ws1.cell(leg_row,   1, "🔴 Red rows = Vacated tenants").font = Font(name="Arial", size=8, italic=True, color="9B1C1C")
    auto_width(ws1)

    # ── 2. Rent Records ───────────────────────────────────────────────────────
    cols_r = ["#","Tenant","Unit","Month","Year","Period",
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
        row = [r.id, r.tenant_name or "", unit, r.month, r.year,
               r.month_label(), r.rent_amount, r.paid_amount or 0,
               r.status, r.payment_date,
               r.payment_method or "", r.transaction_id or "",
               "Yes" if r.carried_forward else "No", r.notes or ""]
        for ci, v in enumerate(row, 1):
            fmt = currency_fmt if ci in (7,8) else (date_fmt if ci == 10 else None)
            c   = data_cell(ws2, ri, ci, v, row_fill, num_fmt=fmt)
            if ci == 9:
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
    cols_v = ["#","Tenant","Unit","Settlement Date","Deposit Held (₹)",
              "Repair Cost (₹)","Other Deduction (₹)","Amount Returned (₹)",
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
        total_ded = (s.repair_cost or 0) + (s.other_deduction or 0)
        net_color = C_GREEN_BG if returned >= (s.deposit_held or 0) * 0.8 else C_AMBER_BG
        row = [s.id, name, unit, s.settlement_date,
               s.deposit_held or 0, s.repair_cost or 0,
               s.other_deduction or 0, returned,
               s.deduction_notes or ""]
        for ci, v in enumerate(row, 1):
            fmt   = currency_fmt if ci in (5,6,7,8) else (date_fmt if ci == 4 else None)
            fill  = net_color if ci == 8 else row_fill
            data_cell(ws5, ri, ci, v, fill, num_fmt=fmt,
                      align="right" if ci in (5,6,7,8) else "left")
        ws5.row_dimensions[ri].height = 18
    if not settlements:
        ws5.cell(3, 1, "No vacate settlements recorded yet.").font = Font(name="Arial", italic=True, size=9, color="888888")
    auto_width(ws5)

    # ── Stream workbook ───────────────────────────────────────────────────────
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

if __name__ == "__main__":
    port=int(os.environ.get("PORT",5000))
    debug=os.environ.get("FLASK_ENV")=="development"
    app.run(host="0.0.0.0",port=port,debug=debug)