"""
models.py — Database models and initialization
"""
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import declared_attr

db = SQLAlchemy()

# ── MULTI-ACCOUNT SCOPING ─────────────────────────────────────────────────────
# Every account (Admin row) owns its own completely separate set of renters,
# rent records and expenses. Each data table carries an `owner_id`, and queries
# are filtered automatically by the listener registered in `enable_owner_scope`,
# so no view has to remember to add the filter itself.

def current_owner_id():
    """The logged-in account's id, or None outside a request/when logged out."""
    try:
        from flask import session, has_request_context
        if not has_request_context():
            return None
        return session.get("owner_id")
    except Exception:
        return None


class OwnedMixin:
    """Marks a table as belonging to one account."""
    @staticmethod
    def _owner_default():
        return current_owner_id()

    @declared_attr
    def owner_id(cls):
        return db.Column(db.Integer, db.ForeignKey("admin.id"),
                         nullable=True, index=True,
                         default=OwnedMixin._owner_default)


def enable_owner_scope(app):
    """Auto-filter every ORM query to the logged-in account's own rows.

    Applied at the session level so relationship loads and lazy loads are
    scoped too — a renter in account A can never surface inside account B.
    """
    from sqlalchemy import event
    from sqlalchemy.orm import with_loader_criteria

    @event.listens_for(db.session, "do_orm_execute")
    def _add_owner_filter(execute_state):
        if not execute_state.is_select or execute_state.is_column_load:
            return
        # Explicit opt-out for admin-level work (user management, migrations)
        if execute_state.execution_options.get("skip_owner_filter", False):
            return
        oid = current_owner_id()
        if oid is None:
            return
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(
                OwnedMixin,
                lambda cls: cls.owner_id == oid,
                include_aliases=True,
            )
        )


def unscoped(query):
    """Run a query without the per-account filter (admin/maintenance use)."""
    return query.execution_options(skip_owner_filter=True)


def get_database_url():
    # `or` (not a get() default): a blank DATABASE_URL= line in .env must mean "use SQLite".
    url = (os.environ.get("DATABASE_URL") or "").strip() or "sqlite:///rent.db"
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)   # Render's old URL format
    # Encrypt the DB connection: require TLS for any non-local PostgreSQL host
    # unless the URL already says otherwise (override with DB_SSLMODE=disable).
    if url.startswith("postgresql"):
        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
        u = urlparse(url)
        q = dict(parse_qsl(u.query))
        host = (u.hostname or "").lower()
        local = host in ("localhost", "127.0.0.1", "::1", "")
        mode = os.environ.get("DB_SSLMODE") or "require"   # blank must NOT disable TLS
        if "sslmode" not in q and not local and mode:
            q["sslmode"] = mode
            url = urlunparse(u._replace(query=urlencode(q)))
    return url

class Tenant(OwnedMixin, db.Model):
    __tablename__ = "tenants"
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(120), nullable=False)
    phone          = db.Column(db.String(20),  nullable=False)
    email          = db.Column(db.String(120), nullable=True)
    unit           = db.Column(db.String(20),  nullable=True, default="")   # type: ignore
    unit_number    = db.Column(db.String(30),  nullable=True, default="")   # e.g. 101, A-2
    amount         = db.Column(db.Float, nullable=False)
    due_day        = db.Column(db.Integer, nullable=False, default=5)   # day of month 1-31
    due_date       = db.Column(db.Date,   nullable=True)   # legacy, kept for migration compat
    status         = db.Column(db.String(10), default="Pending")
    payment_date   = db.Column(db.Date,  nullable=True)
    lease_start       = db.Column(db.Date,  nullable=True)   # legacy, kept for migration compat
    lease_end         = db.Column(db.Date,  nullable=True)   # legacy
    join_date         = db.Column(db.Date,  nullable=True)
    vacated_date      = db.Column(db.Date,  nullable=True)
    occupancy_status  = db.Column(db.String(20), default="Active")  # Active / Vacated
    deposit        = db.Column(db.Float, default=0.0)
    notes          = db.Column(db.Text,  nullable=True)
    photo_path        = db.Column(db.String(255), nullable=True)
    agreement_path    = db.Column(db.String(255), nullable=True)
    payment_method    = db.Column(db.String(20),  nullable=True)   # cash / upi / bank
    transaction_id    = db.Column(db.String(100), nullable=True)
    payment_screenshot= db.Column(db.String(255), nullable=True)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index("ix_tenants_occupancy_status", "occupancy_status"),
        db.Index("ix_tenants_status", "status"),
    )

    def get_due_day(self):
        """Return the due day integer (1–31), falling back to due_date.day for old records."""
        if self.due_day and int(self.due_day) > 0:
            return int(self.due_day)
        if self.due_date:
            return self.due_date.day
        return 5  # sensible default

    # ── Deposit instalment helpers (half-deposit support) ──────────────────
    def deposit_paid(self):
        """Total deposit actually collected so far (sum of instalments)."""
        try:
            return float(sum(p.amount or 0 for p in (self.deposit_payments or [])))
        except Exception:
            return 0.0

    def deposit_balance(self):
        """Deposit still to be collected from this tenant."""
        return max(0.0, float(self.deposit or 0) - self.deposit_paid())

    def deposit_status(self):
        """'Paid' / 'Partial' / 'Unpaid' / 'None' based on instalments collected."""
        agreed = float(self.deposit or 0)
        if agreed <= 0:
            return "None"
        paid = self.deposit_paid()
        if paid <= 0:
            return "Unpaid"
        if paid + 0.01 >= agreed:
            return "Paid"
        return "Partial"

    def deposit_percent(self):
        agreed = float(self.deposit or 0)
        if agreed <= 0:
            return 0
        return min(100, int(round(self.deposit_paid() / agreed * 100)))

    # ── Billing-cycle helpers (rent for month M is billed/due in M+1) ──────
    def due_date_for_rent_month(self, year, month):
        """Rent for (year, month) is collected the FOLLOWING month.
        Returns the actual due date object in that following month."""
        import calendar
        from datetime import date as _date
        y, m = (year + 1, 1) if month == 12 else (year, month + 1)
        day = self.get_due_day()
        max_day = calendar.monthrange(y, m)[1]
        return _date(y, m, min(day, max_day))

    def current_due_date(self):
        """Due date for the CURRENT month's rent — falls in next month."""
        from datetime import date as _date
        today = _date.today()
        return self.due_date_for_rent_month(today.year, today.month)

    def due_date_this_month(self):
        """Return a date object for the due date in the current month."""
        import calendar
        from datetime import date as _date
        today = _date.today()
        day = self.get_due_day()
        # Clamp to last day of month (e.g. day=31 in Feb → 28/29)
        max_day = calendar.monthrange(today.year, today.month)[1]
        return _date(today.year, today.month, min(day, max_day))

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "phone": self.phone,
            "email": self.email or "", "unit": self.unit or "",
            "amount": self.amount,
            "due_day": self.get_due_day(),
            "status": self.status,
            "payment_date": self.payment_date.strftime("%Y-%m-%d") if self.payment_date else None,
            "deposit": self.deposit or 0,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
        }


class DepositPayment(OwnedMixin, db.Model):
    """One instalment of a security deposit.

    Lets a renter pay the deposit in parts (e.g. half now, half later).
    Tenant.deposit stays the AGREED total; the sum of these rows is what
    has actually been collected.
    """
    __tablename__ = "deposit_payments"
    id             = db.Column(db.Integer, primary_key=True)
    tenant_id      = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    tenant_name    = db.Column(db.String(120))
    amount         = db.Column(db.Float, nullable=False)
    payment_date   = db.Column(db.Date, nullable=True)
    method         = db.Column(db.String(30), nullable=True)   # cash / upi / bank
    transaction_id = db.Column(db.String(100), nullable=True)
    notes          = db.Column(db.Text, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    tenant = db.relationship(
        "Tenant",
        backref=db.backref("deposit_payments", order_by="DepositPayment.payment_date"),
    )

    __table_args__ = (
        db.Index("ix_deposit_payments_tenant", "tenant_id"),
    )

    def to_dict(self):
        return {
            "id": self.id, "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name, "amount": self.amount,
            "payment_date": self.payment_date.strftime("%Y-%m-%d") if self.payment_date else None,
            "method": self.method or "", "transaction_id": self.transaction_id or "",
            "notes": self.notes or "",
        }


class RentAmountHistory(OwnedMixin, db.Model):
    """Tracks changes to rent amount and deposit over time (e.g. yearly revision)."""
    __tablename__ = "rent_amount_history"
    id            = db.Column(db.Integer, primary_key=True)
    tenant_id     = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    tenant_name   = db.Column(db.String(120))
    old_amount    = db.Column(db.Float, nullable=False)
    new_amount    = db.Column(db.Float, nullable=False)
    old_deposit   = db.Column(db.Float, default=0.0)
    new_deposit   = db.Column(db.Float, default=0.0)
    effective_from = db.Column(db.Date, nullable=False)   # month the new amount applies from
    notes         = db.Column(db.Text, nullable=True)
    changed_at    = db.Column(db.DateTime, default=datetime.utcnow)
    tenant        = db.relationship("Tenant", backref="amount_history")

    def to_dict(self):
        return {
            "id": self.id, "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "old_amount": self.old_amount, "new_amount": self.new_amount,
            "old_deposit": self.old_deposit, "new_deposit": self.new_deposit,
            "effective_from": self.effective_from.strftime("%Y-%m-%d") if self.effective_from else None,
            "notes": self.notes or "",
            "changed_at": self.changed_at.strftime("%d %b %Y %H:%M") if self.changed_at else None,
        }

class CommonExpense(OwnedMixin, db.Model):
    __tablename__ = "common_expenses"
    id          = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    amount      = db.Column(db.Float, nullable=False)
    category    = db.Column(db.String(80), default="Other")
    split_units = db.Column(db.Integer, default=6)
    date        = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    notes       = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index("ix_common_expenses_date", "date"),
    )

    def to_dict(self):
        return {
            "id": self.id, "description": self.description,
            "amount": self.amount, "category": self.category,
            "split_units": self.split_units,
            "per_unit": round(self.amount / self.split_units, 2) if self.split_units else self.amount,
            "date": self.date.strftime("%Y-%m-%d") if self.date else None,
            "notes": self.notes or "",
        }

class BuildingExpense(OwnedMixin, db.Model):
    __tablename__ = "building_expenses"
    id           = db.Column(db.Integer, primary_key=True)
    description  = db.Column(db.String(200), nullable=False)
    amount       = db.Column(db.Float, nullable=False)
    category     = db.Column(db.String(80), default="Maintenance")
    date         = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    receipt_path = db.Column(db.String(255), nullable=True)
    notes        = db.Column(db.Text, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.Index("ix_building_expenses_date", "date"),
    )

    def to_dict(self):
        return {
            "id": self.id, "description": self.description,
            "amount": self.amount, "category": self.category,
            "date": self.date.strftime("%Y-%m-%d") if self.date else None,
            "notes": self.notes or "",
        }

class ReminderLog(OwnedMixin, db.Model):
    __tablename__ = "reminder_logs"
    id          = db.Column(db.Integer, primary_key=True)
    tenant_id   = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True)
    tenant_name = db.Column(db.String(120))
    channel     = db.Column(db.String(20))
    status      = db.Column(db.String(20))
    message     = db.Column(db.Text)
    sent_at     = db.Column(db.DateTime, default=datetime.utcnow)
    tenant      = db.relationship("Tenant", backref="reminder_logs")

    def to_dict(self):
        return {
            "id": self.id, "tenant_name": self.tenant_name,
            "channel": self.channel, "status": self.status,
            "message": self.message or "",
            "sent_at": self.sent_at.strftime("%d %b %Y %H:%M") if self.sent_at else None,
        }

class Admin(db.Model):
    """A login account. Each account owns an isolated set of property data."""
    __tablename__ = "admin"
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name     = db.Column(db.String(120), nullable=True)
    email         = db.Column(db.String(120), nullable=True)
    property_name = db.Column(db.String(120), nullable=True)  # e.g. "Sunrise Apartments"
    role          = db.Column(db.String(20), default="owner") # owner / superadmin
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime, nullable=True)
    # ── account security ──────────────────────────────────────────────────
    email_verified       = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    session_version      = db.Column(db.Integer, default=0)   # bump → every session revoked
    failed_logins        = db.Column(db.Integer, default=0)
    locked_until         = db.Column(db.DateTime, nullable=True)
    password_changed_at  = db.Column(db.DateTime, nullable=True)

    def is_superadmin(self):
        return (self.role or "").lower() == "superadmin"

    def display_name(self):
        return self.full_name or self.username

    def to_dict(self):
        return {
            "id": self.id, "username": self.username,
            "full_name": self.full_name or "", "email": self.email or "",
            "property_name": self.property_name or "",
            "role": self.role or "owner", "is_active": bool(self.is_active),
            "created_at": self.created_at.strftime("%d %b %Y") if self.created_at else None,
            "last_login": self.last_login.strftime("%d %b %Y %H:%M") if self.last_login else None,
        }


def _bootstrap_admin():
    """Create the first super-admin WITHOUT a well-known password.

    * ADMIN_PASSWORD is used only if it passes the password policy.
    * Otherwise a random one-time password is generated, printed once to the
      server log, and the account is forced to change it at first login.
    """
    import secrets
    from security import hash_password
    from validators import check_password_strength
    username = os.environ.get("ADMIN_USERNAME", "admin").strip().lower() or "admin"
    pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    generated = False
    if pw and check_password_strength(pw, username):
        print("[SECURITY] ADMIN_PASSWORD rejected (too weak / well-known). Generating a random one.")
        pw = ""
    if not pw:
        pw = secrets.token_urlsafe(14)
        generated = True
    admin = Admin(username=username, password_hash=hash_password(pw),
                  full_name="Administrator", property_name="My Property",
                  role="superadmin", is_active=True, email_verified=True,
                  must_change_password=generated, session_version=0)
    db.session.add(admin)
    db.session.commit()
    if generated:
        print("=" * 64)
        print(f"[SECURITY] Initial admin created.  username: {username}")
        print(f"[SECURITY] One-time password: {pw}")
        print("[SECURITY] You must change it at first login. Remove this from your logs afterwards.")
        print("=" * 64)
    else:
        print(f"[DB] Admin '{username}' created from ADMIN_PASSWORD.")
    return admin


def _flag_default_admin_password(admin):
    """Existing deployments: a super-admin still using a well-known password is
    replaced by a random one-time password at start-up (production only).

    Merely *forcing a change at next login* would let anyone who knows the default
    log in first and pick their own password, so the known credential is
    neutralised immediately and the new one is printed once in the server log.
    """
    try:
        import secrets
        from security import verify_password, hash_password, is_production
        from validators import check_password_strength
        if not is_production() or admin.role != "superadmin":
            return
        bad = {"admin123", "admin", "password", "changeme"}
        env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
        if env_pw and check_password_strength(env_pw, admin.username):
            bad.add(env_pw)                       # only a WEAK env value counts as compromised
        if not any(verify_password(admin.password_hash, c) for c in bad):
            return
        new_pw = secrets.token_urlsafe(14)
        admin.password_hash = hash_password(new_pw)
        admin.must_change_password = True
        admin.session_version = (admin.session_version or 0) + 1
        admin.failed_logins, admin.locked_until = 0, None
        db.session.commit()
        print("=" * 64)
        print(f"[SECURITY] Super-admin '{admin.username}' was using a known default password.")
        print("[SECURITY] It has been REPLACED and all sessions revoked.")
        print(f"[SECURITY] One-time password: {new_pw}   (must be changed at first login)")
        print("=" * 64)
    except Exception as ex:                                  # noqa: BLE001
        db.session.rollback()
        print(f"[SECURITY] default-password check skipped: {type(ex).__name__}")


def _lock_down_postgres():
    """Stop Supabase's auto-generated REST API (anon/authenticated roles) from
    touching our tables. The app connects as the table owner, which bypasses
    RLS, so enabling RLS with NO policies denies everyone else. Idempotent."""
    try:
        from sqlalchemy import text
        if "postgresql" not in str(db.engine.url):
            return
        with db.engine.begin() as conn:
            # Never let a busy database hang start-up: give up on the lock after 10 s.
            conn.execute(text("SET LOCAL lock_timeout = '10s'"))
            roles = {r[0] for r in conn.execute(text(
                "SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated')"))}
            for tbl in db.metadata.tables:
                conn.execute(text(f'ALTER TABLE "{tbl}" ENABLE ROW LEVEL SECURITY'))
                for role in roles:
                    conn.execute(text(f'REVOKE ALL ON TABLE "{tbl}" FROM {role}'))
        print("[SECURITY] Row-level security enabled on all app tables.")
    except Exception as ex:                                  # noqa: BLE001
        print(f"[SECURITY] Could not enable RLS ({type(ex).__name__}); run docs/supabase_lockdown.sql manually.")


def init_db(app):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        db.create_all()  # creates all tables including rent_amount_history

        # ── Migration: add due_day column if missing, then populate it ──
        try:
            from sqlalchemy import text
            db_url = str(db.engine.url)
            with db.engine.connect() as conn:
                if "postgresql" in db_url:
                    # Add due_day column if missing
                    conn.execute(text(
                        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS due_day INTEGER DEFAULT 5"
                    ))
                    # Make due_date nullable (was NOT NULL in old schema) so edits don't fail
                    try:
                        conn.execute(text(
                            "ALTER TABLE tenants ALTER COLUMN due_date DROP NOT NULL"
                        ))
                    except Exception:
                        pass  # already nullable
                    conn.execute(text(
                        "UPDATE tenants SET due_day = EXTRACT(DAY FROM due_date)::INTEGER "
                        "WHERE (due_day IS NULL OR due_day = 0) AND due_date IS NOT NULL"
                    ))
                    conn.execute(text(
                        "UPDATE tenants SET due_day = 5 WHERE due_day IS NULL OR due_day = 0"
                    ))
                    # Add performance indexes for frequent queries
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_rent_records_month_year_status "
                        "ON rent_records (month, year, status)"
                    ))
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_rent_records_payment_date_status "
                        "ON rent_records (payment_date, status)"
                    ))
                    conn.execute(text(
                        "CREATE INDEX IF NOT EXISTS ix_tenants_occupancy "
                        "ON tenants (occupancy_status)"
                    ))
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS rent_amount_history (
                            id SERIAL PRIMARY KEY,
                            tenant_id INTEGER REFERENCES tenants(id),
                            tenant_name VARCHAR(120),
                            old_amount FLOAT NOT NULL,
                            new_amount FLOAT NOT NULL,
                            old_deposit FLOAT DEFAULT 0,
                            new_deposit FLOAT DEFAULT 0,
                            effective_from DATE,
                            notes TEXT,
                            changed_at TIMESTAMP DEFAULT NOW()
                        )
                    """))
                else:  # SQLite
                    try:
                        conn.execute(text("ALTER TABLE tenants ADD COLUMN due_day INTEGER DEFAULT 5"))
                    except Exception:
                        pass  # column already exists
                    conn.execute(text(
                        "UPDATE tenants SET due_day = CAST(strftime(\'%d\', due_date) AS INTEGER) "
                        "WHERE (due_day IS NULL OR due_day = 0) AND due_date IS NOT NULL"
                    ))
                    conn.execute(text(
                        "UPDATE tenants SET due_day = 5 WHERE due_day IS NULL OR due_day = 0"
                    ))
                conn.commit()
        except Exception as ex:
            print(f"[Migration] due_day: {ex}")  # log but never crash startup

        # ── Migration: deposit instalments + vacate repair-margin columns ──
        try:
            from sqlalchemy import text
            db_url = str(db.engine.url)
            is_pg = "postgresql" in db_url
            new_cols = [
                ("vacate_settlements", "repair_charged",   "FLOAT DEFAULT 0"),
                ("vacate_settlements", "repair_actual",    "FLOAT DEFAULT 0"),
                ("vacate_settlements", "unpaid_rent",      "FLOAT DEFAULT 0"),
                ("vacate_settlements", "unpaid_rent_ids",  "TEXT"),
                ("vacate_settlements", "unpaid_rent_note", "TEXT"),
            ]
            with db.engine.connect() as conn:
                for table, col, coltype in new_cols:
                    try:
                        if is_pg:
                            conn.execute(text(
                                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {coltype}"
                            ))
                        else:
                            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))
                    except Exception:
                        pass  # column already exists
                # Backfill repair_charged from the legacy repair_cost column
                try:
                    conn.execute(text(
                        "UPDATE vacate_settlements SET repair_charged = repair_cost "
                        "WHERE (repair_charged IS NULL OR repair_charged = 0) AND repair_cost > 0"
                    ))
                except Exception:
                    pass
                conn.commit()
        except Exception as ex:
            print(f"[Migration] settlement columns: {ex}")

        # ── Migration: multi-account columns ──────────────────────────────
        # Adds owner_id to every data table and the profile columns on admin,
        # then hands all pre-existing rows to the first (original) account so
        # nothing disappears when scoping switches on.
        try:
            from sqlalchemy import text
            db_url = str(db.engine.url)
            is_pg = "postgresql" in db_url
            owned_tables = ["tenants", "rent_records", "common_expenses",
                            "building_expenses", "reminder_logs",
                            "vacate_settlements", "rent_amount_history",
                            "deposit_payments"]
            admin_cols = [
                ("full_name",     "VARCHAR(120)"),
                ("email",         "VARCHAR(120)"),
                ("property_name", "VARCHAR(120)"),
                ("role",          "VARCHAR(20) DEFAULT 'owner'"),
                ("is_active",     "BOOLEAN DEFAULT TRUE" if is_pg else "BOOLEAN DEFAULT 1"),
                ("created_at",    "TIMESTAMP"),
                ("last_login",    "TIMESTAMP"),
                # Existing accounts are grandfathered as verified so nobody is locked out.
                ("email_verified",       "BOOLEAN DEFAULT TRUE" if is_pg else "BOOLEAN DEFAULT 1"),
                ("must_change_password", "BOOLEAN DEFAULT FALSE" if is_pg else "BOOLEAN DEFAULT 0"),
                ("session_version",      "INTEGER DEFAULT 0"),
                ("failed_logins",        "INTEGER DEFAULT 0"),
                ("locked_until",         "TIMESTAMP"),
                ("password_changed_at",  "TIMESTAMP"),
            ]
            with db.engine.connect() as conn:
                for tbl in owned_tables:
                    try:
                        if is_pg:
                            conn.execute(text(
                                f"ALTER TABLE {tbl} ADD COLUMN IF NOT EXISTS owner_id INTEGER"))
                        else:
                            conn.execute(text(f"ALTER TABLE {tbl} ADD COLUMN owner_id INTEGER"))
                    except Exception:
                        pass
                    try:
                        conn.execute(text(
                            f"CREATE INDEX IF NOT EXISTS ix_{tbl}_owner_id ON {tbl} (owner_id)"))
                    except Exception:
                        pass
                for col, coltype in admin_cols:
                    try:
                        if is_pg:
                            conn.execute(text(
                                f"ALTER TABLE admin ADD COLUMN IF NOT EXISTS {col} {coltype}"))
                        else:
                            conn.execute(text(f"ALTER TABLE admin ADD COLUMN {col} {coltype}"))
                    except Exception:
                        pass
                try:
                    conn.execute(text("UPDATE admin SET role = 'owner' WHERE role IS NULL"))
                    conn.execute(text("UPDATE admin SET is_active = 1 WHERE is_active IS NULL")
                                 if not is_pg else
                                 text("UPDATE admin SET is_active = TRUE WHERE is_active IS NULL"))
                except Exception:
                    pass
                # Hand legacy (unowned) rows to the original account
                try:
                    first = conn.execute(text("SELECT id FROM admin ORDER BY id ASC LIMIT 1")).fetchone()
                    if first:
                        # The original account becomes the super admin so it
                        # keeps access to user management after the upgrade.
                        conn.execute(text(
                            "UPDATE admin SET role = 'superadmin' WHERE id = :oid"),
                            {"oid": first[0]})
                        for tbl in owned_tables:
                            try:
                                conn.execute(text(
                                    f"UPDATE {tbl} SET owner_id = :oid WHERE owner_id IS NULL"),
                                    {"oid": first[0]})
                            except Exception:
                                pass
                except Exception:
                    pass
                conn.commit()
        except Exception as ex:
            print(f"[Migration] multi-account: {ex}")

        # ── Seed deposit instalments for existing tenants ──────────────────
        # Existing renters already handed over their full deposit, so record
        # it as a single instalment; otherwise they'd all show as "Unpaid".
        try:
            if not unscoped(DepositPayment.query).first():
                seeded = 0
                for t in unscoped(Tenant.query.filter(Tenant.deposit > 0)).all():
                    db.session.add(DepositPayment(
                        tenant_id=t.id, tenant_name=t.name, owner_id=t.owner_id,
                        amount=t.deposit, payment_date=t.join_date,
                        method="cash", notes="Auto-recorded from existing deposit balance.",
                    ))
                    seeded += 1
                if seeded:
                    db.session.commit()
                    print(f"[DB] Seeded {seeded} deposit instalment(s) from existing deposits.")
        except Exception as ex:
            db.session.rollback()
            print(f"[Migration] deposit seed: {ex}")

        first_admin = unscoped(Admin.query).order_by(Admin.id.asc()).first()
        if not first_admin:
            first_admin = _bootstrap_admin()
        else:
            _flag_default_admin_password(first_admin)

        db.session.commit()          # end our own transaction: it would otherwise hold locks the DDL below waits on
        if os.environ.get("DB_ENABLE_RLS", "1") != "0":
            _lock_down_postgres()

        OWNER = first_admin.id
        seed_demo = (os.environ.get("SEED_DEMO_DATA", "").lower() in ("1", "true", "yes")
                     or os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "")).lower() == "development")
        # Demo tenants carry fake phone numbers that could belong to real people and
        # would receive real WhatsApp reminders — never seed them in production.
        if seed_demo and not unscoped(Tenant.query).first():
            from datetime import date
            demo = [
                ("Arjun Sharma",  "919876543210","arjun@email.com",  "Flat 1A",18000, 5, "Paid",   date(2026,3,3), 50000),
                ("Priya Nair",    "919876543211","priya@email.com",  "Flat 1B",16500, 7, "Paid",   date(2026,3,6), 45000),
                ("Ravi Kumar",    "919876543212","ravi@email.com",   "Flat 2A",19000,10, "Pending",None,           55000),
                ("Sneha Iyer",    "919876543213","sneha@email.com",  "Flat 2B",17500,10, "Pending",None,           48000),
                ("Karan Mehta",   "919876543214","karan@email.com",  "Flat 3A",20000,12, "Paid",   date(2026,3,11),60000),
                ("Divya Reddy",   "919876543215","divya@email.com",  "Flat 3B",15000,15, "Pending",None,           42000),
                ("Vikram Singh",  "919876543216","vikram@email.com", "Flat 4A",22000, 8, "Pending",None,           65000),
            ]
            for name,phone,email,unit,amt,due_day,status,paid_on,deposit in demo:
                db.session.add(Tenant(name=name,phone=phone,email=email,unit=unit,amount=amt,
                    due_day=due_day,status=status,payment_date=paid_on,deposit=deposit,
                    join_date=date(2025,4,1), occupancy_status="Active", owner_id=OWNER))

            common_data = [
                ("Water Bill",      2400,"Utilities",  6,date(2026,3,1)),
                ("Lift Maintenance", 900,"Maintenance",6,date(2026,2,15)),
                ("Security Guard",  4200,"Security",   6,date(2026,3,1)),
                ("Cleaning Service",1800,"Cleaning",   6,date(2026,3,5)),
                ("Generator Fuel",  1200,"Utilities",  6,date(2026,2,28)),
            ]
            for desc,amt,cat,units,dt in common_data:
                db.session.add(CommonExpense(description=desc,amount=amt,category=cat,split_units=units,date=dt,owner_id=OWNER))

            building_data = [
                ("Roof Repair",        12000,"Repairs",   date(2026,2,20)),
                ("Plumbing Fix",        3500,"Plumbing",  date(2026,3,2)),
                ("Exterior Paint",     18000,"Renovation",date(2026,1,15)),
                ("CCTV Maintenance",    2800,"Security",  date(2026,2,10)),
                ("Electrical Rewiring", 8500,"Electrical",date(2026,3,8)),
            ]
            for desc,amt,cat,dt in building_data:
                db.session.add(BuildingExpense(description=desc,amount=amt,category=cat,date=dt,owner_id=OWNER))

            db.session.commit()
            print("[DB] Demo data seeded.")

class VacateSettlement(OwnedMixin, db.Model):
    """Records deposit settlement when a renter vacates."""
    __tablename__ = "vacate_settlements"
    id              = db.Column(db.Integer, primary_key=True)
    tenant_id       = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    deposit_held    = db.Column(db.Float, default=0.0)   # deposit actually collected
    repair_cost     = db.Column(db.Float, default=0.0)   # legacy = repair_charged
    other_deduction = db.Column(db.Float, default=0.0)   # any other deductions
    deduction_notes = db.Column(db.Text, nullable=True)  # breakdown of deductions
    return_amount   = db.Column(db.Float, default=0.0)   # final amount returned
    settlement_date = db.Column(db.Date, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    # ── Repair margin ("profit from deposit") ──────────────────────────────
    repair_charged   = db.Column(db.Float, default=0.0)  # billed to the tenant
    repair_actual    = db.Column(db.Float, default=0.0)  # actually spent by owner
    # ── Unpaid rent recovered from the deposit ─────────────────────────────
    unpaid_rent      = db.Column(db.Float, default=0.0)
    unpaid_rent_ids  = db.Column(db.Text, nullable=True) # csv of RentRecord ids
    unpaid_rent_note = db.Column(db.Text, nullable=True) # human-readable months

    tenant = db.relationship("Tenant", backref="vacate_settlement")

    def repair_profit(self):
        """Margin kept by the owner on repairs (charged − actually spent)."""
        return float(self.repair_charged or 0) - float(self.repair_actual or 0)

    def total_deductions(self):
        return (float(self.repair_charged or self.repair_cost or 0)
                + float(self.other_deduction or 0)
                + float(self.unpaid_rent or 0))

    def to_dict(self):
        return {
            "id": self.id, "tenant_id": self.tenant_id,
            "deposit_held": self.deposit_held, "repair_cost": self.repair_cost,
            "repair_charged": self.repair_charged, "repair_actual": self.repair_actual,
            "repair_profit": self.repair_profit(),
            "unpaid_rent": self.unpaid_rent, "unpaid_rent_note": self.unpaid_rent_note or "",
            "other_deduction": self.other_deduction, "deduction_notes": self.deduction_notes or "",
            "return_amount": self.return_amount,
            "settlement_date": self.settlement_date.strftime("%Y-%m-%d") if self.settlement_date else None,
        }

class RentRecord(OwnedMixin, db.Model):
    """One row per tenant per month — the heart of month-wise tracking."""
    __tablename__ = "rent_records"
    id               = db.Column(db.Integer, primary_key=True)
    tenant_id        = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    tenant_name      = db.Column(db.String(120))          # snapshot in case tenant renamed
    month            = db.Column(db.Integer, nullable=False)   # 1-12
    year             = db.Column(db.Integer, nullable=False)
    rent_amount      = db.Column(db.Float,   nullable=False)   # rent charged that month
    paid_amount      = db.Column(db.Float,   nullable=True)    # actual paid
    status           = db.Column(db.String(10), default="Pending")  # Paid / Pending
    payment_date     = db.Column(db.Date,   nullable=True)
    payment_method   = db.Column(db.String(30), nullable=True)
    transaction_id   = db.Column(db.String(100), nullable=True)
    payment_screenshot = db.Column(db.String(255), nullable=True)
    notes            = db.Column(db.Text, nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    carried_forward  = db.Column(db.Boolean, default=False)    # True if unpaid from prev month

    tenant = db.relationship("Tenant", backref="rent_records")

    __table_args__ = (
        db.UniqueConstraint("tenant_id", "month", "year", name="uq_tenant_month_year"),
        db.Index("ix_rent_records_month_year", "month", "year"),
        db.Index("ix_rent_records_status", "status"),
        db.Index("ix_rent_records_payment_date", "payment_date"),
    )

    def month_label(self):
        from datetime import date
        return date(self.year, self.month, 1).strftime("%B %Y")

    # ── Billing cycle display ─────────────────────────────────────────────
    # Nothing in the DB changes: a record still stores ONE month (the month
    # the rent is FOR). It is simply collected in the following month, so we
    # label it as a span, e.g. September 2026 → "Sep–Oct 2026".
    def billing_month_year(self):
        """(year, month) of the month this rent is actually billed/collected in."""
        return (self.year + 1, 1) if self.month == 12 else (self.year, self.month + 1)

    def cycle_label(self):
        """Short span label — 'Sep–Oct 2026' (or 'Dec 2026–Jan 2027' across a year end)."""
        from datetime import date
        by, bm = self.billing_month_year()
        start = date(self.year, self.month, 1)
        end   = date(by, bm, 1)
        if by == self.year:
            return f"{start.strftime('%b')}–{end.strftime('%b %Y')}"
        return f"{start.strftime('%b %Y')}–{end.strftime('%b %Y')}"

    def billed_in_label(self):
        """'billed in October' — the small note shown under the cycle label."""
        from datetime import date
        by, bm = self.billing_month_year()
        return f"billed in {date(by, bm, 1).strftime('%B')}"

    def due_date_obj(self):
        """Actual due date — the due day of the FOLLOWING month."""
        import calendar
        from datetime import date
        by, bm = self.billing_month_year()
        day = self.tenant.get_due_day() if self.tenant else 5
        return date(by, bm, min(day, calendar.monthrange(by, bm)[1]))

    def is_overdue(self, today=None):
        """Unpaid AND past the due day of the following month."""
        from datetime import date
        if self.status == "Paid":
            return False
        return (today or date.today()) > self.due_date_obj()

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "month": self.month,
            "year": self.year,
            "month_label": self.month_label(),
            "cycle_label": self.cycle_label(),
            "billed_in": self.billed_in_label(),
            "rent_amount": self.rent_amount,
            "paid_amount": self.paid_amount,
            "status": self.status,
            "payment_date": self.payment_date.strftime("%Y-%m-%d") if self.payment_date else None,
            "payment_method": self.payment_method or "",
            "transaction_id": self.transaction_id or "",
            "notes": self.notes or "",
            "carried_forward": self.carried_forward,
        }
