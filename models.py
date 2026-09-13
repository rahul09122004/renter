"""
models.py — Database models and initialization
"""
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def get_database_url():
    url = os.environ.get("DATABASE_URL", "sqlite:///rent.db")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    # ✅ Fixes Render's old-format URL to work with SQLAlchemy

    return url
    # ✅ Returns the correct URL

class Tenant(db.Model):
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

    def due_date_this_month(self):
        """Return a date object for the due date in the current month."""
        import calendar
        from datetime import date as _date
        today = _date.today()
        day = self.get_due_day()
        # Clamp to last day of month (e.g. day=31 in Feb → 28/29)
        max_day = calendar.monthrange(today.year, today.month)[1]
        return _date(today.year, today.month, min(day, max_day))

    def is_join_month(self, month, year):
        """True if (month, year) is the calendar month the tenant joined in.
        Rent is billed in arrears (paid the following month), so the join
        month should never be flagged Pending/Overdue — it's their first
        billing cycle and isn't due yet."""
        if not self.join_date:
            return False
        return self.join_date.month == month and self.join_date.year == year

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


class RentAmountHistory(db.Model):
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

class CommonExpense(db.Model):
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

class BuildingExpense(db.Model):
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

class ReminderLog(db.Model):
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
    __tablename__ = "admin"
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    password_hash   = db.Column(db.String(200), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

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
                    # ── Vacate settlement: charged-vs-actual cost + rent deduction ──
                    conn.execute(text(
                        "ALTER TABLE vacate_settlements ADD COLUMN IF NOT EXISTS repair_actual_cost FLOAT DEFAULT 0"
                    ))
                    conn.execute(text(
                        "ALTER TABLE vacate_settlements ADD COLUMN IF NOT EXISTS other_actual_cost FLOAT DEFAULT 0"
                    ))
                    conn.execute(text(
                        "ALTER TABLE vacate_settlements ADD COLUMN IF NOT EXISTS pending_rent_deducted FLOAT DEFAULT 0"
                    ))
                    # ── Admin: login lockout tracking ──
                    conn.execute(text(
                        "ALTER TABLE admin ADD COLUMN IF NOT EXISTS failed_attempts INTEGER DEFAULT 0"
                    ))
                    conn.execute(text(
                        "ALTER TABLE admin ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP"
                    ))
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
                    for col, coltype in (
                        ("repair_actual_cost", "FLOAT DEFAULT 0"),
                        ("other_actual_cost", "FLOAT DEFAULT 0"),
                        ("pending_rent_deducted", "FLOAT DEFAULT 0"),
                    ):
                        try:
                            conn.execute(text(f"ALTER TABLE vacate_settlements ADD COLUMN {col} {coltype}"))
                        except Exception:
                            pass  # already exists
                    for col, coltype in (
                        ("failed_attempts", "INTEGER DEFAULT 0"),
                        ("locked_until", "TIMESTAMP"),
                    ):
                        try:
                            conn.execute(text(f"ALTER TABLE admin ADD COLUMN {col} {coltype}"))
                        except Exception:
                            pass  # already exists
                conn.commit()
        except Exception as ex:
            print(f"[Migration] due_day: {ex}")  # log but never crash startup

        admin_pw = os.environ.get("ADMIN_PASSWORD", "")
        weak_passwords = {"admin123", "password", "changeme", "12345678", ""}
        if os.environ.get("FLASK_ENV") == "production" and admin_pw.lower() in weak_passwords:
            raise RuntimeError(
                "Refusing to start: ADMIN_PASSWORD is missing or a known-weak default. "
                "Set a strong, unique ADMIN_PASSWORD environment variable in production."
            )
        if not Admin.query.first():
            db.session.add(Admin(
                username="admin",
                password_hash=generate_password_hash(admin_pw or os.urandom(12).hex()),
            ))
            db.session.commit()
            print("[DB] Default admin created — username: admin")

        if not Tenant.query.first():
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
                    join_date=date(2025,4,1), occupancy_status="Active"))

            common_data = [
                ("Water Bill",      2400,"Utilities",  6,date(2026,3,1)),
                ("Lift Maintenance", 900,"Maintenance",6,date(2026,2,15)),
                ("Security Guard",  4200,"Security",   6,date(2026,3,1)),
                ("Cleaning Service",1800,"Cleaning",   6,date(2026,3,5)),
                ("Generator Fuel",  1200,"Utilities",  6,date(2026,2,28)),
            ]
            for desc,amt,cat,units,dt in common_data:
                db.session.add(CommonExpense(description=desc,amount=amt,category=cat,split_units=units,date=dt))

            building_data = [
                ("Roof Repair",        12000,"Repairs",   date(2026,2,20)),
                ("Plumbing Fix",        3500,"Plumbing",  date(2026,3,2)),
                ("Exterior Paint",     18000,"Renovation",date(2026,1,15)),
                ("CCTV Maintenance",    2800,"Security",  date(2026,2,10)),
                ("Electrical Rewiring", 8500,"Electrical",date(2026,3,8)),
            ]
            for desc,amt,cat,dt in building_data:
                db.session.add(BuildingExpense(description=desc,amount=amt,category=cat,date=dt))

            db.session.commit()
            print("[DB] Demo data seeded.")

class VacateSettlement(db.Model):
    """Records deposit settlement when a renter vacates."""
    __tablename__ = "vacate_settlements"
    id                    = db.Column(db.Integer, primary_key=True)
    tenant_id             = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=False)
    deposit_held          = db.Column(db.Float, default=0.0)   # original deposit

    # Amount CHARGED to tenant (deducted from their deposit)
    repair_cost           = db.Column(db.Float, default=0.0)
    other_deduction       = db.Column(db.Float, default=0.0)

    # Amount ACTUALLY spent by owner (this is what flows into Building Expenses)
    repair_actual_cost    = db.Column(db.Float, default=0.0)
    other_actual_cost     = db.Column(db.Float, default=0.0)

    # Unpaid rent recovered from the deposit at vacate time
    pending_rent_deducted = db.Column(db.Float, default=0.0)

    deduction_notes       = db.Column(db.Text, nullable=True)  # breakdown of deductions
    return_amount         = db.Column(db.Float, default=0.0)   # final amount returned
    settlement_date       = db.Column(db.Date, nullable=True)
    created_at            = db.Column(db.DateTime, default=datetime.utcnow)
    tenant                = db.relationship("Tenant", backref="vacate_settlement")

    def profit_kept(self):
        """Amount owner keeps beyond real spend — charged minus actually spent."""
        repair_gap = max(0.0, (self.repair_cost or 0) - (self.repair_actual_cost or 0))
        other_gap  = max(0.0, (self.other_deduction or 0) - (self.other_actual_cost or 0))
        return round(repair_gap + other_gap, 2)

    def total_deducted(self):
        return round((self.repair_cost or 0) + (self.other_deduction or 0) + (self.pending_rent_deducted or 0), 2)

    def to_dict(self):
        return {
            "id": self.id, "tenant_id": self.tenant_id,
            "deposit_held": self.deposit_held,
            "repair_cost": self.repair_cost, "repair_actual_cost": self.repair_actual_cost or 0,
            "other_deduction": self.other_deduction, "other_actual_cost": self.other_actual_cost or 0,
            "pending_rent_deducted": self.pending_rent_deducted or 0,
            "profit_kept": self.profit_kept(),
            "deduction_notes": self.deduction_notes or "",
            "return_amount": self.return_amount,
            "settlement_date": self.settlement_date.strftime("%Y-%m-%d") if self.settlement_date else None,
        }

class RentRecord(db.Model):
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

    def is_new_join_month(self):
        """True if this record's month is the tenant's join month — rent for
        this month is billed in arrears next month, so it's not due yet."""
        return bool(self.tenant) and self.tenant.is_join_month(self.month, self.year)

    def effective_status(self):
        """Status label accounting for arrears billing: a tenant's join-month
        record shows 'New Join' instead of 'Pending', since that month's rent
        isn't due until the following month's cycle."""
        if self.status != "Paid" and self.is_new_join_month():
            return "New Join"
        return self.status

    def is_overdue(self, today=None):
        """Whether this record should be flagged overdue — excludes the join
        month, since that rent isn't due yet."""
        from datetime import date as _date
        today = today or _date.today()
        if self.status == "Paid" or self.is_new_join_month():
            return False
        if self.year != today.year or self.month != today.month:
            # Any unpaid record from a past month (not the join month) is overdue.
            return (self.year, self.month) < (today.year, today.month)
        due_day = self.tenant.get_due_day() if self.tenant else 5
        return today.day > due_day

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "month": self.month,
            "year": self.year,
            "month_label": self.month_label(),
            "rent_amount": self.rent_amount,
            "paid_amount": self.paid_amount,
            "status": self.status,
            "payment_date": self.payment_date.strftime("%Y-%m-%d") if self.payment_date else None,
            "payment_method": self.payment_method or "",
            "transaction_id": self.transaction_id or "",
            "notes": self.notes or "",
            "carried_forward": self.carried_forward,
        }
