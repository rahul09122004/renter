"""
scheduler.py — APScheduler background jobs
  - Daily 9:00 AM  : send WhatsApp reminders for due/upcoming rents
  - Monthly 1st    : re-sync tenant status from their new current billing period
  - Daily 12:05 AM : SQLite database backup

Rent is billed in arrears: a tenant's currently-payable record is for LAST
month's usage (Tenant.current_billing_period()), not the current calendar
month — except a brand-new tenant, whose first (not-yet-due) record is this
month's own. All the jobs below respect that.
"""

import os
import shutil
import logging
from datetime import date, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(timezone="Asia/Kolkata")


# ──────────────────────────────────────────
# JOB 1 — Daily reminder (9:00 AM IST)
# ──────────────────────────────────────────
def send_daily_reminders(app):
    """Check tenants whose current billing-period record is unpaid and send
    WhatsApp reminders if their due day is today or in 3 days."""
    from models import Tenant, RentRecord, db
    from whatsapp import send_rent_reminder

    with app.app_context():
        today = date.today()
        active_tenants = Tenant.query.filter_by(occupancy_status="Active").all()
        sent = 0
        checked = 0

        for t in active_tenants:
            bm, by = t.current_billing_period(today)
            rec = RentRecord.query.filter_by(tenant_id=t.id, month=bm, year=by).first()
            if not rec or rec.status == "Paid":
                continue
            if rec.is_not_yet_due(today):
                continue  # brand-new tenant, first bill isn't due yet
            checked += 1
            due_day = t.get_due_day()
            is_due_today = (today.day == due_day)
            is_due_in_3  = ((today + timedelta(days=3)).day == due_day)
            if is_due_today or is_due_in_3:
                label = "today" if is_due_today else f"in 3 days (the {due_day}th)"
                result = send_rent_reminder(
                    to_phone=t.phone,
                    tenant_name=t.name,
                    amount=rec.balance_due() if rec.balance_due() else rec.rent_amount,
                    due_date=f"{due_day}th of every month",
                )
                if "error" not in result:
                    sent += 1
                    logger.info(f"[Scheduler] Reminder → {t.name} ({label}), for {rec.month_label()}")
                else:
                    logger.warning(f"[Scheduler] Failed → {t.name}: {result}")

        logger.info(f"[Scheduler] Daily reminders done. Sent: {sent}/{checked}")


# ──────────────────────────────────────────
# JOB 2 — Monthly status re-sync (1st of month, 12:01 AM)
# ──────────────────────────────────────────
def monthly_status_sync(app):
    """On the 1st of each month, every active tenant's 'current billing
    period' shifts to a new record (last month's usage). Re-sync
    tenant.status/payment fields from THAT record — never blindly reset to
    Pending, since a tenant may already have paid early, or this may be a
    genuinely new (not-yet-due) join-month record."""
    from models import Tenant, RentRecord, db

    with app.app_context():
        today = date.today()
        tenants = Tenant.query.filter_by(occupancy_status="Active").all()
        updated = 0
        for t in tenants:
            bm, by = t.current_billing_period(today)
            rec = RentRecord.query.filter_by(tenant_id=t.id, month=bm, year=by).first()
            if not rec:
                continue
            if t.status != rec.status:
                t.status = rec.status
                if rec.status in ("Paid", "Partial"):
                    t.payment_date   = rec.payment_date
                    t.payment_method = rec.payment_method
                    t.transaction_id = rec.transaction_id
                else:
                    t.payment_date   = None
                    t.payment_method = None
                    t.transaction_id = None
                updated += 1
        db.session.commit()
        logger.info(f"[Scheduler] Monthly status sync done. {updated} tenant(s) updated.")


# ──────────────────────────────────────────
# JOB 3 — Daily DB backup (12:05 AM)
# ──────────────────────────────────────────
def daily_backup(app):
    """Copy SQLite DB to /backup folder with date stamp."""
    src = os.path.join(app.instance_path, "rent.db")
    if not os.path.exists(src):
        # Try project root
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rent.db")

    if not os.path.exists(src):
        logger.warning("[Backup] Database file not found, skipping backup.")
        return

    backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup")
    os.makedirs(backup_dir, exist_ok=True)

    today_str = date.today().strftime("%Y-%m-%d")
    dst = os.path.join(backup_dir, f"rent_backup_{today_str}.db")

    try:
        shutil.copy2(src, dst)
        logger.info(f"[Backup] Saved → {dst}")
    except Exception as e:
        logger.error(f"[Backup] Failed: {e}")


# ──────────────────────────────────────────
# Scheduler init
# ──────────────────────────────────────────
def ensure_monthly_records(app):
    """Ensure each active tenant's CURRENT billing-period record exists
    (last month's usage, or this month's own for a brand-new tenant — see
    Tenant.current_billing_period()). Runs once at midnight via scheduler
    and once at startup — NOT on every request."""
    from models import Tenant, RentRecord, db

    with app.app_context():
        today = date.today()
        active_tenants = Tenant.query.filter_by(occupancy_status="Active").all()
        if not active_tenants:
            return

        # Group tenants by which (month, year) they need a record for —
        # usually all the same, but a tenant who joined this month differs.
        needed = {}  # (month, year) -> [tenant, ...]
        for t in active_tenants:
            bm, by = t.current_billing_period(today)
            needed.setdefault((bm, by), []).append(t)

        created = 0
        for (bm, by), tenants_for_period in needed.items():
            ids = [t.id for t in tenants_for_period]
            existing_ids = {
                tid for (tid,) in db.session.query(RentRecord.tenant_id).filter(
                    RentRecord.month == bm,
                    RentRecord.year == by,
                    RentRecord.tenant_id.in_(ids),
                ).all()
            }
            new_records = [
                RentRecord(
                    tenant_id=t.id, tenant_name=t.name,
                    month=bm, year=by,
                    rent_amount=t.amount, status="Pending",
                )
                for t in tenants_for_period if t.id not in existing_ids
            ]
            if new_records:
                db.session.add_all(new_records)
                created += len(new_records)
        if created:
            db.session.commit()
            logger.info(f"[Scheduler] Created {created} rent record(s) for the current billing cycle.")
        else:
            logger.info("[Scheduler] All current billing-period records already exist.")


def init_scheduler(app):
    """Register all cron jobs and start the scheduler."""

    # Job 0: Ensure current billing-period records exist at midnight IST
    scheduler.add_job(
        func=ensure_monthly_records,
        trigger=CronTrigger(hour=0, minute=0, timezone="Asia/Kolkata"),
        args=[app],
        id="ensure_monthly_records",
        replace_existing=True,
        misfire_grace_time=600,
    )

    # Job 1: Daily reminders at 9:00 AM IST
    scheduler.add_job(
        func=send_daily_reminders,
        trigger=CronTrigger(hour=9, minute=0, timezone="Asia/Kolkata"),
        args=[app],
        id="daily_reminders",
        replace_existing=True,
        misfire_grace_time=300,
    )

    # Job 2: Monthly status re-sync — 1st of month at 12:01 AM IST
    scheduler.add_job(
        func=monthly_status_sync,
        trigger=CronTrigger(day=1, hour=0, minute=1, timezone="Asia/Kolkata"),
        args=[app],
        id="monthly_status_sync",
        replace_existing=True,
    )

    # Job 3: Daily backup at 12:05 AM IST
    scheduler.add_job(
        func=daily_backup,
        trigger=CronTrigger(hour=0, minute=5, timezone="Asia/Kolkata"),
        args=[app],
        id="daily_backup",
        replace_existing=True,
    )

    # Run ensure_monthly_records once at startup to cover the current billing cycle
    ensure_monthly_records(app)

    scheduler.start()
    logger.info("[Scheduler] APScheduler started with 4 jobs.")
