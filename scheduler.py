"""
scheduler.py — APScheduler background jobs
  - Daily 9:00 AM  : send WhatsApp reminders for due/upcoming rents
  - Monthly 1st    : reset all tenant statuses to Pending
  - Daily 12:05 AM : SQLite database backup
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
    """Check pending tenants and send WhatsApp reminders if needed."""
    from models import Tenant, db, unscoped
    from whatsapp import send_rent_reminder

    with app.app_context():
        today = date.today()
        in_3_days = today + timedelta(days=3)

        tenants = unscoped(Tenant.query.filter_by(status="Pending")).all()
        sent = 0

        for t in tenants:
            due_day = t.get_due_day()
            # Rent for month M is collected in M+1, so the amount outstanding
            # right now is the PREVIOUS month's rent, due on the due day of
            # the current month.
            prev_m, prev_y = (12, today.year - 1) if today.month == 1 else (today.month - 1, today.year)
            due_on = t.due_date_for_rent_month(prev_y, prev_m)
            rent_for = date(prev_y, prev_m, 1).strftime("%B %Y")

            # Remind on the due day and 3 days before
            is_due_today = (today == due_on)
            is_due_in_3  = (in_3_days == due_on)
            if is_due_today or is_due_in_3:
                label = "today" if is_due_today else f"in 3 days ({due_on:%d %b})"
                result = send_rent_reminder(
                    to_phone=t.phone,
                    tenant_name=t.name,
                    amount=t.amount,
                    due_date=f"{due_on:%d %b %Y} (for {rent_for})",
                )
                if "error" not in result:
                    sent += 1
                    logger.info(f"[Scheduler] Reminder → {t.name} ({label})")
                else:
                    logger.warning(f"[Scheduler] Failed → {t.name}: {result}")

        logger.info(f"[Scheduler] Daily reminders done. Sent: {sent}/{len(tenants)}")


# ──────────────────────────────────────────
# JOB 2 — Monthly reset (1st of month, 12:01 AM)
# ──────────────────────────────────────────
def monthly_reset(app):
    """Reset all tenants to Pending and clear payment_date on 1st of month."""
    from models import Tenant, db, unscoped

    with app.app_context():
        tenants = unscoped(Tenant.query).all()   # spans every account
        for t in tenants:
            t.status = "Pending"
            t.payment_date = None
        db.session.commit()
        logger.info(f"[Scheduler] Monthly reset done. {len(tenants)} tenants reset.")


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
    """Create Pending RentRecords for all active tenants for the current month if missing.
    Runs once at midnight via scheduler — NOT on every request."""
    from models import Tenant, RentRecord, db, unscoped

    with app.app_context():
        today = date.today()
        # Background jobs run outside a login session, so they must span every
        # account explicitly rather than relying on the per-account filter.
        active_tenants = unscoped(
            Tenant.query.filter_by(occupancy_status="Active")).all()
        if not active_tenants:
            return
        active_ids = [t.id for t in active_tenants]
        existing_ids = {
            tid for (tid,) in unscoped(db.session.query(RentRecord.tenant_id)).filter(
                RentRecord.month == today.month,
                RentRecord.year == today.year,
                RentRecord.tenant_id.in_(active_ids),
            ).all()
        }
        new_records = [
            RentRecord(
                tenant_id=t.id,
                tenant_name=t.name,
                month=today.month,
                year=today.year,
                rent_amount=t.amount,
                status="Pending",
                owner_id=t.owner_id,
            )
            for t in active_tenants
            if t.id not in existing_ids
        ]
        if new_records:
            db.session.add_all(new_records)
            db.session.commit()
            logger.info(f"[Scheduler] Created {len(new_records)} rent record(s) for {today.strftime('%B %Y')}.")
        else:
            logger.info(f"[Scheduler] All rent records already exist for {today.strftime('%B %Y')}.")


def _acquire_scheduler_lock(app):
    """With N gunicorn workers every worker would start its own scheduler and
    tenants would receive N duplicate WhatsApp reminders. Take an exclusive
    file lock so only ONE process per host runs the jobs."""
    try:
        import fcntl
    except ImportError:            # Windows dev machine: single process anyway
        return True
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        fh = open(os.path.join(app.instance_path, "scheduler.lock"), "w")
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        app._scheduler_lock = fh   # keep the handle (and lock) for the process lifetime
        return True
    except OSError:
        return False


def init_scheduler(app):
    """Register all cron jobs and start the scheduler."""
    if not _acquire_scheduler_lock(app):
        logger.info("[Scheduler] Another worker already runs the jobs - skipping.")
        return

    # Job 0: Ensure monthly rent records at midnight IST (replaces per-request call)
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

    # Job 2: Monthly reset — 1st of month at 12:01 AM IST
    scheduler.add_job(
        func=monthly_reset,
        trigger=CronTrigger(day=1, hour=0, minute=1, timezone="Asia/Kolkata"),
        args=[app],
        id="monthly_reset",
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

    # Run ensure_monthly_records once at startup to cover the current month
    ensure_monthly_records(app)

    scheduler.start()
    logger.info("[Scheduler] APScheduler started with 4 jobs.")
