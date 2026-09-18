"""Daily sweep: email a warning for every license within notify_days_before
of its expires_at that hasn't already been notified about. No Celery/cron
dependency - this is a small enough app that a daemon thread sleeping
between checks (started from the web app's own startup, see web/app.py) is
simpler to operate than a second scheduled service."""
from __future__ import annotations

import logging
import smtplib
import threading
import time
from datetime import date, datetime, timedelta, timezone
from email.mime.text import MIMEText

from sqlalchemy import select, update

from . import models as m
from .config import get_settings
from .db import session_scope

log = logging.getLogger("dgl.notify")

_CHECK_INTERVAL_S = 6 * 3600   # re-check a few times a day; expiry_notified_at makes repeats harmless


def _due_licenses(today: date, horizon: date):
    with session_scope() as s:
        rows = s.execute(
            select(m.licenses, m.customers.c.name.label("customer_name"), m.locations.c.name.label("location_name"))
            .select_from(m.licenses
                         .join(m.customers, m.licenses.c.customer_id == m.customers.c.id)
                         .join(m.locations, m.licenses.c.location_id == m.locations.c.id))
            .where(m.licenses.c.expires_at.is_not(None))
            .where(m.licenses.c.expiry_notified_at.is_(None))
            .where(m.licenses.c.expires_at >= today)
            .where(m.licenses.c.expires_at <= horizon)
        ).mappings().all()
    return rows


def _send_email(subject: str, body: str) -> None:
    settings = get_settings()
    if not settings.smtp_host or not settings.notify_to:
        log.warning("SMTP not configured (smtp_host/notify_to) - skipping license-expiry email")
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_username
    recipients = [addr.strip() for addr in settings.notify_to.split(",") if addr.strip()]
    msg["To"] = ", ".join(recipients)

    if settings.smtp_use_ssl:
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
    try:
        if settings.smtp_use_tls and not settings.smtp_use_ssl:
            server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.sendmail(msg["From"], recipients, msg.as_string())
    finally:
        server.quit()


def check_and_send_expiry_warnings() -> int:
    """Returns how many licenses were notified about, for logging/testing."""
    settings = get_settings()
    today = datetime.now(timezone.utc).date()
    horizon = today + timedelta(days=settings.notify_days_before)
    due = _due_licenses(today, horizon)
    if not due:
        return 0

    lines = [
        f"- {r['customer_name']} / {r['location_name']}: license {r['license_uuid']} "
        f"expires {r['expires_at']} (max_machines={r['max_machines']})"
        for r in due
    ]
    body = (
        f"{len(due)} Data Gateway license(s) expire within {settings.notify_days_before} days:\n\n"
        + "\n".join(lines)
    )
    _send_email(f"[dg-licensing] {len(due)} license(s) expiring soon", body)

    with session_scope() as s:
        s.execute(update(m.licenses)
                  .where(m.licenses.c.id.in_([r["id"] for r in due]))
                  .values(expiry_notified_at=datetime.now(timezone.utc)))
    log.info("sent expiry warning for %d license(s)", len(due))
    return len(due)


def run_notify_loop() -> None:
    """Runs forever in a daemon thread - a failed check (bad SMTP creds,
    transient network error) logs and retries next interval instead of
    taking the thread down for good."""
    while True:
        try:
            check_and_send_expiry_warnings()
        except Exception:
            log.exception("license-expiry check failed (will retry next interval)")
        time.sleep(_CHECK_INTERVAL_S)


def start_background_thread() -> None:
    threading.Thread(target=run_notify_loop, daemon=True, name="dgl-notify").start()
