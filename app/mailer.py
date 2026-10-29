"""SMTP sending, shared by the expiry-notification sweep (app/notify.py)
and the forgot-password flow (app/auth.py's reset-token emails)."""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

from .config import get_settings

log = logging.getLogger("dgl.mailer")


def send_email(subject: str, body: str, to: list[str]) -> None:
    """`to` is always explicit - a password-reset link goes to one specific
    user's email, and the expiry-notification sweep (app/notify.py) computes
    its own recipient list from the users table, so there's no separate
    "general notification list" setting to keep in sync with who actually
    has an account."""
    settings = get_settings()
    recipients = to
    if not settings.smtp_host or not recipients:
        log.warning("SMTP not configured (smtp_host) or no recipients - dropping email %r", subject)
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_username
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
