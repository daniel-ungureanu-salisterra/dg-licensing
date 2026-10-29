"""Authentication for the web UI: password hashing, cookie sessions, and
role-gated FastAPI dependencies.

Two roles only:
    admin        - everything: customers, locations, licenses, audit log.
    super_admin  - + user management (create/delete/change-role).
Both roles can issue licenses - user management is the only thing gated,
per the user's explicit requirement.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, HTTPException
from sqlalchemy import delete, insert, select, update

from . import models as m
from .config import get_settings
from .db import session_scope

log = logging.getLogger("dgl.auth")

ROLES = ["admin", "super_admin"]
_RANK = {r: i for i, r in enumerate(ROLES)}
SESSION_COOKIE = "dgl_session"
_PBKDF2_ITERATIONS = 260_000


# --------------------------------------------------------------- passwords
def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Never raises - a malformed/foreign hash just fails verification."""
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def role_at_least(role: str, minimum: str) -> bool:
    return _RANK.get(role, -1) >= _RANK.get(minimum, 99)


# ----------------------------------------------------------------- sessions
def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    ttl = get_settings().session_ttl_hours
    with session_scope() as s:
        s.execute(insert(m.sessions).values(
            token=token, user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl)))
    return token


def destroy_session(token: str) -> None:
    with session_scope() as s:
        s.execute(delete(m.sessions).where(m.sessions.c.token == token))


def clear_all_sessions() -> int:
    """Log everyone out. Called once on every web startup - a redeploy/
    restart should never leave a stale login active."""
    with session_scope() as s:
        return s.execute(delete(m.sessions)).rowcount


def _lookup_session(token: str) -> dict | None:
    with session_scope() as s:
        row = s.execute(
            select(m.sessions.c.expires_at, m.users.c.id, m.users.c.username,
                   m.users.c.role, m.users.c.enabled)
            .select_from(m.sessions.join(m.users, m.sessions.c.user_id == m.users.c.id))
            .where(m.sessions.c.token == token)
        ).mappings().first()
        if not row:
            return None
        if row["expires_at"] < datetime.now(timezone.utc):
            s.execute(delete(m.sessions).where(m.sessions.c.token == token))
            return None
        if not row["enabled"]:
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}


# --------------------------------------------------------- FastAPI wiring
def get_current_user(dgl_session: str | None = Cookie(default=None)) -> dict:
    if not dgl_session:
        raise HTTPException(401, "not authenticated")
    user = _lookup_session(dgl_session)
    if not user:
        raise HTTPException(401, "session expired or invalid")
    return user


def require_role(minimum: str):
    """FastAPI dependency factory: 401 if not logged in, 403 if the caller's
    role doesn't meet `minimum` (one of ROLES)."""
    def _dep(user: dict = Depends(get_current_user)) -> dict:
        if not role_at_least(user["role"], minimum):
            raise HTTPException(403, f"requires {minimum} role or higher")
        return user
    return _dep


# ------------------------------------------------------------- bootstrap
def bootstrap_superadmin() -> None:
    """Create the initial super_admin from SUPERADMIN_USER/PASSWORD if no
    super_admin exists yet - without this there'd be no way to create the
    first account (user management itself requires super_admin to reach).
    Safe to call on every startup - a no-op once any super_admin exists."""
    settings = get_settings()
    if not settings.superadmin_user or not settings.superadmin_password:
        log.warning("SUPERADMIN_USER/PASSWORD not set - no bootstrap account "
                    "will be created. If no users exist yet, nobody will be able to log in.")
        return
    with session_scope() as s:
        exists = s.execute(select(m.users.c.id).where(m.users.c.role == "super_admin")).first()
        if exists:
            return
        s.execute(insert(m.users).values(
            username=settings.superadmin_user,
            email=settings.superadmin_email or f"{settings.superadmin_user}@localhost.invalid",
            password_hash=hash_password(settings.superadmin_password),
            role="super_admin", enabled=True))
    log.info("bootstrapped initial super_admin user %r", settings.superadmin_user)


# --------------------------------------------------------- password resets
# Single-use, short-lived tokens for the "forgot password" email flow -
# separate from sessions since these authenticate one specific action
# (setting a new password) rather than a login.
def find_user_by_email(email: str) -> dict | None:
    with session_scope() as s:
        row = s.execute(select(m.users.c.id, m.users.c.username, m.users.c.email, m.users.c.enabled)
                        .where(m.users.c.email == email)).mappings().first()
    return dict(row) if row and row["enabled"] else None


def create_reset_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    ttl = get_settings().reset_token_ttl_minutes
    with session_scope() as s:
        s.execute(insert(m.password_resets).values(
            token=token, user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl)))
    return token


def consume_reset_token(token: str, new_password: str) -> bool:
    """Validates the token (exists, unexpired, unused), sets the new
    password, marks the token used, and kills every existing session for
    that user - a password reset should always force a fresh login
    everywhere, in case the reset was prompted by a compromised session.
    Returns False (no side effects) for any invalid/expired/reused token."""
    with session_scope() as s:
        row = s.execute(select(m.password_resets.c.user_id, m.password_resets.c.expires_at,
                               m.password_resets.c.used_at)
                        .where(m.password_resets.c.token == token)).mappings().first()
        if not row or row["used_at"] is not None or row["expires_at"] < datetime.now(timezone.utc):
            return False
        s.execute(update(m.users).where(m.users.c.id == row["user_id"])
                  .values(password_hash=hash_password(new_password)))
        s.execute(update(m.password_resets).where(m.password_resets.c.token == token)
                  .values(used_at=datetime.now(timezone.utc)))
        s.execute(delete(m.sessions).where(m.sessions.c.user_id == row["user_id"]))
    return True
