"""dg-licensing web UI + API. Single-page vanilla-JS frontend in index.html
talks to this JSON API, same pattern as Data Gateway's own web app."""
from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path

from fastapi import Cookie, Depends, FastAPI, File, HTTPException, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import delete, insert, select, update

from .. import auth, crypto, licenses as licenses_svc
from .. import models as m
from ..audit import log_action
from ..config import get_settings
from ..db import session_scope, wait_for_db
from ..mailer import send_email
from ..notify import start_background_thread

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dgl.web")
app = FastAPI(title="DG Licensing", version="0.1.0")

_INDEX = Path(__file__).parent / "index.html"


@app.on_event("startup")
def _startup():
    wait_for_db()
    run_startup_migrations_local()
    auth.bootstrap_superadmin()
    n = auth.clear_all_sessions()
    if n:
        log.info("cleared %d session(s) on startup - everyone must log in again", n)
    try:
        crypto.get_or_create_keypair()   # generate the signing key up front, not on the first license
    except crypto.KeyNotConfigured as exc:
        log.warning("signing key not ready yet: %s", exc)
    start_background_thread()   # spawns its own daemon thread - see app/notify.py


def run_startup_migrations_local() -> None:
    """Idempotent ALTER/CREATE steps for schema changes made after the
    original db/schema.sql - initdb only runs once, so an install that
    already has data needs these to pick up later changes on restart, same
    convention as Data Gateway's dg/db.py."""
    from sqlalchemy import text
    from ..db import engine
    stmts = [
        # email: added after the first deploy (forgot-password flow) - the
        # bootstrapped admin row predates it, so backfill before enforcing
        # NOT NULL/UNIQUE rather than have the ALTER fail outright.
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
        "UPDATE users SET email = username || '@localhost.invalid' WHERE email IS NULL",
        "ALTER TABLE users ALTER COLUMN email SET NOT NULL",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users (email)",
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            token       TEXT PRIMARY KEY,
            user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at  TIMESTAMPTZ NOT NULL,
            used_at     TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_password_resets_user ON password_resets (user_id)",
    ]
    try:
        with engine().begin() as conn:
            for stmt in stmts:
                conn.execute(text(stmt))
    except Exception:
        log.exception("startup migration step failed (continuing)")


# ------------------------------------------------------------------ basics
@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _INDEX.read_text(encoding="utf-8")


# --------------------------------------------------------------------- auth
class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginIn, response: Response) -> dict:
    with session_scope() as s:
        row = s.execute(select(m.users).where(m.users.c.username == body.username)).mappings().first()
    if not row or not row["enabled"] or not auth.verify_password(body.password, row["password_hash"]):
        log_action(body.username, "LOGIN_FAILED")
        raise HTTPException(401, "invalid username or password")
    token = auth.create_session(row["id"])
    response.set_cookie(auth.SESSION_COOKIE, token, httponly=True, samesite="lax",
                        max_age=get_settings().session_ttl_hours * 3600)
    log_action(row["username"], "LOGIN_OK")
    return {"username": row["username"], "role": row["role"]}


@app.post("/api/auth/logout")
def logout(response: Response, dgl_session: str | None = Cookie(default=None)) -> dict:
    if dgl_session:
        auth.destroy_session(dgl_session)
    response.delete_cookie(auth.SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: dict = Depends(auth.get_current_user)) -> dict:
    return user


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


@app.post("/api/auth/change-password")
def change_password(body: ChangePasswordIn, user: dict = Depends(auth.get_current_user)) -> dict:
    with session_scope() as s:
        row = s.execute(select(m.users.c.password_hash).where(m.users.c.id == user["id"])).first()
        if not row or not auth.verify_password(body.current_password, row[0]):
            raise HTTPException(400, "current password is incorrect")
        s.execute(update(m.users).where(m.users.c.id == user["id"])
                  .values(password_hash=auth.hash_password(body.new_password)))
    log_action(user["username"], "CHANGE_PASSWORD", target=user["username"])
    return {"ok": True}


class ForgotPasswordIn(BaseModel):
    email: str


# Always the same response whether or not the email matched an account -
# telling an anonymous caller "no such account" would let them enumerate
# valid usernames/emails by trying addresses one at a time.
_FORGOT_PASSWORD_RESPONSE = {"ok": True, "detail": "If that email is registered, a reset link has been sent."}


@app.post("/api/auth/forgot-password")
def forgot_password(body: ForgotPasswordIn) -> dict:
    found = auth.find_user_by_email(body.email.strip())
    if not found:
        # Still logged (without exposing this to the caller) - a burst of
        # these for unknown addresses is worth noticing.
        log_action(body.email.strip(), "FORGOT_PASSWORD_UNKNOWN_EMAIL")
        return _FORGOT_PASSWORD_RESPONSE
    token = auth.create_reset_token(found["id"])
    settings = get_settings()
    link = f"{settings.public_base_url}?reset_token={token}"
    body_text = (
        f"A password reset was requested for your dg-licensing account ({found['username']}).\n\n"
        f"Set a new password here (valid {settings.reset_token_ttl_minutes} minutes, one-time use):\n{link}\n\n"
        "If you didn't request this, you can ignore this email - your password hasn't been changed."
    )
    try:
        send_email("[dg-licensing] Reset your password", body_text, to=[found["email"]])
    except Exception:
        log.exception("failed to send password-reset email to %s", found["email"])
    log_action(found["username"], "FORGOT_PASSWORD_REQUESTED")
    return _FORGOT_PASSWORD_RESPONSE


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str


@app.post("/api/auth/reset-password")
def reset_password(body: ResetPasswordIn) -> dict:
    if len(body.new_password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    if not auth.consume_reset_token(body.token, body.new_password):
        raise HTTPException(400, "this reset link is invalid, expired, or already used - request a new one")
    log_action("(reset link)", "PASSWORD_RESET_COMPLETED", detail=f"token prefix={body.token[:8]}...")
    return {"ok": True}


# -------------------------------------------------------------------- users
class UserIn(BaseModel):
    username: str
    email: str
    password: str
    role: str


@app.get("/api/users")
def list_users(user: dict = Depends(auth.require_role("super_admin"))) -> list[dict]:
    with session_scope() as s:
        rows = s.execute(select(m.users.c.id, m.users.c.username, m.users.c.email, m.users.c.role,
                                m.users.c.enabled, m.users.c.created_at)
                         .order_by(m.users.c.username)).mappings().all()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user(body: UserIn, user: dict = Depends(auth.require_role("super_admin"))) -> dict:
    if body.role not in auth.ROLES:
        raise HTTPException(400, f"role must be one of {auth.ROLES}")
    if len(body.password) < 8:
        raise HTTPException(400, "password must be at least 8 characters")
    try:
        with session_scope() as s:
            new_id = s.execute(insert(m.users).values(
                username=body.username, email=body.email.strip(), password_hash=auth.hash_password(body.password),
                role=body.role, enabled=True).returning(m.users.c.id)).scalar_one()
    except Exception as exc:
        raise HTTPException(400, f"could not create user (duplicate username or email?): {exc}")
    log_action(user["username"], "CREATE_USER", target=body.username, detail=f"role={body.role}")
    return {"id": new_id, "username": body.username, "role": body.role}


class UserPatchIn(BaseModel):
    role: str | None = None
    enabled: bool | None = None
    password: str | None = None
    email: str | None = None


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, body: UserPatchIn, user: dict = Depends(auth.require_role("super_admin"))) -> dict:
    values = {}
    if body.role is not None:
        if body.role not in auth.ROLES:
            raise HTTPException(400, f"role must be one of {auth.ROLES}")
        values["role"] = body.role
    if body.enabled is not None:
        values["enabled"] = body.enabled
    if body.password:
        if len(body.password) < 8:
            raise HTTPException(400, "password must be at least 8 characters")
        values["password_hash"] = auth.hash_password(body.password)
    if body.email:
        values["email"] = body.email.strip()
    if not values:
        raise HTTPException(400, "nothing to update")
    with session_scope() as s:
        row = s.execute(select(m.users.c.username).where(m.users.c.id == user_id)).first()
        if not row:
            raise HTTPException(404, "user not found")
        s.execute(update(m.users).where(m.users.c.id == user_id).values(**values))
    log_action(user["username"], "UPDATE_USER", target=row[0], detail=json.dumps({k: v for k, v in values.items() if k != "password_hash"}))
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(auth.require_role("super_admin"))) -> dict:
    if user_id == user["id"]:
        raise HTTPException(400, "cannot delete your own account")
    with session_scope() as s:
        row = s.execute(select(m.users.c.username, m.users.c.role).where(m.users.c.id == user_id)).first()
        if not row:
            raise HTTPException(404, "user not found")
        if row[1] == "super_admin":
            remaining = s.execute(select(m.users.c.id).where(
                m.users.c.role == "super_admin", m.users.c.id != user_id)).first()
            if not remaining:
                raise HTTPException(400, "cannot delete the last super_admin account")
        s.execute(delete(m.users).where(m.users.c.id == user_id))
    log_action(user["username"], "DELETE_USER", target=row[0])
    return {"ok": True}


# --------------------------------------------------------------- customers
class CustomerIn(BaseModel):
    name: str
    notes: str | None = None


@app.get("/api/customers")
def list_customers(user: dict = Depends(auth.get_current_user)) -> list[dict]:
    with session_scope() as s:
        rows = s.execute(select(m.customers).order_by(m.customers.c.name)).mappings().all()
    return [dict(r) for r in rows]


@app.post("/api/customers")
def create_customer(body: CustomerIn, user: dict = Depends(auth.get_current_user)) -> dict:
    try:
        with session_scope() as s:
            new_id = s.execute(insert(m.customers).values(
                name=body.name, notes=body.notes, created_by=user["username"]
            ).returning(m.customers.c.id)).scalar_one()
    except Exception as exc:
        raise HTTPException(400, f"could not create customer (duplicate name?): {exc}")
    log_action(user["username"], "CREATE_CUSTOMER", target=body.name)
    return {"id": new_id, "name": body.name}


# --------------------------------------------------------------- locations
class LocationIn(BaseModel):
    customer_id: int
    name: str
    address: str | None = None
    notes: str | None = None


@app.get("/api/locations")
def list_locations(customer_id: int | None = None, user: dict = Depends(auth.get_current_user)) -> list[dict]:
    q = select(m.locations)
    if customer_id is not None:
        q = q.where(m.locations.c.customer_id == customer_id)
    with session_scope() as s:
        rows = s.execute(q.order_by(m.locations.c.name)).mappings().all()
    return [dict(r) for r in rows]


@app.post("/api/locations")
def create_location(body: LocationIn, user: dict = Depends(auth.get_current_user)) -> dict:
    try:
        with session_scope() as s:
            new_id = s.execute(insert(m.locations).values(
                customer_id=body.customer_id, name=body.name, address=body.address,
                notes=body.notes, created_by=user["username"]
            ).returning(m.locations.c.id)).scalar_one()
    except Exception as exc:
        raise HTTPException(400, f"could not create location (duplicate name for this customer?): {exc}")
    log_action(user["username"], "CREATE_LOCATION", target=body.name, detail=f"customer_id={body.customer_id}")
    return {"id": new_id, "name": body.name}


# ----------------------------------------------------------------- licenses
@app.post("/api/licenses/parse-request")
async def parse_request_file(file: UploadFile = File(...), user: dict = Depends(auth.get_current_user)) -> dict:
    """Reads the request file the customer downloaded from their DG's
    Licensing panel (build_request_payload() on that side) and returns the
    fields worth prefilling - installation_id above all, since it's a long
    opaque string not worth retyping by hand."""
    try:
        data = json.loads((await file.read()).decode("utf-8"))
    except Exception:
        raise HTTPException(400, "not a valid request file (unreadable JSON)")
    if "installation_id" not in data:
        raise HTTPException(400, "not a valid request file (missing installation_id)")
    return {
        "installation_id": data["installation_id"],
        "current_machine_count": data.get("current_machine_count"),
        "dg_version": data.get("dg_version"),
    }


class LicenseIn(BaseModel):
    customer_id: int
    location_id: int
    installation_id: str
    max_machines: int
    # Deliberately no default for either - see the explicit-choice check
    # below. A blank expires_at used to silently mean "perpetual", which
    # let someone issue a perpetual license by forgetting a date rather
    # than by deciding to - perpetual is now something you have to say,
    # not something that happens when you say nothing.
    perpetual: bool
    expires_at: date | None = None
    notes: str | None = None
    current_machine_count: int | None = None   # from parse-request, just for the over-limit warning


@app.post("/api/licenses")
def create_license(body: LicenseIn, user: dict = Depends(auth.get_current_user)) -> dict:
    if not body.installation_id.strip():
        raise HTTPException(400, "installation_id is required - load the customer's request file first")
    if not body.perpetual and body.expires_at is None:
        raise HTTPException(400, "set an expiry date, or mark this license as perpetual")
    expires_at = None if body.perpetual else body.expires_at

    with session_scope() as s:
        customer = s.execute(select(m.customers.c.name).where(m.customers.c.id == body.customer_id)).first()
        location = s.execute(select(m.locations.c.customer_id).where(m.locations.c.id == body.location_id)).first()
    if not customer:
        raise HTTPException(404, "customer not found")
    if not location:
        raise HTTPException(404, "location not found")
    if location[0] != body.customer_id:
        raise HTTPException(400, "that location does not belong to the selected customer")

    warning = None
    if body.current_machine_count is not None and body.current_machine_count > body.max_machines:
        warning = (f"requester already has {body.current_machine_count} machines configured, "
                   f"more than the {body.max_machines} being granted - it will show as over_limit immediately")

    try:
        result = licenses_svc.issue_license(
            customer_id=body.customer_id, location_id=body.location_id,
            installation_id=body.installation_id.strip(), max_machines=body.max_machines,
            expires_at=expires_at, notes=body.notes,
            customer_name=customer[0], issued_by=user["username"])
    except crypto.KeyNotConfigured as exc:
        raise HTTPException(500, str(exc))
    log_action(user["username"], "ISSUE_LICENSE", target=customer[0],
              detail=f"license_id={result['license_uuid']} max_machines={body.max_machines} "
                     f"expires_at={expires_at or 'perpetual'}")
    result["warning"] = warning
    return json.loads(json.dumps(result, default=str))


class LicenseDeleteIn(BaseModel):
    reason: str


@app.delete("/api/licenses/{license_id}")
def delete_license(license_id: int, body: LicenseDeleteIn, user: dict = Depends(auth.get_current_user)) -> dict:
    if not body.reason.strip():
        raise HTTPException(400, "a reason is required")
    with session_scope() as s:
        row = s.execute(select(m.licenses, m.customers.c.name.label("customer_name"))
                        .select_from(m.licenses.join(m.customers, m.licenses.c.customer_id == m.customers.c.id))
                        .where(m.licenses.c.id == license_id)).mappings().first()
        if not row:
            raise HTTPException(404, "license not found")
        s.execute(delete(m.licenses).where(m.licenses.c.id == license_id))
    # The row is really gone (not a soft-delete/revoke flag) - this detail
    # line is what's left to answer "what was that license, and why was it
    # removed" afterward, so it deliberately repeats everything that
    # mattered about it plus the operator's stated reason.
    log_action(user["username"], "DELETE_LICENSE", target=row["customer_name"],
              detail=f"license_id={row['license_uuid']} installation_id={row['installation_id']} "
                     f"max_machines={row['max_machines']} expires_at={row['expires_at'] or 'perpetual'} "
                     f"reason={body.reason.strip()}")
    return {"ok": True}


@app.get("/api/licenses")
def list_licenses(customer_id: int | None = None, location_id: int | None = None,
                  user: dict = Depends(auth.get_current_user)) -> list[dict]:
    q = (select(m.licenses, m.customers.c.name.label("customer_name"), m.locations.c.name.label("location_name"))
         .select_from(m.licenses
                      .join(m.customers, m.licenses.c.customer_id == m.customers.c.id)
                      .join(m.locations, m.licenses.c.location_id == m.locations.c.id))
         .order_by(m.licenses.c.created_at.desc()))
    if customer_id is not None:
        q = q.where(m.licenses.c.customer_id == customer_id)
    if location_id is not None:
        q = q.where(m.licenses.c.location_id == location_id)
    with session_scope() as s:
        rows = s.execute(q).mappings().all()
    return json.loads(json.dumps([dict(r) for r in rows], default=str))


@app.get("/api/licenses/{license_id}/download")
def download_license(license_id: int, user: dict = Depends(auth.get_current_user)) -> JSONResponse:
    with session_scope() as s:
        row = s.execute(select(m.licenses.c.payload_json, m.licenses.c.signature_b64, m.customers.c.name)
                        .select_from(m.licenses.join(m.customers, m.licenses.c.customer_id == m.customers.c.id))
                        .where(m.licenses.c.id == license_id)).first()
    if not row:
        raise HTTPException(404, "license not found")
    payload, signature, customer_name = row
    filename = customer_name.lower().replace(" ", "_") + "_license.json"
    log_action(user["username"], "DOWNLOAD_LICENSE", target=customer_name, detail=f"license db id={license_id}")
    return JSONResponse(
        content={"payload": payload, "signature": signature},
        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.get("/api/public-key")
def public_key(user: dict = Depends(auth.get_current_user)) -> dict:
    return {"public_key_pem": crypto.get_public_key_pem()}


# --------------------------------------------------------------- audit log
@app.get("/api/audit-log")
def list_audit_log(limit: int = 200, username: str | None = None, action: str | None = None,
                   user: dict = Depends(auth.get_current_user)) -> list[dict]:
    q = select(m.audit_log)
    if username:
        q = q.where(m.audit_log.c.actor_username.ilike(f"%{username}%"))
    if action:
        q = q.where(m.audit_log.c.action == action)
    q = q.order_by(m.audit_log.c.ts.desc()).limit(min(limit, 2000))
    with session_scope() as s:
        rows = s.execute(q).mappings().all()
    return json.loads(json.dumps([dict(r) for r in rows], default=str))
