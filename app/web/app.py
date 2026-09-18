"""dg-licensing web UI + API. Single-page vanilla-JS frontend in index.html
talks to this JSON API, same pattern as Data Gateway's own web app."""
from __future__ import annotations

import json
import logging
import threading
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
from ..db import run_startup_migrations, session_scope, wait_for_db
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
    threading.Thread(target=start_background_thread, daemon=True).start()


def run_startup_migrations_local() -> None:
    # schema.sql (initdb) creates everything for a fresh DB; nothing to
    # migrate yet on an existing one - kept as a hook for future ALTERs,
    # same convention as Data Gateway's dg/db.py.
    pass


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


# -------------------------------------------------------------------- users
class UserIn(BaseModel):
    username: str
    password: str
    role: str


@app.get("/api/users")
def list_users(user: dict = Depends(auth.require_role("super_admin"))) -> list[dict]:
    with session_scope() as s:
        rows = s.execute(select(m.users.c.id, m.users.c.username, m.users.c.role,
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
                username=body.username, password_hash=auth.hash_password(body.password),
                role=body.role, enabled=True).returning(m.users.c.id)).scalar_one()
    except Exception as exc:
        raise HTTPException(400, f"could not create user (duplicate username?): {exc}")
    log_action(user["username"], "CREATE_USER", target=body.username, detail=f"role={body.role}")
    return {"id": new_id, "username": body.username, "role": body.role}


class UserPatchIn(BaseModel):
    role: str | None = None
    enabled: bool | None = None
    password: str | None = None


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
    expires_at: date | None = None   # None = perpetual
    notes: str | None = None
    current_machine_count: int | None = None   # from parse-request, just for the over-limit warning


@app.post("/api/licenses")
def create_license(body: LicenseIn, user: dict = Depends(auth.get_current_user)) -> dict:
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
            installation_id=body.installation_id, max_machines=body.max_machines,
            expires_at=body.expires_at, notes=body.notes,
            customer_name=customer[0], issued_by=user["username"])
    except crypto.KeyNotConfigured as exc:
        raise HTTPException(500, str(exc))
    log_action(user["username"], "ISSUE_LICENSE", target=customer[0],
              detail=f"license_id={result['license_uuid']} max_machines={body.max_machines} "
                     f"expires_at={body.expires_at or 'perpetual'}")
    result["warning"] = warning
    return json.loads(json.dumps(result, default=str))


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
