"""Issuing a license: builds the exact payload shape Data Gateway's
dg/licensing.py verifies, signs it, and records the result. Mirrors
dg-server/tools/issue_license.py's payload construction - keep the two in
sync if that shape ever changes."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import insert, select

from . import crypto, models as m
from .db import session_scope


def issue_license(*, customer_id: int, location_id: int, installation_id: str,
                   max_machines: int, expires_at: date | None, notes: str | None,
                   customer_name: str, issued_by: str) -> dict:
    """Signs and stores a new license. Returns the row as a dict, with an
    extra `file` key holding the exact bytes to hand back as a download -
    the same {"payload": ..., "signature": ...} shape the customer uploads
    into their DG's Licensing panel."""
    license_uuid = uuid.uuid4()
    payload = {
        "license_id": str(license_uuid),
        "customer": customer_name,
        "installation_id": installation_id,
        "max_machines": max_machines,
        "issued_at": datetime.now(timezone.utc).date().isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    signature_b64 = crypto.sign_payload(payload)
    file_obj = {"payload": payload, "signature": signature_b64}

    with session_scope() as s:
        s.execute(insert(m.licenses).values(
            license_uuid=license_uuid, customer_id=customer_id, location_id=location_id,
            installation_id=installation_id, max_machines=max_machines,
            issued_at=date.fromisoformat(payload["issued_at"]), expires_at=expires_at,
            notes=notes, payload_json=payload, signature_b64=signature_b64, issued_by=issued_by))
        row = s.execute(select(m.licenses).where(m.licenses.c.license_uuid == license_uuid)).mappings().first()

    result = dict(row)
    result["file"] = file_obj
    return result
