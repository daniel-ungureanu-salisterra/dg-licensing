"""One place every mutating action logs through, so "who did what" (the
user's requirement #4) can never be added to a route and then forgotten."""
from __future__ import annotations

from sqlalchemy import insert

from . import models as m
from .db import session_scope


def log_action(actor_username: str, action: str, target: str | None = None, detail: str | None = None) -> None:
    with session_scope() as s:
        s.execute(insert(m.audit_log).values(
            actor_username=actor_username, action=action, target=target, detail=detail))
