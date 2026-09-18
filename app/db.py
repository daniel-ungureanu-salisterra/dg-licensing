"""SQLAlchemy engine + session factory. Sync on purpose - this is a small
admin CRUD app, no background worker pool to keep an async bridge for."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import logging
import time

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings

log = logging.getLogger("dgl.db")

_engine = None
_SessionLocal: sessionmaker | None = None


def engine():
    global _engine
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True, future=True)
    return _engine


def _session_factory() -> sessionmaker:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=engine(), expire_on_commit=False, future=True)
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session: commit on success, rollback on error."""
    s = _session_factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def wait_for_db(timeout_s: float = 30.0, interval_s: float = 1.0) -> None:
    """Block until a DB connection succeeds, or give up after timeout_s - see
    Data Gateway's dg/db.py for why this matters on cold start (compose's
    embedded DNS not always ready the instant depends_on says healthy)."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with engine().connect():
                return
        except Exception as exc:  # noqa: BLE001 - deliberately broad, just retrying
            last_err = exc
            time.sleep(interval_s)
    log.warning("wait_for_db: still failing after %.0fs, proceeding anyway (%s)", timeout_s, last_err)


def get_setting(key: str, default: str | None = None) -> str | None:
    with engine().begin() as conn:
        row = conn.execute(text("SELECT value FROM app_settings WHERE key = :key"), {"key": key}).first()
    return row[0] if row else default


def set_setting(key: str, value: str) -> None:
    with engine().begin() as conn:
        conn.execute(text(
            "INSERT INTO app_settings (key, value) VALUES (:key, :value) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        ), {"key": key, "value": value})
