"""The Ed25519 signing keypair this platform issues licenses with, and the
exact canonical-JSON + signature scheme Data Gateway's dg/licensing.py
verifies on the appliance side - these two must never drift apart.

The private key is generated once (first call to get_or_create_keypair,
normally at startup) and stored in the `signing_keys` table encrypted with
Fernet, keyed by LICENSE_MASTER_KEY from .env - which never touches the
database. A DB backup alone can therefore never recover the ability to
mint licenses; that requires the .env file too. The decrypted key is then
held in process memory for the life of the process (see _cached), same
tradeoff every KMS-backed app makes - decrypt once, not on every request.
"""
from __future__ import annotations

import base64
import json
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import insert, select

from . import models as m
from .config import get_settings
from .db import session_scope

log = logging.getLogger("dgl.crypto")

_cached: Ed25519PrivateKey | None = None


class KeyNotConfigured(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = get_settings().license_master_key
    if not key:
        raise KeyNotConfigured(
            "LICENSE_MASTER_KEY is not set - generate one with "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"` "
            "and put it in .env before issuing licenses.")
    try:
        return Fernet(key.encode())
    except Exception as exc:
        raise KeyNotConfigured(f"LICENSE_MASTER_KEY is not a valid Fernet key: {exc}") from exc


def get_or_create_keypair() -> Ed25519PrivateKey:
    global _cached
    if _cached is not None:
        return _cached
    fernet = _fernet()
    with session_scope() as s:
        row = s.execute(select(m.signing_keys.c.private_key_encrypted).order_by(m.signing_keys.c.id).limit(1)).first()
        if row:
            try:
                pem = fernet.decrypt(bytes(row[0]))
            except InvalidToken as exc:
                raise KeyNotConfigured(
                    "stored signing key could not be decrypted - LICENSE_MASTER_KEY doesn't "
                    "match what it was encrypted with (wrong .env? restored from a different install?)") from exc
            _cached = serialization.load_pem_private_key(pem, password=None)
            return _cached

        log.info("no signing key found - generating a new Ed25519 keypair")
        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        s.execute(insert(m.signing_keys).values(
            public_key_pem=public_pem, private_key_encrypted=fernet.encrypt(pem)))
        _cached = private_key
        return _cached


def get_public_key_pem() -> str:
    """For display in the UI - this is the string that goes into Data
    Gateway's dg/licensing.py as _PUBLIC_KEY_PEM on a fresh install of this
    platform (it's baked into the DG image, so it only needs setting once
    per signing key, not per license)."""
    with session_scope() as s:
        row = s.execute(select(m.signing_keys.c.public_key_pem).order_by(m.signing_keys.c.id).limit(1)).first()
    if row:
        return row[0]
    # Not generated yet - generating it now also creates+stores it.
    return get_or_create_keypair().public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def canonical(payload: dict) -> bytes:
    # Must exactly match dg/licensing.py's _canonical() on the DG side -
    # same payload bytes in, same signature verifies on the appliance.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict) -> str:
    private_key = get_or_create_keypair()
    signature = private_key.sign(canonical(payload))
    return base64.b64encode(signature).decode()
