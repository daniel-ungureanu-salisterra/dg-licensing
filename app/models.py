"""SQLAlchemy table definitions. Mirror of db/schema.sql - kept as Core
Table objects (not full ORM) to stay close to the SQL, same convention as
Data Gateway's dg/models.py."""
from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()

users = Table(
    "users", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("username", Text, nullable=False, unique=True),
    Column("password_hash", Text, nullable=False),
    Column("role", Text, nullable=False),
    Column("enabled", Boolean, nullable=False, server_default="true"),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

sessions = Table(
    "sessions", metadata,
    Column("token", Text, primary_key=True),
    Column("user_id", BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

customers = Table(
    "customers", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("name", Text, nullable=False, unique=True),
    Column("notes", Text),
    Column("created_by", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

locations = Table(
    "locations", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("customer_id", BigInteger, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False),
    Column("name", Text, nullable=False),
    Column("address", Text),
    Column("notes", Text),
    Column("created_by", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

signing_keys = Table(
    "signing_keys", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("public_key_pem", Text, nullable=False),
    Column("private_key_encrypted", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

licenses = Table(
    "licenses", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("license_uuid", UUID(as_uuid=True), nullable=False, unique=True),
    Column("customer_id", BigInteger, ForeignKey("customers.id"), nullable=False),
    Column("location_id", BigInteger, ForeignKey("locations.id"), nullable=False),
    Column("installation_id", Text, nullable=False),
    Column("max_machines", Integer, nullable=False),
    Column("issued_at", Date, nullable=False),
    Column("expires_at", Date),
    Column("notes", Text),
    Column("payload_json", JSONB, nullable=False),
    Column("signature_b64", Text, nullable=False),
    Column("issued_by", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    Column("expiry_notified_at", DateTime(timezone=True)),
)

audit_log = Table(
    "audit_log", metadata,
    Column("id", BigInteger, primary_key=True),
    Column("ts", DateTime(timezone=True), server_default=func.now()),
    Column("actor_username", Text, nullable=False),
    Column("action", Text, nullable=False),
    Column("target", Text),
    Column("detail", Text),
)
