-- dg-licensing schema. Applied once by Postgres's own initdb (mounted as
-- /docker-entrypoint-initdb.d/10-schema.sql - see docker-compose.yml), same
-- convention as the Data Gateway project this tool issues licenses for.

CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    -- Required so the forgot-password flow has somewhere to send the reset
    -- link (app/auth.py's create_reset_token / app/web/app.py's
    -- /api/auth/forgot-password) - unique so a lookup by email is
    -- unambiguous.
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    -- Two roles only: 'admin' and 'super_admin'. Both can create customers/
    -- locations/licenses - the only difference is user management, enforced
    -- in app/auth.py's require_role().
    role          TEXT NOT NULL CHECK (role IN ('admin', 'super_admin')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token       TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

-- Single-use, short-lived tokens for the "forgot password" email link -
-- separate from `sessions` since these authenticate one specific action
-- (setting a new password), not a login.
CREATE TABLE password_resets (
    token       TEXT PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX ix_password_resets_user ON password_resets (user_id);
CREATE INDEX ix_sessions_expires ON sessions (expires_at);

CREATE TABLE customers (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    notes       TEXT,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE locations (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    address     TEXT,
    notes       TEXT,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (customer_id, name)
);
CREATE INDEX ix_locations_customer ON locations (customer_id);

-- The Ed25519 keypair this platform signs licenses with. Single row in
-- practice (see app/crypto.py) - a table rather than a bare file so it lives
-- in the same backed-up place as everything else. private_key_encrypted is
-- the PEM bytes through Fernet, keyed by DG_LICENSING_MASTER_KEY (.env, never
-- in the DB) - a DB dump alone is never enough to recover the signing key.
CREATE TABLE signing_keys (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_key_pem          TEXT NOT NULL,
    private_key_encrypted   BYTEA NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Mirrors the payload shape dg/licensing.py on the Data Gateway side
-- verifies (license_id/customer/installation_id/max_machines/issued_at/
-- expires_at + signature) - see app/licenses.py's issue() for exactly how
-- payload_json is built and signed. location/notes are extra fields DG's
-- verifier ignores (it only reads the five it checks), kept here for this
-- platform's own tracking.
CREATE TABLE licenses (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    license_uuid        UUID NOT NULL UNIQUE,
    customer_id         BIGINT NOT NULL REFERENCES customers(id),
    location_id         BIGINT NOT NULL REFERENCES locations(id),
    installation_id     TEXT NOT NULL,
    max_machines        INTEGER NOT NULL,
    issued_at           DATE NOT NULL,
    expires_at          DATE,              -- NULL = perpetual
    notes               TEXT,
    payload_json        JSONB NOT NULL,    -- exact signed payload, for re-download/audit
    signature_b64        TEXT NOT NULL,
    issued_by            TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set once the 30-days-to-expiry notification has actually been sent,
    -- so the daily sweep (app/notify.py) never emails the same license
    -- twice. Cleared if expires_at changes (e.g. a renewal) so a shortened
    -- date can still trigger a fresh warning.
    expiry_notified_at   TIMESTAMPTZ
);
CREATE INDEX ix_licenses_customer ON licenses (customer_id);
CREATE INDEX ix_licenses_location ON licenses (location_id);
CREATE INDEX ix_licenses_expires ON licenses (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE audit_log (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_username  TEXT NOT NULL,
    action          TEXT NOT NULL,
    target          TEXT,
    detail          TEXT
);
CREATE INDEX ix_audit_log_ts ON audit_log (ts DESC);
CREATE INDEX ix_audit_log_actor ON audit_log (actor_username);

CREATE TABLE app_settings (key TEXT PRIMARY KEY, value TEXT);
