"""Environment-driven settings."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    # Postgres
    postgres_user: str = "dgl"
    postgres_password: str = "dgl"
    postgres_db: str = "dgl"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # Web
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    session_ttl_hours: int = 12

    # Bootstraps the initial super_admin account on first startup (only if no
    # super_admin exists yet) - same pattern as Data Gateway's own
    # DG_SUPERADMIN_USER/PASSWORD.
    superadmin_user: str = ""
    superadmin_password: str = ""
    superadmin_email: str = ""

    # Symmetric key (Fernet, `python -c "from cryptography.fernet import
    # Fernet; print(Fernet.generate_key().decode())"`) that encrypts the
    # Ed25519 signing private key at rest in the DB - see app/crypto.py.
    # Deliberately lives only here (.env), never in the database, so a DB
    # dump alone can never recover the signing key.
    license_master_key: str = ""

    # SMTP for license-expiry notifications (app/notify.py). smtp_use_tls
    # (STARTTLS on smtp_port, typically 587) vs smtp_use_ssl (implicit TLS,
    # typically 465) - Gmail supports both; STARTTLS/587 is the default here.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_from: str = ""
    # How many days before expires_at a license first gets flagged.
    notify_days_before: int = 30

    # Forgot-password flow (app/auth.py's reset-token functions, wired up in
    # app/web/app.py). The link mailed to a user is
    # f"{public_base_url}?reset_token=..." - the app has no way to know its
    # own externally-reachable URL on its own (it's mounted under a Caddy
    # path prefix it's unaware of - see the /licensing handle_path block),
    # so this has to be set explicitly rather than derived.
    public_base_url: str = "https://vpna.salisterra.ro/licensing/"
    reset_token_ttl_minutes: int = 60

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
