# dg-licensing

Web platform for issuing and tracking Data Gateway license files - replaces
the manual `tools/issue_license.py` CLI in the `dg-server` project.

## What it does

- Tracks **customers** and **locations** (a license belongs to both).
- Issues Ed25519-signed license files in the exact shape `dg/licensing.py`
  (in `dg-server`) verifies - the signing key lives on this server,
  encrypted at rest, so issuing a license is one click instead of a manual
  CLI run on someone's own laptop.
- Two roles: **admin** and **super_admin** - only super_admin manages user
  accounts; both can create customers/locations/licenses.
- A full **audit log** of every action, tagged with who did it.
- Licenses can be **perpetual** (no expiry) or dated, with a free-text
  **notes** field for commercial terms/observations.
- A background check emails a warning (default 30 days out) before any
  dated license expires.

## Local development

```
cp .env.example .env      # fill in POSTGRES_*, SUPERADMIN_*, LICENSE_MASTER_KEY at minimum
docker compose up --build -d
```

Then open `http://localhost:8082` (or whatever port you mapped) and log in
with `SUPERADMIN_USER`/`SUPERADMIN_PASSWORD` from `.env`.

Generate `LICENSE_MASTER_KEY` once with:

```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Deployment

Runs as its own small Docker Compose stack (its own Postgres, one `web`
service) behind an existing Caddy instance on the target host - see that
host's own `Caddyfile` for the exact reverse-proxy line. Not exposed to the
open internet; only reachable however that Caddy vhost already is.

## Wiring up the Data Gateway side

The public key shown in Admin -> (once exposed in the UI) / via
`GET /api/public-key` needs to replace `_PUBLIC_KEY_PEM` in `dg-server`'s
`dg/licensing.py` - only needs doing once per signing key, not per license,
since the private key never changes once generated.
