# Operations

Operational runbook for a shared/production deployment: how to terminate TLS in
front of the API, and how to back up and restore PostgreSQL together with the
on-disk binary store. It complements [SECURITY.md](SECURITY.md) (posture and
threat boundaries) and [DEVELOPMENT.md](DEVELOPMENT.md) (local setup).

The application binds plain HTTP and keeps no TLS or credential state of its own.
Everything below assumes you place it behind a reverse proxy and configure it
through `RLAB_*` environment variables (see
[config.py](../backend/reversing_lab/config.py)).

## Two pieces of durable state

A deployment persists analysis results in **two** places that must be backed up
and restored together:

1. **The database** (`RLAB_DATABASE_URL`) — projects, jobs, findings, memory and
   dynamic records, CTF state, reports, audit events, and per-principal binary
   grants. Rows reference stored binaries by their SHA-256.
2. **The binary/dump store** (`RLAB_STORAGE_DIR`, default `./data/binaries`) —
   the uploaded bytes on disk, named by server-computed SHA-256.

The database holds references, the store holds the bytes. A backup of one without
the other is inconsistent: database rows will point at missing files, or orphan
files will accumulate. Treat the pair as a single backup unit.

---

## TLS deployment

### Posture

- The API and UI listen on plain HTTP (`:8000` and `:5173`). Do **not** expose
  those ports directly to an untrusted network.
- Terminate TLS at a reverse proxy on the same host or a trusted network segment,
  and forward cleartext to the API over loopback or a private link.
- Enable authentication (`RLAB_AUTH_MODE=api_key`, see
  [AUTHENTICATION.md](AUTHENTICATION.md)) whenever the deployment is reachable by
  more than the local operator. Auth-disabled mode must never be internet-facing.
- Set `RLAB_CORS_ORIGINS` to the exact HTTPS origin(s) the UI is served from —
  not a wildcard, and not the `http://localhost:5173` development default.
- The in-process rate limiter (`RLAB_RATE_LIMIT_ENABLED`) is per-worker and not
  distributed; for multi-worker or multi-host deployments also enforce a global
  limit at the proxy. See [SECURITY.md](SECURITY.md).

### Example: nginx terminating TLS in front of the API

```nginx
server {
    listen 443 ssl http2;
    server_name reversing-lab.example.internal;

    ssl_certificate     /etc/ssl/reversing-lab/fullchain.pem;
    ssl_certificate_key /etc/ssl/reversing-lab/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Uploads are magic-allowlisted and byte-capped by the API, but bound the
    # proxy too. Keep this >= RLAB_MAX_MEMORY_DUMP_BYTES (default 512 MiB).
    client_max_body_size 512m;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location /api/ {
        proxy_pass         http://127.0.0.1:8000/;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 360s;   # >= RLAB_MAX_ANALYSIS_SECONDS for long jobs
    }

    location / {
        proxy_pass       http://127.0.0.1:5173/;
        proxy_set_header Host $host;
    }
}

# Redirect cleartext to HTTPS.
server {
    listen 80;
    server_name reversing-lab.example.internal;
    return 301 https://$host$request_uri;
}
```

### Example: Caddy (automatic certificates)

```caddy
reversing-lab.example.internal {
    encode gzip
    request_body {
        max_size 512MB
    }
    handle_path /api/* {
        reverse_proxy 127.0.0.1:8000
    }
    reverse_proxy 127.0.0.1:5173
}
```

Caddy provisions and renews certificates automatically for a resolvable public
name; for a purely internal name, supply `tls /path/cert.pem /path/key.pem`
inside the block.

### Verifying the TLS front door

```bash
# Certificate chain and expiry.
echo | openssl s_client -connect reversing-lab.example.internal:443 -servername \
  reversing-lab.example.internal 2>/dev/null | openssl x509 -noout -dates -issuer

# API reachable only through HTTPS, and auth enforced (expect 401 without a key).
curl -sS -o /dev/null -w '%{http_code}\n' https://reversing-lab.example.internal/api/health
```

---

## PostgreSQL

SQLite remains the zero-configuration development database. A shared deployment
should use PostgreSQL 16 (the version exercised in CI). Install the optional
driver with `pip install -r backend/requirements-postgres.txt` and point the app
at it:

```bash
export RLAB_DATABASE_URL="postgresql+psycopg://reversing_lab:CHANGE_ME@db-host:5432/reversing_lab"
```

Apply the schema before first start, and after every upgrade, with Alembic from
the `backend/` directory:

```bash
cd backend
alembic upgrade head
alembic check   # exits non-zero if the model and migrations have drifted
```

### Backup

Back up the database and the binary store **as one unit**. A logical dump plus a
tar of the store is portable and simple; run them close together and, for a busy
deployment, pause uploads (or take the API offline) for the moment of the
snapshot so the two halves agree.

```bash
# 1. Database — custom format, compressed, restorable with pg_restore.
pg_dump --format=custom --no-owner --no-privileges \
  "postgresql://reversing_lab:CHANGE_ME@db-host:5432/reversing_lab" \
  --file "backup-$(date +%F).dump"

# 2. Binary store — the content-addressed bytes on disk.
tar --create --gzip \
  --file "binaries-$(date +%F).tar.gz" \
  --directory /var/lib/rlab binaries
```

Store both artifacts together, encrypted at rest, with a retention policy that
matches your audit requirements. The database dump alone cannot reconstruct
uploaded samples.

### Restore

Restore into an empty database and an empty store, in this order.

```bash
# 1. Create a fresh, empty database.
createdb -h db-host -U postgres reversing_lab

# 2. Restore the schema and rows.
pg_restore --no-owner --no-privileges \
  --dbname "postgresql://reversing_lab:CHANGE_ME@db-host:5432/reversing_lab" \
  "backup-2026-09-07.dump"

# 3. Restore the binary store to RLAB_STORAGE_DIR's parent.
tar --extract --gzip \
  --file "binaries-2026-09-07.tar.gz" \
  --directory /var/lib/rlab

# 4. Reconcile the schema with the running code, then start the API.
cd backend && alembic upgrade head && alembic check
```

### Restore rehearsal

An untested backup is a guess. Rehearse restore on a throwaway target on a fixed
cadence (for example monthly, and before any major upgrade). The drill both
proves the backups and confirms the database–store pair is internally
consistent.

```bash
# 1. Restore into a scratch database and scratch store (steps 1–4 above,
#    pointed at reversing_lab_restore_test and /tmp/rlab-restore).

# 2. Schema is current — no pending drift.
cd backend
RLAB_DATABASE_URL="postgresql+psycopg://reversing_lab:CHANGE_ME@db-host:5432/reversing_lab_restore_test" \
  alembic check

# 3. Row counts are plausible (spot-check the largest tables).
psql "postgresql://reversing_lab:CHANGE_ME@db-host:5432/reversing_lab_restore_test" \
  -c "select relname, n_live_tup from pg_stat_user_tables order by n_live_tup desc limit 10;"

# 4. Referential consistency: every binary referenced by the database exists on
#    disk in the restored store, and vice versa. Compare the distinct SHA-256
#    values recorded in the database against the filenames in the store; an empty
#    diff on both sides means the two halves agree.
```

Record each rehearsal (date, backup timestamp restored, outcome, and any drift or
missing-file findings) so the runbook stays honest about when restore was last
proven to work.

### Point-in-time recovery

The logical-dump workflow above gives per-backup granularity. If you need
point-in-time recovery between backups, run PostgreSQL with WAL archiving
(`archive_mode`, `archive_command`) or a managed service that provides it, and
pair each base backup with a matching binary-store snapshot so a restored
database and its byte store still line up.
