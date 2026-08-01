# Development

## Local setup

```bash
cd backend
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn reversing_lab.api.app:app --reload
```

```bash
cd frontend
npm ci
npm run dev
```

The Vite server proxies `/api` to `http://127.0.0.1:8000`. Override with
`VITE_API_TARGET`.

## Required checks

```bash
cd backend && ../.venv/bin/pytest
cd frontend && npm test && npm run build && npm audit
git diff --check
git status
```

There is currently no configured Ruff, mypy, or ESLint command; do not claim those
checks ran. Add configuration and fix the existing baseline before making them CI gates.

## Test fixtures

Backend tests synthesize small safe ELF/PE/Mach-O samples or use inert buffers. Never
commit live malware, credentials, customer dumps, or proprietary binaries. External
tool and sandbox tests mock process/provider boundaries.

Frontend tests use Vitest, jsdom, and Testing Library. They cover state components,
API errors, disabled sandbox readiness, graph rendering, windowed large tables, and
keyboard panel resizing.

## Database changes

Alembic configuration lives in `backend/alembic`. Create every schema change as a new
revision and run:

```bash
cd backend
alembic upgrade head
alembic check
pytest tests/test_migrations.py
```

`python -m reversing_lab.database.migrate` upgrades fresh/versioned databases. An older
unversioned `create_all` database is stamped only after its table and column sets match
the current ORM metadata exactly; partial or drifted schemas are rejected. Back up real
data before stamping or upgrading. `init_db()` retains idempotent `create_all` behavior
for local backward compatibility, but production startup should run the migration
bootstrap first. PostgreSQL must be added to CI before claiming production support.

## Adding an adapter

- keep an explicit protocol and availability check;
- resolve executables from trusted configuration;
- use fixed argv, `shell=False`, sanitized environment, private temporary workspace,
  timeout, resource/output limits, structured errors, cancellation where supported;
- never accept arbitrary plugin/command arguments from HTTP;
- test unavailable, timeout, malformed output, and injection cases;
- document provenance and unsupported capabilities.

## Docker development

`docker compose up --build` runs API/UI as non-root processes with a named data volume.
Source bind mounts enable reload. This setup is not a binary execution sandbox.
