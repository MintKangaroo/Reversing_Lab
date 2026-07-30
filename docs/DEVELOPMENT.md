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

Development currently calls SQLAlchemy `create_all`; additive tables appear in a fresh
SQLite DB. There is no Alembic history. Until migrations are introduced, do not make
destructive or incompatible column changes. PostgreSQL migration work must add Alembic
and test upgrade/downgrade paths.

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
