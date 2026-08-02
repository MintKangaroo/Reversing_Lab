# Authentication and roles

## Deployment modes

Authentication is optional so existing local workflows remain compatible.

- `RLAB_AUTH_MODE=disabled` grants the local request context the `admin` role. Use
  this only on a trusted loopback/private development host.
- `RLAB_AUTH_MODE=api_key` requires an HTTP bearer key for every endpoint except
  `GET /api/health`. Startup fails when no valid digest mapping is configured.

The browser keeps the entered raw key only in module memory. It is not written to
local storage, session storage, URLs, or cookies. Reloading or locking the workbench
forgets it. Authenticated file exports are fetched with the bearer header and then
downloaded as a blob.

## Key configuration

Generate a high-entropy key using an approved secret manager, distribute it over a
separate secure channel, and place only its lowercase SHA-256 digest in configuration.
The interactive command below avoids putting the raw key in shell history:

```bash
cd backend
python - <<'PY'
import getpass, hashlib
raw = getpass.getpass("New API key: ")
print(hashlib.sha256(raw.encode("utf-8")).hexdigest())
PY
```

Configure a JSON object whose keys are digests and values are
`principal:viewer|analyst|admin`:

```bash
export RLAB_AUTH_MODE=api_key
export RLAB_AUTH_API_KEY_HASHES='{
  "<viewer-digest>": "reviewer-one:viewer",
  "<analyst-digest>": "analyst-one:analyst",
  "<admin-digest>": "platform-admin:admin"
}'
```

Restart the API after changing the mapping. Rotation means adding a new digest,
distributing the replacement key, then removing the old digest. Raw keys must never
be logged, committed, or stored in `.env` files.

## Authorization semantics

| Role | HTTP access | Project visibility |
|---|---|---|
| `viewer` | read-only methods | own projects only |
| `analyst` | read and mutation methods | own projects only |
| `admin` | read and mutation methods | all projects for audit/operations |

Project creation records the authenticated principal as owner. A non-admin receives
404, rather than existence disclosure, when requesting another owner's project.
Legacy projects with no owner remain visible only to admins while authentication is
enabled.

This is a coarse deployment control, not a complete multi-tenant authorization
system. Binary samples, annotations/bookmarks, memory dumps, dynamic runs, jobs, CTF
workspaces, artifacts, and reports currently remain in a shared authenticated
catalog. Do not place mutually untrusted tenants in the same deployment.

## Operational requirements

- terminate TLS at a trusted reverse proxy; bearer keys over plaintext HTTP are not
  protected;
- rate-limit failed authentication and upload requests at that proxy;
- restrict CORS to the deployed UI origin;
- use a secret manager for the digest mapping and rotate keys periodically;
- keep access/audit logs, but redact `Authorization` headers;
- do not expose auth-disabled mode outside a trusted local network;
- prefer OIDC or short-lived centrally revoked credentials for larger teams.

`GET /api/auth/me` returns the current principal and role. `GET /api/health` exposes
only whether authentication is required; it does not reveal users, digests, or other
secrets. The settings endpoint similarly reports mode/scope without key material.
