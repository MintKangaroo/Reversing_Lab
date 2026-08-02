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

| Role | HTTP access | Resource visibility |
|---|---|---|
| `viewer` | read-only methods | grants and resources for its principal ID |
| `analyst` | read and mutation methods | grants and resources for its principal ID |
| `admin` | read and mutation methods | all resources for audit/operations |

Projects, annotations, bookmarks, artifacts, jobs, memory dumps, dynamic runs, CTF
workspaces, and challenge attempts record the authenticated principal as owner. A
non-admin receives 404, rather than existence disclosure, when requesting another
owner's resource. CTF notes and project samples inherit their parent ownership.

Binary bytes remain globally content-addressed so identical uploads occupy one physical
file. `binary_access` stores a separate principal grant and display filename. Uploading
the same bytes while authenticated grants only that principal access; knowing or
guessing a SHA is insufficient. Existing data upgraded through revision 0004 is assigned
to the `local` owner. Admins can audit it; another principal can acquire a binary grant
by uploading the identical authorized sample.

Multiple keys may use the same principal ID with different roles, for example a
read-only `analyst-one:viewer` key and a mutation-capable `analyst-one:analyst` key.
They intentionally share the same owner scope.

This is an application-level owner boundary, not a complete hardened multi-tenant
identity system. API keys are long-lived, admin access is global, and OIDC, centralized
revocation, persistent audit events, retention workflows, and server-side rate limits
are not yet implemented. Use separate deployments for strongly isolated tenants.

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
