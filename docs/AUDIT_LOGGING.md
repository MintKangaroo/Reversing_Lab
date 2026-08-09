# Audit logging and export

## Recorded metadata

Reversing Lab records POST, PUT, PATCH, and DELETE request metadata after handling. A
server UUID is returned as `X-Request-ID` and links the response to the event. Stored
fields are principal/role, method, matched route template, allowlisted resource ID,
status/outcome, and timestamp.

Request bodies, bearer credentials, query strings, upload display names, decoder input,
and raw sample data are not copied into audit rows. The application exposes list and
export operations but no audit update/delete API. Owned-data retention preserves these
rows.

## Exporting

Use the Settings **Export JSONL** action or download a filtered UTC range:

```bash
curl -fOJ \
  -H "Authorization: Bearer $RLAB_API_KEY" \
  --get http://127.0.0.1:8000/api/audit-events/export \
  --data-urlencode 'created_after=2026-08-01T00:00:00Z' \
  --data-urlencode 'created_before=2026-09-01T00:00:00Z'
```

Do not put a raw API key directly in command history. The example assumes an ephemeral
environment variable supplied by an approved secret workflow. Admin export scope is all
principals; analyst/viewer scope is only their principal. The configured record cap is
checked before streaming. Narrow the UTC range if HTTP 413 is returned.

## JSONL structure

1. `manifest`: schema, creation time, scope, filters, algorithm, and `manifest_hash`;
2. zero or more oldest-first `event` records with `previous_hash` and `record_hash`;
3. `footer`: record count, manifest hash, final chain head, and `complete: true`.

Absence of a valid footer means the transfer is incomplete. Each event hash is:

```text
SHA256(previous_hash + "\n" + canonical_event_json)
```

Canonical JSON uses sorted keys, UTF-8, no optional whitespace, and excludes the two
chain fields. The manifest hash uses the same canonical encoding before adding its own
`manifest_hash` field.

## Trust and rotation boundary

The chain is calculated at export time. It can detect later editing, removal, or
reordering within that completed file, but it does not prove the source database was
complete or unmodified. For a stronger boundary, immediately transmit exports over an
authenticated channel to independently controlled signed or WORM-backed storage and
record its object version/hash in the organization's audit system.

Reversing Lab intentionally performs no automatic audit-row deletion. Retention period,
legal hold, archival rotation, external signing, access review, and secure disposal are
deployment responsibilities. Validate an external copy before applying any operator-run
database lifecycle policy.
