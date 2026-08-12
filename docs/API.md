# API

FastAPI serves OpenAPI at `/docs` and `/openapi.json`. All application endpoints use
the `/api` prefix. Addresses are JSON integers; clients may send strict decimal or
`0x...` strings where an address is a path/query parameter.

## Authentication

Authentication defaults to disabled for local backward compatibility. With
`RLAB_AUTH_MODE=api_key`, `GET /api/health` remains public and every other endpoint
requires `Authorization: Bearer <raw-key>`. `GET /api/auth/me` returns the current
principal and role. Viewers can use only GET/HEAD/OPTIONS; analyst and admin keys can
mutate state. Resource reads/writes are owner-scoped for non-admin users.

Binary access uses per-principal grants while preserving hash-based physical
deduplication. Projects, annotations/bookmarks, artifacts, jobs, dumps, dynamic runs,
CTF state, and reports use or inherit the principal owner scope. Cross-owner identifiers
return 404; admins retain global audit access. Configuration and residual identity
limitations are documented in [AUTHENTICATION.md](AUTHENTICATION.md).

Every response includes a server-generated `X-Request-ID`. POST/PATCH/PUT/DELETE
requests create an audit event after handling. Audit metadata excludes the body,
authorization header, query string, and decoder input.

## Samples and static analysis

| Method | Endpoint |
|---|---|
| POST / GET | `/binaries` |
| GET | `/binaries/{sha}/info` |
| GET | `/binaries/{sha}/strings`, `/hex`, `/entropy`, `/packing` |
| GET | `/binaries/{sha}/functions` |
| GET | `/binaries/{sha}/functions/{address}` |
| GET | `/binaries/{sha}/functions/{address}/disassembly` |
| GET | `/binaries/{sha}/functions/{address}/decompile` |
| GET | `/binaries/{sha}/functions/{address}/cfg` |
| GET | `/binaries/{sha}/callgraph`, `/flow-summary` |
| GET | `/binaries/{sha}/obfuscation`, `/findings` |
| POST / GET | `/binaries/{sha}/annotations`, `/bookmarks` |
| POST / GET | `/binaries/{sha}/unpack`, `/artifacts` |
| GET | `/binaries/{sha}/report?format=json|markdown|html` |

Functions, strings, hex, graphs, and high-volume analysis are bounded or paginated.
Memory module, handle, and region responses retain integer values and also include exact
hex display fields for JavaScript clients.

## Projects, jobs, memory, and dynamic

| Method | Endpoint |
|---|---|
| GET / POST | `/projects` |
| GET / PATCH | `/projects/{id}` |
| POST | `/projects/{id}/samples/{sha}` |
| GET | `/jobs`, `/jobs/{id}`, `/jobs/{id}/stream` |
| POST | `/jobs/{id}/cancel` |
| POST / GET | `/memory-dumps`, `/memory-dumps/{id}` |
| POST / GET | `/memory-dumps/{id}/analysis` |
| GET | `/memory-dumps/{id}/processes`, `/modules`, `/handles`, `/regions`, `/network`, `/findings` |
| POST | `/memory-dumps/{id}/regions/inspect` |
| GET | `/memory-dumps/{id}/region-artifacts` |
| GET | `/memory-dumps/{id}/region-artifacts/{artifact_id}` |
| GET | `/memory-dumps/{id}/region-artifacts/{artifact_id}/hex`, `/disassembly`, `/download` |
| GET | `/dynamic-analysis/readiness` |
| POST | `/dynamic-analysis` |
| GET / POST | `/dynamic-analysis/{run_id}`, `/cancel` |
| GET | `/dynamic-analysis/{run_id}/events`, `/artifacts` |

`/memory-dumps/{id}/network` supports bounded `offset`/`limit` pagination and exact
`pid`, case-insensitive `protocol`/`state`, and bounded `keyword` filters. Filtering
operates only on the already bounded result artifact and never becomes a plugin or CLI
argument.

`/memory-dumps/{id}/handles` supports the same bounded pagination, exact `pid`,
case-insensitive exact `object_type`, and bounded `keyword` filters. Keyword matching
includes process/name/type and server-rendered object/handle/access hex values. Filters
operate only on the stored bounded artifact.

Region inspection accepts only a normalized PID/start pair, `architecture=x86|x86_64`,
and literal `acknowledged=true`. It returns a `memory-region-inspection` job. On
completion, `result_ref` is the owner-scoped artifact ID. Hex pages are capped at 4 KiB
and disassembly at 2,000 requested instructions in addition to the global instruction
cap. The raw download name is server generated from the content hash.

## CTF, tools, and capabilities

| Method | Endpoint |
|---|---|
| GET / POST | `/ctf-workspaces` |
| GET / PATCH | `/ctf-workspaces/{id}` |
| POST | `/ctf-workspaces/{id}/notes` |
| GET | `/ctf-workspaces/{id}/export?format=markdown|json` |
| POST | `/tools/decode` |
| GET | `/tooling`, `/tooling/{tool_name}`, `/tooling/configuration` |
| GET / POST | `/challenges`, `/challenges/{slug}/submit` |

Decoder input is not persisted. Transform operation names and parameter types are
allowlisted by Pydantic.

## Audit and owned-data retention

| Method | Endpoint | Behavior |
|---|---|---|
| GET | `/audit-events?offset=0&limit=100` | principal-scoped page; admins can inspect all principals |
| GET | `/audit-events/export` | bounded, oldest-first hash-chained JSONL stream |
| GET | `/retention/preview?include_binary_access=false` | counts current-principal records without deleting |
| POST | `/retention/purge` | deletes current-principal mutable state after exact confirmation |

Audit filters are `action`, `resource_type`, and `outcome=succeeded|denied|failed`;
`limit` is capped at 500. Purge accepts JSON
`{"confirmation":"PURGE:<principal-id>","include_binary_access":false}`. It never
purges another owner implicitly, even for admins, and it retains audit events. Active
owned jobs return 409. Including binary access deletes physical hash content only if no
grant or analysis reference remains.

Audit export accepts the same exact-value filters plus timezone-aware `created_after`
(inclusive) and `created_before` (exclusive). Naive timestamps are rejected. Exports
above `RLAB_MAX_AUDIT_EXPORT_RECORDS` return 413 and require a narrower UTC range. The
response includes `X-Audit-Export-Records`, `nosniff`, and an attachment filename.
JSONL format and verification are documented in [AUDIT_LOGGING.md](AUDIT_LOGGING.md).

## Errors

- `404`: unknown content hash/resource or malformed binary identifier;
- `413`: upload exceeds its configured bound;
- `415`: unsupported executable format;
- `422`: malformed address/request or analysis failure mapped to client-safe detail;
- `401`: missing or invalid bearer key when authentication is enabled;
- `403`: authenticated viewer attempted a mutation;
- `409`: result requested before job completion or retention blocked by an active job;
- `503`: explicitly requested optional tool/provider is unavailable.

Example:

```bash
BASE=http://127.0.0.1:8000/api
read -rsp "API key: " API_KEY && echo
SHA=$(curl -s -H "Authorization: Bearer $API_KEY" -F file=@./authorized.elf "$BASE/binaries" | jq -r .sha256)
curl -s -H "Authorization: Bearer $API_KEY" "$BASE/binaries/$SHA/functions?limit=50" | jq
curl -OJ -H "Authorization: Bearer $API_KEY" "$BASE/binaries/$SHA/report?format=markdown"
unset API_KEY
```
