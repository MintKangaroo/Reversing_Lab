# API

FastAPI serves OpenAPI at `/docs` and `/openapi.json`. All application endpoints use
the `/api` prefix. Addresses are JSON integers; clients may send strict decimal or
`0x...` strings where an address is a path/query parameter.

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

## Projects, jobs, memory, and dynamic

| Method | Endpoint |
|---|---|
| GET / POST | `/projects` |
| GET / PATCH | `/projects/{id}` |
| POST | `/projects/{id}/samples/{sha}` |
| GET | `/jobs`, `/jobs/{id}`, `/jobs/{id}/events` |
| POST | `/jobs/{id}/cancel` |
| POST / GET | `/memory-dumps`, `/memory-dumps/{id}` |
| POST / GET | `/memory-dumps/{id}/analysis` |
| GET | `/memory-dumps/{id}/processes`, `/regions`, `/findings` |
| GET | `/dynamic-analysis/readiness` |
| POST | `/dynamic-analysis` |
| GET / POST | `/dynamic-analysis/{run_id}`, `/cancel` |
| GET | `/dynamic-analysis/{run_id}/events`, `/artifacts` |

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

## Errors

- `404`: unknown content hash/resource or malformed binary identifier;
- `413`: upload exceeds its configured bound;
- `415`: unsupported executable format;
- `422`: malformed address/request or analysis failure mapped to client-safe detail;
- `409`: result requested before job completion;
- `503`: explicitly requested optional tool/provider is unavailable.

Example:

```bash
BASE=http://127.0.0.1:8000/api
SHA=$(curl -s -F file=@./authorized.elf "$BASE/binaries" | jq -r .sha256)
curl -s "$BASE/binaries/$SHA/functions?limit=50" | jq
curl -OJ "$BASE/binaries/$SHA/report?format=markdown"
```
