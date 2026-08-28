# Security

## Safe deployment posture

Reversing Lab assumes every upload is hostile. Run it on a dedicated analysis network
with least-privilege filesystem access. Optional digest-backed bearer authentication
is available but disabled by default for local compatibility. Any shared deployment
must enable it behind TLS and proxy rate limiting; auth-disabled mode must not be
exposed directly to the internet.

The built-in roles are deliberately coarse. Viewers are HTTP read-only, analysts may
mutate state, and admins may audit all resources. Non-admin access is enforced through
binary grants and owner-scoped repositories for projects, overlays, artifacts, jobs,
dumps, dynamic runs, CTF state, and reports. Cross-owner lookups return 404. This is
still not a complete identity/control plane: OIDC and centralized revocation remain
future work. See [AUTHENTICATION.md](AUTHENTICATION.md).

An opt-in per-principal rate limiter (`RLAB_RATE_LIMIT_ENABLED`, with
`RLAB_RATE_LIMIT_REQUESTS` per `RLAB_RATE_LIMIT_WINDOW_SECONDS`) rejects excess requests
with `429` and a `Retry-After` header, keyed on the authenticated principal (falling back
to client host). The counter is in-process: it is a real guardrail for a single-worker
deployment, but a multi-worker or multi-host deployment must still enforce a global limit
at the proxy or with a shared store — the in-process limiter is not distributed.

Mutation requests receive a server-generated request ID and append method, matched
route template, principal/role, resource metadata, status, and outcome to the database.
The audit path never stores request bodies, authorization headers, query strings, or
decoder input. The repository exposes no update/delete method, and built-in retention
never deletes audit rows. This is application-level append-only behavior, not a
cryptographically sealed ledger; ship events to independent append-only storage for a
strong operational audit boundary.

The JSONL export preserves principal scope, requires timezone-aware range filters, and
is rejected before streaming when its record count exceeds the configured cap. Its
export-time hash chain detects changes inside a completed exported file. Since the
application itself creates that chain, it cannot establish source-database integrity;
anchor or sign exports in an independently controlled system.

## Upload and storage controls

- binary and memory uploads stop reading as soon as their configured byte limit is
  exceeded and return HTTP 413;
- executable formats are magic-allowlisted before binary persistence;
- user filenames are sanitized basenames used only as display metadata;
- file paths are derived from server-computed SHA-256 values;
- identical binary bytes are physically deduplicated while per-principal grants retain
  isolated display filenames;
- malformed/non-lowercase SHA paths resolve to 404, never a filesystem lookup;
- archives are not accepted, avoiding zip-slip, nested archive, and decompression bomb
  paths.

## Parsing and analysis controls

Parsers wrap malformed library inputs in typed errors. Settings bound functions,
instructions, graph nodes, strings, memory processes/threads/modules/handles/regions/network
records/findings,
explicit region bytes, events,
output sizes, elapsed time, and concurrent jobs. A clean heuristic result is not a
safety verdict.

## External tools

Ghidra decompile, UPX unpack, and Volatility calls use fixed executable resolution and
argument vectors, `shell=False`, timeouts, private temporary directories, bounded
structured output, and sanitized environments. Volatility plugin names are chosen by
server code from an allowlist. Process-list/tree, command-line, thread, DLL, handle,
VAD, and network plugins fail independently;
external output is normalized as untrusted data and each result retains its provider.
RWX/private-executable VAD findings are heuristic and explicitly identify common JIT,
instrumentation, and compatibility-layer false positives. UPX is explicit opt-in,
never overwrites the original, and records both hashes and size/section changes.

VAD extraction is a separate acknowledged job, never an automatic side effect of
triage. PID/start must match stored Volatility evidence, architecture is enum-allowlisted,
and the complete VAD must fit `RLAB_MAX_MEMORY_REGION_EXTRACT_BYTES`. Provider filenames
cannot select a filesystem path. Extracted bytes are hash-addressed, owner-scoped,
integrity-checked before each view/download, and reclaimed through the retention path.
Capstone reads the artifact as data and never executes it.

Network records are provider observations rather than IOC verdicts. Public remote
addresses produce informational findings only. A wildcard listener is raised at low
severity only when Volatility cannot attribute it to a process. API network filters are
bounded artifact queries and are never forwarded to Volatility.

Handle records are bounded provider observations. API filters apply only to the stored
artifact and never become provider arguments. Object addresses, access masks, names,
and types can be stale, incomplete, or fabricated by a compromised provider and must
be correlated before drawing conclusions.

Command lines may contain secrets or personal data and remain confined to the
owner-scoped result artifact; they are not copied into audit events. Thread records and
their start-address/VAD correlations are bounded provider evidence, not proof of code
injection or liveness. Thread API filters query only the stored artifact.

Legacy whole-binary integration adapters are optional and should be placed in an
additional process/container boundary for hostile production workloads. No optional
tool is required for core API availability.

## Dynamic analysis

The default provider is disabled. The API process never executes samples. Readiness is
deny-by-default and evaluates all required guardrails. Docker alone is not considered
a strong malware boundary; use a disposable VM worker for real malware. See
[DYNAMIC_ANALYSIS.md](DYNAMIC_ANALYSIS.md).

## Data handling

Decoder playground input is transformed in-memory for the request and is not stored.
Analyst notes are stored and HTML report output escapes them. Dynamic/memory bulk data
uses compressed or content-addressed artifacts. Logs should contain identifiers and state, not raw sample
contents or decoder input.

Owned-data deletion is explicit and dry-run-first. Even an administrator can purge only
the current principal's scope. Exact typed confirmation is required; queued/running
owned jobs cause HTTP 409. Binary grants are optional in the purge, and physical sample
bytes are reclaimed only after all access and analysis references are gone. Metadata is
committed before unlinking, and only direct files under configured storage roots can be
removed. Operators still need backup, legal hold, retention duration, and secure media
disposal policies.

## Production hardening checklist

- enable API-key auth or add OIDC, terminate TLS, rate-limit failures, and redact
  authorization headers from logs;
- test every new repository and ID-based route for owner filtering and 404 behavior;
- terminate TLS at a trusted reverse proxy;
- use the Alembic workflow and tested PostgreSQL migration path; rehearse restore and
  encrypt database connections and backups;
- isolate parser/external-tool workers with OS resource controls;
- keep storage non-executable and mount it `noexec,nodev,nosuid`;
- restrict outbound network and CORS origins;
- run API/UI as non-root users;
- ship built-in audit events to independently controlled append-only storage;
- scan dependencies and container images in CI;
- rotate/delete samples according to legal retention requirements.

## Vulnerability reporting

Do not attach real malware or sensitive customer samples to a public issue. Report a
minimal reproduction and security impact through the repository owner's private
security contact/channel.
