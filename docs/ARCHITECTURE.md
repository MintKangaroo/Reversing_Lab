# Architecture

## Goals and boundaries

Reversing Lab unifies static analysis, dump triage, isolated-provider orchestration,
CTF investigation state, and evidence-linked reporting. Uploaded executable bytes are
untrusted data. The API process parses but never executes them.

Out of scope: unauthorized intrusion, credential theft, malware deployment, automated
DRM bypass, production-service exploitation, and an API-process execution fallback.

## Component map

```text
Browser
└── React workbench
    ├── hash routing and resizable panels
    ├── explorer / analysis tabs / inspector / jobs
    └── CFG, call graph, timeline, CTF, reports, settings
         │ REST + SSE
         ▼
FastAPI
├── optional bearer auth / coarse HTTP roles
├── api/routes
│   ├── binaries / analysis / reports
│   ├── memory / dynamic / jobs
│   └── projects / CTF / tooling / audit / retention / challenges
├── parser ── normalized BinaryInfo
├── analysis + analyzer + disassembler
├── decompiler adapters
├── memory adapters
├── dynamic provider interface
├── DB-backed bounded job runner
└── repositories
    ├── SQLite/PostgreSQL-ready metadata indexes
    ├── content-addressed binary/artifact bytes
    └── compressed memory/dynamic JSON artifacts
```

## Dependency direction

Parser dataclasses are the stable vocabulary. Analysis code depends on normalized
models rather than LIEF objects; API schemas adapt domain objects at the boundary.
Repositories own SQL/filesystem access. UI code accesses only the HTTP API.

```text
api → analysis/analyzer/disassembler/decompiler/memory/dynamic → parser.models
 │
 └→ database repositories → SQLAlchemy / content-addressed files
```

## Core flows

### Static sample

1. Multipart input is read in bounded chunks.
2. Magic allowlisting precedes persistence.
3. Server-computed SHA-256 becomes the identity and disk filename.
4. The parser produces cached normalized metadata.
5. bounded analyzers recover functions, instructions, graphs, findings, and flow.
6. annotations/bookmarks remain separate user provenance overlays.
7. reports rebuild from the canonical model and state limitations.

### Memory dump

1. A separately bounded upload is stored by hash.
2. SQL stores dump/job/result indexes.
3. a DB-backed job performs basic data-only triage.
4. if explicitly requested and available, the adapter runs only server-selected
   Volatility plugins.
5. `pslist`, `pstree`, `dlllist`, `vadinfo`, and `netscan` outputs are independently
   normalized into bounded process-tree, loaded-module, region, and network records;
   one plugin failure does not discard successful sibling results.
6. VAD permissions and mapping provenance produce reviewable RWX/private-executable
   heuristic findings. Public endpoints remain informational observations, while only
   unattributed wildcard listeners receive a low-severity review signal.
7. large results are gzip JSON artifacts, not one row per module/socket/string/region.

### Dynamic analysis

1. readiness evaluates provider, worker, resource, timeout, network, workspace,
   sample-path, and acknowledgement guards.
2. failure of any guard blocks both UI and API.
3. a provider receives the validated content-addressed path and immutable policy.
4. provider output is bounded and stored as compressed events/artifact metadata.
5. the API never substitutes local subprocess execution.

### Mutation audit and retention

1. authorization resolves the principal before a mutation reaches a route;
2. middleware assigns a server UUID request ID and records only method, matched route
   template, status/outcome, principal, role, and allowlisted resource identifiers;
3. request bodies, authorization headers, query values, and decoder input are never
   copied into audit storage;
4. retention preview counts only the current principal's resources, including for an
   administrator;
5. purge requires the exact `PURGE:<principal-id>` confirmation and refuses while an
   owned job is queued or running;
6. the database transaction commits before files are removed, paths must be direct
   children of configured storage roots, and referenced content-addressed binaries
   remain intact.

## Data and persistence

SQLAlchemy models index projects, binaries, annotations, bookmarks, jobs, artifacts,
memory dumps, dynamic runs, and CTF state. Binary/dump/derived bytes use hashes as
filenames. High-volume events/results live in gzip JSON artifacts; SQL stores metadata
and references. SQLite is the supported development database. The repository pattern
avoids SQLite-only query constructs. Alembic owns the baseline schema; a conservative
bootstrap stamps an older `create_all` database only when every table and column
matches a known revision. Revision 0002 adds nullable project ownership and safely
upgrades the pre-ownership baseline. Revision 0003 uses portable 64-bit columns for
binary/artifact/dump sizes and virtual addresses. CI validates fresh PostgreSQL 16
upgrade, metadata drift, full downgrade/re-upgrade, and high-address repository
round-trips. Backup/restore, high availability, and workload sizing remain deployment
responsibilities rather than application-level guarantees.

Revision 0004 adds per-principal binary access grants and non-null ownership for
projects, annotations, bookmarks, artifacts, jobs, memory dumps, dynamic runs, CTF
workspaces, and challenge attempts. Legacy rows are conservatively assigned to the
`local` owner. Project samples and CTF notes inherit their parent scope. Repository
dependencies apply the authenticated principal scope consistently; background workers
use internal unrestricted repositories only after the request path has authorized the
job/run/dump. Admins retain cross-owner operational access.

Physical binary bytes remain deduplicated by SHA-256. The grant row owns the analyst's
display filename, avoiding cross-owner filename leakage without duplicating content.
This database boundary does not replace a mature identity provider, persistent audit
archive, rate limiting, or deployment-level isolation.

Revision 0005 adds append-only mutation audit metadata. Reads are principal-scoped,
while administrators can inspect all principals. Audit rows intentionally outlive the
built-in owned-data purge. They are append-only by repository/API convention, not a
cryptographically sealed or WORM-backed ledger; production deployments should export
them to an independently controlled audit system.

Audit export uses a dedicated streaming database session so it does not depend on
framework-specific request-dependency cleanup timing. A count is checked against the
configured hard cap before response creation, then a bounded oldest-first query emits
manifest/event/footer JSONL. An export-time SHA-256 chain links canonical event records.
The chain is portable integrity metadata, not proof that the source database was
complete and not a substitute for an external signed/WORM trust anchor.

## Analysis accuracy and provenance

Every derived result distinguishes:

- `verified`: directly parsed bytes/header/table information
- `heuristic`: bounded rule or metric
- `inferred`: reconstructed meaning such as pseudo-C/program stage
- `dynamic`: provider observation
- `user`: analyst annotation

Addresses remain integers in API/domain models and are formatted as `0x...` by the UI.
Decompiler output is explicitly estimated C-like code, never claimed as original source.

## Performance controls

Settings cap upload sizes, instructions, functions, CFG/call graph nodes, strings,
YARA matches, memory processes/modules/regions/network records/findings, dynamic events, job
concurrency, analysis/decompiler time, and external output. The API paginates
functions, hex, memory processes/modules/regions/network records, and dynamic events.
Large UI tables use windowed rendering.

## Technology decisions

- FastAPI/Pydantic preserve the existing API and OpenAPI surface.
- SQLAlchemy repositories are contract-tested against SQLite and PostgreSQL without
  binding services to either dialect.
- Capstone and LIEF remain the primary disassembly/parser dependencies.
- a simple DB-backed thread runner fits local deployment; distributed queues can be
  added behind the runner interface later.
- no graph/editor/state library was added. SVG layouts, hooks, and hash routing keep
  the production bundle small; current JS is about 71 KiB gzip.
- Vitest/Testing Library are development-only and do not enter the production bundle.

## Current extension seams

- `DecompilerAdapter`: Ghidra and built-in pseudo-C today.
- `SandboxProvider`: disabled and no-execution mock today.
- `VolatilityAdapter`: fixed plugin allowlist.
- integration adapters: radare2/Ghidra/Binary Ninja.
- repository interfaces: metadata storage and future migrations.
