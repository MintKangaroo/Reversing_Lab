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
│   └── projects / CTF / tooling / challenges
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
5. large results are gzip JSON artifacts, not one row per string/region.

### Dynamic analysis

1. readiness evaluates provider, worker, resource, timeout, network, workspace,
   sample-path, and acknowledgement guards.
2. failure of any guard blocks both UI and API.
3. a provider receives the validated content-addressed path and immutable policy.
4. provider output is bounded and stored as compressed events/artifact metadata.
5. the API never substitutes local subprocess execution.

## Data and persistence

SQLAlchemy models index projects, binaries, annotations, bookmarks, jobs, artifacts,
memory dumps, dynamic runs, and CTF state. Binary/dump/derived bytes use hashes as
filenames. High-volume events/results live in gzip JSON artifacts; SQL stores metadata
and references. SQLite is the supported development database. The repository pattern
avoids SQLite-only query constructs. Alembic owns the baseline schema; a conservative
bootstrap stamps an older `create_all` database only when every table and column
matches a known revision. Revision 0002 adds nullable project ownership and safely
upgrades the pre-ownership baseline. PostgreSQL deployment validation remains future
work.

When API-key authentication is active, projects are owner-scoped for non-admin
principals and admins can inspect all projects. The remaining resource repositories
are shared, so the auth layer is a coarse deployment control rather than a complete
multi-tenant boundary.

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
YARA matches, dynamic events, job concurrency, analysis/decompiler time, and external
output. The API paginates functions, hex, memory processes/regions, and dynamic events.
Large UI tables use windowed rendering.

## Technology decisions

- FastAPI/Pydantic preserve the existing API and OpenAPI surface.
- SQLAlchemy repositories support SQLite now without binding services to it.
- Capstone and LIEF remain the primary disassembly/parser dependencies.
- a simple DB-backed thread runner fits local deployment; distributed queues can be
  added behind the runner interface later.
- no graph/editor/state library was added. SVG layouts, hooks, and hash routing keep
  the production bundle small; current JS is about 69 KiB gzip.
- Vitest/Testing Library are development-only and do not enter the production bundle.

## Current extension seams

- `DecompilerAdapter`: Ghidra and built-in pseudo-C today.
- `SandboxProvider`: disabled and no-execution mock today.
- `VolatilityAdapter`: fixed plugin allowlist.
- integration adapters: radare2/Ghidra/Binary Ninja.
- repository interfaces: metadata storage and future migrations.
