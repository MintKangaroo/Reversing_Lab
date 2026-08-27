# Reversing Workbench Implementation Plan

This document records the repository audit performed before implementation. It is
intentionally evidence-based: “implemented” means a code path and test were found in
this repository, not merely that a dependency is listed or a roadmap mentions it.

## Phase 1 repository audit

Audit date: 2026-07-30

Baseline:

- Branch before work: `main`, clean and equal to `origin/main` at `d3227b3`.
- Work branch: `feature/reversing-workbench`.
- Backend: Python 3.10-compatible FastAPI application with Pydantic 2, SQLAlchemy 2,
  LIEF, Capstone, pyelftools, and pefile dependencies.
- Frontend: React 18 JavaScript SPA built by Vite 5; no router, query cache, global
  store, component-test runner, type checker, or linter is configured.
- Baseline verification: 57 backend tests passed with 92% statement coverage; the
  frontend production build passed.

### Existing module map

| Area | Existing implementation | Important constraints |
| --- | --- | --- |
| Parsing | Normalized frozen dataclasses; LIEF-backed ELF, PE, and thin Mach-O parsers | pyelftools and pefile are installed but not used as cross-check backends |
| Static content | ASCII/UTF-16LE strings, paged hex, Shannon entropy | Results are bounded, but strings use offset-only pagination |
| Disassembly | Capstone linear disassembly for x86, x86-64, ARM, ARM64, MIPS, PPC | No function recovery, xrefs, annotations, source lines, or semantic operands |
| Graphs | Intraprocedural CFG using leaders and direct branch targets | Tuple edges have no type; no dominators, loop metadata, call graph, or export |
| Packing | Weighted section name, entropy, imports, and W+X heuristics | Legacy score is an unbounded evidence sum and has no confidence/provenance model |
| External tools | radare2, Ghidra, Binary Ninja capability adapters | These are generic whole-binary integrations, not decompiler providers |
| Persistence | SQLite-ready SQLAlchemy models for binaries and challenge attempts | Tables are created with `create_all`; no migrations, projects, jobs, or artifacts |
| API | Upload/list/info/strings/hex/entropy/packing/disassembly/CFG/integrations/challenges | No jobs, functions, findings, annotations, reports, memory, dynamic, or tooling API |
| Frontend | Upload sidebar and tabbed static-analysis view; challenge catalog | Fixed two-column layout; no routing, resizable workbench, inspector, or console |
| Tests | Generated safe ELF/PE/Mach-O fixtures; parser/analyzer/API/CFG/challenge tests | No frontend tests, security regression suite, adapter mocks, or end-to-end workflow |

### Requested capability gap

| Capability | Status before this work | Planned implementation |
| --- | --- | --- |
| Content-addressed binary storage | Implemented | Preserve; harden streaming upload and identifier validation |
| Binary metadata and mitigations | Partial | Add compiler/build/timestamp, canary/CFG/signing/debug/stripped/TLS/overlay facts where verifiable |
| Function inventory/details/xrefs | Missing | Bounded static function discovery with provenance and persistent analyst overlays |
| Address-scoped disassembly | Partial | Preserve legacy endpoint; add function-scoped normalized endpoint and annotations |
| CFG | Partial | Add typed edges, loop/unreachable flags, bounds, and JSON/SVG export metadata |
| Call graph and flow summary | Missing | Static direct-call graph plus evidence-linked heuristic summary |
| Decompilation | Missing | Provider protocol, Ghidra capability adapter, safe fallback pseudo-C |
| Packing evidence | Partial | Add confidence, detected packer list, normalized evidence, and next steps without breaking legacy fields |
| Obfuscation findings | Missing | Bounded, evidence-based static heuristics with explicit false-positive caveats |
| Deobfuscation playground | Missing | Pure data transformations only; no uploaded-code execution |
| Memory analysis | Missing | Content-addressed dump storage, job framework, allowlisted Volatility adapter, safe basic/raw fallback |
| Dynamic analysis | Missing by design | Opt-in provider protocol; unavailable/disabled unless every guardrail is configured |
| Job queue/progress/cancel | Missing | Simple DB-backed runner with bounded concurrency and terminal cancellation |
| Projects/annotations/bookmarks | Missing | SQLAlchemy models and CRUD without changing existing binary identity |
| CTF workspace | Partial challenges only | Persistent notes, hypotheses, bookmarks, checklist, decoder playground, write-up export |
| Reports | Missing | JSON, Markdown, and safe self-contained HTML exports with limitations |
| Professional workbench UI | Missing | Dark app shell, project tree, analysis tabs, inspector, bottom activity panel, keyboard navigation |
| Tool status/graceful degradation | Partial | Unified tooling API covering decompilers, Volatility, UPX, and sandbox readiness |
| WebSocket/SSE progress | Missing | Bounded SSE job stream; polling remains available |

### Technical debt and security findings

1. `UploadFile.read()` reads an entire request into memory before enforcing
   `max_upload_bytes`. The replacement must stream into a private temporary file,
   stop at the configured limit, hash incrementally, and never use the client
   filename as a path.
2. Binary route identifiers are unconstrained strings. Storage currently remains safe
   because the database resolves the path, but strict 64-character lowercase SHA-256
   validation will make the contract and logs safer.
3. **Resolved in follow-up:** Alembic owns the baseline and project-ownership revision;
   the bootstrap refuses unknown unversioned schema drift.
4. External adapter subprocesses use fixed argument vectors and no shell, but timeout,
   output limits, sanitized environment, resource limits, audit records, and
   cancellation are not implemented uniformly.
5. Parsed objects are cached in process memory only. Large derived outputs have no
   artifact persistence or invalidation/version metadata.
6. The CFG boundary heuristic is intentionally small and can miss multi-return
   functions or include adjacent code. Every derived result must retain heuristic
   provenance and expose truncation.
7. Challenge submissions are stored verbatim. CTF notes are user-authored evidence,
   but candidate secrets should be clearly scoped and exportable/deletable; decoder
   inputs should not be persisted by default.
8. **Resolved at the application owner boundary:** optional API-key roles, binary
   grants, and owner-scoped resource repositories are implemented. OIDC, rate limiting,
   persistent audit events, and retention workflows remain required for a mature
   multi-tenant control plane.
9. There is no frontend lint, type-check, or test script. New UI code will avoid a
   broad TypeScript migration and introduce only the minimum test/tooling needed.
10. Python 3.10 is the current supported baseline despite the target preference for
    3.11+. Compatibility will be retained; CI should cover 3.10 and 3.11+ before the
    minimum version is raised.

## Architecture decisions

1. Preserve `parser.models` as the dependency-free binary vocabulary. Function,
   evidence, graph, decompiler, and finding models live in dedicated analysis modules
   rather than making the format parsers depend on higher layers.
2. Keep all legacy routes and response fields. New normalized fields and routes are
   additive, and legacy CFG/disassembly consumers continue to work.
3. Use a small DB-backed job runner before introducing a broker. Heavy result bodies
   are stored as content-addressed compressed JSON artifacts; SQL rows hold state and
   indexes.
4. Treat verified bytes, heuristic facts, inferred summaries, dynamic observations,
   and analyst annotations as different provenance kinds throughout the API and UI.
5. Never run an uploaded sample in the API process. The dynamic API is a guardrail
   gate over a provider interface, and its default provider is explicitly unavailable.
6. External binaries are resolved by configured/allowlisted executable paths and run
   with an argument vector, sanitized environment, timeout, output cap, and no shell.
7. Implement dependency-light UI primitives first. Graphs remain native SVG and
   resizable panels use browser pointer events, avoiding a heavy graph/layout package
   until graph scale demonstrates the need.

## Phased implementation and expected files

| Phase | Deliverable | Principal files |
| --- | --- | --- |
| 2 | Workbench shell, tokens, responsive/resizable panels, common states | `frontend/src/App.jsx`, `frontend/src/styles.css`, `frontend/src/components/common.jsx` |
| 3 | Function discovery, detail, xrefs, annotations, call graph | `analysis/functions.py`, `analysis/models.py`, binary/project routes, workbench components |
| 4 | Decompiler protocol, Ghidra provider, fallback pseudo-C, source map UI | `decompiler/`, schemas/routes/tests, code viewer |
| 5 | Evidence/finding engine, packer expansion, safe transforms, explicit UPX action | `analysis/findings.py`, `analyzer/packing.py`, `deobfuscation.py`, routes/tests |
| 6 | Typed CFG/call graph and evidence-linked flow summary | `analysis/graphs.py`, routes/tests, graph UI |
| 7 | Memory dump model/storage/jobs and allowlisted Volatility interface | `memory/`, jobs/models/routes/tests, memory UI |
| 8 | Sandbox provider contract, readiness gate, mock tests, event timeline | `dynamic/`, jobs/routes/tests, timeline UI |
| 9 | CTF workspace persistence, notes/bookmarks/checklist, decoder, exports | database/routes/schemas/tests, CTF components |
| 10 | Resource hardening, report exports, docs, CI, full regression verification | config/security/report modules, `.github/workflows`, `docs/`, README |

The implementation deliberately does not include automatic DRM bypass, arbitrary
Volatility plugins, arbitrary command execution, privileged containers, host mounts,
or automatic unpacking. UPX unpacking, when available, remains an explicit user
action and produces a separate immutable artifact.

## Completion record

Implementation completed on branch `feature/reversing-workbench` on 2026-07-30.
Phases 2–10 were delivered as separate functional commits. The initial local
verification before the follow-up hardening work was:

- backend: 98 tests passed; one upstream Starlette TestClient deprecation warning;
- frontend: 7 tests passed; Vite production build passed;
- dependency audit: zero npm vulnerabilities;
- Docker Compose configuration parsed successfully.

Subsequent hardening added Alembic revisions, optional API-key roles, project
ownership, and PostgreSQL 16 migration/repository contract CI. Remaining items are
recorded in [ROADMAP.md](ROADMAP.md), including production database operations, full
OIDC and external audit archival, RetDec/r2ghidra, richer memory normalization, and a
real VM-backed sandbox provider.

Follow-up verification on 2026-08-02: 104 backend tests and 10 frontend tests passed;
the Vite production build and high-severity npm audit also passed.

PostgreSQL follow-up on 2026-08-02: revision 0003 converted persisted sizes and virtual
addresses to portable 64-bit columns. A PostgreSQL 16 container passed fresh upgrade,
drift check, downgrade/re-upgrade, and high-address repository round-trip tests.

Resource-ownership follow-up on 2026-08-02: revision 0004 added content-addressed
binary grants and principal ownership for mutable investigation resources. SQLite and
PostgreSQL contracts cover legacy `local` backfill, cross-owner 404 responses,
per-principal filenames and overlays, and admin audit access.

Audit/retention follow-up on 2026-08-09: revision 0005 added request-correlated,
body-free mutation audit metadata and a principal-scoped audit API/UI. Retention now
supports preview, exact typed confirmation, active-job refusal, optional grant removal,
and reference-safe file reclamation under configured roots. Verification passed 117
default backend tests plus the PostgreSQL 16 contract, 15 frontend tests, production
build, Alembic drift/round-trip checks on both dialects, and a zero-vulnerability npm
audit.

Audit-export follow-up on 2026-08-09: a principal-scoped, bounded JSONL endpoint now
streams canonical oldest-first events with a manifest, completeness footer, and
export-time SHA-256 hash chain. UTC filters and a configurable preflight record cap
prevent unbounded downloads. The Settings UI can download the export, while the trust
model and external signed/WORM archival boundary are documented explicitly.
Verification passed 118 default backend tests plus the PostgreSQL 16 repository
contract, 16 frontend tests, the Vite production build, zero-vulnerability npm audit,
and focused Ruff checks for the new exporter/route/tests.

Memory-normalization follow-up on 2026-08-09: the fixed Volatility execution plan now
normalizes `windows.pslist.PsList`, `windows.dlllist.DllList`, and
`windows.vadinfo.VadInfo` independently. Bounded loaded-module and VAD records are
available through paginated APIs and dedicated workbench tabs. Writable-executable and
private executable unmapped regions produce evidence-linked heuristic findings with
false-positive caveats. Verification passed 123 default backend tests (plus one
PostgreSQL-only skip), 17 frontend tests, the Vite production build, zero-vulnerability
npm audit, and focused Ruff checks for the new adapter/models/tests.

Process-tree/network follow-up on 2026-08-09: the server-selected Volatility plan now
also normalizes nested `windows.pstree.PsTree` and `windows.netscan.NetScan` results.
Process ancestry, orphan context, network endpoints, provider provenance, exact large
offset display, bounded filters, and conservative public-endpoint/listener findings are
available through the API and workbench. Verification passed 124 default backend tests
(plus one PostgreSQL-only skip), 18 frontend tests, production build, zero-vulnerability
npm audit, and focused Ruff checks.

Region-inspection follow-up on 2026-08-09: analysts can explicitly extract one exact,
normalized Windows VAD through fixed `VadInfo` arguments after acknowledgement. Revision
0006 indexes owner-scoped, content-addressed region artifacts without storing bytes in
database rows. The workbench provides bounded paged hex, analyst-selected x86/x86-64
Capstone decoding, artifact download, provider/hash provenance, and execution caveats.
Path traversal, malformed selection, unavailable provider, integrity, migration, API,
and UI flows have dedicated safe-fixture tests.

Handle-normalization follow-up on 2026-08-12: the server-selected Volatility plan now
also normalizes bounded `windows.handles.Handles` output. The API and Memory workbench
expose PID/object-type/keyword filters over the stored result artifact, exact hex fields
for object offsets, handle values, and access masks, provider provenance, and explicit
stale/incomplete-evidence caveats. Plugin failure remains isolated from sibling results.
Focused verification passed eight backend Volatility/analyzer tests, direct persisted
artifact and OpenAPI contract checks, all 20 frontend tests, and the production build.

Process-context follow-up on 2026-08-12: fixed `windows.cmdline.CmdLine` output now
enriches bounded process records, while `windows.threads.Threads` produces a separately
bounded, filterable thread artifact with exact ETHREAD and start-address hex fields.
Kernel/Win32 starts inside an already suspicious VAD create a conservative correlation
finding with explicit JIT/stale-evidence caveats. Focused backend contracts, all 21
frontend tests, and the production build passed.
