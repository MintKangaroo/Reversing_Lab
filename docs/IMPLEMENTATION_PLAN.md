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
3. `Base.metadata.create_all()` has no migration history. The development database can
   be extended additively for now; an Alembic baseline is required before production
   rollout or destructive schema evolution.
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
8. CORS is development-oriented and there is no authentication/authorization model.
   Deployment documentation must keep the service local/private until an auth layer
   is added.
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
