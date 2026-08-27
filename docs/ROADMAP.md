# Roadmap

## Implemented

- dark resizable analysis shell and hash routing;
- normalized static parsing and function analysis;
- richer PE/ELF/Mach-O mitigation & provenance metadata (stack canary, Control Flow
  Guard/CET, code signing, debug info, build ID/UUID, TLS callbacks/PT_TLS, overlay),
  tri-state where a mitigation is not applicable to the format;
- synchronized disassembly/pseudo-C, CFG, call graph, flow summary;
- windowed function inventory (reuses the common virtualized table for interactive,
  selectable rows) that stays responsive at the 5k-function cap;
- evidence/provenance finding model, packing and obfuscation heuristics;
- safe UPX and data-only decoder tools;
- DB-backed jobs, memory triage, Volatility allowlist, normalized process tree/command
  line/thread/DLL/handle/VAD/network records, evidenced review findings, and explicit bounded VAD hex/disassembly
  artifacts;
- disabled/mock dynamic provider and readiness UI;
- persistent CTF workspace and report export;
- Alembic baseline with conservative legacy SQLite bootstrap;
- PostgreSQL 16 migration round-trip CI and 64-bit repository contract tests;
- optional digest-backed bearer authentication, coarse roles, full resource ownership
  migration, and content-addressed binary access grants;
- body-free append-only mutation audit events, request correlation, principal-scoped
  audit UI, bounded hash-chained JSONL export, and dry-run-first owned-data retention
  with reference-safe file reclaim;
- backend/frontend/security regression tests, CI, development containers.

## Near term

1. PostgreSQL backup/restore rehearsal, TLS deployment guide, concurrency/load testing,
   and production observability.
2. OIDC/short-lived credentials, centralized revocation, server-side rate limiting,
   and a managed provider that anchors exports in signed/WORM-backed storage with an
   archival policy.
3. RetDec and r2ghidra adapters with the same process hardening contract.
4. paginated artifact download and explicit report association for memory/dynamic runs.
5. source-line mapping and improved ARM/AArch64/MIPS CFG recovery.

## Medium term

- out-of-process parser/external-tool workers;
- VM sandbox provider reference implementation with authenticated worker protocol;
- Volatility registry, YARA, and additional OS/architecture region providers;
- YARA/FLOSS/capa adapters and normalized provenance;
- detector plugin registry and curated fixture corpus;
- scalable PostgreSQL job claiming and optional Celery/RQ adapter;
- report templates, signing, and PDF handled by a separate safe renderer.

## Explicitly not planned

- API-process binary execution;
- arbitrary server-side decoder/code execution;
- automatic unpacking of unknown protectors;
- credential theft, persistence deployment, exploit delivery, or unauthorized access;
- claims that pseudo-C is the original source or Docker alone is strong malware isolation.
