# Roadmap

## Implemented

- dark resizable analysis shell and hash routing;
- normalized static parsing and function analysis;
- synchronized disassembly/pseudo-C, CFG, call graph, flow summary;
- evidence/provenance finding model, packing and obfuscation heuristics;
- safe UPX and data-only decoder tools;
- DB-backed jobs, memory triage, Volatility allowlist;
- disabled/mock dynamic provider and readiness UI;
- persistent CTF workspace and report export;
- Alembic baseline with conservative legacy SQLite bootstrap;
- optional digest-backed bearer authentication, coarse roles, project ownership migration;
- backend/frontend/security regression tests, CI, development containers.

## Near term

1. PostgreSQL migration CI and subsequent revision upgrade/downgrade fixtures.
2. OIDC/short-lived credentials, ownership for every resource, audit-event persistence,
   retention/deletion API, and server-side rate limiting.
3. RetDec and r2ghidra adapters with the same process hardening contract.
4. richer PE/ELF mitigation metadata: canary, CFG, signing, debug/build ID, TLS, overlay.
5. paginated artifact download and explicit report association for memory/dynamic runs.
6. function-list windowing (the common table already has windowed rendering).
7. source-line mapping and improved ARM/AArch64/MIPS CFG recovery.

## Medium term

- out-of-process parser/external-tool workers;
- VM sandbox provider reference implementation with authenticated worker protocol;
- Volatility modules, trees, DLLs, regions, handles, network, registry, and YARA models;
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
