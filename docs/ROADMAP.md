# Roadmap

## Implemented

- dark resizable analysis shell and hash routing;
- normalized static parsing and function analysis;
- richer PE/ELF/Mach-O mitigation & provenance metadata (stack canary, Control Flow
  Guard/CET, code signing, debug info, build ID/UUID, TLS callbacks/PT_TLS, overlay),
  tri-state where a mitigation is not applicable to the format;
- synchronized disassembly/pseudo-C, CFG, call graph, flow summary;
- r2ghidra and RetDec decompiler adapters reusing the Ghidra process-hardening contract
  (fixed argv, minimal env, timeout, output cap, graceful degradation to pseudo-C);
  both live-verified end-to-end against real installs (radare2 6.2.0 + r2ghidra plugin,
  RetDec v5.0), each emitting a per-line source map for decompiled-line-to-address sync;
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
- opt-in per-principal server-side rate limiting (in-process fixed window, 429 +
  Retry-After);
- paginated memory region-artifact listing (offset/limit/total page envelope);
- body-free append-only mutation audit events, request correlation, principal-scoped
  audit UI, bounded hash-chained JSONL export, and dry-run-first owned-data retention
  with reference-safe file reclaim;
- backend/frontend/security regression tests, CI, development containers.

## Near term

1. production observability is in place — request correlation (`X-Request-ID`
   reused/minted, threaded through logs and audit rows), structured text/JSON logging
   with a per-request access line, a database-backed `/health/ready` readiness probe, a
   Prometheus `/metrics` endpoint (request counts + latency by route/status, job
   gauges), and a bounded read-only load-testing harness
   ([OBSERVABILITY.md](OBSERVABILITY.md)). TLS deployment guide and PostgreSQL
   backup/restore rehearsal are documented in [OPERATIONS.md](OPERATIONS.md). Remaining
   ops work is concurrency/scale tuning driven by these signals.
2. OIDC/short-lived credentials, centralized revocation,
   and a managed provider that anchors exports in signed/WORM-backed storage with an
   archival policy.
3. explicit report association for dynamic runs now lands in the Reports workspace
   (a sample's runs are listed with per-run report export); memory-dump reports export
   from the Memory workspace since dumps are standalone uploads, not binary-scoped.
4. ARM/AArch64/MIPS control-flow recovery now classifies branches
   architecture-neutrally: direct targets are read in each architecture's operand
   syntax (`#0x..`, last-operand for `cbz`/`beq`), calls that Capstone also tags as
   jumps (`bl`/`blr`) no longer produce branch edges, and return idioms outside the
   `return` group (`bx lr`, `jr $ra`) and MIPS `jal`/`bal` calls are recognized by
   mnemonic (source-line mapping already lands via the decompiler adapters). Remaining:
   apply the same normalization to the function-inventory/call-graph pass
   (`analysis/functions.py` still parses the first operand and misses MIPS `jal`
   targets), and precise MIPS branch-delay-slot attribution.

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
