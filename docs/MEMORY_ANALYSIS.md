# Memory Analysis

## Supported inputs

- Windows dump signature recognition and optional Volatility 3 process extraction;
- Linux ELF core-dump metadata recognition;
- process dump / raw memory region basic triage.

Basic triage never executes data. It extracts bounded strings, URLs, IPv4 addresses,
domains, and possible secret-material markers. Secret-like material is labelled
`possible secret material`, not asserted as a recovered key.

## Workflow

1. `POST /api/memory-dumps` with multipart `file`.
2. `POST /api/memory-dumps/{id}/analysis` with `use_volatility`.
3. poll `GET /api/jobs/{job_id}` or use the jobs SSE endpoint.
4. read summary, processes, regions, and findings endpoints.

Uploads have a dedicated `RLAB_MAX_MEMORY_DUMP_BYTES` bound. Results are compressed JSON
artifacts rather than one SQL row per string or region.

## Volatility 3

Set `RLAB_VOLATILITY_PATH=vol`. Only server-selected plugins in
`memory/volatility.py::ALLOWED_PLUGINS` can run. API users cannot submit plugin names or
CLI arguments. Calls use a fixed argv, no shell, timeout, output limit, and temporary
stdout/stderr files.

Current normalized extraction uses `windows.pslist.PsList`. The allowlist also records
future-safe candidates, but DLL, tree, network, handle, registry, YARA, region dump, and
region disassembly normalization are not complete.

## Safety

Memory dumps can contain credentials, keys, personal data, and proprietary code. Apply
access controls, encrypted storage/backups, short retention, and secure deletion in
production. Do not upload customer dumps to a public deployment.
