# Memory Analysis

Memory analysis treats every dump and provider response as hostile data. The API never
executes bytes from a dump. Basic triage works without external tools; compatible
Windows full dumps can additionally use a fixed Volatility 3 execution plan.

## Supported inputs

- Windows full-dump signature recognition and optional Volatility 3 extraction;
- Windows minidump metadata recognition;
- Linux ELF core-dump metadata recognition;
- process dump and raw memory-region data-only triage.

Basic triage extracts bounded strings, URLs, IPv4 addresses, domains, and
secret-material markers. A secret-like marker is labelled `possible secret material`,
not asserted to be a valid or recoverable credential.

## Quick workflow

1. Open **Memory** and upload a dump you are authorized to inspect.
2. Keep **Use allowlisted Volatility plugins** enabled only when Volatility is
   available and the input is a compatible Windows full dump.
3. Start analysis and monitor the bounded background job.
4. Review **Processes**, **Modules**, **Regions**, and **Findings**. Provider warnings
   show partial plugin failures without hiding successful results.

Equivalent API flow:

```text
POST /api/memory-dumps                         multipart file
POST /api/memory-dumps/{id}/analysis           {"use_volatility": true}
GET  /api/jobs/{job_id}                        poll state/progress
GET  /api/memory-dumps/{id}/analysis           summary
GET  /api/memory-dumps/{id}/processes          paginated
GET  /api/memory-dumps/{id}/modules            paginated
GET  /api/memory-dumps/{id}/regions            paginated
GET  /api/memory-dumps/{id}/findings
```

Results are compressed JSON artifacts rather than one database row per string, module,
or region. Existing artifacts without a `modules` collection remain readable and
report a module count of zero.

Addresses remain integers in the normalized artifact and API contract. Module and
region responses additionally expose server-generated `base_address_hex`, `start_hex`,
and `end_hex` fields so browser clients preserve exact 64-bit display values.

## Volatility 3 contract

Install Volatility 3 separately and point the application at its executable:

```bash
export RLAB_VOLATILITY_PATH=vol
vol --help
```

The server, not the API caller, selects plugins. Current normalized execution uses:

| Plugin | Normalized output | Failure behavior |
|---|---|---|
| `windows.pslist.PsList` | PID, PPID, name, thread count | process capability remains unavailable |
| `windows.dlllist.DllList` | PID, base, size, name, path, load time | module capability remains unavailable |
| `windows.vadinfo.VadInfo` | PID, range, protection, private flag, mapping, tag | memory map remains unavailable |

Each plugin runs separately. Missing symbols or a malformed result from one plugin is
recorded as a provider warning and does not discard successful sibling plugin output.
API users cannot submit plugin names or raw CLI arguments.

Calls use a fixed argument vector, `shell=False`, a sanitized environment, a timeout,
private temporary stdout/stderr files, and an external-output size cap. Normalized
collections have independent limits:

```env
RLAB_MAX_MEMORY_DUMP_BYTES=536870912
RLAB_MAX_MEMORY_PROCESSES=10000
RLAB_MAX_MEMORY_MODULES=50000
RLAB_MAX_MEMORY_REGIONS=100000
RLAB_MAX_MEMORY_FINDINGS=1000
RLAB_MAX_EXTERNAL_OUTPUT_BYTES=2097152
```

## Region findings

The VAD normalizer marks two review signals:

- writable and executable protection, such as `PAGE_EXECUTE_READWRITE`;
- private executable memory with no mapped file.

These are heuristics, not proof of injection. JIT runtimes, unpackers, instrumentation,
compatibility layers, and legitimate runtime loaders can create similar mappings. Each
finding includes PID/process context, range, protection, mapping state, provider,
confidence, and a false-positive caveat. Correlate it with region bytes and dynamic
observations before escalating.

## Known limitations

- Minidumps currently receive metadata/basic triage, not the full Windows plugin plan.
- Process command lines, thread details, process tree, handles, registry, network,
  YARA, region byte export, and region disassembly are not yet normalized.
- Volatility output is provider-supplied evidence. Bounds prevent unbounded storage but
  cannot make a compromised external tool truthful.
- The current in-process job runner is cancellation-aware between application steps,
  but it is not a hard CPU or memory isolation boundary for an external tool.

Memory dumps can contain credentials, keys, personal data, and proprietary code. Use
owner-scoped authentication, encrypted storage/backups, short retention, and secure
deletion in production. Never upload a customer dump to a public deployment.
