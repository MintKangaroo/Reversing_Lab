# Security

## Safe deployment posture

Reversing Lab assumes every upload is hostile. Run it on a dedicated analysis network,
behind authentication added by the deployer, with least-privilege filesystem access.
The current application does not include authentication/RBAC and must not be exposed
directly to the public internet.

## Upload and storage controls

- binary and memory uploads stop reading as soon as their configured byte limit is
  exceeded and return HTTP 413;
- executable formats are magic-allowlisted before binary persistence;
- user filenames are sanitized basenames used only as display metadata;
- file paths are derived from server-computed SHA-256 values;
- malformed/non-lowercase SHA paths resolve to 404, never a filesystem lookup;
- archives are not accepted, avoiding zip-slip, nested archive, and decompression bomb
  paths.

## Parsing and analysis controls

Parsers wrap malformed library inputs in typed errors. Settings bound functions,
instructions, graph nodes, strings, events, output sizes, elapsed time, and concurrent
jobs. A clean heuristic result is not a safety verdict.

## External tools

Ghidra decompile, UPX unpack, and Volatility calls use fixed executable resolution and
argument vectors, `shell=False`, timeouts, private temporary directories, bounded
structured output, and sanitized environments. Volatility plugin names are chosen by
server code from an allowlist. UPX is explicit opt-in, never overwrites the original,
and records both hashes and size/section changes.

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
uses compressed artifacts. Logs should contain identifiers and state, not raw sample
contents or decoder input.

## Production hardening checklist

- add OIDC/session authentication and project-level authorization;
- terminate TLS at a trusted reverse proxy;
- use PostgreSQL with migrations and encrypted backups;
- isolate parser/external-tool workers with OS resource controls;
- keep storage non-executable and mount it `noexec,nodev,nosuid`;
- restrict outbound network and CORS origins;
- run API/UI as non-root users;
- ship audit logs to append-only storage;
- scan dependencies and container images in CI;
- rotate/delete samples according to legal retention requirements.

## Vulnerability reporting

Do not attach real malware or sensitive customer samples to a public issue. Report a
minimal reproduction and security impact through the repository owner's private
security contact/channel.
