# Threat Model

## Assets

- uploaded binary and memory-dump confidentiality/integrity;
- analyst annotations, CTF notes, reports, and project membership;
- API/worker availability;
- host filesystem, process namespace, credentials, and network;
- correctness/provenance of analysis conclusions.

## Trust boundaries

```text
untrusted browser/upload
        │
        ▼
TLS proxy / bearer auth / HTTP validation boundary
        │
        ▼
API + parser ── database/artifact storage
        │
        └── explicit adapter boundary ── isolated worker/VM
```

Uploads, archive-like bytes, filenames, addresses, query values, external-tool output,
and provider event streams are untrusted. Environment configuration and the database
are operator-controlled but still validated before sensitive use.

## Representative threats and mitigations

| Threat | Current mitigation | Residual risk |
|---|---|---|
| oversized upload / memory exhaustion | bounded chunk reader, separate limits | reverse proxy must also cap bodies |
| path traversal | hash-derived paths, filename basename, strict SHA ID | operator-tampered DB paths need monitoring |
| malformed parser input | format detection, typed errors, analysis bounds | native parser library bugs remain possible |
| command injection | fixed argv, no shell, allowlisted plugins | external tool vulnerabilities remain |
| decompression bomb | archive uploads unsupported | future archive support needs a dedicated extractor |
| unsafe sample execution | API has no execution path, disabled provider | custom provider security is operator responsibility |
| container escape | VM provider recommended; no Docker-only security claim | no production VM provider ships today |
| stored HTML injection | report escaping, React default escaping | Markdown consumers choose their own renderer policy |
| result spoofing | provenance/source provider fields | provider authenticity/signing not implemented |
| unauthenticated access | optional digest-backed bearer keys, fail-fast configuration | auth is disabled by default; TLS and proxy rate limiting are operator duties |
| cross-user project access | owner-scoped queries; admin audit role; 404 on mismatch | legacy unowned projects require admin handling |
| cross-user non-project data access | authenticated catalog boundary only | samples, dumps, runs, jobs, CTF state, and artifacts need owner scoping for multi-tenancy |
| resource starvation | bounded jobs/results, cancellation | in-process runner is not a hard CPU isolation boundary |

## Abuse cases explicitly rejected

The product does not implement credential collection, persistence deployment,
unauthorized remote execution, exploit delivery, DRM bypass automation, or arbitrary
server-side code execution for decoder loops.

## Assumptions

- users analyze only samples they own or are authorized to inspect;
- authenticated operators in one deployment are mutually trusted for shared catalogs;
- operators protect the host and external-tool installation;
- dynamic providers implement their advertised isolation outside the API process;
- generated findings are reviewed rather than treated as verdicts.
