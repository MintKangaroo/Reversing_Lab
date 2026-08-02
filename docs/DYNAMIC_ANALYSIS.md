# Dynamic Analysis

## Current status

Dynamic analysis is opt-in and disabled by default. The shipped `disabled` provider
cannot execute. The shipped `mock` provider validates orchestration and emits one
`mock_no_execution` control event without executing bytes. A real sandbox worker is not
included.

## Readiness gate

All checks must pass:

1. provider configured;
2. isolated worker available;
3. CPU, memory, and process limits configured;
4. timeout configured;
5. network policy configured;
6. private writable workspace configured;
7. content-addressed sample path validated;
8. analyst acknowledgement completed.

The UI button and `POST /api/dynamic-analysis` are both denied when readiness is false.

## Required provider policy

`SandboxPolicy` communicates blocked/default network, CPU, memory, timeout, process
count, read-only base, temporary overlay, no host mounts, no Docker socket, no
privileged mode, no host PID/network namespace, and destruction after analysis.

Provider implementations must run out of process. For real malware use a disposable
VM, a separately managed network segment, a clean snapshot, authenticated control
channel, and artifact-only return. Do not interpret this repository's development
Docker files as a sandbox.

## Provider contract

Implement `SandboxProvider.readiness()` and `SandboxProvider.analyze()`. `analyze`
receives a validated server path, immutable policy, and cancellable job context. It
returns normalized `DynamicResult` events/artifacts and explicitly lists unsupported
event families.

Never accept arbitrary command lines, image names, mounts, or provider arguments from
an API request. Provider selection and templates belong to trusted server configuration.

## Event and retention model

Normalized events include timestamp, process/thread identifiers, category, operation,
target, result, argument summary, optional call stack, severity, and source provider.
Events are capped and stored as gzip JSON artifacts; SQL stores the run/job/result
index. API queries paginate and filter by category, severity, process, and keyword.

## Configuration example

For control-plane tests only:

```bash
export RLAB_SANDBOX_PROVIDER=mock
export RLAB_SANDBOX_WORKSPACE_DIR=/private/rlab-sandbox-work
export RLAB_SANDBOX_NETWORK_POLICY=blocked
```

The directory must exist. This does not turn the mock provider into an execution
sandbox.
