# Decompilation

## Accuracy statement

Decompiler output is estimated C-like code. It is not the original source and can have
incorrect types, variables, control structures, and function boundaries. UI, API, and
reports attach provider, confidence, provenance, warnings, and address source maps.

## Adapter interface

`DecompilerAdapter` exposes:

```python
name: str
is_available() -> bool
decompile_function(binary_path, address, options) -> DecompiledFunction
```

`DecompiledFunction` includes address/name/language/code/warnings/confidence, variables,
parameters, return type, source map, provider, elapsed time, and provenance.

## Providers

1. Ghidra headless: configure `GHIDRA_HOME`; uses a private project, fixed Java script,
   fixed argv, timeout, no shell, bounded JSON output, and deletes the temporary project.
2. built-in pseudo-C: always available and intentionally conservative.

RetDec and radare2/r2ghidra adapters are planned but not implemented.

## Fallback behavior

`provider=auto` tries Ghidra only when available and falls back to pseudo-C without
failing the whole API. The fallback recognizes direct calls, returns, conditional
branches, simple loop candidates, stack locals/immediates, and some global/indirect
access patterns. It uses neutral names and does not assert unsupported types.

## Endpoint

```text
GET /api/binaries/{sha}/functions/{address}/decompile?provider=auto|ghidra|pseudo_c
```

Addresses accept decimal or strict `0x` syntax and remain integers in the response's
source map.
