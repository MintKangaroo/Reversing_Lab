# Reversing Lab — Architecture

A web platform for learning reverse engineering. Users upload binaries (ELF / PE /
Mach-O), inspect their structure at every level (headers, sections, symbols,
imports/exports, strings, hex, disassembly, control-flow graph), and solve hands-on
challenges (hidden strings, XOR, Base64, CrackMe, packing detection, malware triage).

## 1. Goals & non-goals

**Goals**
- Correct, format-aware static analysis of the three mainstream executable formats.
- A clean HTTP API that the React front-end (or any client) can consume.
- Production-grade code: typed, tested, logged, with explicit error handling.
- Extensible challenge framework with server-side answer verification.
- Optional integration with external RE tooling (radare2, Ghidra, Binary Ninja)
  that degrades gracefully when the tool is not installed.

**Non-goals**
- Dynamic analysis / sandboxed execution of samples (static only, by design — the
  platform never executes uploaded binaries).
- A full decompiler. Disassembly + CFG only; decompilation is delegated to
  integrations where available.

## 2. High-level module map

```
backend/reversing_lab/
├── config.py            # Settings (pydantic), single source of runtime config
├── logging_config.py    # Structured logging setup
├── errors.py            # Domain exception hierarchy
├── parser/              # Binary format → normalized model
│   ├── models.py        # Frozen dataclasses: BinaryInfo, Section, Symbol, ...
│   ├── base.py          # AbstractBinaryParser
│   ├── detect.py        # Magic-byte format detection
│   ├── factory.py       # Format → parser resolution
│   ├── elf_parser.py    # LIEF-backed ELF parser
│   ├── pe_parser.py     # LIEF-backed PE parser
│   └── macho_parser.py  # LIEF-backed Mach-O parser
├── analyzer/            # Format-agnostic content analysis
│   ├── strings.py       # ASCII/UTF-16 string extraction
│   ├── hexdump.py       # Paged hex viewer
│   ├── entropy.py       # Shannon entropy (whole-file + windowed)
│   └── packing.py       # Packer / obfuscation heuristics
├── disassembler/
│   ├── disassembler.py  # Capstone wrapper, arch/mode resolution
│   └── cfg.py           # Basic-block + control-flow-graph builder
├── challenge/
│   ├── models.py        # Challenge, ChallengeResult
│   ├── base.py          # AbstractChallenge (generate + verify)
│   ├── registry.py      # Name → challenge class
│   └── generators/      # One module per challenge type
├── integrations/        # External tool adapters (radare2 / ghidra / binja)
├── database/            # SQLAlchemy models, session, repositories
└── api/                 # FastAPI app, routers, schemas, DI
```

The dependency direction is strictly one-way:

```
api  ─▶  challenge / analyzer / disassembler / parser / integrations  ─▶  parser.models
 │                                                          
 └────────────────────▶  database
```

`parser.models` is the shared, dependency-free vocabulary. Nothing in `parser`
imports from `analyzer`, `disassembler`, or `api` — this keeps the analysis core
usable as a plain library, independent of the web layer (Dependency Inversion).

## 3. Data flow

1. **Upload** — client `POST`s bytes to `/api/binaries`. The API computes a SHA-256
   digest (the binary's identity), persists metadata + bytes via the repository, and
   returns a `binary_id`.
2. **Detect & parse** — on first inspection, `detect.py` reads the magic bytes,
   `factory.py` selects a parser, and the parser produces a normalized `BinaryInfo`.
   Parsers never trust the input: malformed structures raise `ParseError`, never crash.
3. **Analyze on demand** — each view (`/sections`, `/strings`, `/hex`,
   `/disassembly`, `/cfg`, ...) is a separate endpoint so the front-end fetches only
   what a tab needs. Expensive results (parse tree, disassembly) are cached per binary.
4. **Challenges** — `/api/challenges` lists generated challenges; a challenge bundles
   a downloadable artifact and a server-side verifier. Answers are checked on the
   server (`POST /api/challenges/{id}/submit`); the solution never leaves the server.

## 4. Key design decisions

| Decision | Rationale |
|----------|-----------|
| LIEF as the primary parser backend | One API across ELF/PE/Mach-O, robust against malformed files, actively maintained. `pyelftools`/`pefile` are available for format-specific cross-checks and are listed as required deps per spec. |
| Normalized `parser.models` dataclasses | Decouples every consumer from library-specific types; the API schema maps 1:1 to these, and swapping a backend never ripples outward. |
| On-demand, per-view endpoints | A 50 MB binary should not force a multi-megabyte JSON response; each tab pulls its own slice with pagination. |
| Never execute uploaded binaries | The platform is static-only. Uploaded bytes are treated as hostile data, never as code. |
| Integrations behind a capability check | radare2/Ghidra/Binary Ninja are optional; adapters report `available=False` instead of failing the request when a tool is absent. |
| Server-side challenge verification | Prevents trivially reading the answer from client code; supports hashed or exact-match verifiers. |

## 5. Security posture

- Uploaded binaries are **never executed**. All analysis is static.
- Upload size is capped (`MAX_UPLOAD_BYTES`) and the format allow-list is enforced
  before any heavy parsing.
- Disassembly and CFG construction are bounded (instruction/among-block caps) to
  prevent CPU/memory exhaustion on adversarial inputs.
- External-tool integrations run tools with fixed argument lists and timeouts; no
  shell string interpolation of user input.
- All parsing runs inside try/except that converts library faults into typed
  `ParseError`s — a malformed sample degrades the response, it never takes down the API.

## 6. Testing strategy

- **Unit** tests per module against small, checked-in fixture binaries generated at
  test time (see `tests/fixtures`), plus synthetic byte buffers for analyzers.
- **Contract** tests for the API via FastAPI's `TestClient`.
- **Challenge** round-trip tests: generate → solve programmatically → verify accepts
  the intended answer and rejects wrong ones.
