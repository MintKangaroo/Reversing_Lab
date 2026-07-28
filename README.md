<div align="center">

# 🔬 Reversing Lab

**A web platform for learning reverse engineering.**
Upload a binary, inspect it at every level — headers, sections, symbols, imports/exports,
strings, hex, disassembly, control-flow graph — and sharpen your skills on hands-on
challenges.

Supports **ELF**, **PE**, and **Mach-O**. Built with a typed, tested Python analysis
core (Capstone · LIEF · pyelftools · pefile) behind a FastAPI service, with a React
front-end.

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![Tests](https://img.shields.io/badge/tests-57%20passing-3fb950)
![Coverage](https://img.shields.io/badge/coverage-92%25-3fb950)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## Table of contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [API reference](#api-reference)
- [Challenges](#challenges)
- [External tool integrations](#external-tool-integrations)
- [Testing](#testing)
- [Security posture](#security-posture)
- [Limitations & roadmap](#limitations--roadmap)
- [License](#license)

---

## Screenshots

### Binary overview — format, architecture, security mitigations
The overview surfaces the header essentials and mitigation flags (PIE/ASLR, NX, RELRO)
at a glance, plus format-specific metadata.

![Overview](docs/screenshots/02-overview.png)

### Sections & symbols
Per-section virtual address, size, file offset, **entropy**, and read/write/exec flags —
and the full symbol table with type, binding, and import/export scope.

![Sections](docs/screenshots/03-sections.png)
![Symbols](docs/screenshots/04-symbols.png)

### Imports & strings
Imported symbols with library attribution, and ASCII/UTF-16LE string extraction with
file offsets and encodings.

![Imports](docs/screenshots/05-imports.png)
![Strings](docs/screenshots/06-strings.png)

### Hex viewer
A paged `offset | hex | ascii` dump that streams one page at a time, so multi-megabyte
files never have to be transferred whole.

![Hex viewer](docs/screenshots/07-hex.png)

### Disassembly
Capstone-powered linear disassembly with syntax highlighting; control-flow instructions
(`jmp`, `je`, `call`, `ret`) are colored so branches stand out.

![Disassembly](docs/screenshots/08-disassembly.png)

### Control-flow graph
Basic blocks recovered with the classic leader algorithm and laid out as an interactive
SVG — **green** edges for taken branches, **yellow** for fall-through.

![Control flow graph](docs/screenshots/09-cfg.png)

### Packing detection
Weighted heuristics (known packer section names, high-entropy executable sections, a
small import table, W+X sections) produce an explained verdict and a per-window entropy
profile. Below: a clean binary vs. a UPX-style packed sample.

![Packing — clean](docs/screenshots/10-packing.png)
![Packing — detected](docs/screenshots/14-packing-detected.png)

### External tool integrations
radare2, Ghidra, and Binary Ninja adapters report availability and run on demand —
degrading gracefully when a tool isn't installed.

![Integrations](docs/screenshots/11-integrations.png)

### Challenges
Six hands-on challenges with difficulty badges, downloadable **real binary** artifacts,
hints, and server-side answer verification.

![Challenges](docs/screenshots/12-challenges.png)
![Challenge solved](docs/screenshots/13-challenge-solved.png)

---

## Features

### Supported formats
| Format | Backend | Notes |
|--------|---------|-------|
| **ELF** | LIEF | Executables & shared objects; RELRO detected via `GNU_RELRO` segment |
| **PE** | LIEF | PE32 / PE32+; DLL characteristics → PIE/NX; import & export tables |
| **Mach-O** | LIEF | Thin single-arch executables & dylibs |

### Analysis views
`Header` · `Sections` · `Symbols` · `Imports` · `Exports` · `Strings` · `Hex Viewer`
· `Disassembly` · `Control Flow Graph` · `Packing Detection`

### Challenge types
`Hidden String` · `XOR` · `Base64` · `CrackMe` · `Packing Detection` · `Malware Triage`

### Under the hood
- **Normalized model.** Every parser emits the same frozen dataclasses
  (`BinaryInfo`, `Section`, `Symbol`, …), so nothing downstream depends on a specific
  parsing library.
- **Bounded everywhere.** Upload size, instruction counts, string counts, and CFG size
  are all capped to keep adversarial inputs from exhausting resources.
- **Static only.** Uploaded binaries are **never executed** — they are treated as hostile
  data from the moment they arrive.

---

## Architecture

The backend is a plain, framework-agnostic analysis library with a thin FastAPI layer on
top. Dependencies point in one direction only, toward a dependency-free vocabulary of
data models:

```
 React UI  ──HTTP──▶  FastAPI (api/)
                          │
        ┌─────────────────┼──────────────────┬───────────────┐
        ▼                 ▼                  ▼               ▼
     parser/          analyzer/        disassembler/     challenge/      integrations/
   (LIEF-backed)   (strings, hex,     (Capstone +        (6 generators,  (radare2, ghidra,
        │           entropy, packing)   CFG builder)      verifier)       binary ninja)
        ▼
   parser/models.py  ◀── shared, dependency-free dataclasses ──▶  api/schemas.py
        │
        ▼
     database/  (SQLAlchemy models · repositories · session)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, data flow, and the
rationale behind each key decision.

---

## Project structure

```
reversing_lab/
├── backend/
│   ├── reversing_lab/
│   │   ├── config.py            # pydantic settings (env-overridable)
│   │   ├── logging_config.py    # centralized logging
│   │   ├── errors.py            # domain exception hierarchy
│   │   ├── parser/              # ELF/PE/Mach-O → normalized BinaryInfo
│   │   ├── analyzer/            # strings, hexdump, entropy, packing
│   │   ├── disassembler/        # Capstone wrapper + CFG builder
│   │   ├── challenge/           # framework + 6 generators + registry
│   │   ├── integrations/        # radare2 / ghidra / binary ninja adapters
│   │   ├── database/            # SQLAlchemy models, session, repositories
│   │   └── api/                 # FastAPI app, routers, schemas, DI
│   ├── tests/                   # 57 tests, ~92% coverage
│   ├── pyproject.toml
│   └── requirements.txt
├── frontend/                    # React + Vite single-page app
│   └── src/{api.js, App.jsx, components/}
└── docs/
    ├── ARCHITECTURE.md
    └── screenshots/
```

---

## Getting started

### Prerequisites
- Python **3.10+**
- Node **18+** (for the front-end)

### 1 · Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Run the API (creates ./reversing_lab.db and ./data/binaries on first start)
uvicorn reversing_lab.api.app:app --reload --port 8000
```

Interactive API docs are then served at **http://localhost:8000/docs**.

Configuration is via `RLAB_`-prefixed environment variables (see
[`config.py`](backend/reversing_lab/config.py)), for example:

```bash
export RLAB_MAX_UPLOAD_BYTES=67108864      # 64 MiB upload cap
export RLAB_DATABASE_URL="sqlite:///./rlab.db"
export RLAB_CORS_ORIGINS='["http://localhost:5173"]'
```

### 2 · Frontend

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173  (proxies /api → http://127.0.0.1:8000)
```

Point the dev proxy at a different backend with `VITE_API_TARGET=http://host:port npm run dev`.

Build for production with `npm run build` (emits static assets to `frontend/dist/`).

---

## API reference

All endpoints are under `/api`. Binaries are identified by their **SHA-256**.

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Liveness + version |
| `POST` | `/binaries` | Upload a binary (multipart `file`); returns its `sha256` |
| `GET`  | `/binaries` | List uploaded binaries |
| `GET`  | `/binaries/{sha}/info` | Header, sections, symbols, imports, exports |
| `GET`  | `/binaries/{sha}/strings?min_length=&limit=` | Extracted strings |
| `GET`  | `/binaries/{sha}/hex?offset=&length=` | Paged hex dump |
| `GET`  | `/binaries/{sha}/entropy?window=` | Whole-file + windowed entropy |
| `GET`  | `/binaries/{sha}/packing` | Packing verdict with rationale |
| `GET`  | `/binaries/{sha}/disassembly?address=&count=` | Linear disassembly |
| `GET`  | `/binaries/{sha}/cfg?address=` | Control-flow graph |
| `POST` | `/binaries/{sha}/integrations/{name}` | Run an external tool |
| `GET`  | `/integrations` | Availability of radare2 / Ghidra / Binary Ninja |
| `GET`  | `/challenges` | List challenges (metadata only) |
| `GET`  | `/challenges/{slug}/artifact` | Download a challenge's binary |
| `POST` | `/challenges/{slug}/submit` | Verify an answer (`{"answer": "RLAB{...}"}`) |

Domain errors map to precise status codes: `415` unsupported format, `404` not found,
`422` parse/disassembly failure, `503` integration unavailable.

Example:

```bash
# Upload and inspect
SHA=$(curl -s -F file=@/bin/ls http://localhost:8000/api/binaries | jq -r .sha256)
curl -s http://localhost:8000/api/binaries/$SHA/info | jq '{format:.binary_format, arch:.architecture, sections:(.sections|length)}'
curl -s "http://localhost:8000/api/binaries/$SHA/packing" | jq '{packed:.likely_packed, score, packer:.detected_packer}'
```

---

## Challenges

Every challenge ships a **real ELF binary** you analyze with the very same tools the
platform provides, and every answer is a flag of the form `RLAB{...}`, verified on the
server with a constant-time comparison (the solution never reaches the client).

| Slug | Title | Difficulty | Skill exercised |
|------|-------|-----------|-----------------|
| `hidden-string` | Hidden String | easy | Strings / Hex |
| `xor-decode` | XOR Decode | easy | Single-byte XOR |
| `base64-decode` | Base64 Decode | easy | Strings + Base64 |
| `crackme-disasm` | CrackMe | medium | Disassembly reading |
| `packing-detection` | Packing Detection | medium | Entropy & sections |
| `malware-triage` | Malware Analysis | hard | Strings + Base64 + XOR (layered IOC recovery) |

> The malware-triage sample is deliberately **benign and non-executable** — it only
> *contains* indicators and an encoded C2 config. All analysis is static.

---

## External tool integrations

The three integrations are optional and detected at runtime; the API reports each one's
availability and only runs a tool that is present.

| Tool | Enabled when | What it returns |
|------|--------------|-----------------|
| **radare2** | `r2` is on `PATH` | Function list from `aa; aflj` |
| **Ghidra** | `GHIDRA_HOME` points at an install | Headless auto-analysis summary |
| **Binary Ninja** | the licensed `binaryninja` module imports | Recovered function names |

Integrations shell out with **fixed argument vectors** (never `shell=True`) and a bounded
timeout, operating only on the server-controlled, content-hash file path.

---

## Testing

```bash
cd backend
pytest                      # 57 tests
pytest --cov=reversing_lab  # with coverage (~92%)
```

The suite synthesizes minimal, valid ELF/PE/Mach-O fixtures at test time (no opaque blobs
checked in), exercises every analyzer and the disassembler/CFG, round-trips all six
challenges (generate → solve programmatically → verify accepts the intended answer and
rejects wrong ones), and contract-tests the API through FastAPI's `TestClient`.

---

## Security posture

- **Never executes** uploaded binaries — static analysis only.
- **Upload size** capped (`RLAB_MAX_UPLOAD_BYTES`) and **format allow-listed** before any
  heavy parsing.
- **Bounded analysis:** disassembly, CFG, string, and hex operations all have hard limits.
- **No path traversal:** stored files are named by content hash; user input never reaches
  a filesystem path.
- **Robust parsing:** library faults are converted to typed `ParseError`s — a malformed
  sample degrades the response, it never crashes the service.
- **Challenge answers** are verified server-side with `hmac.compare_digest` and are never
  serialized to clients.

> **Dev-server note:** the front-end's Vite 5 toolchain pulls in an esbuild advisory that
> affects only the local dev server, not the production `dist/` build. Upgrading to Vite 8
> is a breaking change and intentionally deferred.

---

## Limitations & roadmap

- Disassembly/CFG are strongest on **x86/x86-64**; ARM/MIPS/PPC decode but the CFG
  function-extent heuristic is tuned for x86.
- CFG recovery is intraprocedural and follows **direct** branches; indirect jumps are
  recorded as terminators without a static target.
- Mach-O **fat/universal** binaries are detected but only thin slices are fully modeled.
- Planned: multi-arch CFG polish, symbol demangling, and a persistent per-user
  challenge scoreboard.

---

## License

MIT © MintKangaroo — see [`LICENSE`](LICENSE).
