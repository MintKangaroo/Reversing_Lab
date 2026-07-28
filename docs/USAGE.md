# Usage Guide

Practical walkthroughs for the three ways to use Reversing Lab: the web UI, the HTTP API,
and the analysis core as a Python library.

## 1 · Analyze a binary in the web UI

1. Start the backend (`uvicorn reversing_lab.api.app:app --port 8000`) and the front-end
   (`npm run dev`), then open http://localhost:5173.
2. Drag a binary onto the **Upload** panel (or click to browse). ELF, PE, and Mach-O are
   accepted; anything else is rejected with a clear message.
3. The sample appears in the sidebar and its **Overview** opens automatically.
4. Walk the tabs:
   - **Sections / Symbols / Imports / Exports** — structural metadata, with entropy and
     flags per section.
   - **Strings** — adjust *Min length* to trade recall for noise.
   - **Hex** — page through the raw bytes with `Prev` / `Next`.
   - **Disassembly** — linear disassembly from the entry point; flow instructions are
     highlighted.
   - **Control Flow** — the entry function's basic-block graph.
   - **Packing** — a verdict plus the evidence and an entropy histogram.
   - **Integrations** — run radare2 / Ghidra / Binary Ninja if installed.

## 2 · Solve a challenge

1. Click **Challenges** in the header.
2. Pick a card, read the description, and **Download** its artifact.
3. Analyze the artifact — either back in the **Analyze** view (upload it) or with your own
   tools.
4. Enter the recovered `RLAB{...}` flag and **Submit**. Correct answers are marked
   *Solved* and the progress counter updates.

**Worked example — `xor-decode`:** the flag is stored between `XOR:` and `:END` markers,
single-byte-XORed with `0x5A`. Find the bytes in the Hex view, XOR them back, and submit
the result.

## 3 · Use the API directly

```bash
BASE=http://localhost:8000/api

# Upload
SHA=$(curl -s -F file=@./sample.elf $BASE/binaries | jq -r .sha256)

# Structural info
curl -s $BASE/binaries/$SHA/info | jq '{fmt:.binary_format, arch:.architecture, entry:.entry_point}'

# Disassemble 20 instructions from the entry point
curl -s "$BASE/binaries/$SHA/disassembly?count=20" | jq '.instructions[] | .text'

# Control-flow graph
curl -s $BASE/binaries/$SHA/cfg | jq '{blocks:(.blocks|length), edges:(.edges|length)}'

# Submit a challenge answer
curl -s -X POST $BASE/challenges/hidden-string/submit \
  -H 'content-type: application/json' \
  -d '{"answer":"RLAB{str1ngs_r3v34l_s3cr3ts}"}' | jq
```

## 4 · Use the analysis core as a library

The core is usable without the web layer:

```python
from reversing_lab.parser import parse_binary
from reversing_lab.analyzer import extract_strings, detect_packing
from reversing_lab.disassembler import disassemble, build_cfg

data = open("sample.elf", "rb").read()
info = parse_binary(data)
print(info.binary_format, info.architecture, hex(info.entry_point))

for s in extract_strings(data, min_length=6)[:10]:
    print(hex(s.offset), s.value)

report = detect_packing(info, data)
print("packed?", report.likely_packed, report.detected_packer)

cfg = build_cfg(info, data)                       # entry-point function
print(len(cfg.blocks), "basic blocks", len(cfg.edges), "edges")
```
