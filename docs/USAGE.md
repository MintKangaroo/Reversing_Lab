# Usage Guide

Practical walkthroughs for the web UI, HTTP API, and analysis core. For the complete
endpoint inventory and security boundaries, see [API.md](API.md) and
[SECURITY.md](SECURITY.md).

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
   - **Functions / Disassembly / Pseudo-C** — choose one recovered function and keep
     address context synchronized. Pseudo-C is an estimate, not recovered source.
   - **CFG / Call Graph / Program Flow** — review typed edges and linked evidence.
   - **Packing** — a verdict plus the evidence and an entropy histogram.
   - **Integrations** — inspect optional provider availability.
5. Use the inspector to save a function name, comment, or bookmark.
6. Export JSON, Markdown, or HTML from **Reports**.

Memory dumps use the dedicated **Memory** screen. Dynamic analysis remains locked until
an out-of-process provider passes every readiness guard; the API never falls back to
executing a sample locally.

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

# Functions and estimated pseudo-C
ADDRESS=$(curl -s "$BASE/binaries/$SHA/functions?limit=1" | jq -r '.items[0].address')
curl -s "$BASE/binaries/$SHA/functions/$ADDRESS/decompile?provider=pseudo_c" | jq '.code'

# Evidence-linked Markdown report
curl -OJ "$BASE/binaries/$SHA/report?format=markdown"

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

Do not call arbitrary decoder code or execute uploaded bytes from library integrations.
For dynamic workflows, implement the documented isolated provider contract.
