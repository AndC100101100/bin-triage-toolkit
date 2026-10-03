# Binary Triage Toolkit

An open-source toolkit for automated binary analysis and triage, inspired by tools like opengrep.
It has two orientations: **pwn triage for Attack & Defense (A&D)** — the primary focus for
ECSC/FAUST — and malware/forensic analysis.

> ## ⚡ Attack & Defense (ECSC / FAUST) — start here
>
> In A&D the vulnerable services are usually **Linux ELF binaries** (C/C++/Rust). The `triage`
> command gives a fast first pass over *all* the service binaries at once: exploit mitigations
> (checksec), dangerous functions → exploitation primitives, heap/win-symbol surface, and a
> **ranked attack-surface score** (a triage aid for *where to look first* — **not** a verdict).
> Then you hand off to Ghidra/pwntools.
>
> **Scope, honestly:** this is static analysis of the *binary*. It cannot see logic, use-after-free,
> or crypto bugs — exactly the kinds A&D hosts like to plant — so **a LOW/MINIMAL score never means
> "safe"**. In A&D you usually *have* the source (it's on your vulnbox), so **triage the source with
> Opengrep first**; reach for this tool for **stripped / no-source binaries**, and for `checksec` +
> `diff` on any binary.
>
> ```bash
> pip install -e ".[ad]"                      # pwntools + capstone engine (no AI)
> binary-triage triage path/to/service/ --profile ad --emit-exploit   # rank + pwntools skeleton
> binary-triage diff pristine_bin patched_bin                         # defense: what did the patch change?
> ```
>
> **Competition constraints** (see the `config/settings.ad.yaml` profile):
> - **No AI at runtime** — Magika (an ML model) is **disabled**; file typing falls back to
>   libmagic / magic bytes.
> - **Offline** — use `requirements-ad.txt` (cache wheels during prep); no network calls.
> - **ELF-first** — the malware modules (YARA families, CAPA/MITRE, PE/Office) are turned off.
> - Fits the *A&D toolkit* workflow: **Opengrep** (source code) + **dep-scan** (dependency CVEs)
>   + **this toolkit** (ELF binaries).

## 🎯 Goal

Provide fast, automated first-pass analysis of binaries — the way opengrep does for source code —
ideal for:
- Attack & Defense competitions (FAUST, ECSC, Attacking-Lab)
- CTF (Capture The Flag) events
- Initial forensic analysis
- Malware triage
- Security research

## 🚀 Features

### Attack & Defense (pwn) triage
- **Exploit mitigations (checksec)**: NX, PIE, stack canary, RELRO (full/partial), FORTIFY,
  stripped, static — via pwntools, with a `checksec`/`readelf` fallback.
- **Vulnerable-surface mapping**: dangerous imported functions (`gets`, `strcpy`, `system`,
  format-string family, …) mapped to exploitation primitives, plus win/backdoor symbol detection.
- **Ranked exploitability**: a score + verdict per binary, so you know what to attack first.
- **pwntools skeleton emitter** (`--emit-exploit`) and **binary diffing** (`diff`) for patch /
  opponent analysis.

### Fast static analysis (malware/forensic)
- **File identification**: magic numbers, Magika (AI — disabled in the A&D profile)
- **Signature detection**: YARA rules
- **Capability analysis**: CAPA (MITRE ATT&CK mapping)
- **String & IOC extraction**: URLs, IPs, domains, emails, paths (plus A&D strings:
  flag paths, `/bin/sh`, format specifiers, secrets)
- **Metadata**: ExifTool for forensic information

### Format-specific analysis
- **ELF (Linux/Unix)**: readelf/pwntools — symbols, sections, architecture, mitigations
- **PE (Windows)**: Detect It Easy, sections, imports/exports
- **Office documents**: oletools, macro extraction

### Reports
- Structured JSON for integration with other tools
- Human-readable Markdown
- Pretty terminal tables (via `rich`)

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/AndC100101100/bin-triage-toolkit.git
cd bin-triage-toolkit

# A&D (recommended): pwn engine, no AI, offline
pip install -e ".[ad]"
# or, for malware/forensic analysis (includes AI modules):
pip install -e ".[malware]"
# minimal offline set for the competition:
#   pip install -r requirements-ad.txt

# External tools (install via system package manager / pipx, not pip):
#   checksec, binutils (readelf/objdump/nm), ROPgadget/ropper, one_gadget, pwninit,
#   ghidra and/or radare2   -> the hand-off after triage
# For the malware path (optional):
sudo apt-get install yara libimage-exiftool-perl   # YARA + ExifTool
pip install flare-capa                             # CAPA
# Detect It Easy (PE analysis): https://github.com/horsicq/Detect-It-Easy
```

## 🔧 Basic usage

```bash
# A&D: rank the ELF service binaries by exploitability (offline, no-AI profile)
binary-triage triage path/to/service/ --profile ad --recursive --emit-exploit

# Diff two ELF binaries (pristine vs patched / opponent)
binary-triage diff pristine_bin patched_bin

# Malware/forensic: full analysis of one file
binary-triage analyze sample.bin

# Quick analysis (file identification + YARA only)
binary-triage analyze sample.bin --quick

# Specific modules
binary-triage analyze sample.bin --modules yara_scanner,capa_analyzer,string_extractor

# Batch a directory
binary-triage batch ./samples --pattern "*" --output ./results

# JSON output (for automation)
binary-triage analyze sample.bin --format json --output report.json
```

## 📊 Analysis modules

### Pwn Triage (A&D core)
```python
from binary_triage.analyzers import PwnTriage

result = PwnTriage().analyze("service_binary")
r = result.results
print(r["mitigations"])            # {'nx': False, 'pie': False, 'canary': False, 'relro': 'Partial', ...}
print(r["dangerous_functions"])    # [{'function': 'gets', 'primitive': 'stack buffer overflow', ...}]
print(r["win_symbols"])            # ['win']
print(r["exploitability"])         # {'score': 100, 'verdict': 'HIGH', 'summary': '...'}
```

### Binary diff
```python
from binary_triage.analyzers import BinDiff

result = BinDiff().diff("pristine", "patched")
print(result.results["suspect_functions"])   # functions that changed = likely the bug/patch
```

### String & A&D/IOC extractor
```python
from binary_triage.analyzers import StringExtractor

res = StringExtractor({"extract_ad": True}).analyze("service_binary")
print(res.results["ad_strings"])   # {'flag_paths': [...], 'shell': ['/bin/sh'], ...}
print(res.results["iocs"])         # URLs/IPs/domains (malware framing; off in the A&D profile)
```

### ELF / PE / File identification / YARA / CAPA
```python
from binary_triage.analyzers import ELFAnalyzer, FileIdentifier

print(ELFAnalyzer().analyze("sample.elf").results["security"])   # checksec dict
print(FileIdentifier().analyze("sample.bin").results["file_type"])
# YaraScanner, CapaAnalyzer, PEAnalyzer follow the same analyze() -> AnalysisResult shape.
```

## 🎨 Example output (triage)

```
                         Exploitability Triage (ranked)
┏━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━┳━━━━━━━┳━━━━┳━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━┓
┃ Binary    ┃ Score ┃ Verdict ┃ Arch  ┃ NX ┃ PIE ┃ Canary ┃ RELRO   ┃ Danger ┃ Win ┃
┡━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━╇━━━━━━━╇━━━━╇━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━┩
│ vuln_weak │ 100   │ HIGH    │ amd64 │ ✗  │ ✗   │ ✗      │ Partial │ gets,… │ win │
│ vuln_hard │ 68    │ HIGH    │ amd64 │ ✓  │ ✓   │ ✓      │ Full    │ gets,… │ win │
└───────────┴───────┴─────────┴───────┴────┴─────┴────────┴─────────┴────────┴─────┘
```

## 🏗️ Architecture

```
bin-triage-toolkit/
├── src/binary_triage/
│   ├── analyzers/
│   │   ├── base.py              # BaseAnalyzer ABC + AnalysisResult / FileInfo
│   │   ├── pwn_triage.py        # A&D: checksec + dangerous funcs + exploitability score
│   │   ├── bindiff.py           # pristine vs patched/opponent diff
│   │   ├── elf_analyzer.py      # ELF header/sections/symbols/security
│   │   ├── file_identifier.py   # magic / Magika (AI, off in A&D)
│   │   ├── string_extractor.py  # strings + A&D strings + IOCs
│   │   ├── yara_scanner.py      # YARA (optional, [malware])
│   │   ├── capa_analyzer.py     # CAPA / MITRE (optional, [malware])
│   │   └── pe_analyzer.py       # Windows PE (optional, [malware])
│   ├── main.py                  # CLI: analyze, batch, triage, diff
│   └── __main__.py              # python -m binary_triage
├── config/
│   ├── settings.yaml            # default profile
│   ├── settings.ad.yaml         # Attack & Defense profile (offline, no AI)
│   └── yara_rules/ad_indicators.yar
├── examples/                    # ad_workflow.py, ctf_workflow.py, basic_usage.py
└── tests/                       # vuln.c + test_pwn_triage.py
```

## 🔍 Use cases

### Attack & Defense — triage the service binaries
```bash
# Rank every ELF under a service tree and emit pwntools skeletons for exploitable ones
binary-triage triage /srv/services/ --profile ad --recursive --emit-exploit
```

### Attack & Defense — binary patching / opponent analysis
```bash
# Confirm our in-place patch changed only what we intended; or infer an opponent's patched bug
binary-triage diff pristine_bin other_bin
```

### Malware / forensic — full analysis
```bash
binary-triage analyze evidence.bin --format markdown --output investigation.md
```

## 🤝 Comparison with other tools

| Feature            | Binary Triage Toolkit | Cuckoo | REMnux |
|--------------------|-----------------------|--------|--------|
| Static analysis    | ✅                    | ❌     | ✅     |
| Pwn/A&D triage      | ✅                    | ❌     | ❌     |
| Dynamic analysis   | ❌                    | ✅     | ✅     |
| Open source        | ✅                    | ✅     | ✅     |
| Simple CLI         | ✅                    | ❌     | ✅     |
| JSON/automation    | ✅                    | ✅     | ❌     |

## ⚠️ Limitations (and what's deliberately out of scope for now)

- **Static, binary-only.** No data-flow — it reports that a risky function/surface *exists*, not
  that user input *reaches* it. The score is a triage aid, not an exploitability proof.
- **C/libc-centric catalog.** Dangerous-function mapping targets the C/libc idiom (incl. FORTIFY
  `_chk` and `__isoc99_` variants). **Rust/Go binaries** (different panic/alloc/idioms) are not yet
  modelled — planned as a follow-up, per-binary-type.
- **Source beats this when you have it.** Opengrep on source is the primary code-review lane;
  binary triage is the no-source/stripped fallback plus checksec/diff.

## 📝 Roadmap

- [x] Project base structure
- [x] PE/ELF analysis (core modules + file-id/strings)
- [x] YARA / CAPA integration (optional, `[malware]`)
- [x] IOC extractor + A&D strings
- [x] **A&D pwn triage** (`triage`: checksec + dangerous functions + score)
- [x] **Binary diff** (`diff`: pristine vs patched/opponent)
- [x] pwntools skeleton emitter (`--emit-exploit`)
- [x] Offline / no-AI profile (`--profile ad`)
- [x] CLI (`analyze`, `batch`, `triage`, `diff`)
- [ ] HTML report generator
- [ ] `--from-container` (pull a binary off a running vulnbox)
- [ ] Per-binary-type depth: Rust / Go idioms, static-vs-dynamic nuances
- [ ] Optional data-flow (angr/decompiler) to confirm reachability of a sink
- [ ] REST API / Docker / CI

## 🤝 Contributing

Contributions are welcome:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgements

Inspired by open-source tools such as:
- [pwntools](https://github.com/Gallopsled/pwntools) — binary exploitation / ELF parsing
- [CAPA](https://github.com/mandiant/capa) — Mandiant/FireEye
- [YARA](https://github.com/VirusTotal/yara) — VirusTotal
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) — horsicq
- [oletools](https://github.com/decalage2/oletools) — decalage2
- [Semgrep](https://github.com/semgrep/semgrep) — concept inspiration

## 📧 Contact

- GitHub Issues: [bin-triage-toolkit/issues](https://github.com/AndC100101100/bin-triage-toolkit/issues)

---

**⚠️ Disclaimer**: This tool is designed for legitimate security analysis. Misuse may be illegal.
Use it responsibly.
