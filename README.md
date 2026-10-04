# Binary Triage Toolkit

Fast, static, offline first-pass triage of ELF binaries. It tells you *what a binary is, what's
notable about it, and where to start* — then hands off to Ghidra/pwntools/radare2 for the actual
deep work. Built for Attack & Defense (ECSC/FAUST) and CTF pwn/rev, with a malware/forensic mode.

Design: **one extraction, multiple lenses.** A single neutral fact-base (`elf_facts`) is read by a
`pwn` lens, a `rev` lens, and the malware analyzers. Deep analysis (exploit confirmation,
decompilation, dependency CVE scanning) is deliberately a **hand-off, not a feature** — see
[What it does not do](#what-it-does-not-do).

## Install

```bash
git clone https://github.com/AndC100101100/bin-triage-toolkit.git
cd bin-triage-toolkit
pip install -e ".[ad]"          # pwn/rev engine: pwntools + capstone (no AI)
#   or, from the repo without installing:  export PYTHONPATH=src
```

Offline competition setup: `pip install -r requirements-ad.txt` (cache wheels during prep).
Malware/forensic extras (YARA, CAPA, PE, Magika): `pip install -e ".[malware]"`.

External tools used when present (none required): `checksec`, `readelf`/`nm`/`objdump` (binutils),
and for the hand-off `ghidra`, `radare2`, `ROPgadget`, `one_gadget`, `pwninit`.

## Commands

### `triage` — pwn / A&D attack-surface (default lens)

Ranks ELF targets by attack surface so you know what to look at first.

```bash
binary-triage triage <file|dir ...> --profile ad [--recursive] [--emit-exploit] [-o OUTDIR]
```

Reports per binary: exploit mitigations (NX, PIE, canary, RELRO, FORTIFY, static, stripped);
dangerous **called** functions mapped to primitives (`gets`→BOF, `system`→ret2system,
`printf`→format string, …); heap surface (UAF/double-free); win/backdoor symbols; pwn strings
(`/bin/sh`, flag paths); and a ranked **attack-surface score** (a *where-to-look* aid, not a
verdict). `--emit-exploit` writes a pwntools skeleton per target. Libraries/`.o`/solutions are
listed separately as References (with a ret2libc hint), never ranked as targets.

```bash
binary-triage triage ./service/ --profile ad --recursive --emit-exploit
binary-triage triage ./bin/server --profile ad -o reports/   # also writes reports/server.json
```

Static binaries: a bundled-libc function being *present* is not proof it's *called*, so for static
binaries dangerous functions are listed as "present (unconfirmed)" and not scored — disassemble to
confirm.

### `rev` — reverse-engineering orientation

Answers "what is this and where do I start reversing it" for the rev category.

```bash
binary-triage rev <file|dir ...> --profile ad [--recursive] [-o OUTDIR]
```

Reports: language + compiler (Go/Rust/C++/C, from `.comment`/strings/symbols), arch/bits,
static/PIE/stripped, user-defined function count + sample (libc/runtime filtered out), packer (UPX,
stripped section headers), anti-debug indicators (from imports + strings, not bundled-libc noise),
categorised strings (flags/secrets, urls, paths, commands, format, asserts), libc version
fingerprint, and language-specific **hand-off tips** (Ghidra/radare2; `c++filt`/`rustfilt`;
Go `.gopclntab`). Orientation only — the RE happens in the tools it points you to.

```bash
binary-triage rev ./challenges/ --profile ad --recursive
```

### `diff` — binary diff (defense / opponent analysis)

```bash
binary-triage diff <pristine> <other> [-f table|json]
```

Section, symbol, byte-range and changed-function diff between two ELFs. Use it to confirm an
in-place patch changed only what you intended, or to spot which function an opponent patched
(= the bug they found).

### `analyze` / `batch` — malware / forensic mode

```bash
binary-triage analyze <file> [--quick] [--modules yara_scanner,capa_analyzer,string_extractor]
binary-triage batch <dir> --pattern '*' -o results/
```

File identification (libmagic/Magika), YARA, CAPA (MITRE ATT&CK), PE/Office analysis, string/IOC
extraction. Requires the `[malware]` extra. Not used in A&D (Magika is an ML model → disabled by the
`ad` profile).

## Profiles

`--profile ad` (default for `triage`/`rev`) loads `config/settings.ad.yaml`: ELF-first, **no AI at
runtime** (Magika off; libmagic/magic-byte typing), IOC extraction off, malware modules off, quiet
logging. Point `--config FILE` at your own YAML to override. Without a profile the full default
config (`config/settings.yaml`) applies.

## Binary roles

Every target is classified from ELF structure (ET_REL, PT_INTERP, DT_SONAME, static-PIE), not just
its name:

| Role | Meaning |
|------|---------|
| `executable` | a real target — ranked/triaged |
| `library` | libc / `ld` / `.so` module — a reference (pair for ret2libc, fingerprint version) |
| `relocatable` | `.o` object — not runnable |
| `solution?` | looks like a provided exploit/solution, not a challenge |

## What it does not do

By design, these are hand-offs, not features (keeps the tool focused and its output trustworthy):

- **Confirm exploitability / data-flow** — it flags that a dangerous sink or surface *exists*, not
  that input reaches it. Confirm in pwntools/gdb.
- **Decompile / analyse control flow** — that's Ghidra/radare2; the tool tells you which to use and how.
- **Dependency CVE scanning (SCA)** — use OWASP dep-scan as a separate lane. The one SCA slice kept
  in-tool is the libc **version fingerprint** (for ret2libc).

A low/MINIMAL score never means "safe": static analysis can't see logic, use-after-free or crypto
bugs. If you have the source, review it (e.g. with Opengrep) first; this tool is the
stripped/no-source fallback plus checksec/diff/orientation.

## Library use

```python
from binary_triage.analyzers import PwnTriage, RevTriage, BinDiff
from binary_triage.analyzers import elf_facts

pwn = PwnTriage().analyze("server").results          # mitigations, dangerous_functions, exploitability
rev = RevTriage().analyze("server").results          # toolchain, functions, strings, handoff, orientation
diff = BinDiff().diff("pristine", "patched").results # suspect_functions, symbol/section deltas
mitig = elf_facts.checksec("server")                 # raw fact-base primitives
```

## Architecture

```
src/binary_triage/
├── analyzers/
│   ├── elf_facts.py      # neutral fact-base: role, checksec, symbols, strings,
│   │                     #   toolchain/packer/anti-debug, libc fingerprint (shared)
│   ├── pwn_triage.py     # pwn lens  -> attack-surface view
│   ├── rev_triage.py     # rev lens  -> orientation view
│   ├── bindiff.py        # two-binary diff
│   ├── file_identifier / yara_scanner / capa_analyzer / pe_analyzer / string_extractor  # malware mode
│   └── base.py           # BaseAnalyzer, AnalysisResult, FileInfo
├── main.py               # CLI: triage, rev, diff, analyze, batch
└── __main__.py           # python -m binary_triage
config/settings.ad.yaml   # Attack & Defense profile (offline, no AI)
```

## Limitations

- Static and binary-only; no data-flow (the score is a triage aid, not a proof).
- Dangerous-function catalog is C/libc-centric; Rust/Go idioms are not yet modelled (roadmap).
- Language/compiler/packer detection is heuristic (`.comment`, strings, symbols, sections).

## Tests

```bash
pip install -e ".[dev]"
pytest            # pwn + rev + bindiff; tests compile tests/vuln.c, skip if gcc is absent
```

## License

MIT — see [LICENSE](LICENSE).
