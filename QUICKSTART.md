# Quick Start

Get a binary triaged in under a minute. See [README.md](README.md) for the full command
reference and design.

## Install

```bash
cd bin-triage-toolkit
pip install -e ".[ad]"          # pwn/rev engine: pwntools + capstone (no AI)
#   or run from the repo without installing:  export PYTHONPATH=src
```

- Offline / competition: `pip install -r requirements-ad.txt`
- Malware/forensic mode (YARA, CAPA, PE, Magika): `pip install -e ".[malware]"`
- Dev/tests: `pip install -e ".[dev]"`

If `python3 -m binary_triage` says "No module named binary_triage", either install (above) or
`export PYTHONPATH=src` from the repo root.

## Attack & Defense / CTF pwn

```bash
# Rank ELF service binaries by attack surface; drop a pwntools skeleton per target
binary-triage triage path/to/service/ --profile ad --recursive --emit-exploit
```

Shows mitigations (NX/PIE/canary/RELRO), dangerous called functions → primitives, win symbols,
and a where-to-look score. Libraries/`.o`/solutions are split out as References, not ranked.

```bash
# Defense / opponent analysis: what changed between two builds of a binary
binary-triage diff pristine_bin patched_bin
```

## CTF rev

```bash
# What is it, and where do I start reversing it?
binary-triage rev path/to/challenges/ --profile ad --recursive
```

Shows language/compiler, arch/bits, static/PIE/stripped, user functions, packer, anti-debug,
notable strings, libc version, and Ghidra/radare2 hand-off tips.

## Malware / forensic

Requires the `[malware]` extra (not used in A&D — Magika is an ML model, off in the `ad` profile):

```bash
binary-triage analyze sample.bin                       # file id, YARA, CAPA, strings/IOCs
binary-triage analyze sample.bin --modules yara_scanner,capa_analyzer
binary-triage batch ./samples --pattern '*' -o results/
```

## JSON output (automation)

```bash
binary-triage triage ./server --profile ad -o reports/   # writes reports/server.json
binary-triage rev    ./server --profile ad -o reports/
```

## Python API

```python
from binary_triage.analyzers import PwnTriage, RevTriage, BinDiff
print(PwnTriage().analyze("server").results["exploitability"])
print(RevTriage().analyze("server").results["orientation"])
print(BinDiff().diff("pristine", "patched").results["suspect_functions"])
```

## Safety

Analyzing untrusted binaries is static here (nothing is executed), but if you go on to run or
debug one, do it in an isolated VM.
