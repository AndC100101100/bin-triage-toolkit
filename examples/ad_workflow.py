#!/usr/bin/env python3
"""
A&D Workflow — fast pwn triage of service binaries for Attack & Defense.

Usage:
    python examples/ad_workflow.py <binary-or-service-dir> [more ...]

Mirrors `binary-triage triage --profile ad`: ELF-first, offline, no AI.
For each ELF it prints exploit mitigations, dangerous functions mapped to
primitives, win/backdoor symbols, and a ranked exploitability verdict, then
writes a pwntools skeleton for anything exploitable.
"""

import sys
from pathlib import Path

from binary_triage.analyzers import PwnTriage, StringExtractor
from binary_triage.main import _iter_elf_targets, _emit_exploit_skeleton


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    pwn = PwnTriage()
    strings = StringExtractor({"extract_iocs": False, "extract_ad": True})

    binaries = list(_iter_elf_targets(sys.argv[1:], recursive=True))
    if not binaries:
        print("No ELF binaries found.")
        sys.exit(1)

    results = []
    for b in binaries:
        r = pwn.analyze(b).results
        results.append((b, r))

    results.sort(key=lambda x: x[1].get("exploitability", {}).get("score", 0), reverse=True)

    for b, r in results:
        expl = r.get("exploitability", {})
        print(f"\n{'='*70}\n{b}  ->  {expl.get('summary', '')}\n{'='*70}")
        print(f"  score    : {expl.get('score')}  ({expl.get('verdict')})")
        print(f"  drivers  : {'; '.join(expl.get('drivers', [])) or '-'}")
        dfs = ", ".join(f"{d['function']}({d['primitive']})" for d in r.get("dangerous_functions", []))
        print(f"  danger   : {dfs or '-'}")
        print(f"  win syms : {', '.join(r.get('win_symbols', [])) or '-'}")

        ad = strings.analyze(b).results.get("ad_strings", {})
        if ad.get("flag_paths"):
            print(f"  flags    : {', '.join(ad['flag_paths'][:5])}")

        if expl.get("score", 0) > 0:
            skel = _emit_exploit_skeleton(b, r)
            print(f"  skeleton : {skel}")


if __name__ == "__main__":
    main()
