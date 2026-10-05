"""
Performance guard for the diff engine (Task 2).

The old byte-range engine ran difflib.SequenceMatcher over whole-file bytes
(quadratic): it took ~32 s on a 16 KB binary and never finished on a ~1 MB
static one. This test diffs two ~1 MB statically-linked binaries and asserts
completion under a generous CI bound, so a regression to O(n^2) fails loudly.
"""
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from binary_triage.analyzers import BinDiff

SRC = r'''
#include <stdio.h>
#include <string.h>
void handle(char*s){ char b[64]; strcpy(b,s); puts(b); }
int main(int c,char**v){ if(c>1) handle(v[1]); return 0; }
'''


def _build_static(tmp, name, extra=""):
    if not shutil.which("gcc"):
        pytest.skip("gcc unavailable")
    c = tmp / f"{name}.c"
    c.write_text(SRC + extra)
    out = tmp / name
    try:
        subprocess.run(["gcc", "-O1", "-static", "-w", str(c), "-o", str(out)], check=True)
    except subprocess.CalledProcessError:
        pytest.skip("static linking unavailable on this host")
    if out.stat().st_size < 200_000:
        pytest.skip("static binary smaller than expected; perf test not meaningful")
    return out


def test_large_static_diff_completes_quickly(tmp_path):
    a = _build_static(tmp_path, "big_a")
    # a trailing comment shifts nothing in code but forces a non-identical build
    b = _build_static(tmp_path, "big_b", "\nint unused_pad(int x){return x+1;}\n")
    start = time.monotonic()
    r = BinDiff(config={"timeout": 3.0}).diff(a, b).results
    elapsed = time.monotonic() - start
    # Generous CI bound; real runtime is ~1-2 s. O(n^2) would blow far past this.
    assert elapsed < 10.0, f"diff took {elapsed:.1f}s (possible O(n^2) regression)"
    assert "a" in r and "b" in r
