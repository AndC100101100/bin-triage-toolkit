"""
Tests for the A&D pwn triage path.

Builds (or reuses) a deliberately-vulnerable ELF and asserts that mitigations,
dangerous-function mapping, win-symbol detection and scoring behave. Skips
cleanly if a C compiler is unavailable.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_triage.analyzers import PwnTriage, BinDiff

HERE = Path(__file__).parent
SRC = HERE / "vuln.c"


def _build(name, flags):
    out = HERE / name
    if out.exists():
        return out
    if not shutil.which("gcc") or not SRC.exists():
        pytest.skip("gcc or tests/vuln.c unavailable")
    subprocess.run(["gcc", *flags, "-w", str(SRC), "-o", str(out)], check=True)
    return out


@pytest.fixture(scope="module")
def weak():
    return _build("vuln_weak", ["-fno-stack-protector", "-no-pie", "-z", "execstack"])


@pytest.fixture(scope="module")
def hard():
    return _build("vuln_hard", ["-fstack-protector-all", "-pie", "-fPIE",
                                 "-D_FORTIFY_SOURCE=2", "-O2", "-Wl,-z,relro,-z,now"])


def test_weak_is_high_risk(weak):
    r = PwnTriage().analyze(weak).results
    m = r["mitigations"]
    assert m["nx"] is False and m["pie"] is False and m["canary"] is False
    assert r["exploitability"]["verdict"] == "HIGH"
    assert r["exploitability"]["score"] >= 60


def test_dangerous_functions_and_win(weak):
    r = PwnTriage().analyze(weak).results
    funcs = {d["function"] for d in r["dangerous_functions"]}
    assert {"gets", "system"} <= funcs
    assert "win" in r["win_symbols"]


def test_hardened_has_mitigations(hard):
    m = PwnTriage().analyze(hard).results["mitigations"]
    assert m["nx"] is True and m["canary"] is True and m["pie"] is True


def test_non_elf_is_skipped(tmp_path):
    f = tmp_path / "notelf.txt"
    f.write_text("hello world")
    res = PwnTriage().analyze(f)
    assert res.status.value == "skipped"


def test_bindiff_finds_changed_functions(weak, hard):
    r = BinDiff().diff(weak, hard).results
    assert r["identical"] is False
    # vuln/win exist in both but differ -> should be flagged as suspects
    assert "suspect_functions" in r
