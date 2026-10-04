"""
Tests for the rev (reverse-engineering orientation) lens and the shared
elf_facts base. Self-contained: compiles tests/vuln.c, skips if gcc is absent.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_triage.analyzers import RevTriage
from binary_triage.analyzers import elf_facts as F

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
def stripped_bin():
    return _build("vuln_stripped", ["-no-pie", "-s"])  # -s strips .symtab


def test_rev_orientation_basics(weak):
    r = RevTriage().analyze(weak).results
    assert r["role"] == "executable"
    assert r["toolchain"]["language"] == "C"
    assert r["toolchain"]["compiler"]            # .comment carried a GCC/clang string
    assert r["format"]["arch"] == "amd64"
    assert r["format"]["stripped"] is False
    assert r["handoff"]                          # always suggests a next tool


def test_rev_lists_user_functions(weak):
    r = RevTriage().analyze(weak).results
    # vuln.c defines win()/vuln()/main(); libc/runtime names must be filtered out.
    sample = set(r["functions"]["sample"])
    assert {"win", "vuln"} & sample
    assert not any(s.startswith("_dl_") or s.startswith("__libc") for s in sample)


def test_rev_marks_stripped(stripped_bin):
    r = RevTriage().analyze(stripped_bin).results
    assert r["format"]["stripped"] is True
    assert "note" in r["functions"]              # Ghidra auto-analysis hint
    assert any("ghidra" in t.lower() for t in r["handoff"])


def test_rev_non_elf_skipped(tmp_path):
    f = tmp_path / "notelf.txt"
    f.write_text("hello")
    assert RevTriage().analyze(f).status.value == "skipped"


def test_facts_role_classification(weak):
    data = weak.read_bytes()
    assert F.classify_role(weak, data, static=False) == "executable"
    assert F.is_elf(weak)
