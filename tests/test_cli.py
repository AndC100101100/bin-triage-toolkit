"""
CLI smoke tests: invoke the actual commands end-to-end so wiring bugs
(missing imports, bad option handling, the references/library path) are caught.
Self-contained: compiles tests/vuln.c as an executable and as a .so; skips if
gcc is unavailable.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from binary_triage.main import cli

HERE = Path(__file__).parent
SRC = HERE / "vuln.c"


def _need_gcc():
    if not shutil.which("gcc") or not SRC.exists():
        pytest.skip("gcc or tests/vuln.c unavailable")


@pytest.fixture(scope="module")
def weak():
    _need_gcc()
    out = HERE / "vuln_weak"
    if not out.exists():
        subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-z", "execstack",
                        "-w", str(SRC), "-o", str(out)], check=True)
    return out


@pytest.fixture(scope="module")
def libdir(weak):
    """A directory holding a target executable + a shared library (library role)."""
    d = HERE / "_cli_fixture"
    d.mkdir(exist_ok=True)
    (d / "target").write_bytes(weak.read_bytes())
    so = d / "libtest.so"
    if not so.exists():
        subprocess.run(["gcc", "-shared", "-fPIC", "-w", str(SRC), "-o", str(so)], check=True)
    return d


def test_cli_triage_executable(weak):
    r = CliRunner().invoke(cli, ["triage", str(weak), "--profile", "ad"])
    assert r.exit_code == 0, r.output
    assert "Attack-Surface Triage" in r.output


def test_cli_triage_with_library_references(libdir):
    # Exercises the references/library branch (where the re.search NameError lived).
    r = CliRunner().invoke(cli, ["triage", str(libdir), "--profile", "ad", "--recursive"])
    assert r.exit_code == 0, r.output
    assert "References" in r.output
    assert "library" in r.output


def test_cli_rev_runs(weak):
    r = CliRunner().invoke(cli, ["rev", str(weak), "--profile", "ad"])
    assert r.exit_code == 0, r.output
    assert "Orientation" in r.output


def test_cli_diff_runs(weak):
    r = CliRunner().invoke(cli, ["diff", str(weak), str(weak)])
    assert r.exit_code == 0, r.output
    assert "identical" in r.output.lower()
