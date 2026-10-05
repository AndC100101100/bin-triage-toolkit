"""
Tests for the dashboard-style findings layer. vuln.c defines win() (calls
system) and uses gets(), compiled no-PIE / no-canary -> predictable findings.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_triage.analyzers import PwnTriage, RevTriage
from binary_triage.analyzers.findings import build_findings, counts

HERE = Path(__file__).parent
SRC = HERE / "vuln.c"


@pytest.fixture(scope="module")
def weak():
    out = HERE / "vuln_weak"
    if out.exists():
        return out
    if not shutil.which("gcc") or not SRC.exists():
        pytest.skip("gcc or tests/vuln.c unavailable")
    subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-z", "execstack",
                    "-w", str(SRC), "-o", str(out)], check=True)
    return out


def test_findings_cover_the_obvious(weak):
    p = PwnTriage().analyze(weak).results
    r = RevTriage().analyze(weak).results
    fs = build_findings(weak.name, p, r)
    ids = {f["id"] for f in fs}
    # win() calls system -> behavioral win target; gets() -> overflow; no canary/PIE/NX.
    assert "fn-calls-exec" in ids
    assert "unbounded-input-gets" in ids
    assert "no-stack-canary" in ids
    assert "nx-disabled" in ids


def test_findings_are_ranked_errors_first(weak):
    fs = build_findings(weak.name, PwnTriage().analyze(weak).results)
    sevs = [f["severity"] for f in fs]
    assert sevs == sorted(sevs, key=lambda s: {"ERROR": 0, "WARNING": 1, "INFO": 2}[s])
    c = counts(fs)
    assert c["total"] == len(fs) and c["ERROR"] >= 1


def test_every_finding_has_direction(weak):
    # Each finding must carry a substantive, digestible explanation (not just a label).
    fs = build_findings(weak.name, PwnTriage().analyze(weak).results)
    for f in fs:
        assert len(f["message"]) > 50, f["id"]
        assert f["impact"] and f["id"] and f["where"] and f["confidence"]
