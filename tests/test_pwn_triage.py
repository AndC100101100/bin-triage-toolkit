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


# ---- Task 5: network-facing detection ----
_NETSRC = (
    '#include <sys/socket.h>\n#include <netinet/in.h>\n#include <unistd.h>\n'
    'int main(){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={0};'
    'bind(s,(void*)&a,sizeof a);listen(s,1);int c=accept(s,0,0);'
    'char b[64];recv(c,b,sizeof b,0);return 0;}\n'
)
_PLAINSRC = '#include <stdio.h>\nint main(){long n=0;for(int i=0;i<1000;i++)n+=i;printf("%ld\\n",n);return 0;}\n'


def _build_src(tmp, name, src):
    if not shutil.which("gcc"):
        pytest.skip("gcc unavailable")
    c = tmp / f"{name}.c"
    c.write_text(src)
    out = tmp / name
    subprocess.run(["gcc", "-O1", "-w", str(c), "-o", str(out)], check=True)
    return out


def test_network_facing_server_flagged(tmp_path):
    srv = _build_src(tmp_path, "srv", _NETSRC)
    r = PwnTriage().analyze(srv).results
    assert r["network_facing"] is True
    assert {"listen", "accept"} & set(r["network_calls"])


def test_compute_helper_not_network_facing(tmp_path):
    plain = _build_src(tmp_path, "plain", _PLAINSRC)
    r = PwnTriage().analyze(plain).results
    assert r["network_facing"] is False
    assert r["network_calls"] == []


# ---- Task 6: fewer false positives in string / symbol signals ----
def test_flag_path_rejects_glibc_noise():
    from binary_triage.analyzers.pwn_triage import STRING_PATTERNS
    pat = STRING_PATTERNS["flag_path"]
    # glibc printf-internal words must NOT match
    for noise in (b"flag", b"flags", b"FLAGS_1.", b"conv_flags"):
        assert not pat.fullmatch(noise), noise
    # genuine references MUST match
    assert pat.search(b"/srv/flag")
    assert pat.search(b"./flag.txt")
    assert pat.search(b"flag{abc123}")
    assert pat.search(b"FLAG{x}")


def test_win_symbol_is_a_weak_score_driver():
    """A win-*named* symbol alone must contribute the downweighted value (8),
    not dominate like a confirmed bug would (pins Task 6's reweight)."""
    pt = PwnTriage()
    base, _ = pt._score({}, [], [], [], {}, False, False)
    named, drivers = pt._score({}, [], ["process_login"], [], {}, False, False)
    assert named - base == 8, (base, named)
    assert any("weak signal" in d for d in drivers)
    # a behavioral win target (actually calls system) stays full weight
    beh, _ = pt._score({}, [], [], [{"func": "f", "callee": "system"}], {}, False, False)
    assert beh - base == 20
