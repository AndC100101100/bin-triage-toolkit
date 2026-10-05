"""
Task 8: score-validation harness.

Guards the ranking against regressions: a known-vulnerable C service must rank
above a known-benign one, and Go/Rust (static, memory-safe runtime) must land in
the needs-manual bucket rather than being scored and buried. Run it as:

    make validate            # or: pytest -m validation -v

It builds a small self-contained corpus (so it runs anywhere with a toolchain).
Point BT_VALIDATION_CORPUS at a directory of real services (e.g. compiled FAUST
binaries with known planted bugs) to validate against the real distribution too;
each immediate subdirectory is treated as one service and its most-vulnerable
binary's rank is reported.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from binary_triage.analyzers import PwnTriage

pytestmark = pytest.mark.validation

# name -> (source, language, expected: 'vulnerable' | 'benign' | 'needs-manual')
# Vulnerable cases use bugs the tool CAN see statically (unbounded gets/strcpy).
# (A printf(user) format-string is deliberately NOT used here: import-based triage
# can't tell it from a safe printf — that's the documented data-flow limitation,
# not something the ranking should pretend to catch.)
_CORPUS = {
    "overflow_svc": (
        '#include <stdio.h>\nvoid handle(){char b[64];gets(b);puts(b);}\n'
        'int main(){handle();return 0;}\n', "c", "vulnerable"),
    "strcpy_svc": (
        '#include <string.h>\n#include <stdio.h>\n'
        'int main(int c,char**v){char b[32];if(c>1){strcpy(b,v[1]);puts(b);}return 0;}\n',
        "c", "vulnerable"),
    "benign_compute": (
        '#include <unistd.h>\nint main(){long n=0;for(int i=0;i<100000;i++)n+=i*i;return (int)(n&0x7f);}\n',
        "c", "benign"),
    "go_svc": (
        'package main\nimport("net";"fmt")\nfunc main(){l,_:=net.Listen("tcp",":0");fmt.Println(l)}\n',
        "go", "needs-manual"),
}


def _build(tmp, name, src, lang):
    out = tmp / name
    if lang == "c":
        if not shutil.which("gcc"):
            pytest.skip("gcc unavailable")
        c = tmp / f"{name}.c"
        c.write_text(src)
        subprocess.run(["gcc", "-O1", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                       check=True)
    else:
        if not shutil.which("go"):
            pytest.skip("go unavailable")
        c = tmp / f"{name}.go"
        c.write_text(src)
        env = {**os.environ, "GOFLAGS": "-trimpath", "GOTELEMETRY": "off"}
        subprocess.run(["go", "build", "-o", str(out), str(c)], check=True, env=env)
    return out


def _rank(binaries):
    """Return (scored_ranked, needs_manual_names). Mirrors the triage partition."""
    pt = PwnTriage()
    scored, needs_manual = [], set()
    for b in binaries:
        r = pt.analyze(b).results
        if r.get("role") != "executable":
            continue
        name = b.name
        score = r.get("exploitability", {}).get("score", 0)
        if r.get("triage_status") == "needs-manual":
            needs_manual.add(name)
        else:
            scored.append((name, score))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored, needs_manual


def test_known_vulnerable_ranks_above_benign(tmp_path, capsys):
    built = []
    for name, (src, lang, _) in _CORPUS.items():
        built.append(_build(tmp_path, name, src, lang))
    scored, needs_manual = _rank(built)

    order = [n for n, _ in scored]
    with capsys.disabled():
        print("\n  scored ranking:", scored)
        print("  needs-manual:", sorted(needs_manual))

    # Go service is flagged for manual review, not scored/buried.
    assert "go_svc" in needs_manual

    # Every vulnerable C service ranks above every benign one.
    assert "benign_compute" in order
    benign_rank = order.index("benign_compute")
    for name, (_, lang, expect) in _CORPUS.items():
        if expect == "vulnerable" and name in order:
            assert order.index(name) < benign_rank, f"{name} ranked below benign ({order})"


@pytest.mark.skipif(not os.environ.get("BT_VALIDATION_CORPUS"),
                    reason="set BT_VALIDATION_CORPUS to a real service corpus dir")
def test_real_corpus_reports_rank_of_vulnerable(capsys):
    """When a real corpus is provided, report where each service's most-vulnerable
    binary lands. Informational (prints ranks); assertions are left to the
    operator per service since ground-truth varies."""
    from binary_triage.main import _iter_elf_targets
    root = Path(os.environ["BT_VALIDATION_CORPUS"])
    with capsys.disabled():
        for svc in sorted(p for p in root.iterdir() if p.is_dir()):
            bins = list(_iter_elf_targets([str(svc)], recursive=True))
            scored, needs_manual = _rank(bins)
            print(f"\n[{svc.name}] scored={scored} needs-manual={sorted(needs_manual)}")
    assert True
