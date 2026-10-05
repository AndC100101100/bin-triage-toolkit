"""
Tests for the normalized patch-guard diff (Tasks 2/3).

A one-line source patch must report *only* the touched functions (not the whole
program) despite relocation noise, and identical source relocated to a different
layout must report *no* changes. Also covers the allowlist gate exit codes.
Self-contained: compiles small C programs with gcc; skips if gcc is unavailable.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from binary_triage.analyzers import BinDiff
from binary_triage.main import cli

# A tiny note service with a planted index/UAF bug, and a one-line patched copy.
SVC = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct note { char *buf; size_t len; };
struct note *notes[16];
void handle_create(void){ size_t n; if(scanf("%zu",&n)!=1) return; struct note*x=malloc(sizeof *x); x->buf=malloc(n); x->len=n; if(read(0,x->buf,n)<0) return; for(int i=0;i<16;i++) if(!notes[i]){notes[i]=x;break;} }
void handle_get(void){ int i; if(scanf("%d",&i)!=1) return; if(IDXCHECK i<16 && notes[i]) printf("%s\n", notes[i]->buf); }
void handle_del(void){ int i; if(scanf("%d",&i)!=1) return; if(i>=0&&i<16&&notes[i]){ free(notes[i]->buf); free(notes[i]); NULLOUT } }
int main(){ setvbuf(stdout,0,_IONBF,0); char cmd[16]; while(fgets(cmd,sizeof cmd,stdin)){ if(!strncmp(cmd,"create",6)) handle_create(); else if(!strncmp(cmd,"get",3)) handle_get(); else if(!strncmp(cmd,"del",3)) handle_del(); } }
'''

# An extra unused function that only shifts later functions' addresses (identical
# source for handle_*): exercises address normalization, not a real code change.
PAD = r'''
int PADNAME(int a){ return a*3+1; }
'''


def _gcc():
    if not shutil.which("gcc"):
        pytest.skip("gcc unavailable")


def _build(tmp, name, body, flags=()):
    _gcc()
    c = tmp / f"{name}.c"
    c.write_text(body)
    out = tmp / name
    subprocess.run(["gcc", "-O1", "-w", *flags, str(c), "-o", str(out)], check=True)
    return out


def _vuln(tmp):
    return _build(tmp, "svc", SVC.replace("IDXCHECK", "").replace("NULLOUT", ""))


def _patched(tmp):
    return _build(tmp, "svc_patched",
                  SVC.replace("IDXCHECK", "i>=0 &&").replace("NULLOUT", "notes[i]=0;"))


def test_intended_patch_reports_only_touched_functions(tmp_path):
    a, b = _vuln(tmp_path), _patched(tmp_path)
    r = BinDiff().diff(a, b).results
    assert r["identical"] is False
    # The one-line patch touched handle_get (bound) and handle_del (null-out) only.
    assert set(r["suspect_functions"]) == {"handle_get", "handle_del"}, r["suspect_functions"]


def test_identical_source_relocated_has_no_suspects(tmp_path):
    """Same handle_* source, different layout (an extra unused fn shifts addresses)
    => normalization must mask the relocation and report no changed functions."""
    base = SVC.replace("IDXCHECK", "").replace("NULLOUT", "")
    a = _build(tmp_path, "a", base)
    b = _build(tmp_path, "b", PAD.replace("PADNAME", "pad_fn") + base)
    r = BinDiff().diff(a, b).results
    if r["identical"]:
        pytest.skip("toolchain produced byte-identical output; normalization not exercised")
    assert r["suspect_functions"] == [], r["suspect_functions"]


def test_gate_allowlist_pass_and_fail(tmp_path):
    a, b = _vuln(tmp_path), _patched(tmp_path)
    run = CliRunner()
    ok = run.invoke(cli, ["diff", "--allow", "handle_get", "--allow", "handle_del", str(a), str(b)])
    assert ok.exit_code == 0, ok.output
    bad = run.invoke(cli, ["diff", "--allow", "handle_get", str(a), str(b)])
    assert bad.exit_code == 2, bad.output
    assert "handle_del" in bad.output  # the unexpected change is named


def test_allow_file(tmp_path):
    a, b = _vuln(tmp_path), _patched(tmp_path)
    allow = tmp_path / "allow.txt"
    allow.write_text("# intended patch\nhandle_get\nhandle_del\n")
    r = CliRunner().invoke(cli, ["diff", "--allow-file", str(allow), str(a), str(b)])
    assert r.exit_code == 0, r.output


def test_no_allowlist_is_informational_exit_zero(tmp_path):
    a, b = _vuln(tmp_path), _patched(tmp_path)
    r = CliRunner().invoke(cli, ["diff", str(a), str(b)])
    assert r.exit_code == 0, r.output
