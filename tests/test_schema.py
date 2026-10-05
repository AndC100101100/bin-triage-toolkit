"""
Task 7: `triage -f json` emits the stable shared schema, and user-controlled
strings (binary names/symbols) are escaped before going into rich markup.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from binary_triage.main import cli

HERE = Path(__file__).parent
SCHEMA = HERE.parent / "schema" / "finding.v1.json"
VULN = HERE / "vuln.c"

jsonschema = pytest.importorskip("jsonschema")


def _weak(tmp):
    if not shutil.which("gcc") or not VULN.exists():
        pytest.skip("gcc or vuln.c unavailable")
    out = tmp / "weak"
    subprocess.run(["gcc", "-fno-stack-protector", "-no-pie", "-w", str(VULN), "-o", str(out)],
                   check=True)
    return out


def test_triage_json_validates_against_schema(tmp_path):
    weak = _weak(tmp_path)
    r = CliRunner().invoke(cli, ["triage", str(weak), "--profile", "ad", "-f", "json"])
    assert r.exit_code == 0, r.output
    doc = json.loads(r.output)
    schema = json.loads(SCHEMA.read_text())
    jsonschema.validate(doc, schema)  # raises on any contract violation
    assert doc["schema_version"] == "1.0"
    assert doc["source"] == "bin-triage"
    assert doc["findings"], "weak binary should produce findings"
    # every record carries the fields a downstream consumer relies on
    f0 = doc["findings"][0]
    assert {"binary", "finding_class", "rule_id", "severity", "confidence",
            "triage_status", "source"} <= set(f0)


def test_binary_name_with_markup_does_not_break_table(tmp_path):
    weak = _weak(tmp_path)
    tricky = tmp_path / "a[red]b"
    tricky.write_bytes(weak.read_bytes())
    r = CliRunner().invoke(cli, ["triage", str(tricky), "--profile", "ad"])
    assert r.exit_code == 0, r.output
    # The bracket is rendered literally (escaped), not consumed as a rich [red] tag.
    # (The narrow Binary column may truncate, so match the escaped prefix, not the
    # whole name.) Without escaping, "[red]" would be eaten and "a[" would vanish.
    assert "a[" in r.output
