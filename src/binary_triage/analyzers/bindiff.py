"""
BinDiff - compare two ELF binaries for A&D.

Defense: confirm our in-place patch changed only what we intended (didn't break
the service the checker exercises). Offense: diff a captured/opponent binary
against the pristine one to infer which function they patched -> that's the bug.

Local/offline, no AI. Uses pwntools when available for symbol/section detail;
always provides hash + size + byte-range deltas with the stdlib alone.
"""

import hashlib
import logging
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import AnalysisResult, AnalysisStatus

logger = logging.getLogger(__name__)

try:
    from pwn import ELF, context as _pwn_context
    _pwn_context.log_level = "error"
    PWNTOOLS_AVAILABLE = True
except Exception:  # pragma: no cover
    PWNTOOLS_AVAILABLE = False


class BinDiff:
    """Compare two ELF binaries."""

    name = "bindiff"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_ranges = self.config.get("max_ranges", 50)

    def diff(self, path_a: Path, path_b: Path) -> AnalysisResult:
        try:
            a = path_a.read_bytes()
            b = path_b.read_bytes()
        except OSError as e:
            return AnalysisResult(analyzer=self.name, status=AnalysisStatus.FAILURE, error=str(e))

        results: Dict[str, Any] = {
            "a": {"path": str(path_a), "size": len(a), "sha256": hashlib.sha256(a).hexdigest()},
            "b": {"path": str(path_b), "size": len(b), "sha256": hashlib.sha256(b).hexdigest()},
            "identical": a == b,
        }

        if results["identical"]:
            results["note"] = "Binaries are byte-identical."
            return AnalysisResult(analyzer=self.name, status=AnalysisStatus.SUCCESS, results=results)

        results["changed_byte_ranges"] = self._byte_ranges(a, b)
        if PWNTOOLS_AVAILABLE:
            results["sections"] = self._section_diff(path_a, path_b)
            results["symbols"] = self._symbol_diff(path_a, path_b)
            results["suspect_functions"] = self._suspect_functions(path_a, path_b)

        return AnalysisResult(analyzer=self.name, status=AnalysisStatus.SUCCESS, results=results)

    def _byte_ranges(self, a: bytes, b: bytes) -> List[Dict[str, int]]:
        """Coarse list of differing offset ranges (opcodes=replace/insert/delete)."""
        sm = SequenceMatcher(None, a, b, autojunk=False)
        ranges = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal":
                ranges.append({"a_start": i1, "a_end": i2, "b_start": j1, "b_end": j2, "op": tag})
            if len(ranges) >= self.max_ranges:
                break
        return ranges

    def _section_diff(self, pa: Path, pb: Path) -> List[Dict[str, Any]]:
        ea, eb = ELF(str(pa), checksec=False), ELF(str(pb), checksec=False)
        out = []
        names = {s.name for s in ea.sections} | {s.name for s in eb.sections}
        for n in sorted(names):
            sa = ea.get_section_by_name(n)
            sb = eb.get_section_by_name(n)
            da = bytes(sa.data()) if sa else b""
            db = bytes(sb.data()) if sb else b""
            if da != db:
                out.append({
                    "section": n,
                    "a_size": len(da), "b_size": len(db),
                    "a_sha": hashlib.sha256(da).hexdigest()[:16] if da else None,
                    "b_sha": hashlib.sha256(db).hexdigest()[:16] if db else None,
                })
        return out

    def _symbol_diff(self, pa: Path, pb: Path) -> Dict[str, List[str]]:
        ea, eb = ELF(str(pa), checksec=False), ELF(str(pb), checksec=False)
        sa, sb = set(ea.symbols or {}), set(eb.symbols or {})
        return {"added": sorted(sb - sa), "removed": sorted(sa - sb)}

    def _suspect_functions(self, pa: Path, pb: Path) -> List[str]:
        """Functions present in both but whose .text bytes changed = likely the patch."""
        ea, eb = ELF(str(pa), checksec=False), ELF(str(pb), checksec=False)
        suspects = []
        common = set(ea.functions or {}) & set(eb.functions or {})
        for name in sorted(common):
            fa, fb = ea.functions[name], eb.functions[name]
            try:
                ba = ea.read(fa.address, fa.size)
                bb = eb.read(fb.address, fb.size)
            except Exception:
                continue
            if fa.size != fb.size or ba != bb:
                suspects.append(name)
        return suspects
