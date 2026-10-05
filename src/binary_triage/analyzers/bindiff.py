"""
BinDiff - compare two builds of the SAME service binary, for Attack & Defense.

Its real A&D job is a **patch guard**: after you patch your own service in place,
diff the pristine build against the patched one and confirm the change touched
*only* the function(s) you meant to touch and nothing else (so you don't break
what the checker exercises). It is a self-check on your own box.

(In ECSC you don't receive opponents' binaries — only captured traffic — so this
is not an "opponent binary" tool; see the A&D toolkit traffic workflow for that.)

Two builds of the same source relocate differently: addresses, relative call
targets and RIP-relative displacements shift in nearly every function, so a raw
byte compare reports "everything changed." BinDiff compares function bodies at
the *normalized disassembly* level (capstone, position-dependent operands
masked) so a plain recompile of identical source compares equal, and only a real
code change shows up.

Local/offline, no AI. Uses pwntools for symbol/section/function detail and
capstone for normalization; always provides hash + size + changed-section list
with the stdlib alone. Every pass is bounded by a wall-clock budget and degrades
gracefully rather than hanging on a large static binary.
"""

import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import AnalysisResult, AnalysisStatus

logger = logging.getLogger(__name__)

try:
    from . import _pwnguard  # noqa: F401  (disables pwntools' PyPI update check; must precede `from pwn`)
    from pwn import ELF, context as _pwn_context
    _pwn_context.log_level = "error"
    PWNTOOLS_AVAILABLE = True
except Exception:  # pragma: no cover
    PWNTOOLS_AVAILABLE = False

try:
    import capstone as _cs
    CAPSTONE_AVAILABLE = True
except Exception:  # pragma: no cover
    CAPSTONE_AVAILABLE = False

# Sections whose bytes shift on every recompile and carry no patch signal on their
# own; skipped by the byte-range descent unless the caller asks for everything.
_NOISE_SECTIONS = re.compile(r"^\.(symtab|strtab|shstrtab|debug|comment|note|eh_frame)")

# pwntools arch string -> (capstone arch, capstone mode) for normalization.
# Built with getattr so a capstone build missing/renaming an arch constant just
# omits that entry (that arch falls back to raw-byte compare) instead of failing
# the whole import. aarch64 is CS_ARCH_ARM64 on 4.x, CS_ARCH_AARCH64 on 5.x.
_CS_ARCH = {}
if CAPSTONE_AVAILABLE:
    def _arch(name):
        return getattr(_cs, "CS_ARCH_" + name, None)

    _aarch64 = _arch("ARM64") or _arch("AARCH64")
    _candidates = {
        ("amd64", 64):   (_arch("X86"), _cs.CS_MODE_64),
        ("i386", 32):    (_arch("X86"), _cs.CS_MODE_32),
        ("arm", 32):     (_arch("ARM"), _cs.CS_MODE_ARM),
        ("thumb", 32):   (_arch("ARM"), _cs.CS_MODE_THUMB),
        ("aarch64", 64): (_aarch64, _cs.CS_MODE_ARM),
        ("mips", 32):    (_arch("MIPS"), _cs.CS_MODE_MIPS32),
        ("mips64", 64):  (_arch("MIPS"), _cs.CS_MODE_MIPS64),
        ("powerpc", 32): (_arch("PPC"), _cs.CS_MODE_32),
        ("powerpc64", 64): (_arch("PPC"), _cs.CS_MODE_64),
    }
    _CS_ARCH = {k: v for k, v in _candidates.items() if v[0] is not None}

# Mnemonics whose operand is a (relative/absolute) code target that relocates on
# rebuild: keep the mnemonic, drop the target. Covers x86 call/jmp/jcc, ARM b/bl.
_BRANCH_RE = re.compile(r"^(call|callq|jmp|jmpq|j[a-z]{1,3}|b|bl|blx|bx|b\.[a-z]{1,2}|cbz|cbnz)$")
# A RIP/PC-relative memory operand: the displacement relocates on rebuild.
_RIP_DISP_RE = re.compile(r"(rip|pc)\s*[+-]\s*0x[0-9a-fA-F]+")
# A large hex literal (>= 0x1000) is almost always an address; small immediates
# (bounds, sizes, constants) are real semantics and are preserved.
_BIG_HEX_RE = re.compile(r"0x[0-9a-fA-F]{4,}")


class BinDiff:
    """Compare two builds of one ELF: a normalized, bounded patch guard."""

    name = "bindiff"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_ranges = self.config.get("max_ranges", 50)
        # Wall-clock budget for the whole diff; degrade past it rather than hang.
        self.timeout = float(self.config.get("timeout", 3.0))

    def diff(self, path_a: Path, path_b: Path,
             timeout: Optional[float] = None) -> AnalysisResult:
        budget = float(timeout) if timeout is not None else self.timeout
        deadline = time.monotonic() + budget
        try:
            a = path_a.read_bytes()
            b = path_b.read_bytes()
        except OSError as e:
            return AnalysisResult(analyzer=self.name, status=AnalysisStatus.FAILURE, error=str(e))

        results: Dict[str, Any] = {
            "a": {"path": str(path_a), "size": len(a), "sha256": hashlib.sha256(a).hexdigest()},
            "b": {"path": str(path_b), "size": len(b), "sha256": hashlib.sha256(b).hexdigest()},
            "identical": a == b,
            "timeout": budget,
            "degraded": False,
        }

        if results["identical"]:
            results["note"] = "Binaries are byte-identical."
            return AnalysisResult(analyzer=self.name, status=AnalysisStatus.SUCCESS, results=results)

        if PWNTOOLS_AVAILABLE:
            try:
                ea = ELF(str(path_a), checksec=False)
                eb = ELF(str(path_b), checksec=False)
                results["sections"] = self._section_diff(ea, eb)
                results["symbols"] = self._symbol_diff(ea, eb)
                results["suspect_functions"] = self._suspect_functions(ea, eb, deadline)
                results["changed_byte_ranges"] = self._section_byte_ranges(
                    ea, eb, results["sections"], deadline)
            except Exception as ex:  # pragma: no cover - defensive
                logger.debug("pwntools diff path failed: %s", ex)
                results["degraded"] = True
        else:
            results["degraded"] = True

        if results.get("degraded") and "suspect_functions" not in results:
            # No pwntools (or it failed): honest hash+size+note, no O(n^2) scan.
            results["note"] = ("degraded: pwntools/capstone unavailable — reporting hash+size only. "
                               "Install the `ad` extra for function-level diff.")

        if time.monotonic() > deadline:
            results["degraded"] = True
            results.setdefault("note", "degraded: wall-clock budget exceeded; "
                                       "results may be partial (see --timeout).")

        return AnalysisResult(analyzer=self.name, status=AnalysisStatus.SUCCESS, results=results)

    # ----- section-scoped diff (O(n), not O(n^2)) -----
    def _section_diff(self, ea, eb) -> List[Dict[str, Any]]:
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

    def _section_byte_ranges(self, ea, eb, changed_sections, deadline,
                             include_noise: bool = False) -> List[Dict[str, Any]]:
        """Differing offset windows, scoped to changed non-noise sections only.

        Replaces the old whole-file difflib.SequenceMatcher (quadratic, never
        finished on real binaries). Each section is walked once with a fixed
        window, so the whole pass is O(total section bytes)."""
        ranges: List[Dict[str, Any]] = []
        window = 16
        for sec in changed_sections:
            if len(ranges) >= self.max_ranges or time.monotonic() > deadline:
                break
            n = sec["section"]
            if not include_noise and _NOISE_SECTIONS.match(n):
                continue
            sa = ea.get_section_by_name(n)
            sb = eb.get_section_by_name(n)
            da = bytes(sa.data()) if sa else b""
            db = bytes(sb.data()) if sb else b""
            off = ea.get_section_by_name(n).header.sh_offset if sa else 0
            length = min(len(da), len(db))
            i = 0
            while i < length:
                if da[i:i + window] != db[i:i + window]:
                    start = i
                    while i < length and da[i:i + window] != db[i:i + window]:
                        i += window
                    ranges.append({"section": n, "sec_start": start, "sec_end": min(i, length),
                                   "file_offset": off + start, "op": "replace"})
                    if len(ranges) >= self.max_ranges:
                        break
                else:
                    i += window
            if len(da) != len(db):
                ranges.append({"section": n, "sec_start": length,
                               "sec_end": max(len(da), len(db)),
                               "file_offset": off + length,
                               "op": "resize"})
        return ranges

    def _symbol_diff(self, ea, eb) -> Dict[str, List[str]]:
        sa, sb = set(ea.symbols or {}), set(eb.symbols or {})
        return {"added": sorted(sb - sa), "removed": sorted(sa - sb)}

    # ----- normalized function comparison (the patch guard) -----
    @staticmethod
    def _cs_for(elf):
        key = (getattr(elf, "arch", None), getattr(elf, "bits", None))
        spec = _CS_ARCH.get(key)
        if not spec:
            return None
        md = _cs.Cs(*spec)
        md.detail = False
        return md

    @staticmethod
    def _normalize_op(mnemonic: str, op_str: str) -> str:
        """Mask position-dependent operands so two recompiles of identical source
        compare equal, while keeping real immediates (bounds/sizes/constants)."""
        if _BRANCH_RE.match(mnemonic):
            # Operand is a code target that relocates — keep only the mnemonic.
            return "<rel>"
        s = _RIP_DISP_RE.sub(r"\1+<disp>", op_str)
        s = _BIG_HEX_RE.sub("<addr>", s)
        return s

    def _normalize_fn(self, md, code: bytes, addr: int) -> Optional[List[str]]:
        if md is None:
            return None
        insns = []
        for ins in md.disasm(code, addr):
            insns.append(ins.mnemonic + " " + self._normalize_op(ins.mnemonic, ins.op_str))
        return insns

    def _suspect_functions(self, ea, eb, deadline) -> List[str]:
        """Functions in both builds whose *normalized* body changed = the real
        patch. Relocation-only differences (addresses, rel targets, RIP disp) are
        normalized away, so a clean recompile yields no suspects."""
        md_a, md_b = self._cs_for(ea), self._cs_for(eb)
        suspects = []
        common = set(ea.functions or {}) & set(eb.functions or {})
        for name in sorted(common):
            if time.monotonic() > deadline:
                break
            fa, fb = ea.functions[name], eb.functions[name]
            try:
                ba = ea.read(fa.address, fa.size)
                bb = eb.read(fb.address, fb.size)
            except Exception:
                continue
            if ba == bb:
                continue
            na = self._normalize_fn(md_a, ba, fa.address)
            nb = self._normalize_fn(md_b, bb, fb.address)
            if na is None or nb is None:
                # No capstone for this arch: fall back to size + raw bytes.
                if fa.size != fb.size or ba != bb:
                    suspects.append(name)
            elif na != nb:
                suspects.append(name)
        return suspects

    @staticmethod
    def gate(suspects: List[str], allowlist: List[str]) -> Dict[str, Any]:
        """Patch-guard verdict: changed functions outside the allowlist are
        violations. Returns {violations, allowed_hit, ok}. ``ok`` is True only
        when every changed function was allowlisted."""
        allow = set(allowlist or [])
        violations = sorted(s for s in suspects if s not in allow)
        allowed_hit = sorted(s for s in suspects if s in allow)
        return {"violations": violations, "allowed_hit": allowed_hit, "ok": not violations}
