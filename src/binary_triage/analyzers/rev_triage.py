"""
Rev Triage lens - reverse-engineering ORIENTATION view over the elf_facts base.

A second lens (not a second engine): it reads the same neutral fact-base that
the pwn lens does, but answers a different question -- "what is this binary and
where do I start reversing it?" rather than "how do I pop it?". It reports
language/compiler/packer, user-defined functions (libc filtered out),
categorised strings, anti-debug indicators and a libc fingerprint, then points
you at the right deep tool (Ghidra / radare2). It does NOT decompile or analyse
control flow -- that is the hand-off.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo
from . import elf_facts as F

# rev-relevant string buckets (orientation, not IOC/malware framing)
REV_STRING_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>]{4,}"),
    "paths": re.compile(r"/(?:usr|etc|home|tmp|proc|bin|lib|var|dev|opt)/[\w./-]+"),
    "flags_secrets": re.compile(r"(?i)(flag\{[^}]*\}|flag[\w./-]*|secret[\w./-]*|password[\w./-]*|token[\w./-]*)"),
    "format": re.compile(r"%(?:\d+\$)?[ -+#0]*\d*(?:\.\d+)?[hljztL]*[diouxXeEfFgGaAcsp]"),
    "commands": re.compile(r"\b(?:/bin/(?:sh|bash)|system|execve|popen|/usr/bin/\w+)\b"),
    "errors_asserts": re.compile(r"(?i)(assert|panic|unreachable|segmentation fault|stack smashing|__assert)"),
}

_SAMPLE = 25


class RevTriage(BaseAnalyzer):
    """Reverse-engineering orientation lens over elf_facts."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("rev_triage", config)
        self.max_sample = self.config.get("max_sample", _SAMPLE)

    def can_analyze(self, file_info: FileInfo) -> bool:
        if file_info.file_type:
            return any(x in file_info.file_type.lower()
                       for x in ("elf", "executable", "shared object"))
        return F.is_elf(file_info.path)

    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        if file_data is None:
            try:
                file_data = file_path.read_bytes()
            except OSError as e:
                return self._create_result(AnalysisStatus.FAILURE, error=str(e))
        if file_data[:4] != b"\x7fELF":
            return self._create_result(AnalysisStatus.SKIPPED,
                                       error="Not an ELF file (rev_triage is ELF-only)")

        warnings: List[str] = []
        mit = F.checksec(file_path, warnings=warnings)
        syms = F.symbols(file_path, file_data, warnings)
        static = bool(mit.get("static"))
        role = F.classify_role(file_path, file_data, static)
        secs = F.section_names(file_path)
        strings = F.ascii_strings(file_data, min_len=5)
        # Honest "stripped" for RE: a dynamic binary keeps its dynamic symbols
        # (imports) even when .symtab is stripped, so pwntools' symbol-count check
        # reports it as not-stripped. For reversing, what matters is whether
        # user-function *names* survive -> judge by .symtab (or missing sections).
        stripped = (".symtab" not in secs) if secs else True
        mit["stripped"] = stripped  # honest value flows to handoff/orientation too

        toolchain = F.detect_toolchain(file_path, strings, secs, syms)
        packer = F.detect_packer(file_path, strings, secs)
        anti_debug = F.detect_anti_debug(syms, strings)
        ufuncs = F.user_functions(syms)
        libc = F.libc_fingerprint(strings, syms) if role == "library" else None
        str_cats = self._categorise_strings(strings)
        handoff = self._handoff(file_path, role, mit, toolchain, packer, ufuncs)

        fmt = {
            "arch": mit.get("arch"), "bits": mit.get("bits"), "endian": mit.get("endian"),
            "static": static, "stripped": stripped, "pie": mit.get("pie"),
            "buildid": mit.get("buildid"), "entry": mit.get("entry"),
        }
        functions = {
            "user_count": len(ufuncs),
            "sample": ufuncs[: self.max_sample],
            "total_defined": len(syms.get("defined", set())),
        }
        if stripped:
            functions["note"] = ("stripped (.symtab absent): no user function names. Load in "
                                 "Ghidra/radare2 and let auto-analysis recover functions; start at entry/main.")

        results = {
            "role": role,
            "format": fmt,
            "toolchain": toolchain,
            "packer": packer or None,
            "functions": functions,
            "anti_debug": anti_debug,
            "strings": {"total": len(strings), "categories": str_cats},
            "libc": libc,
            "handoff": handoff,
            "orientation": self._orientation(role, fmt, toolchain, packer, functions, anti_debug, libc),
        }
        return self._create_result(AnalysisStatus.SUCCESS, results=results, warnings=warnings)

    def _categorise_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        text = "\n".join(strings)
        out: Dict[str, List[str]] = {}
        for name, pat in REV_STRING_PATTERNS.items():
            seen, vals = set(), []
            for m in pat.finditer(text):
                v = m.group()
                if len(v) < 3 or v in seen:
                    continue
                seen.add(v)
                vals.append(v)
                if len(vals) >= self.max_sample:
                    break
            if vals:
                out[name] = vals
        return out

    @staticmethod
    def _handoff(file_path, role, mit, toolchain, packer, ufuncs) -> List[str]:
        name = file_path.name
        tips: List[str] = []
        if packer:
            if any("UPX" in p for p in packer):
                tips.append(f"unpack first: `upx -d {name}`")
            else:
                tips.append("section headers look stripped/packed — identify the packer before RE")
        tips.append(f"decompile: `ghidra` (import {name}, run auto-analysis) or `r2 -A {name}` / rizin")
        tips.append(f"quick disasm: `objdump -d {name} | less` (entry: {mit.get('entry')})")
        lang = (toolchain or {}).get("language")
        if lang == "Go":
            tips.append("Go binary: symbols live in .gopclntab — use a Go-aware loader "
                        "(Ghidra golang analyzer / IDA golang) or `GoReSym`")
        elif lang == "Rust":
            tips.append("Rust binary: demangle with `rustfilt` / rustc-demangle; expect heavy monomorphised generics")
        elif lang == "C++":
            tips.append("C++: demangle with `c++filt`; recover vtables for class structure")
        if mit.get("stripped"):
            tips.append("stripped: no names — start at entry/main; Ghidra will auto-name FUN_*")
        return tips

    @staticmethod
    def _orientation(role, fmt, toolchain, packer, functions, anti_debug, libc) -> str:
        parts = []
        lang = (toolchain or {}).get("language") or "?"
        comp = (toolchain or {}).get("compiler")
        parts.append(f"{lang}{(' ' + comp) if comp else ''}")
        parts.append(f"{fmt.get('arch')}/{fmt.get('bits')}")
        flags = []
        if fmt.get("static"):
            flags.append("static")
        if fmt.get("pie"):
            flags.append("PIE")
        flags.append("stripped" if fmt.get("stripped") else "has-symbols")
        parts.append(" ".join(flags))
        if not fmt.get("stripped"):
            parts.append(f"{functions.get('user_count', 0)} user funcs")
        if packer:
            parts.append("PACKED:" + ",".join(packer))
        if anti_debug:
            parts.append(f"anti-debug ({len(anti_debug)})")
        if libc:
            parts.append(f"glibc {libc}")
        if role != "executable":
            parts.insert(0, f"({role})")   # parens, not [brackets]: rich eats [tags]
        return " | ".join(parts)

    def get_supported_types(self):
        return {"elf", "elf32", "elf64"}
