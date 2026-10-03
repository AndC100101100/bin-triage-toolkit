"""
Pwn Triage - Attack & Defense oriented ELF exploitability triage.

This is the A&D counterpart to the malware-oriented analyzers: instead of
"is this malicious", it answers "how do I pop this service binary, and how
worried should I be about mine". It reports exploit mitigations (checksec),
maps dangerous imported functions to exploit primitives, finds pwn-relevant
strings (/bin/sh, flag paths), and produces a ranked exploitability score.

Engine preference (all local / offline, no AI):
  1. pwntools  (from pwn import ELF)  -- our day-of exploit library, most reliable
  2. checksec  (shelled out)          -- mitigation fallback
  3. readelf / nm / objdump           -- last-resort symbol/mitigation parsing
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)

try:
    # pwntools is noisy by default; keep it quiet and import lazily-safe.
    from pwn import ELF, context as _pwn_context
    _pwn_context.log_level = "error"
    PWNTOOLS_AVAILABLE = True
except Exception:  # pragma: no cover - env without pwntools
    PWNTOOLS_AVAILABLE = False


# Dangerous libc functions -> (exploit primitive, weight, note)
DANGEROUS_FUNCS: Dict[str, Dict[str, Any]] = {
    "gets":      {"primitive": "stack buffer overflow", "weight": 25, "note": "unbounded stdin read -> classic BOF"},
    "strcpy":    {"primitive": "buffer overflow",       "weight": 15, "note": "no bounds check"},
    "strcat":    {"primitive": "buffer overflow",       "weight": 12, "note": "no bounds check"},
    "sprintf":   {"primitive": "buffer overflow",       "weight": 15, "note": "unbounded formatted write"},
    "vsprintf":  {"primitive": "buffer overflow",       "weight": 15, "note": "unbounded formatted write"},
    "scanf":     {"primitive": "buffer overflow",       "weight": 12, "note": "check for %s without width"},
    "__isoc99_scanf": {"primitive": "buffer overflow",  "weight": 12, "note": "check for %s without width"},
    "sscanf":    {"primitive": "buffer overflow",       "weight": 8,  "note": "check for %s without width"},
    "read":      {"primitive": "overflow (len-controlled)", "weight": 8, "note": "review size arg vs buffer"},
    "memcpy":    {"primitive": "overflow (len-controlled)", "weight": 8, "note": "review size arg"},
    "alloca":    {"primitive": "stack clash",           "weight": 6,  "note": "attacker-sized stack alloc"},
    "system":    {"primitive": "ret2system / command exec", "weight": 15, "note": "/bin/sh one-shot if reachable"},
    "execve":    {"primitive": "command exec",          "weight": 12, "note": "direct exec"},
    "execl":     {"primitive": "command exec",          "weight": 12, "note": "direct exec"},
    "execlp":    {"primitive": "command exec",          "weight": 12, "note": "direct exec"},
    "popen":     {"primitive": "command exec",          "weight": 12, "note": "shell pipe"},
    "mprotect":  {"primitive": "RWX / shellcode",       "weight": 8,  "note": "can mark memory executable"},
    "mmap":      {"primitive": "RWX / shellcode",       "weight": 6,  "note": "check PROT_EXEC usage"},
    "printf":    {"primitive": "format string (maybe)", "weight": 8,  "note": "flag if format arg is user-controlled"},
    "fprintf":   {"primitive": "format string (maybe)", "weight": 6,  "note": "flag if format arg is user-controlled"},
    "snprintf":  {"primitive": "format string (maybe)", "weight": 5,  "note": "flag if format arg is user-controlled"},
    "vsnprintf": {"primitive": "format string (maybe)", "weight": 5,  "note": "flag if format arg is user-controlled"},
    "vfprintf":  {"primitive": "format string (maybe)", "weight": 5,  "note": "flag if format arg is user-controlled"},
    "syslog":    {"primitive": "format string (maybe)", "weight": 5,  "note": "flag if format arg is user-controlled"},
}

# Heap allocator functions — presence (esp. free + alloc) means UAF/double-free/
# heap-overflow surface. Ubiquitous, so informational + a small score bump only.
HEAP_FUNCS = {"malloc", "calloc", "realloc", "free", "strdup", "strndup"}

# Symbol names that smell like intentional win/backdoor functions (CTF staple)
WIN_SYMBOL_RE = re.compile(
    r"(^|_)(win|shell|backdoor|admin|debug|secret|flag|getflag|cat_?flag|give_?shell|magic|print_?flag)($|_)",
    re.IGNORECASE,
)

# pwn-relevant strings
STRING_PATTERNS = {
    "shell": re.compile(rb"/bin/(?:sh|bash|dash)\b"),
    "flag_path": re.compile(rb"(?:/[\w./-]*)?flag(?:[\w.]*)", re.IGNORECASE),
    "format_specifier": re.compile(rb"%(?:\d+\$)?[ -+#0]*\d*(?:\.\d+)?[hljztL]*[diouxXeEfFgGaAcspn%]"),
}


class PwnTriage(BaseAnalyzer):
    """A&D exploitability triage for ELF service binaries."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("pwn_triage", config)
        self.checksec_path = self.config.get("checksec_path", "checksec")
        self.max_strings = self.config.get("max_strings", 40)

    def can_analyze(self, file_info: FileInfo) -> bool:
        if file_info.file_type:
            return "elf" in file_info.file_type.lower() or "executable" in file_info.file_type.lower() or "shared object" in file_info.file_type.lower()
        # Fall back to magic bytes if the file type was not identified
        return _is_elf(file_info.path)

    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        if file_data is None:
            try:
                file_data = file_path.read_bytes()
            except OSError as e:
                return self._create_result(AnalysisStatus.FAILURE, error=str(e))

        if not file_data[:4] == b"\x7fELF":
            return self._create_result(
                AnalysisStatus.SKIPPED,
                error="Not an ELF file (pwn_triage is ELF-only)",
            )

        warnings: List[str] = []
        mitigations = self._checksec(file_path, warnings)
        symbols = self._symbols(file_path, file_data, warnings)
        all_names = symbols["imports"] | symbols["defined"]
        dangerous = self._map_dangerous(all_names)
        heap_funcs, heap_risky = self._heap_surface(all_names)
        win_syms = sorted(s for s in symbols["defined"] if WIN_SYMBOL_RE.search(s))
        strings = self._pwn_strings(file_data)

        score, drivers = self._score(mitigations, dangerous, win_syms, strings, heap_risky)
        verdict = self._verdict(score)

        results = {
            "mitigations": mitigations,
            "dangerous_functions": dangerous,
            "heap_functions": heap_funcs,
            "win_symbols": win_syms,
            "interesting_strings": strings,
            "exploitability": {
                "score": score,
                "verdict": verdict,
                "drivers": drivers,
                "summary": self._summary(mitigations, dangerous, win_syms, strings, verdict),
                "caveat": self.CAVEAT,
            },
            "engine": "pwntools" if PWNTOOLS_AVAILABLE else "fallback",
        }
        status = AnalysisStatus.SUCCESS if mitigations else AnalysisStatus.PARTIAL_SUCCESS
        return self._create_result(status, results=results, warnings=warnings)

    # ----- mitigations (checksec) -----
    def _checksec(self, file_path: Path, warnings: List[str]) -> Dict[str, Any]:
        if PWNTOOLS_AVAILABLE:
            try:
                e = ELF(str(file_path), checksec=False)
                relro = getattr(e, "relro", None)
                return {
                    "arch": getattr(e, "arch", None),
                    "bits": getattr(e, "bits", None),
                    "endian": getattr(e, "endian", None),
                    "nx": bool(getattr(e, "nx", False)),
                    "pie": bool(getattr(e, "pie", False)),
                    "canary": bool(getattr(e, "canary", False)),
                    "relro": (relro or "No").title() if isinstance(relro, str) else ("Full" if relro else "No"),
                    "fortify": bool(getattr(e, "fortify", False)),
                    "stripped": not bool(getattr(e, "symbols", {})),
                    "static": bool(getattr(e, "statically_linked", False)),
                    "rpath": getattr(e, "rpath", None),
                    "runpath": getattr(e, "runpath", None),
                }
            except Exception as e:  # pragma: no cover
                warnings.append(f"pwntools ELF parse failed: {e}")
        # checksec fallback
        try:
            out = subprocess.run(
                [self.checksec_path, "--file=" + str(file_path), "--format=json"],
                capture_output=True, text=True, timeout=20,
            )
            import json as _json
            data = _json.loads(out.stdout or "{}")
            item = next(iter(data.values())) if data else {}
            return {
                "nx": item.get("nx") == "yes",
                "pie": "yes" in str(item.get("pie", "")).lower(),
                "canary": item.get("canary") == "yes",
                "relro": str(item.get("relro", "no")).title(),
                "fortify": item.get("fortify") == "yes",
                "stripped": None, "static": None,
            }
        except Exception as e:
            warnings.append(f"checksec fallback failed: {e}")
            return {}

    # ----- symbols / imports -----
    def _symbols(self, file_path: Path, file_data: bytes, warnings: List[str]) -> Dict[str, Set[str]]:
        imports: Set[str] = set()
        defined: Set[str] = set()
        if PWNTOOLS_AVAILABLE:
            try:
                e = ELF(str(file_path), checksec=False)
                imports |= set(getattr(e, "plt", {}) or {})
                imports |= {n for n, s in (getattr(e, "symbols", {}) or {}).items() if s == 0}
                defined |= {n for n in (getattr(e, "symbols", {}) or {})}
                return {"imports": imports, "defined": defined}
            except Exception as e:  # pragma: no cover
                warnings.append(f"pwntools symbol read failed: {e}")
        # nm / objdump fallback
        for cmd in (["nm", "-D", str(file_path)], ["objdump", "-T", str(file_path)]):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                for line in out.stdout.splitlines():
                    parts = line.split()
                    if parts:
                        imports.add(parts[-1])
            except Exception:
                continue
        return {"imports": imports, "defined": defined}

    @staticmethod
    def _normalize(name: str):
        """Strip FORTIFY/isoc99 wrappers: __sprintf_chk->sprintf, __isoc99_scanf->scanf."""
        base = name.split("@")[0]
        fortified = False
        if base.startswith("__isoc99_"):
            base = base[len("__isoc99_"):]
        if base.startswith("__") and base.endswith("_chk"):
            base, fortified = base[2:-4], True
        return base, fortified

    def _map_dangerous(self, names: Set[str]) -> List[Dict[str, Any]]:
        found, seen = [], set()
        for name in sorted(names):
            base, fortified = self._normalize(name)
            if base not in DANGEROUS_FUNCS or base in seen:
                continue
            seen.add(base)
            entry = {"function": base, **DANGEROUS_FUNCS[base]}
            if fortified:
                # FORTIFY blocks the easy cases (e.g. %n in writable mem); still worth a look.
                entry["weight"] = max(2, entry["weight"] // 2)
                entry["note"] += " (FORTIFY-wrapped; review size/fmt args)"
                entry["fortified"] = True
            found.append(entry)
        return found

    @staticmethod
    def _heap_surface(names: Set[str]):
        present = sorted(n.split("@")[0] for n in names if n.split("@")[0] in HEAP_FUNCS)
        risky = "free" in present and any(a in present for a in ("malloc", "calloc", "realloc"))
        return present, risky

    def _pwn_strings(self, data: bytes) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for name, pat in STRING_PATTERNS.items():
            seen, vals = set(), []
            for m in pat.finditer(data):
                v = m.group().decode("latin-1", "replace")
                if v not in seen:
                    seen.add(v)
                    vals.append(v)
                if len(vals) >= self.max_strings:
                    break
            if vals:
                out[name] = vals
        return out

    # ----- scoring -----
    def _score(self, mit, dangerous, win_syms, strings, heap_risky=False):
        score = 0
        drivers: List[str] = []

        def add(points, why):
            nonlocal score
            score += points
            drivers.append(why)

        if mit.get("nx") is False:
            add(20, "NX disabled (executable stack -> shellcode)")
        if mit.get("canary") is False:
            add(15, "no stack canary")
        if mit.get("pie") is False:
            add(15, "no PIE (fixed addresses)")
        relro = str(mit.get("relro", "")).lower()
        if relro in ("no", "none", "partial"):
            add(5 if relro == "partial" else 8, f"{relro or 'no'} RELRO (GOT overwrite)")
        if mit.get("static"):
            add(5, "statically linked (gadget-rich)")

        for d in dangerous:
            add(d["weight"], f"imports {d['function']} -> {d['primitive']}")
        if win_syms:
            add(20, f"win/backdoor symbol(s): {', '.join(win_syms[:3])}")
        if heap_risky:
            add(8, "heap allocator in use (review UAF / double-free / heap overflow)")
        if strings.get("shell"):
            add(8, "/bin/sh string present")

        return min(score, 100), drivers

    # A score is an attack-SURFACE indicator, not a verdict. Static import/mitigation
    # analysis cannot see logic, UAF, or crypto bugs — exactly the ones A&D hosts favor
    # (see the A&D toolkit's corpus notes). A low score never means "safe".
    CAVEAT = ("static attack-surface only — a LOW/MINIMAL score does NOT mean safe; "
              "logic/UAF/crypto bugs are invisible here. If you have the source, triage it "
              "with Opengrep first; use this for stripped/no-source binaries + checksec/diff.")

    @staticmethod
    def _verdict(score: int) -> str:
        """Attack-surface band, not an exploitability guarantee."""
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def _summary(mit, dangerous, win_syms, strings, verdict) -> str:
        bits = []
        if mit:
            flags = []
            flags.append("NX" if mit.get("nx") else "no-NX")
            flags.append("PIE" if mit.get("pie") else "no-PIE")
            flags.append("canary" if mit.get("canary") else "no-canary")
            flags.append(f"{mit.get('relro', '?')}-RELRO")
            if mit.get("stripped"):
                flags.append("stripped")
            if mit.get("static"):
                flags.append("static")
            bits.append(" ".join(flags))
        if dangerous:
            bits.append("danger: " + ", ".join(sorted({d["function"] for d in dangerous})))
        if win_syms:
            bits.append("win: " + ", ".join(win_syms[:3]))
        return f"[{verdict}] " + " | ".join(bits)

    def get_supported_types(self) -> Set[str]:
        return {"elf", "elf32", "elf64"}


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False
