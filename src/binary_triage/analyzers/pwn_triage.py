"""
Pwn Triage lens - Attack & Defense exploitability VIEW over the elf_facts base.

This is a *lens*, not an engine: it reads the neutral fact-base from
`elf_facts` and renders the "how do I pop this / how worried should I be"
view -- dangerous called functions mapped to exploit primitives, win/backdoor
symbols, heap surface, and a ranked attack-surface score.

Static only. It points at the surface; it does NOT confirm a bug exists.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo
from . import elf_facts as F

# Re-export so existing imports (tests, CLI) keep working.
PWNTOOLS_AVAILABLE = F.PWNTOOLS_AVAILABLE
_is_elf = F.is_elf

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

HEAP_FUNCS = {"malloc", "calloc", "realloc", "free", "strdup", "strndup"}

# calling one of these makes a function a ret2win / ret2system target by behavior
EXEC_CALLEES = {"system", "execve", "execl", "execlp", "execvp", "execle", "posix_spawn", "popen"}

# BSD-socket symbols a network-facing service calls. Presence of these among the
# functions a binary actually calls marks it as the service worth attacking /
# patching first in a multi-ELF tree (vs a pure compute helper). These are symbol
# *names* we look for, not sockets this tool opens.
NET_SYMS = {"accept", "accept4", "listen", "bind", "recv", "recvfrom", "recvmsg",
            "socket", "socketpair", "getaddrinfo"}

WIN_SYMBOL_RE = re.compile(
    r"(^|_)(win|shell|backdoor|admin|debug|secret|flag|getflag|cat_?flag|give_?shell|magic|print_?flag)($|_)",
    re.IGNORECASE,
)

STRING_PATTERNS = {
    "shell": re.compile(rb"/bin/(?:sh|bash|dash)\b"),
    # Only a genuine flag reference: a path whose last component is flag-like
    # (/srv/flag, ./flag.txt) OR a CTF flag token (FLAG{...}). The old bare-word
    # pattern matched glibc printf-internal tables ("flag", "flags", "FLAGS_1.").
    "flag_path": re.compile(
        rb"\.?(?:/[\w.\-]+)*/[\w.\-]*flag[\w.\-]*"   # path whose last component is flag-like
        rb"|\w*flag\w*\{[^}\n]{1,80}\}",             # a FLAG{...} token
        re.IGNORECASE),
    "format_specifier": re.compile(rb"%(?:\d+\$)?[ -+#0]*\d*(?:\.\d+)?[hljztL]*[diouxXeEfFgGaAcspn%]"),
}


class PwnTriage(BaseAnalyzer):
    """A&D exploitability lens over elf_facts."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__("pwn_triage", config)
        self.checksec_path = self.config.get("checksec_path", "checksec")
        self.max_strings = self.config.get("max_strings", 40)
        # Recover actually-called functions in non-stripped static binaries via a
        # single objdump disassembly pass. Default on; set false if it's too slow
        # on a large service tree.
        self.static_calls = self.config.get("static_calls", True)

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
                                       error="Not an ELF file (pwn_triage is ELF-only)")

        warnings: List[str] = []
        mitigations = F.checksec(file_path, self.checksec_path, warnings)
        syms = F.symbols(file_path, file_data, warnings)
        static = bool(mitigations.get("static"))
        stripped = bool(mitigations.get("stripped"))
        role = F.classify_role(file_path, file_data, static)

        # Language matters for how to read this binary: Go/Rust link their runtime
        # statically and are memory-safe, so "imports" say little about real calls.
        secs = F.section_names(file_path)
        strings_list = F.ascii_strings(file_data, min_len=4, limit=20000)
        language = F.detect_toolchain(file_path, strings_list, secs, syms).get("language")

        # One objdump pass (when enabled) recovers which functions are *actually*
        # called — needed for static binaries (no PLT imports) and used to find
        # behavioral win targets for every executable.
        want_callees = set(EXEC_CALLEES)
        recover_static = static and not stripped and self.static_calls
        if recover_static:
            want_callees |= set(DANGEROUS_FUNCS) | HEAP_FUNCS
        all_sites = F.call_sites(file_path, want_callees) if role == "executable" else []
        win_targets = [s for s in all_sites if s["callee"] in EXEC_CALLEES]

        # Dynamic binary: imports (PLT/undefined) = functions it actually calls.
        # Static binary: no imports. Recover confirmed-called funcs from the
        # disassembly (honest: actual `call <fn>` sites, not bundled-libc presence).
        if static:
            call_names = {s["callee"] for s in all_sites} if recover_static else set()
        else:
            call_names = syms["imports"]
        dangerous = self._map_dangerous(call_names)
        heap_funcs, heap_risky = self._heap_surface(call_names)
        static_present = self._map_dangerous(syms["defined"]) if static else []

        # Network-facing: does it actually call the socket-server syscalls? This is
        # the signal for "which binary in the tree is the service" worth hitting first.
        net_calls = sorted({n.split("@")[0] for n in call_names} & NET_SYMS)
        network_facing = bool(net_calls)

        win_candidates = syms["functions"] or syms["defined"]
        user_funcs = {s for s in win_candidates if not F.LIBC_NOISE_RE.match(s)}
        win_syms = sorted(s for s in user_funcs if WIN_SYMBOL_RE.search(s))
        strings = self._pwn_strings(file_data)

        score, drivers = self._score(mitigations, dangerous, win_syms, win_targets,
                                     strings, heap_risky, network_facing)
        verdict = self._verdict(score)

        # Triage status: can this be *scored* from static facts, or does it need a
        # manual look? Static/stripped/Go/Rust binaries don't expose their real
        # call surface to static import analysis, so they must not sink below
        # scored C binaries in the ranking — they go in a separate "needs-manual"
        # bucket at the top instead. (We do NOT invent scores from bundled libc.)
        triage_status, triage_reason = self._triage_status(
            role, static, stripped, language, recovered=recover_static)

        results = {
            "role": role,
            "language": language,
            "triage_status": triage_status,
            "triage_reason": triage_reason,
            "network_facing": network_facing,
            "network_calls": net_calls,
            "mitigations": mitigations,
            "dangerous_functions": dangerous,
            "heap_functions": heap_funcs,
            "win_symbols": win_syms,
            "win_targets": win_targets,
            "interesting_strings": strings,
            "exploitability": {
                "score": score,
                "verdict": verdict,
                "drivers": drivers,
                "summary": self._summary(mitigations, dangerous, win_syms, win_targets, strings, verdict, role),
                "caveat": self.CAVEAT,
            },
            "engine": "pwntools" if F.PWNTOOLS_AVAILABLE else "fallback",
        }
        if static:
            results["static_present_functions"] = static_present
            results["static_note"] = (
                "statically linked: libc is bundled, so dangerous/heap functions are "
                "reported as 'present' (unconfirmed), not scored. Disassemble to see which "
                "are actually called, e.g. `objdump -d <bin> | grep -E 'call|bl '`."
            )
        if role == "library":
            # The one in-tool SCA slice: fingerprint the libc version so the
            # References table can pair it with targets for ret2libc / one_gadget.
            results["libc_version"] = F.libc_fingerprint(F.ascii_strings(file_data, min_len=5), syms)
        status = AnalysisStatus.SUCCESS if mitigations else AnalysisStatus.PARTIAL_SUCCESS
        return self._create_result(status, results=results, warnings=warnings)

    # ----- triage status (scorable vs needs-manual) -----
    @staticmethod
    def _triage_status(role, static, stripped, language, recovered=False):
        """Return ('scored'|'needs-manual', [reasons]). Only linked executables are
        ever 'scored'; anything whose real call surface is invisible to static
        import analysis is flagged for a manual look so it isn't buried."""
        if role != "executable":
            return "scored", []  # libraries/objects are handled as references, not ranked
        reasons = []
        if language in ("Go", "Rust"):
            reasons.append(f"{language} (memory-safe runtime, statically linked; "
                           "imports don't reflect the real call surface)")
        if static and stripped:
            reasons.append("static + stripped (no symbols — called functions unrecoverable)")
        elif static:
            reasons.append("statically linked" + (
                " (dangerous funcs below are confirmed-called via disassembly, not imports)"
                if recovered else " (symbols stripped from .plt; disassemble to confirm calls)"))
        elif stripped:
            reasons.append("stripped (.symtab removed — function names gone)")
        return ("needs-manual" if reasons else "scored"), reasons

    # ----- dangerous-function mapping -----
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
    def _score(self, mit, dangerous, win_syms, win_targets, strings, heap_risky=False,
               network_facing=False):
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
        # Behavioral win (a function that actually calls system/exec*) is a strong,
        # reusable signal: full weight. A win-*named* symbol is only a jeopardy-CTF
        # convention — real ECSC/FAUST services use realistic names, so it rarely
        # fires and must not drive the score; downweighted and labelled as such.
        if win_targets:
            tgt = win_targets[0]
            add(20, f"ret2win target: {tgt['func']}() calls {tgt['callee']}")
        if win_syms:
            add(8, f"jeopardy-style symbol name(s): {', '.join(win_syms[:3])} (weak signal)")
        if heap_risky:
            add(8, "heap allocator in use (review UAF / double-free / heap overflow)")
        if strings.get("shell"):
            add(8, "/bin/sh string present")
        if network_facing:
            add(5, "network-facing (calls listen/accept/recv) — attacker-reachable surface")

        return min(score, 100), drivers

    CAVEAT = ("static attack-surface only — a LOW/MINIMAL score does NOT mean safe; "
              "logic/UAF/crypto bugs are invisible here. If you have the source, triage it "
              "with Opengrep first; use this for stripped/no-source binaries + checksec/diff.")

    @staticmethod
    def _verdict(score: int) -> str:
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "MINIMAL"

    @staticmethod
    def _summary(mit, dangerous, win_syms, win_targets, strings, verdict, role="executable") -> str:
        bits = []
        if role != "executable":
            bits.append(f"({role})")
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
        elif win_targets:
            bits.append("ret2win: " + ", ".join(sorted({t["func"] for t in win_targets})[:3]))
        return f"[{verdict}] " + " | ".join(bits)

    def get_supported_types(self) -> Set[str]:
        return {"elf", "elf32", "elf64"}
