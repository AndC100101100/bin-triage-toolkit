"""
elf_facts - the neutral fact-base for ELF binaries.

One extraction, read by every lens. The `pwn` lens (pwn_triage) and the `rev`
lens (rev_triage) are *views* over these facts; they must not run their own
separate engines. Anything here is a plain, static, offline observation about a
binary -- never a judgement, never a score. Judgements live in the lenses.

Engine preference (all local / offline, no AI):
  1. pwntools  (from pwn import ELF)
  2. readelf / nm / objdump / strings
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

try:
    from pwn import ELF, context as _pwn_context
    _pwn_context.log_level = "error"
    logging.getLogger("pwnlib").setLevel(logging.ERROR)
    PWNTOOLS_AVAILABLE = True
except Exception:  # pragma: no cover
    PWNTOOLS_AVAILABLE = False

# glibc / loader / libstdc++ / compiler-runtime symbols that flood static binaries
# and produce false "interesting symbol" hits. Filtered before any name matching.
LIBC_NOISE_RE = re.compile(
    r"^(_dl_|__?libc|__GI_|_IO_|__pthread|_nl_|__gconv|__gnu|__cxa|__gthread|"
    r"__tunable|__nptl|__vdso|__sysv|__assert|__register|register_tm|frame_dummy|"
    r"__do_global|__static_initialization|_ZNS|_ZNK|_ZSt|__cxxabi|_ZdlPv|_Znwm|"
    r"__intel_|__gmon|_init$|_fini$|_start$|__stack_chk|deregister_tm|__libc_csu)"
)


# --------------------------------------------------------------------------- #
# ELF structure helpers
# --------------------------------------------------------------------------- #
def is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def has_interp(path: Path) -> bool:
    """True if the ELF has a PT_INTERP => a (static-)dynamic executable, not a .so."""
    if PWNTOOLS_AVAILABLE:
        try:
            return bool(getattr(ELF(str(path), checksec=False), "linker", None))
        except Exception:
            pass
    try:
        out = subprocess.run(["readelf", "-l", str(path)],
                             capture_output=True, text=True, timeout=15).stdout
        return "INTERP" in out or "interpreter" in out
    except Exception:
        return True


def has_soname(path: Path) -> bool:
    """True if the ELF declares DT_SONAME (a real shared library, not a static-PIE exe)."""
    try:
        out = subprocess.run(["readelf", "-d", str(path)],
                             capture_output=True, text=True, timeout=15).stdout
        return "SONAME" in out
    except Exception:
        return False


def classify_role(file_path: Path, file_data: bytes, static: bool = False) -> str:
    """target executable vs shared library vs relocatable object vs provided solution."""
    e_type = int.from_bytes(file_data[16:18], "little") if len(file_data) >= 18 else 0
    name = file_path.name.lower()
    if e_type == 1 or name.endswith(".o"):
        return "relocatable"
    is_lib_name = bool(re.search(r"(^|/)(ld-|libc|libstdc\+\+|libm|libpthread|libdl|libgcc)[-.]", name)) \
        or name.endswith(".so") or ".so." in name or ".cpython-" in name
    if e_type == 3:  # ET_DYN -- PIE executables AND shared libraries
        if is_lib_name:
            return "library"
        if has_interp(file_path) or static:
            return "executable"
        return "library" if has_soname(file_path) else "executable"
    if is_lib_name:
        return "library"
    if re.search(r"(^|[._-])(solve|exploit|solution|poc|sol)([._-]|$)", name):
        return "solution?"
    return "executable"


def checksec(file_path: Path, checksec_path: str = "checksec",
             warnings: Optional[List[str]] = None) -> Dict[str, Any]:
    """Exploit mitigations + arch/linkage facts."""
    warnings = warnings if warnings is not None else []
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
                "buildid": (getattr(e, "buildid", None) or b"").hex() or None if hasattr(e, "buildid") else None,
                "entry": getattr(e, "entry", None),
            }
        except Exception as ex:  # pragma: no cover
            warnings.append(f"pwntools ELF parse failed: {ex}")
    try:
        import json as _json
        out = subprocess.run([checksec_path, "--file=" + str(file_path), "--format=json"],
                             capture_output=True, text=True, timeout=20)
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
    except Exception as ex:
        warnings.append(f"checksec fallback failed: {ex}")
        return {}


def symbols(file_path: Path, file_data: bytes,
            warnings: Optional[List[str]] = None) -> Dict[str, Set[str]]:
    """imports (dynamically-called), defined (all), functions (STT_FUNC/text)."""
    warnings = warnings if warnings is not None else []
    imports: Set[str] = set()
    defined: Set[str] = set()
    functions: Set[str] = set()
    if PWNTOOLS_AVAILABLE:
        try:
            e = ELF(str(file_path), checksec=False)
            imports |= set(getattr(e, "plt", {}) or {})
            imports |= {n for n, s in (getattr(e, "symbols", {}) or {}).items() if s == 0}
            defined |= {n for n in (getattr(e, "symbols", {}) or {})}
            functions |= {n for n in (getattr(e, "functions", {}) or {})}
            return {"imports": imports, "defined": defined, "functions": functions}
        except Exception as ex:  # pragma: no cover
            warnings.append(f"pwntools symbol read failed: {ex}")
    try:
        out = subprocess.run(["nm", "-D", "-u", str(file_path)],
                             capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            parts = line.split()
            if parts:
                imports.add(parts[-1])
    except Exception:
        pass
    try:
        out = subprocess.run(["nm", str(file_path)],
                             capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name, typ = parts[-1], parts[-2]
                defined.add(name)
                if typ in ("T", "t", "W", "w"):
                    functions.add(name)
    except Exception:
        pass
    return {"imports": imports, "defined": defined, "functions": functions}


def ascii_strings(data: bytes, min_len: int = 4, limit: int = 100000) -> List[str]:
    out, cur = [], bytearray()
    for byte in data:
        if 0x20 <= byte < 0x7F:
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
                if len(out) >= limit:
                    break
            cur = bytearray()
    if len(cur) >= min_len and len(out) < limit:
        out.append(cur.decode("ascii"))
    return out


# --------------------------------------------------------------------------- #
# rev-relevant observations (still neutral facts)
# --------------------------------------------------------------------------- #
def section_names(file_path: Path) -> Set[str]:
    try:
        out = subprocess.run(["readelf", "-S", str(file_path)],
                             capture_output=True, text=True, timeout=15).stdout
        return set(re.findall(r"\]\s+(\.[\w.\-]+)", out))
    except Exception:
        return set()


def comment_section(file_path: Path) -> str:
    try:
        out = subprocess.run(["readelf", "-p", ".comment", str(file_path)],
                             capture_output=True, text=True, timeout=15).stdout
        return out
    except Exception:
        return ""


def detect_toolchain(file_path: Path, strings_list: List[str], secs: Set[str],
                     syms: Dict[str, Set[str]]) -> Dict[str, Optional[str]]:
    """Best-effort language + compiler. Facts, lightly interpreted."""
    joined = "\n".join(strings_list[:20000])
    language = "C"  # default for a libc-linked ELF with none of the markers below
    if ".gopclntab" in secs or "Go build ID" in joined or "go1." in joined or \
            any(n.startswith("runtime.") for n in syms.get("functions", set())):
        language = "Go"
    elif "/rustc/" in joined or "RUST_BACKTRACE" in joined or "cargo" in joined or \
            "rust_begin_unwind" in syms.get("defined", set()):
        language = "Rust"
    elif "libstdc++" in joined or any(n.startswith(("_ZNSt", "_ZSt", "_ZNK")) for n in syms.get("defined", set())) or \
            "__cxa_throw" in (syms.get("imports", set()) | syms.get("defined", set())):
        language = "C++"
    # Compiler: trust the .comment section first; only then fall back to strings.
    # Versions must look real (N.N[.N]) so junk like "go4" in libc data can't match.
    compiler = None
    cre = re.compile(r"GCC:\s*\([^)]*\)\s*\d+\.\d+(?:\.\d+)?|clang version \d+\.\d+(?:\.\d+)?|"
                     r"rustc \d+\.\d+(?:\.\d+)?|go\d+\.\d+(?:\.\d+)?")
    for hay in (comment_section(file_path), joined):
        m = cre.search(hay)
        if m:
            compiler = m.group(0).replace("GCC: ", "GCC ").strip()
            break
    return {"language": language, "compiler": compiler}


def detect_packer(file_path: Path, strings_list: List[str], secs: Set[str]) -> List[str]:
    hits = []
    joined = "\n".join(strings_list[:5000])
    if "UPX!" in joined or {"UPX0", "UPX1"} & secs or "$Info: This file is packed with the UPX" in joined:
        hits.append("UPX")
    if ".upx" in " ".join(secs):
        hits.append("UPX")
    if not secs and not hits:
        hits.append("section headers stripped (possibly packed/obfuscated)")
    return sorted(set(hits))


# Anti-debug detection must distinguish *calling* a syscall from merely containing
# its symbol. A shared library (libc) EXPORTS ptrace/fork/personality; a statically
# linked binary BUNDLES them. Neither means the program uses them for anti-debug.
# So symbol hints are checked against IMPORTS only (functions the program calls);
# string hints are literal tokens the program references.
ANTI_DEBUG_SYMS = {
    "ptrace": "ptrace() self-attach / debugger check",
    "personality": "personality(ADDR_NO_RANDOMIZE) / anti-ASLR",
    "prctl": "prctl (may set PR_SET_DUMPABLE)",
}
ANTI_DEBUG_STRINGS = {
    "PTRACE_TRACEME": "PTRACE_TRACEME reference",
    "/proc/self/status": "reads /proc/self/status (TracerPid check)",
    "TracerPid": "TracerPid check",
    "/proc/self/stat": "reads /proc/self/stat",
}


def detect_anti_debug(syms: Dict[str, Set[str]], strings_list: List[str]) -> List[str]:
    imports = {n.split("@")[0] for n in syms.get("imports", set())}
    sset = set(strings_list)
    found = [d for k, d in ANTI_DEBUG_SYMS.items() if k in imports]
    found += [d for k, d in ANTI_DEBUG_STRINGS.items() if k in sset]
    return sorted(set(found))


_LIBC_VER_RE = re.compile(r"(?:GNU C Library|glibc).{0,40}?release version (\d+\.\d+)")
_LIBC_VER_RE2 = re.compile(r"GLIBC_(\d+\.\d+\.?\d*)")


def libc_fingerprint(strings_list: List[str], syms: Dict[str, Set[str]]) -> Optional[str]:
    """Extract a glibc version from a libc.so's own strings/versioned symbols."""
    joined = "\n".join(strings_list[:20000])
    m = _LIBC_VER_RE.search(joined)
    if m:
        return m.group(1)
    vers = sorted({v for n in syms.get("defined", set()) for v in _LIBC_VER_RE2.findall(n)},
                  key=lambda s: tuple(int(x) for x in s.split(".")))
    return vers[-1] if vers else None


def user_functions(syms: Dict[str, Set[str]]) -> List[str]:
    """Program-defined functions with libc/runtime noise filtered out."""
    funcs = syms.get("functions") or syms.get("defined") or set()
    return sorted(f for f in funcs if not LIBC_NOISE_RE.match(f))
