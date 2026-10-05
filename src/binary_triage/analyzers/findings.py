"""
findings - turn the neutral elf_facts / lens results into dashboard-style findings.

Same shape the team already reads from the Opengrep web dashboard: each finding is
severity + impact + a stable rule id + location + a plain-English note that says
*why it matters* and *which direction to go* (offense pointer + defensive patch).

Every rule fires on a general property any binary can have (like an Opengrep rule
firing across services) — not a recipe tuned to one challenge. This is what the
binary tool contributes for the "binary-only service, not analyzed - reverse it"
rows the source scanner can't touch.
"""

from typing import Any, Dict, List, Optional

SEV_RANK = {"ERROR": 0, "WARNING": 1, "INFO": 2}
IMPACT_RANK = {"rce": 0, "flag-leak": 1, "auth-bypass": 2, "memory-corruption": 3,
               "integrity": 4, "dos": 5, "info": 6}


def _f(sev, impact, rid, where, conf, msg) -> Dict[str, Any]:
    return {"severity": sev, "impact": impact, "id": rid, "where": where,
            "confidence": conf, "message": msg}


def build_findings(name: str, pwn: Dict[str, Any], rev: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Facts (pwn + optional rev results) -> ranked list of findings for one binary."""
    out: List[Dict[str, Any]] = []
    mit = pwn.get("mitigations", {}) or {}
    role = pwn.get("role", "executable")
    dangerous = pwn.get("dangerous_functions", []) or []
    dfns = {d["function"] for d in dangerous}
    input_fns = dfns & {"gets", "scanf", "__isoc99_scanf", "read", "strcpy", "strcat",
                        "sprintf", "vsprintf", "fgets", "memcpy"}

    # --- exploit mitigations (only meaningful for a linked executable image) ---
    if role == "executable":
        if mit.get("nx") is False:
            out.append(_f("ERROR", "rce", "nx-disabled", name, "HIGH",
                "NX is off (executable stack). Shellcode placed on the stack will run. "
                "Offense: overflow -> jump to stack shellcode. Patch: don't link with -z execstack."))
        if mit.get("canary") is False:
            sev = "ERROR" if input_fns else "WARNING"
            out.append(_f(sev, "memory-corruption", "no-stack-canary", name, "HIGH" if input_fns else "MEDIUM",
                "No stack canary: a stack overflow can overwrite the saved return address directly, "
                "no cookie to leak or forge" + (f" (and it reads input via {', '.join(sorted(input_fns))})." if input_fns else ".") +
                " Offense: cyclic pattern -> find the offset -> control RIP. Patch: -fstack-protector-strong."))
        if mit.get("pie") is False:
            out.append(_f("WARNING", "memory-corruption", "no-pie", name, "HIGH",
                "No PIE: the binary loads at a fixed base, so function and ROP-gadget addresses are "
                "static (no info leak needed). Makes ret2win / ROP much easier. Patch: -fPIE -pie."))
        relro = str(mit.get("relro", "")).lower()
        if relro in ("no", "none", "partial"):
            out.append(_f("INFO" if relro == "partial" else "WARNING", "memory-corruption", "relro-weak", name, "MEDIUM",
                f"{relro or 'no'} RELRO: the GOT is writable. A write primitive can overwrite a GOT entry "
                "to hijack control flow. Patch: -Wl,-z,relro,-z,now (Full RELRO)."))

    # --- behavioral: a function that calls system/exec* is a win target by behavior ---
    for t in (pwn.get("win_targets", []) or [])[:6]:
        out.append(_f("ERROR", "rce", "fn-calls-exec", f"{name}:{t['func']} @ {t['site']}", "HIGH",
            f"`{t['func']}()` calls `{t['callee']}` — a 'win' target by behavior (its name needn't say 'win'). "
            "Offense: if you can control RIP (see the overflow findings), return straight here for a shell/flag. "
            "Patch (your box): this is usually the intended bug — fix whatever lets RIP be controlled."))
    for s in (pwn.get("win_symbols", []) or [])[:6]:
        out.append(_f("WARNING", "rce", "win-named-symbol", f"{name}:{s}", "MEDIUM",
            f"Function named `{s}` looks like an intentional win/backdoor. Inspect it; it may hand out a shell or the flag."))

    # --- dangerous input / format functions (collapsed per rule, not per symbol) ---
    fmt_fns, scanf_seen = [], False
    for d in dangerous:
        fn = d["function"]
        if fn == "gets":
            out.append(_f("ERROR", "memory-corruption", "unbounded-input-gets", name, "HIGH",
                "`gets()` — unbounded stdin read into a fixed buffer: classic stack overflow. "
                "Offense: overflow to control RIP. Patch: replace with fgets(buf, sizeof buf, stdin)."))
        elif fn in ("strcpy", "strcat", "sprintf", "vsprintf"):
            out.append(_f("WARNING", "memory-corruption", f"unbounded-{fn}", name, "MEDIUM",
                f"`{fn}` writes without a length limit. If the source can exceed the destination -> overflow. "
                "Offense: check the call site's buffer size. Patch: snprintf / strlcpy / strncat with sizeof(dst)."))
        elif fn in ("scanf", "__isoc99_scanf", "sscanf"):
            if not scanf_seen:
                scanf_seen = True
                out.append(_f("WARNING", "memory-corruption", "scanf-no-width", name, "MEDIUM",
                    "`scanf` family — check for `%s` without a width specifier (unbounded). Patch: use a width, e.g. %63s."))
        elif fn in ("printf", "fprintf", "snprintf", "vsnprintf", "vfprintf", "syslog"):
            fmt_fns.append(fn)
    if fmt_fns:
        out.append(_f("WARNING", "memory-corruption", "format-string", name, "MEDIUM",
            f"printf-family present ({', '.join(sorted(set(fmt_fns)))}). If any call passes attacker input as the "
            "*format* string, that's an arbitrary read/write via %n/%s. Offense: look for printf(user). "
            "Patch: printf(\"%s\", user)."))

    heap = pwn.get("heap_functions", []) or []
    if "free" in heap and any(a in heap for a in ("malloc", "calloc", "realloc")):
        out.append(_f("INFO", "memory-corruption", "heap-allocator", name, "LOW",
            "Heap allocator in use (malloc + free). If any object is freed and later reused, look for "
            "use-after-free / double-free. Patch: null the pointer after free; avoid reuse."))

    if (pwn.get("interesting_strings", {}) or {}).get("shell"):
        out.append(_f("INFO", "rce", "shell-string", name, "MEDIUM",
            "`/bin/sh` string present — a ready argument for system()/execve() if you can reach one."))

    if pwn.get("network_facing"):
        calls = ", ".join(pwn.get("network_calls", [])) or "socket API"
        out.append(_f("INFO", "info", "network-facing", name, "HIGH",
            f"Network-facing: calls {calls}. This is the attacker-reachable service in the tree — "
            "attack/patch it before compute-only helpers. Trace input from the accept()/recv() path."))

    if mit.get("static"):
        out.append(_f("INFO", "info", "static-linked", name, "HIGH",
            "Statically linked: gadget-rich (whole libc inside) and no libc leak needed, but the dangerous "
            "functions above are 'present', not confirmed-called — disassemble to see which are actually used."))

    # --- rev-side observations (orientation) ---
    if rev:
        fmt = rev.get("format", {}) or {}
        for p in (rev.get("packer") or []):
            out.append(_f("WARNING", "info", "packed", name, "MEDIUM",
                f"Looks packed/obfuscated ({p}). Unpack before reversing (e.g. `upx -d`)."))
        if rev.get("anti_debug"):
            out.append(_f("INFO", "info", "anti-debug", name, "MEDIUM",
                "Anti-debug indicators: " + "; ".join(rev["anti_debug"]) + ". May hinder dynamic analysis / gdb."))
        if fmt.get("stripped"):
            out.append(_f("INFO", "info", "stripped", name, "HIGH",
                "Stripped (no symbol names). Load in Ghidra/radare2, run auto-analysis, start at entry/main."))

    out.sort(key=lambda f: (SEV_RANK.get(f["severity"], 3), IMPACT_RANK.get(f["impact"], 9)))
    return out


def counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    c = {"total": len(findings), "ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


# --------------------------------------------------------------------------- #
# Shared finding schema (schema/finding.v1.json) — the stable contract a
# downstream consumer (patch dashboard, merge step, or the Opengrep producer in
# Task 10) relies on. build_findings() stays the internal/dashboard shape;
# to_schema_findings() maps it to the versioned contract.
# --------------------------------------------------------------------------- #
SCHEMA_VERSION = "1.0"

_CONF_MAP = {"HIGH": "high", "MEDIUM": "med", "LOW": "low"}
_RULE_CLASS = {
    "nx-disabled": "weak-mitigation", "no-stack-canary": "weak-mitigation",
    "no-pie": "weak-mitigation", "relro-weak": "weak-mitigation",
    "fn-calls-exec": "command-exec", "shell-string": "command-exec",
    "win-named-symbol": "win-target",
    "unbounded-input-gets": "buffer-overflow", "scanf-no-width": "buffer-overflow",
    "format-string": "format-string",
    "heap-allocator": "heap-misuse",
    "network-facing": "network-facing",
    "static-linked": "triage-note", "packed": "triage-note",
    "anti-debug": "triage-note", "stripped": "triage-note",
}


def _finding_class(rule_id: str) -> str:
    if rule_id in _RULE_CLASS:
        return _RULE_CLASS[rule_id]
    if rule_id.startswith("unbounded-"):
        return "buffer-overflow"
    return "other"


def to_schema_findings(binary: str, internal: List[Dict[str, Any]],
                       triage_status: str = "scored", service: Optional[str] = None,
                       source: str = "bin-triage") -> List[Dict[str, Any]]:
    """Map internal/dashboard findings to schema/finding.v1.json finding records."""
    recs = []
    for f in internal:
        rid = f["id"]
        recs.append({
            "source": source,
            "service": service,
            "binary": binary,
            "finding_class": _finding_class(rid),
            "rule_id": rid,
            "location": f.get("where") or binary,
            "severity": f["severity"],
            "impact": f.get("impact", "info"),
            "confidence": _CONF_MAP.get(f.get("confidence", ""), "low"),
            "evidence": (f.get("message", "") or "")[:200],
            "triage_status": triage_status,
            "message": f.get("message", ""),
        })
    return recs


def schema_envelope(records: List[Dict[str, Any]], source: str = "bin-triage") -> Dict[str, Any]:
    import datetime
    return {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "findings": records,
    }
