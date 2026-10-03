/*
 * ad_indicators.yar — Attack & Defense pwn indicators (NOT malware families).
 *
 * These flag exploitable surface in a benign-but-vulnerable service binary:
 * dangerous libc imports, shell strings, and CTF-style win/backdoor symbols.
 * Optional: pwn_triage already covers this via symbol parsing; this ruleset is
 * for teams that want a YARA pass too. Keep offline; no network.
 */

rule ad_dangerous_imports
{
    meta:
        description = "Imports classic memory-unsafe libc functions"
        category = "pwn-surface"
    strings:
        $gets   = "gets"
        $strcpy = "strcpy"
        $sprintf = "sprintf"
        $scanf  = "scanf"
        $system = "system"
    condition:
        uint32(0) == 0x464c457f and 2 of them
}

rule ad_shell_string
{
    meta:
        description = "Contains a shell path (ret2system / one_gadget target)"
        category = "pwn-surface"
    strings:
        $sh = "/bin/sh"
        $bash = "/bin/bash"
    condition:
        uint32(0) == 0x464c457f and any of them
}

rule ad_win_symbol
{
    meta:
        description = "CTF-style win/backdoor/flag symbol name present"
        category = "pwn-surface"
    strings:
        $w1 = "win"
        $w2 = "give_shell"
        $w3 = "backdoor"
        $w4 = "cat_flag"
        $w5 = "print_flag"
        $w6 = "getflag"
    condition:
        uint32(0) == 0x464c457f and any of them
}
