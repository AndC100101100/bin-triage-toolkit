"""
Binary Triage Toolkit - Main CLI application
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.markup import escape

from .analyzers.findings import (
    build_findings, counts as finding_counts, to_schema_findings, schema_envelope,
)

from .analyzers import (
    FileIdentifier,
    YaraScanner,
    CapaAnalyzer,
    StringExtractor,
    PEAnalyzer,
    ELFAnalyzer,
    PwnTriage,
    RevTriage,
    BinDiff,
    FileInfo,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for pretty output
console = Console()


class BinaryTriage:
    """Main binary triage orchestrator"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize binary triage
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize analyzers
        self.analyzers = {
            "file_identifier": FileIdentifier(self.config.get("file_identifier")),
            "yara_scanner": YaraScanner(self.config.get("yara_scanner")),
            "capa_analyzer": CapaAnalyzer(self.config.get("capa_analyzer")),
            "string_extractor": StringExtractor(self.config.get("string_extractor")),
            "pe_analyzer": PEAnalyzer(self.config.get("pe_analyzer")),
            "elf_analyzer": ELFAnalyzer(self.config.get("elf_analyzer")),
            "pwn_triage": PwnTriage(self.config.get("pwn_triage")),
        }
    
    def analyze_file(
        self,
        file_path: Path,
        modules: Optional[List[str]] = None,
        quick: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze a binary file
        
        Args:
            file_path: Path to file to analyze
            modules: List of specific modules to run (None = all)
            quick: Quick mode (only file_identifier and yara_scanner)
            
        Returns:
            Dictionary with analysis results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Create file info
        file_info = FileInfo.from_path(file_path)
        
        # Read file data once
        file_data = file_path.read_bytes()
        
        # Determine which analyzers to run
        if quick:
            analyzers_to_run = ["file_identifier", "yara_scanner"]
        elif modules:
            analyzers_to_run = modules
        else:
            analyzers_to_run = list(self.analyzers.keys())
        
        # Run analyzers
        results = {
            "file_info": {
                "path": str(file_path),
                "name": file_info.name,
                "size": file_info.size,
                "sha256": file_info.sha256,
                "md5": file_info.md5,
                "sha1": file_info.sha1,
            },
            "analyzers": {}
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for analyzer_name in analyzers_to_run:
                if analyzer_name not in self.analyzers:
                    console.print(f"[yellow]Warning: Unknown analyzer '{analyzer_name}'[/yellow]")
                    continue
                
                analyzer = self.analyzers[analyzer_name]
                
                task = progress.add_task(f"Running {analyzer_name}...", total=None)
                
                try:
                    # Update file_info with results from file_identifier
                    if analyzer_name == "file_identifier":
                        result = analyzer.analyze(file_path, file_data)
                        if result.is_successful():
                            file_info.file_type = result.results.get("file_type")
                            file_info.mime_type = result.results.get("mime_type")
                            file_info.magic = result.results.get("magic_type")
                    
                    # Check if analyzer can process this file
                    elif not analyzer.can_analyze(file_info):
                        progress.update(task, description=f"[yellow]Skipping {analyzer_name} (unsupported file type)[/yellow]")
                        continue
                    else:
                        result = analyzer.analyze(file_path, file_data)
                    
                    results["analyzers"][analyzer_name] = result.to_dict()
                    
                    if result.is_successful():
                        progress.update(task, description=f"[green]✓ {analyzer_name}[/green]")
                    else:
                        progress.update(task, description=f"[red]✗ {analyzer_name}[/red]")
                
                except Exception as e:
                    logger.exception(f"Analyzer {analyzer_name} failed: {e}")
                    progress.update(task, description=f"[red]✗ {analyzer_name} (error)[/red]")
                    results["analyzers"][analyzer_name] = {
                        "analyzer": analyzer_name,
                        "status": "failure",
                        "error": str(e)
                    }
        
        return results


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Binary Triage Toolkit - Automated binary analysis and triage"""
    pass


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--modules', '-m', multiple=True, help='Specific modules to run (can be used multiple times)')
@click.option('--quick', '-q', is_flag=True, help='Quick mode (only file identification and YARA)')
@click.option('--format', '-f', type=click.Choice(['json', 'markdown', 'table']), default='table', help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file (default: stdout)')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file')
def analyze(file_path: str, modules: tuple, quick: bool, format: str, output: Optional[str], config: Optional[str]):
    """Analyze a binary file"""
    
    try:
        # Load config if provided
        triage_config = {}
        if config:
            import yaml
            with open(config) as f:
                triage_config = yaml.safe_load(f)
        
        # Create triage instance
        triage = BinaryTriage(triage_config)
        
        # Analyze file
        console.print(f"\n[bold blue]Analyzing:[/bold blue] {file_path}\n")
        
        results = triage.analyze_file(
            Path(file_path),
            modules=list(modules) if modules else None,
            quick=quick
        )
        
        # Format output
        if format == 'json':
            output_text = json.dumps(results, indent=2)
        elif format == 'markdown':
            output_text = format_markdown(results)
        else:  # table
            display_table_results(results)
            return
        
        # Write output
        if output:
            Path(output).write_text(output_text)
            console.print(f"\n[green]Results written to:[/green] {output}")
        else:
            console.print(output_text)
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--pattern', '-p', default='*', help='File pattern to match (e.g., *.exe)')
@click.option('--recursive', '-r', is_flag=True, help='Scan recursively')
@click.option('--output', '-o', type=click.Path(), required=True, help='Output directory for results')
def batch(directory: str, pattern: str, recursive: bool, output: str):
    """Analyze multiple files in a directory"""
    
    try:
        dir_path = Path(directory)
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Find files
        if recursive:
            files = list(dir_path.rglob(pattern))
        else:
            files = list(dir_path.glob(pattern))
        
        console.print(f"\n[bold blue]Found {len(files)} files to analyze[/bold blue]\n")
        
        # Create triage instance
        triage = BinaryTriage()
        
        # Analyze each file
        for file_path in files:
            if not file_path.is_file():
                continue
            
            console.print(f"[cyan]Analyzing:[/cyan] {file_path.name}")
            
            try:
                results = triage.analyze_file(file_path)
                
                # Save results
                result_file = output_path / f"{file_path.name}.json"
                result_file.write_text(json.dumps(results, indent=2))
                
            except Exception as e:
                console.print(f"[red]Error analyzing {file_path.name}:[/red] {e}")
        
        console.print(f"\n[green]Batch analysis complete. Results saved to:[/green] {output_path}")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def display_table_results(results: Dict[str, Any]) -> None:
    """Display results in table format"""
    
    # File info panel
    file_info = results["file_info"]
    file_panel = Panel(
        f"[bold]Name:[/bold] {file_info['name']}\n"
        f"[bold]Size:[/bold] {file_info['size']:,} bytes\n"
        f"[bold]SHA256:[/bold] {file_info['sha256']}\n"
        f"[bold]MD5:[/bold] {file_info['md5']}",
        title="[bold cyan]File Information[/bold cyan]",
        border_style="cyan"
    )
    console.print(file_panel)
    console.print()
    
    # Analyzer results
    for analyzer_name, analyzer_result in results["analyzers"].items():
        status = analyzer_result.get("status", "unknown")
        
        # Status color
        if status == "success":
            status_color = "green"
            status_icon = "✓"
        elif status == "partial_success":
            status_color = "yellow"
            status_icon = "⚠"
        elif status == "failure":
            status_color = "red"
            status_icon = "✗"
        else:
            status_color = "gray"
            status_icon = "○"
        
        # Create table for this analyzer
        table = Table(title=f"[bold]{analyzer_name.replace('_', ' ').title()}[/bold]", show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value")
        
        # Add status
        table.add_row("Status", f"[{status_color}]{status_icon} {status}[/{status_color}]")
        
        # Add key results
        analyzer_results = analyzer_result.get("results", {})
        
        if analyzer_name == "yara_scanner":
            if matches := analyzer_results.get("rules"):
                table.add_row("Matches", f"{len(matches)} rules")
                table.add_row("Rules", ", ".join(matches[:5]) + ("..." if len(matches) > 5 else ""))
            if families := analyzer_results.get("families"):
                table.add_row("Families", ", ".join(families))
        
        elif analyzer_name == "capa_analyzer":
            if rules := analyzer_results.get("rules"):
                table.add_row("Capabilities", f"{len(rules)} detected")
            if mitre := analyzer_results.get("mitre_attack"):
                table.add_row("MITRE ATT&CK", f"{len(mitre)} techniques")
        
        elif analyzer_name == "string_extractor":
            counts = analyzer_results.get("string_count", {})
            table.add_row("ASCII Strings", str(counts.get("ascii", 0)))
            table.add_row("Unicode Strings", str(counts.get("unicode", 0)))
            
            iocs = analyzer_results.get("iocs", {})
            if urls := iocs.get("urls"):
                table.add_row("URLs", str(len(urls)))
            if ips := iocs.get("ips"):
                table.add_row("IPs", str(len(ips)))
        
        elif analyzer_name == "file_identifier":
            if file_type := analyzer_results.get("file_type"):
                table.add_row("Type", file_type)
            if mime := analyzer_results.get("mime_type"):
                table.add_row("MIME", mime)
        
        elif analyzer_name == "pe_analyzer":
            if pefile_data := analyzer_results.get("pefile"):
                if machine := pefile_data.get("machine"):
                    table.add_row("Architecture", machine)
                if sections := pefile_data.get("sections"):
                    table.add_row("Sections", str(len(sections)))
            if die_data := analyzer_results.get("die"):
                if packer := die_data.get("packer"):
                    table.add_row("Packer", packer)
                if compiler := die_data.get("compiler"):
                    table.add_row("Compiler", compiler)
        
        elif analyzer_name == "elf_analyzer":
            if header := analyzer_results.get("header"):
                if machine := header.get("machine"):
                    table.add_row("Architecture", machine)
                if elf_type := header.get("type"):
                    table.add_row("Type", elf_type)
            if security := analyzer_results.get("security"):
                sec_features = [k for k, v in security.items() if v]
                if sec_features:
                    table.add_row("Security", ", ".join(sec_features))
        
        # Add error if present
        if error := analyzer_result.get("error"):
            table.add_row("Error", f"[red]{error}[/red]")
        
        console.print(table)
        console.print()


def format_markdown(results: Dict[str, Any]) -> str:
    """Format results as markdown"""
    
    md = "# Binary Triage Report\n\n"
    
    # File info
    file_info = results["file_info"]
    md += "## File Information\n\n"
    md += f"- **Name:** {file_info['name']}\n"
    md += f"- **Size:** {file_info['size']:,} bytes\n"
    md += f"- **SHA256:** `{file_info['sha256']}`\n"
    md += f"- **MD5:** `{file_info['md5']}`\n\n"
    
    # Analyzer results
    md += "## Analysis Results\n\n"
    
    for analyzer_name, analyzer_result in results["analyzers"].items():
        md += f"### {analyzer_name.replace('_', ' ').title()}\n\n"
        
        status = analyzer_result.get("status", "unknown")
        md += f"**Status:** {status}\n\n"
        
        if error := analyzer_result.get("error"):
            md += f"**Error:** {error}\n\n"
        
        analyzer_results = analyzer_result.get("results", {})
        
        if analyzer_results:
            md += "```json\n"
            md += json.dumps(analyzer_results, indent=2)
            md += "\n```\n\n"
    
    return md


# ---------------------------------------------------------------------------
# Attack & Defense commands
# ---------------------------------------------------------------------------
from .analyzers.pwn_triage import _is_elf  # noqa: E402


def _load_profile_config(profile: Optional[str], config_path: Optional[str]) -> Dict[str, Any]:
    """Load a settings file. Explicit --config wins; else a named --profile."""
    import yaml
    if config_path:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    if profile:
        # Look next to the package's config/ dir, then CWD.
        candidates = [
            Path(__file__).resolve().parents[2] / "config" / f"settings.{profile}.yaml",
            Path.cwd() / "config" / f"settings.{profile}.yaml",
        ]
        for c in candidates:
            if c.exists():
                with open(c) as f:
                    return yaml.safe_load(f) or {}
        console.print(f"[yellow]Profile '{profile}' not found; using defaults.[/yellow]")
    return {}


def _iter_elf_targets(paths, recursive: bool):
    """Expand files/dirs (incl. enochecker3 service trees) into ELF binaries,
    de-duplicated by content hash (repos often ship the same binary under both
    src/ and attachments/)."""
    import hashlib
    skip = {".git", "node_modules", "__pycache__", "docs"}
    seen_hashes = set()

    def _emit(f: Path):
        try:
            h = hashlib.sha256(f.read_bytes()).hexdigest()
        except OSError:
            return None
        if h in seen_hashes:
            return None
        seen_hashes.add(h)
        return f

    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if _is_elf(p) and _emit(p):
                yield p
        elif p.is_dir():
            walker = p.rglob("*") if recursive else p.glob("*")
            for f in sorted(walker):
                if any(part in skip for part in f.parts):
                    continue
                if f.is_file() and _is_elf(f) and _emit(f):
                    yield f


def _emit_exploit_skeleton(binary: Path, pwn_results: Dict[str, Any]) -> Path:
    """Write a ready-to-edit pwntools exploit skeleton next to the binary."""
    mit = pwn_results.get("mitigations", {})
    win = pwn_results.get("win_symbols", [])
    danger = [d["function"] for d in pwn_results.get("dangerous_functions", [])]
    out = binary.parent / f"{binary.name}_exploit.py"
    skeleton = f'''#!/usr/bin/env python3
# Auto-generated pwntools skeleton for {binary.name}
# Triage: {pwn_results.get("exploitability", {}).get("summary", "")}
# Mitigations: {mit}
# Dangerous funcs: {", ".join(danger) or "none found"}
# Win/backdoor symbols: {", ".join(win) or "none found"}
from pwn import *

context.binary = exe = ELF({str(binary.name)!r})
# context.log_level = "debug"

HOST, PORT = "TARGET_IP", 1337  # <-- fill from attack info (02/03)

def conn():
    return remote(HOST, PORT) if args.REMOTE else process(exe.path)

def main():
    io = conn()
    # --- offsets / gadgets -------------------------------------------------
    # cyclic(200) to find the offset, then set it:
    # offset = cyclic_find(0x6161616c)
    {"# win = exe.symbols[%r]" % win[0] if win else "# win = <address>"}
    # libc = ELF('./libc.so.6')  # if ret2libc; pin the exact libc
    # --- payload -----------------------------------------------------------
    payload = b"A" * 64
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
'''
    out.write_text(skeleton)
    return out


@cli.command()
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Recurse into directories / service trees")
@click.option("--emit-exploit", is_flag=True, help="Write a pwntools exploit skeleton per binary")
@click.option("--output", "-o", type=click.Path(), help="Directory to write per-binary JSON reports")
@click.option("--profile", default="ad", help="Settings profile (default: ad = offline/no-AI)")
@click.option("--config", "-c", type=click.Path(exists=True), help="Explicit config file (overrides --profile)")
@click.option("--format", "-f", "fmt", type=click.Choice(["table", "json"]), default="table",
              help="table (default) or json (schema/finding.v1.json envelope)")
def triage(targets, recursive, emit_exploit, output, profile, config, fmt):
    """A&D exploitability triage of ELF service binaries (ranked)."""
    cfg = _load_profile_config(profile, config)
    analyzer = PwnTriage(cfg.get("pwn_triage"))
    strings = StringExtractor({**(cfg.get("string_extractor") or {}), "extract_iocs": False, "extract_ad": True})

    binaries = list(_iter_elf_targets(targets, recursive))
    if not binaries:
        if fmt == "json":
            print(json.dumps(schema_envelope([]), indent=2))
        else:
            console.print("[yellow]No ELF binaries found in the given targets.[/yellow]")
        return

    out_dir = Path(output) if output else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    scored, needs_manual, references = [], [], []
    for b in binaries:
        res = analyzer.analyze(b)
        r = res.results
        role = r.get("role", "executable")
        expl = r.get("exploitability", {})
        score = expl.get("score", 0)
        if role != "executable":
            references.append((b, r, score))
        elif r.get("triage_status") == "needs-manual":
            needs_manual.append((b, r, score))
        else:
            scored.append((b, r, score))
        if out_dir:
            try:
                str_res = strings.analyze(b).results.get("ad_strings", {})
            except Exception:
                str_res = {}
            payload = {"file": str(b), "pwn_triage": r, "ad_strings": str_res}
            (out_dir / f"{b.name}.json").write_text(json.dumps(payload, indent=2, default=str))
        if emit_exploit and role == "executable" and score > 0:
            skel = _emit_exploit_skeleton(b, r)
            console.print(f"[green]exploit skeleton:[/green] {skel}")

    if fmt == "json":
        # Schema-conforming findings across all target executables (scored first,
        # then needs-manual), for a downstream dashboard / merge step.
        recs = []
        for b, r, _ in scored + needs_manual:
            fs = build_findings(b.name, r)
            recs.extend(to_schema_findings(b.name, fs,
                                           triage_status=r.get("triage_status", "scored")))
        print(json.dumps(schema_envelope(recs), indent=2, default=str))
        return

    # Needs-manual bucket (static / stripped / Go / Rust) goes ABOVE the ranked
    # targets: these can't be scored from static imports, so they must never sink
    # below a scored C binary just because their call surface is invisible here.
    if needs_manual:
        nm = Table(title="[bold yellow]⚠ Needs manual look — not scorable statically[/bold yellow]")
        for col in ("Binary", "Why", "Lang", "Arch", "NX", "PIE", "Canary", "Danger (if recovered)", "Win"):
            nm.add_column(col)
        needs_manual.sort(key=lambda x: x[2], reverse=True)
        for b, r, score in needs_manual:
            m = r.get("mitigations", {})
            why = "; ".join(r.get("triage_reason", [])) or "needs manual review"
            danger = ",".join(sorted({d["function"] for d in r.get("dangerous_functions", [])})) or "—"
            win = r.get("win_symbols") or [t["func"] for t in r.get("win_targets", [])]
            nm.add_row(
                escape(b.name), escape(why[:60]), escape(str(r.get("language") or "?")),
                str(m.get("arch", "?")),
                "✓" if m.get("nx") else "[red]✗[/red]",
                "✓" if m.get("pie") else "[red]✗[/red]",
                "✓" if m.get("canary") else "[red]✗[/red]",
                escape(danger[:40]),
                escape(",".join(win)[:24]) or "—",
            )
        console.print(nm)
        console.print("[dim]→ reverse these in Ghidra/radare2; static imports under-count their surface.[/dim]\n")

    targets = scored
    # network-facing breaks ties so the actual service sorts above compute helpers
    # of equal score.
    targets.sort(key=lambda x: (x[2], x[1].get("network_facing", False)), reverse=True)

    table = Table(title="[bold]Attack-Surface Triage (ranked targets)[/bold]")
    for col in ("Binary", "Score", "Verdict", "Arch", "Net", "NX", "PIE", "Canary", "RELRO", "Danger", "Win"):
        table.add_column(col)
    verdict_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "MINIMAL": "green"}
    for b, r, score in targets:
        m = r.get("mitigations", {})
        v = r.get("exploitability", {}).get("verdict", "?")
        danger = ",".join(sorted({d["function"] for d in r.get("dangerous_functions", [])})) or "-"
        note = " [dim](static: funcs unconfirmed)[/dim]" if m.get("static") else ""
        win = r.get("win_symbols") or [t["func"] for t in r.get("win_targets", [])]
        table.add_row(
            escape(b.name), str(score),
            f"[{verdict_color.get(v, 'white')}]{v}[/{verdict_color.get(v, 'white')}]",
            str(m.get("arch", "?")),
            "[green]net[/green]" if r.get("network_facing") else "-",
            "✓" if m.get("nx") else "[red]✗[/red]",
            "✓" if m.get("pie") else "[red]✗[/red]",
            "✓" if m.get("canary") else "[red]✗[/red]",
            str(m.get("relro", "?")),
            escape(danger[:40]) + note,
            escape(",".join(win)[:24]) or "-",
        )
    if targets:
        console.print(table)
    else:
        console.print("[yellow]No target executables found (only libraries/objects below).[/yellow]")

    # References: libraries, relocatables, provided solutions — not ranked as targets.
    if references:
        ref = Table(title="[dim]References (not targets)[/dim]")
        for col in ("File", "Role", "Note"):
            ref.add_column(col)
        libc_vers = set()           # versions of the libc proper (for the ret2libc hint)
        for b, r, _ in references:
            role = r.get("role")
            if role == "library":
                ver = r.get("libc_version")
                low = b.name.lower()
                if re.search(r"(^|/)libc[-.]", low) or low == "libc.so.6":
                    hint = f"glibc {ver} — ret2libc target (pin it + one_gadget)" if ver else "the libc — ret2libc target"
                    if ver:
                        libc_vers.add(ver)
                elif low.startswith("ld-") or "ld-linux" in low:
                    hint = f"glibc {ver} loader (ld.so)" if ver else "dynamic loader (ld.so)"
                else:
                    hint = f"shared library (glibc symbols {ver})" if ver else "shared library — reference"
            else:
                hint = {"relocatable": ".o object — not runnable",
                        "solution?": "looks like a provided exploit/solution"}.get(role, "")
            ref.add_row(escape(b.name), escape(role or "?"), escape(hint))
        console.print(ref)

        # ret2libc pairing hint: the libc proper + any dynamically-linked target.
        dyn_targets = [b for b, r, _ in targets if r.get("mitigations", {}).get("static") is False]
        if libc_vers and dyn_targets:
            console.print(
                f"[green]ret2libc:[/green] dynamic target(s) can be popped through the bundled "
                f"libc (glibc {', '.join(sorted(libc_vers))}). Pin it: `pwn.ELF('libc.so.6')`; "
                f"magic gadgets: `one_gadget libc.so.6`.")

    console.print(
        "\n[yellow]⚠ Static attack-surface only — a LOW/MINIMAL score does NOT mean safe[/yellow] "
        "(logic/UAF/crypto bugs are invisible here).")
    console.print(
        "[dim]Have the source? Triage it with Opengrep first — this is the no-source/stripped "
        "fallback (+ checksec/diff). Hand off to Ghidra/pwntools; see A&D toolkit 03/05.[/dim]")


@cli.command()
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Recurse into directories / service trees")
@click.option("--output", "-o", type=click.Path(), help="Directory to write per-binary JSON reports")
@click.option("--profile", default="ad", help="Settings profile (default: ad = offline/no-AI)")
@click.option("--config", "-c", type=click.Path(exists=True), help="Explicit config file (overrides --profile)")
def rev(targets, recursive, output, profile, config):
    """Reverse-engineering orientation of ELF binaries (what is it, where to start)."""
    cfg = _load_profile_config(profile, config)
    analyzer = RevTriage(cfg.get("rev_triage"))

    binaries = list(_iter_elf_targets(targets, recursive))
    if not binaries:
        console.print("[yellow]No ELF binaries found in the given targets.[/yellow]")
        return

    out_dir = Path(output) if output else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    analyzed = []
    for b in binaries:
        r = analyzer.analyze(b).results
        analyzed.append((b, r))
        if out_dir:
            (out_dir / f"{b.name}.json").write_text(json.dumps(r, indent=2, default=str))

    table = Table(title="[bold]Reverse-Engineering Orientation[/bold]")
    for col in ("Binary", "Role", "Lang", "Bits", "Flags", "User fns", "Anti-dbg", "Notable strings"):
        table.add_column(col)
    for b, r in analyzed:
        fmt = r.get("format", {})
        tc = r.get("toolchain", {})
        flags = []
        if fmt.get("static"):
            flags.append("static")
        flags.append("PIE" if fmt.get("pie") else "no-PIE")
        flags.append("stripped" if fmt.get("stripped") else "symbols")
        cats = r.get("strings", {}).get("categories", {})
        notable = ",".join(k for k in ("flags_secrets", "urls", "commands", "errors_asserts") if k in cats) or "-"
        fns = r.get("functions", {})
        fn_cell = "stripped" if fmt.get("stripped") else str(fns.get("user_count", 0))
        ad = r.get("anti_debug", [])
        table.add_row(
            escape(b.name), escape(r.get("role", "?")),
            escape(tc.get("language") or "?"),
            str(fmt.get("bits", "?")),
            " ".join(flags),
            fn_cell,
            str(len(ad)) if ad else "-",
            escape(notable),
        )
    console.print(table)
    # Per-binary orientation one-liners + hand-off, printed below the table.
    for b, r in analyzed:
        console.print(f"\n[bold cyan]{escape(b.name)}[/bold cyan]: {escape(str(r.get('orientation', '')))}")
        if r.get("packer"):
            console.print(f"  [red]packer:[/red] {escape(', '.join(r['packer']))}")
        if r.get("anti_debug"):
            console.print(f"  [yellow]anti-debug:[/yellow] {escape('; '.join(r['anti_debug']))}")
        if r.get("libc"):
            console.print(f"  [green]libc:[/green] glibc {r['libc']} (pin for ret2libc / one_gadget)")
        for tip in r.get("handoff", [])[:4]:
            console.print(f"  → {tip}")
    console.print("\n[dim]Orientation only — the actual RE happens in Ghidra/radare2. "
                  "This tells you what you're looking at and where to start.[/dim]")


@cli.command()
@click.argument("pristine", type=click.Path(exists=True))
@click.argument("other", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["table", "json"]), default="table")
@click.option("--allow", "allow", multiple=True,
              help="Function allowed to change (repeatable). Turns diff into a patch gate.")
@click.option("--allow-file", type=click.Path(exists=True),
              help="File of allowed-to-change function names (one per line; # comments ok).")
@click.option("--timeout", type=float, default=3.0, show_default=True,
              help="Wall-clock budget (s); degrades to hash+sections rather than hang.")
def diff(pristine, other, format, allow, allow_file, timeout):
    """Patch guard: diff a pristine build of YOUR service against the patched one.

    Confirms the patch changed only the function(s) you intended. Function bodies
    are compared at normalized-disassembly level, so a plain recompile of
    unchanged source shows no changes (relocation noise is masked out).

    With --allow/--allow-file this becomes a gate: exit 0 if the only changed
    functions are allowlisted, exit 2 otherwise (for deploy scripts)."""
    result = BinDiff().diff(Path(pristine), Path(other), timeout=timeout)
    r = result.results

    allowlist = list(allow)
    if allow_file:
        for line in Path(allow_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allowlist.append(line)
    gate_on = bool(allowlist)

    suspects = r.get("suspect_functions", []) or []
    gate = BinDiff.gate(suspects, allowlist)
    r["gate"] = {**gate, "enforced": gate_on, "allowlist": sorted(set(allowlist))}
    # exit 2 only when enforcing an allowlist and something outside it changed.
    exit_code = 2 if (gate_on and not gate["ok"]) else 0

    if format == "json":
        print(json.dumps(result.to_dict(), indent=2, default=str))
        sys.exit(exit_code)
    if r.get("identical"):
        console.print("[green]Binaries are byte-identical.[/green]")
        sys.exit(0)
    console.print(Panel(
        f"A: {r['a']['path']}  ({r['a']['size']:,} B)\n"
        f"B: {r['b']['path']}  ({r['b']['size']:,} B)\n"
        f"changed byte-ranges: {len(r.get('changed_byte_ranges', []))}"
        + ("  [yellow](degraded)[/yellow]" if r.get("degraded") else ""),
        title="[bold cyan]Binary Patch Diff[/bold cyan]", border_style="cyan"))
    if r.get("note"):
        console.print(f"[yellow]{escape(str(r['note']))}[/yellow]")
    if suspects:
        console.print(f"[bold red]Changed functions:[/bold red] {escape(', '.join(suspects))}")
    else:
        console.print("[green]No changed functions (after normalization).[/green]")
    syms = r.get("symbols", {})
    if syms.get("added"):
        console.print(f"[green]Symbols added:[/green] {escape(', '.join(syms['added'][:20]))}")
    if syms.get("removed"):
        console.print(f"[yellow]Symbols removed:[/yellow] {escape(', '.join(syms['removed'][:20]))}")
    if sec := r.get("sections"):
        console.print(f"[cyan]Changed sections:[/cyan] {escape(', '.join(s['section'] for s in sec))}")
    if gate_on:
        if gate["ok"]:
            console.print(f"[bold green]✓ patch gate PASS[/bold green] — only allowlisted "
                          f"function(s) changed ({escape(', '.join(gate['allowed_hit']) or 'none')}).")
        else:
            console.print(f"[bold red]✗ patch gate FAIL[/bold red] — unexpected change(s): "
                          f"{escape(', '.join(gate['violations']))}. "
                          f"Allowlisted: {escape(', '.join(allowlist))}.")
    sys.exit(exit_code)


_SEV_STYLE = {"ERROR": "bold red", "WARNING": "yellow", "INFO": "dim cyan"}


@cli.command()
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, help="Recurse into directories / service trees")
@click.option("--output", "-o", type=click.Path(), help="Write report.html + report.md here")
@click.option("--profile", default="ad", help="Settings profile (default: ad = offline/no-AI)")
@click.option("--config", "-c", type=click.Path(exists=True), help="Explicit config file (overrides --profile)")
def report(targets, recursive, output, profile, config):
    """Consolidated, dashboard-style findings over all binaries (shareable HTML/MD)."""
    cfg = _load_profile_config(profile, config)
    pwn = PwnTriage(cfg.get("pwn_triage"))
    rev = RevTriage(cfg.get("rev_triage"))

    binaries = list(_iter_elf_targets(targets, recursive))
    if not binaries:
        console.print("[yellow]No ELF binaries found in the given targets.[/yellow]")
        return

    report_rows = []  # (name, role, findings, counts)
    skipped = []      # libraries / objects / solutions — references, not targets
    for b in binaries:
        p = pwn.analyze(b).results
        role = p.get("role", "executable")
        if role != "executable":
            skipped.append((b.name, role))
            continue
        r = rev.analyze(b).results
        fs = build_findings(b.name, p, r)
        report_rows.append((b.name, role, fs, finding_counts(fs)))

    # order: binaries with the most severe findings first
    report_rows.sort(key=lambda x: (-x[3].get("ERROR", 0), -x[3].get("WARNING", 0), x[0]))

    # ---- terminal (the dashboard-style view) ----
    for name, role, fs, c in report_rows:
        head = f"[bold]{escape(name)}[/bold] ({role}) — {c['total']} finding(s): " \
               f"[bold red]{c['ERROR']} error[/bold red] · [yellow]{c['WARNING']} warning[/yellow] · {c['INFO']} info"
        console.print("\n" + head)
        if not fs:
            console.print("  [dim]no notable static findings — reverse it (Ghidra/radare2)[/dim]")
        for f in fs:
            style = _SEV_STYLE.get(f["severity"], "white")
            console.print(
                f"  [{style}]{f['severity']}[/{style}] "
                f"[magenta]{f['impact']}[/magenta] [cyan]{f['id']}[/cyan] "
                f"{escape(f['where'])}  [dim]conf {f['confidence']}[/dim]")
            console.print(f"    {escape(f['message'])}")

    if output:
        out = Path(output); out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(_findings_md(report_rows))
        (out / "report.html").write_text(_findings_html(report_rows))
        console.print(f"\n[green]Wrote[/green] {out/'report.md'} and {out/'report.html'}")

    if skipped:
        console.print(f"\n[dim]Skipped {len(skipped)} reference(s) (not targets): "
                      + ", ".join(f"{n} ({r})" for n, r in skipped[:8])
                      + ("…" if len(skipped) > 8 else "") + "[/dim]")
    console.print("\n[dim]Static binary triage — points you at the surface; confirm/exploit in "
                  "Ghidra/pwntools. Covers the binary-only services the source scanner can't.[/dim]")


def _findings_md(rows) -> str:
    lines = ["# Binary triage report", ""]
    for name, role, fs, c in rows:
        lines.append(f"## {name} ({role}) — {c['total']} findings: {c['ERROR']} error, {c['WARNING']} warning, {c['INFO']} info")
        if not fs:
            lines.append("- _no notable static findings — reverse it (Ghidra/radare2)_")
        for f in fs:
            lines.append(f"- **{f['severity']}** · `{f['impact']}` · `{f['id']}` · {f['where']} · conf {f['confidence']}  \n  {f['message']}")
        lines.append("")
    return "\n".join(lines)


def _findings_html(rows) -> str:
    import html
    css = ("body{font:14px system-ui,sans-serif;margin:2rem;max-width:60rem}"
           "h2{border-bottom:1px solid #ccc;padding-top:1rem}"
           ".f{border-left:4px solid #ccc;padding:.4rem .8rem;margin:.5rem 0;background:#fafafa}"
           ".ERROR{border-color:#d33}.WARNING{border-color:#e90}.INFO{border-color:#09c}"
           ".tag{display:inline-block;font:12px monospace;background:#eee;border-radius:3px;padding:0 .4rem;margin-right:.3rem}"
           ".sev-ERROR{color:#d33;font-weight:bold}.sev-WARNING{color:#b70}.sev-INFO{color:#09c}"
           ".msg{margin-top:.3rem;color:#333}")
    parts = [f"<!doctype html><meta charset=utf-8><title>Binary triage report</title><style>{css}</style>",
             "<h1>Binary triage report</h1>"]
    for name, role, fs, c in rows:
        parts.append(f"<h2>{html.escape(name)} <small>({role}) — {c['ERROR']} error · {c['WARNING']} warning · {c['INFO']} info</small></h2>")
        if not fs:
            parts.append("<p><em>no notable static findings — reverse it (Ghidra/radare2)</em></p>")
        for f in fs:
            parts.append(
                f"<div class='f {f['severity']}'>"
                f"<span class='sev-{f['severity']}'>{f['severity']}</span> "
                f"<span class='tag'>{html.escape(f['impact'])}</span>"
                f"<span class='tag'>{html.escape(f['id'])}</span>"
                f"<span class='tag'>{html.escape(f['where'])}</span>"
                f"<span class='tag'>conf {f['confidence']}</span>"
                f"<div class='msg'>{html.escape(f['message'])}</div></div>")
    return "\n".join(parts)


if __name__ == "__main__":
    cli()
