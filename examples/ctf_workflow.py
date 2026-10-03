#!/usr/bin/env python3
"""
CTF Workflow Example - Quick triage for CTF challenges
"""

import json
from pathlib import Path
from binary_triage import BinaryTriage

def ctf_quick_triage(binary_path: Path):
    """
    Quick triage workflow for CTF challenges
    
    Focus on:
    - File identification
    - YARA signatures
    - String/IOC extraction
    - Basic PE/ELF analysis
    """
    print(f"\n{'='*60}")
    print(f"CTF Quick Triage: {binary_path.name}")
    print(f"{'='*60}\n")
    
    triage = BinaryTriage()
    
    # Quick analysis (file ID + YARA only)
    print("[1/2] Running quick scan (file ID + YARA)...")
    results = triage.analyze_file(binary_path, quick=True)
    
    # Check file type
    file_id = results['analyzers'].get('file_identifier', {}).get('results', {})
    file_type = file_id.get('file_type', 'unknown')
    print(f"  File Type: {file_type}")
    
    # Check YARA matches
    yara = results['analyzers'].get('yara_scanner', {}).get('results', {})
    if yara.get('rules'):
        print(f"  ⚠️  YARA Matches: {len(yara['rules'])} rules")
        print(f"     Rules: {', '.join(yara['rules'][:3])}")
        if yara.get('families'):
            print(f"     Families: {', '.join(yara['families'])}")
    else:
        print("  ✓ No YARA matches (likely clean or unknown)")
    
    # Full analysis with strings and format-specific tools
    print("\n[2/2] Running detailed analysis...")
    
    modules = ['string_extractor']
    if 'pe' in file_type.lower():
        modules.append('pe_analyzer')
    elif 'elf' in file_type.lower():
        modules.append('elf_analyzer')
    
    detailed_results = triage.analyze_file(binary_path, modules=modules)
    
    # Extract interesting strings/IOCs
    strings = detailed_results['analyzers'].get('string_extractor', {}).get('results', {})
    iocs = strings.get('iocs', {})
    
    print("\n📋 Interesting Findings:")
    
    if iocs.get('urls'):
        print(f"\n  URLs ({len(iocs['urls'])}):")
        for url in iocs['urls'][:5]:
            print(f"    - {url['value']}")
    
    if iocs.get('ips'):
        print(f"\n  IP Addresses ({len(iocs['ips'])}):")
        for ip in iocs['ips'][:5]:
            print(f"    - {ip['value']}")
    
    if iocs.get('domains'):
        print(f"\n  Domains ({len(iocs['domains'])}):")
        for domain in iocs['domains'][:5]:
            print(f"    - {domain['value']}")
    
    # PE-specific info
    if 'pe_analyzer' in detailed_results['analyzers']:
        pe_results = detailed_results['analyzers']['pe_analyzer']['results']
        
        if die := pe_results.get('die'):
            if packer := die.get('packer'):
                print(f"\n  🔒 Packer Detected: {packer}")
            if compiler := die.get('compiler'):
                print(f"  🔨 Compiler: {compiler}")
        
        if pefile := pe_results.get('pefile'):
            if imports := pefile.get('imports'):
                print(f"\n  📚 Imported DLLs: {len(imports)}")
                suspicious_dlls = [dll for dll in imports.keys() 
                                  if any(x in dll.lower() for x in ['ws2_32', 'wininet', 'urlmon'])]
                if suspicious_dlls:
                    print(f"     Suspicious: {', '.join(suspicious_dlls)}")
    
    # ELF-specific info
    if 'elf_analyzer' in detailed_results['analyzers']:
        elf_results = detailed_results['analyzers']['elf_analyzer']['results']
        
        if header := elf_results.get('header'):
            print(f"\n  🏗️  Architecture: {header.get('machine')}")
            print(f"  📦 Type: {header.get('type')}")
        
        if security := elf_results.get('security'):
            enabled = [k.upper() for k, v in security.items() if v]
            disabled = [k.upper() for k, v in security.items() if not v]
            if enabled:
                print(f"  🛡️  Security: {', '.join(enabled)}")
            if disabled:
                print(f"  ⚠️  Missing: {', '.join(disabled)}")
    
    print(f"\n{'='*60}")
    print("Analysis complete!")
    print(f"{'='*60}\n")
    
    # Save full results
    output_file = Path(f"{binary_path.name}_triage.json")
    output_file.write_text(json.dumps(detailed_results, indent=2))
    print(f"Full results saved to: {output_file}")

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ctf_workflow.py <binary_file>")
        print("\nExample: python ctf_workflow.py challenge.bin")
        sys.exit(1)
    
    binary_path = Path(sys.argv[1])
    
    if not binary_path.exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    ctf_quick_triage(binary_path)

if __name__ == "__main__":
    main()
