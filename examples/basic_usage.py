#!/usr/bin/env python3
"""
Basic usage example for Binary Triage Toolkit
"""

from pathlib import Path
from binary_triage import BinaryTriage

def main():
    # Initialize triage
    triage = BinaryTriage()
    
    # Analyze a single file
    sample_path = Path("sample.exe")
    
    if sample_path.exists():
        print(f"Analyzing {sample_path}...")
        
        # Full analysis
        results = triage.analyze_file(sample_path)
        
        # Print summary
        print("\n=== Analysis Summary ===")
        print(f"File: {results['file_info']['name']}")
        print(f"SHA256: {results['file_info']['sha256']}")
        print(f"\nAnalyzers run: {len(results['analyzers'])}")
        
        # Check YARA matches
        if 'yara_scanner' in results['analyzers']:
            yara_results = results['analyzers']['yara_scanner']['results']
            if yara_results.get('rules'):
                print(f"\nYARA Matches: {len(yara_results['rules'])}")
                print(f"Rules: {', '.join(yara_results['rules'][:5])}")
        
        # Check CAPA capabilities
        if 'capa_analyzer' in results['analyzers']:
            capa_results = results['analyzers']['capa_analyzer']['results']
            if capa_results.get('rules'):
                print(f"\nCapa Capabilities: {len(capa_results['rules'])}")
                print(f"MITRE ATT&CK Techniques: {len(capa_results.get('mitre_attack', []))}")
        
        # Check IOCs
        if 'string_extractor' in results['analyzers']:
            string_results = results['analyzers']['string_extractor']['results']
            iocs = string_results.get('iocs', {})
            
            if iocs.get('urls'):
                print(f"\nURLs found: {len(iocs['urls'])}")
                for url in iocs['urls'][:3]:
                    print(f"  - {url['value']}")
            
            if iocs.get('ips'):
                print(f"\nIPs found: {len(iocs['ips'])}")
                for ip in iocs['ips'][:3]:
                    print(f"  - {ip['value']}")
    else:
        print(f"Sample file not found: {sample_path}")
        print("Please provide a binary file to analyze")

if __name__ == "__main__":
    main()
