# Binary Triage Toolkit - Examples

This directory contains example scripts demonstrating different use cases for the Binary Triage Toolkit.

## Examples

### 1. Basic Usage (`basic_usage.py`)

Simple example showing how to analyze a single binary file programmatically.

```bash
python basic_usage.py
```

**Use case:** Quick integration into existing Python scripts

### 2. CTF Workflow (`ctf_workflow.py`)

Optimized workflow for CTF (Capture The Flag) challenges with quick triage and detailed analysis.

```bash
python ctf_workflow.py challenge.bin
```

**Features:**
- Quick scan (file ID + YARA)
- Detailed string/IOC extraction
- Format-specific analysis (PE/ELF)
- Suspicious indicator highlighting
- JSON output for further processing

**Use case:** Rapid binary analysis during time-limited CTF events

### 3. CLI Usage

The toolkit also provides a command-line interface:

```bash
# Quick analysis
binary-triage analyze sample.exe --quick

# Full analysis with specific modules
binary-triage analyze sample.exe --modules yara_scanner,capa_analyzer,string_extractor

# Batch analysis
binary-triage batch ./samples --pattern "*.exe" --output ./results

# JSON output
binary-triage analyze sample.exe --format json --output report.json

# Markdown report
binary-triage analyze sample.exe --format markdown --output report.md
```

## Common Workflows

### Attack & Defense Events

For Attack & Defense competitions like FAUST or ECSC:

```bash
# Monitor captured binaries
watch -n 5 'binary-triage batch /captures --pattern "*" --output /analysis'

# Quick triage of suspicious binary
binary-triage analyze suspicious.bin --quick --format table
```

### Malware Analysis

For malware triage and initial analysis:

```bash
# Full analysis with all modules
binary-triage analyze malware.exe --format json --output full_report.json

# Focus on capabilities and IOCs
binary-triage analyze malware.exe --modules capa_analyzer,string_extractor,yara_scanner
```

### Forensic Investigation

For forensic analysis:

```bash
# Comprehensive analysis with custom config
binary-triage analyze evidence.bin --config forensic_config.yaml --format markdown --output investigation.md
```

## Custom Configuration

Create a `config.yaml` file to customize analyzer behavior:

```yaml
yara_scanner:
  rules_path: "/path/to/custom/rules"
  timeout: 120

capa_analyzer:
  rules_path: "/path/to/capa/rules"
  verbose: true

string_extractor:
  min_length: 6
  max_strings: 5000
```

Then use it:

```bash
binary-triage analyze sample.exe --config config.yaml
```

## Tips for CTF/A&D Events

1. **Pre-compile YARA rules** for faster scanning:
   ```python
   import yara
   rules = yara.compile(filepaths={'namespace': 'rules.yar'})
   rules.save('compiled.yarc')
   ```

2. **Use quick mode** for initial triage:
   ```bash
   binary-triage analyze unknown.bin --quick
   ```

3. **Focus on IOCs** for network-based challenges:
   ```bash
   binary-triage analyze binary --modules string_extractor --format json | jq '.analyzers.string_extractor.results.iocs'
   ```

4. **Batch process** captured binaries:
   ```bash
   binary-triage batch /captures --recursive --output /results
   ```

5. **Integrate with other tools**:
   ```bash
   # Extract IOCs and feed to other tools
   binary-triage analyze sample.exe --format json | jq -r '.analyzers.string_extractor.results.iocs.urls[].value' | xargs -I {} curl {}
   ```

## Troubleshooting

### YARA not finding matches
- Ensure rules are in the correct path
- Check rule syntax with `yara -w rules.yar`
- Verify compiled rules are up to date

### CAPA not working
- Install CAPA: `pip install flare-capa`
- Verify CAPA is in PATH: `which capa`
- Check file is supported (PE x86/x64 or ELF)

### DIE (Detect It Easy) not available
- Download from: https://github.com/horsicq/Detect-It-Easy
- Add to PATH or specify path in config

### Performance issues
- Use `--quick` mode for initial triage
- Reduce `max_strings` in config
- Enable `fast_mode` for YARA
- Use compiled YARA rules

## Contributing

Have a useful workflow or example? Submit a PR!

1. Create your example script
2. Add documentation here
3. Test with sample binaries
4. Submit pull request

## Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [CAPA Documentation](https://github.com/mandiant/capa)
- [CTF Time](https://ctftime.org/) - Find CTF events
- [Malware Bazaar](https://bazaar.abuse.ch/) - Sample binaries
