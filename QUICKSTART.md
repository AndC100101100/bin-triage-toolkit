# Binary Triage Toolkit - Quick Start Guide

Get started with Binary Triage Toolkit in 5 minutes!

## 🚀 Installation

### Option 1: Install from source (Recommended for development)

```bash
cd binary-triage-toolkit
pip install -e .
```

### Option 2: Install with pip (when published)

```bash
pip install binary-triage-toolkit
```

### Option 3: Install with optional dependencies

```bash
# With development tools
pip install -e ".[dev]"

# With advanced features
pip install -e ".[advanced]"

# Everything
pip install -e ".[dev,advanced]"
```

## 📋 Prerequisites

### Required Tools

1. **Python 3.9+**
   ```bash
   python --version
   ```

2. **YARA** (for signature scanning)
   ```bash
   # macOS
   brew install yara
   
   # Ubuntu/Debian
   sudo apt-get install yara
   
   # Or via pip
   pip install yara-python
   ```

3. **CAPA** (for capability detection)
   ```bash
   pip install flare-capa
   ```

### Optional Tools (Recommended)

4. **Detect It Easy** (for PE analysis)
   - Download: https://github.com/horsicq/Detect-It-Easy/releases
   - Add to PATH or configure in settings.yaml

5. **llvm-readelf** (for ELF analysis)
   ```bash
   # macOS
   brew install llvm
   
   # Ubuntu/Debian
   sudo apt-get install llvm
   ```

## 🎯 Quick Usage

### 1. Analyze a Single Binary

```bash
# Quick scan (file ID + YARA only)
binary-triage analyze sample.exe --quick

# Full analysis
binary-triage analyze sample.exe

# Specific modules
binary-triage analyze sample.exe --modules yara_scanner,capa_analyzer
```

### 2. Batch Analysis

```bash
# Analyze all files in directory
binary-triage batch ./samples --output ./results

# Recursive with pattern
binary-triage batch ./samples --pattern "*.exe" --recursive --output ./results
```

### 3. Different Output Formats

```bash
# Table format (default, pretty output)
binary-triage analyze sample.exe

# JSON format (for automation)
binary-triage analyze sample.exe --format json --output report.json

# Markdown format (for documentation)
binary-triage analyze sample.exe --format markdown --output report.md
```

## ⚡ Attack & Defense Quick Start (ECSC / FAUST)

```bash
pip install -e ".[ad]"                         # pwn engine, no AI

# Rank the ELF service binaries by exploitability (offline, no-AI profile)
binary-triage triage path/to/service/ --profile ad --emit-exploit

# Defense: what did a patch / an opponent's binary change?
binary-triage diff pristine_bin patched_bin

# Or the Python example
python examples/ad_workflow.py path/to/service/
```

`triage` prints a ranked table (checksec + dangerous functions + win symbols) and, with
`--emit-exploit`, drops a `<bin>_exploit.py` pwntools skeleton. Hand off to Ghidra/pwntools.

## 🎮 CTF / Malware Quick Start

Perfect for CTF/forensic triage (needs the `[malware]` extra for YARA/CAPA/PE):

```bash
# Quick triage
python examples/ctf_workflow.py challenge.bin

# Or use CLI
binary-triage analyze challenge.bin --quick --format table
```

## 🔧 Configuration

Create a custom config file:

```yaml
# my_config.yaml
yara_scanner:
  rules_path: "/path/to/my/rules"
  timeout: 120

capa_analyzer:
  verbose: true

string_extractor:
  min_length: 6
```

Use it:

```bash
binary-triage analyze sample.exe --config my_config.yaml
```

## 📚 Python API

```python
from pathlib import Path
from binary_triage import BinaryTriage

# Initialize
triage = BinaryTriage()

# Analyze file
results = triage.analyze_file(Path("sample.exe"))

# Access results
print(f"SHA256: {results['file_info']['sha256']}")

# Check YARA matches
yara_results = results['analyzers']['yara_scanner']['results']
if yara_results.get('rules'):
    print(f"YARA matches: {yara_results['rules']}")

# Check IOCs
iocs = results['analyzers']['string_extractor']['results']['iocs']
print(f"URLs found: {len(iocs.get('urls', []))}")
```

## 🐛 Troubleshooting

### YARA not working
```bash
# Check YARA installation
python -c "import yara; print(yara.__version__)"

# Install if missing
pip install yara-python
```

### CAPA not found
```bash
# Check CAPA installation
capa --version

# Install if missing
pip install flare-capa
```

### No YARA rules
```bash
# Download sample rules
mkdir -p config/yara_rules
cd config/yara_rules
git clone https://github.com/Yara-Rules/rules.git
```

### Permission errors
```bash
# Run with appropriate permissions
sudo binary-triage analyze /path/to/file
```

## 📖 Next Steps

1. **Read the full documentation**: See `README.md`
2. **Check examples**: See `examples/` directory
3. **Customize configuration**: Edit `config/settings.yaml`
4. **Add custom YARA rules**: Place in `config/yara_rules/`
5. **Integrate with your workflow**: Use Python API or CLI

## 🎯 Common Use Cases

### Malware Analysis
```bash
binary-triage analyze malware.exe --format json --output analysis.json
```

### CTF Challenge
```bash
binary-triage analyze challenge.bin --quick
```

### Forensic Investigation
```bash
binary-triage analyze evidence.exe --format markdown --output investigation.md
```

### Batch Processing
```bash
binary-triage batch /suspicious/files --recursive --output /analysis/results
```

## 💡 Tips

1. **Use quick mode** for initial triage
2. **Pre-compile YARA rules** for better performance
3. **Focus on specific modules** to save time
4. **Use JSON output** for automation
5. **Check examples/** for workflow ideas

## 🆘 Getting Help

- **Documentation**: See `README.md` and `examples/README.md`
- **Issues**: https://github.com/AndC100101100/bin-triage-toolkit/issues
- **Examples**: Check `examples/` directory

## ⚠️ Security Warning

This tool analyzes potentially malicious binaries. Always:
- Run in isolated environment (VM recommended)
- Never execute analyzed binaries directly
- Be cautious with extracted IOCs
- Follow responsible disclosure practices

---

**Ready to start?** Try: `binary-triage analyze --help`
