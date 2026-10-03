"""
ELF Analyzer - Linux/Unix Executable and Linkable Format analysis
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class ELFAnalyzer(BaseAnalyzer):
    """
    Analyze ELF (Executable and Linkable Format) files
    
    Features:
    - ELF header analysis
    - Section analysis
    - Symbol table extraction
    - Dynamic dependencies
    - Architecture detection
    - Security features (NX, PIE, RELRO, Stack Canary)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize ELF analyzer
        
        Args:
            config: Configuration dictionary with:
                - readelf_path: Path to readelf/llvm-readelf (default: llvm-readelf)
                - timeout: Analysis timeout in seconds (default: 60)
        """
        super().__init__("elf_analyzer", config)

        # Prefer llvm-readelf (supports --elf-output-style=JSON used below), but
        # fall back to GNU readelf, which is what most Linux boxes actually ship.
        # With GNU readelf the JSON-based methods degrade to {} while the
        # text-based security/dynamic checks still work.
        self.readelf_path = self.config.get("readelf_path") or self._pick_readelf()
        self.timeout = self.config.get("timeout", 60)

        # Check readelf availability
        self._check_readelf_availability()
    
    @staticmethod
    def _pick_readelf() -> str:
        import shutil
        for cand in ("llvm-readelf", "readelf"):
            if shutil.which(cand):
                return cand
        return "llvm-readelf"

    def _check_readelf_availability(self) -> None:
        """Check if readelf is available"""
        try:
            result = subprocess.run(
                [self.readelf_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"readelf is available: {self.readelf_path}")
            else:
                logger.warning("readelf is not available")
                self.enabled = False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning(f"readelf is not available at {self.readelf_path}")
            self.enabled = False
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """Check if file is an ELF executable"""
        if not self.enabled:
            return False
        
        # Check file type
        if file_info.file_type:
            elf_indicators = ["elf", "executable", "shared object"]
            return any(indicator in file_info.file_type.lower() for indicator in elf_indicators)
        
        return True
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Analyze ELF file
        
        Args:
            file_path: Path to ELF file
            file_data: Optional file data (not used by readelf)
            
        Returns:
            AnalysisResult with ELF analysis
        """
        if not self.enabled:
            return self._create_result(
                status=AnalysisStatus.SKIPPED,
                error="ELF analyzer is not available (readelf not found)"
            )
        
        try:
            results = {
                "header": self._extract_header(file_path),
                "sections": self._extract_sections(file_path),
                "symbols": self._extract_symbols(file_path),
                "dynamic": self._extract_dynamic(file_path),
                "security": self._check_security_features(file_path),
            }
            
            # Get formatted output for human readability
            formatted = self._get_formatted_output(file_path)
            
            status = AnalysisStatus.SUCCESS if results["header"] else AnalysisStatus.NO_RESULTS
            
            return self._create_result(
                status=status,
                results=results,
                metadata={
                    "formatted_output": formatted,
                    "readelf_path": self.readelf_path,
                }
            )
        
        except Exception as e:
            logger.exception(f"ELF analysis failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"ELF analysis failed: {str(e)}"
            )
    
    def _extract_header(self, file_path: Path) -> Dict[str, Any]:
        """Extract ELF header information"""
        cmd = [self.readelf_path, "-h", "--elf-output-style=JSON", str(file_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to extract ELF header: {result.stderr}")
                return {}
            
            # Parse JSON output
            output = json.loads(result.stdout)
            
            if not output or not isinstance(output, list):
                return {}
            
            file_data = output[0]
            elf_header = file_data.get("ElfHeader", {})
            
            return {
                "class": elf_header.get("Class"),
                "data": elf_header.get("Data"),
                "version": elf_header.get("Version"),
                "os_abi": elf_header.get("OS/ABI"),
                "type": elf_header.get("Type"),
                "machine": elf_header.get("Machine"),
                "entry_point": elf_header.get("Entry point address"),
            }
        
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.warning(f"Failed to extract ELF header: {e}")
            return {}
    
    def _extract_sections(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract section information"""
        cmd = [self.readelf_path, "-S", "--elf-output-style=JSON", str(file_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return []
            
            # Parse JSON output
            output = json.loads(result.stdout)
            
            if not output or not isinstance(output, list):
                return []
            
            file_data = output[0]
            sections = file_data.get("Sections", [])
            
            return [
                {
                    "name": section.get("Name", {}).get("Value"),
                    "type": section.get("Type", {}).get("Value"),
                    "address": section.get("Address", {}).get("Value"),
                    "offset": section.get("Offset", {}).get("Value"),
                    "size": section.get("Size", {}).get("Value"),
                    "flags": section.get("Flags", {}).get("Value"),
                }
                for section in sections
            ]
        
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.warning(f"Failed to extract sections: {e}")
            return []
    
    def _extract_symbols(self, file_path: Path) -> Dict[str, List[str]]:
        """Extract symbol table"""
        cmd = [self.readelf_path, "-s", "--elf-output-style=JSON", str(file_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {"symbols": [], "count": 0}
            
            # Parse JSON output
            output = json.loads(result.stdout)
            
            if not output or not isinstance(output, list):
                return {"symbols": [], "count": 0}
            
            file_data = output[0]
            symbols = file_data.get("Symbols", [])
            
            # Extract symbol names
            symbol_names = []
            for symbol in symbols:
                if name := symbol.get("Name", {}).get("Value"):
                    symbol_names.append(name)
            
            return {
                "symbols": symbol_names[:100],  # Limit to first 100
                "count": len(symbol_names),
                "truncated": len(symbol_names) > 100,
            }
        
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.warning(f"Failed to extract symbols: {e}")
            return {"symbols": [], "count": 0}
    
    def _extract_dynamic(self, file_path: Path) -> Dict[str, Any]:
        """Extract dynamic section information"""
        cmd = [self.readelf_path, "-d", str(file_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {"libraries": [], "rpath": None, "runpath": None}
            
            # Parse output
            libraries = []
            rpath = None
            runpath = None
            
            for line in result.stdout.split("\n"):
                if "NEEDED" in line:
                    # Extract library name
                    match = line.split("[")
                    if len(match) > 1:
                        lib = match[1].rstrip("]")
                        libraries.append(lib)
                
                elif "RPATH" in line:
                    match = line.split("[")
                    if len(match) > 1:
                        rpath = match[1].rstrip("]")
                
                elif "RUNPATH" in line:
                    match = line.split("[")
                    if len(match) > 1:
                        runpath = match[1].rstrip("]")
            
            return {
                "libraries": libraries,
                "rpath": rpath,
                "runpath": runpath,
            }
        
        except subprocess.TimeoutExpired as e:
            logger.warning(f"Failed to extract dynamic info: {e}")
            return {"libraries": [], "rpath": None, "runpath": None}
    
    def _check_security_features(self, file_path: Path) -> Dict[str, Any]:
        """Check for exploit-mitigation features (text readelf; works with GNU readelf)."""
        security = {
            "nx": False,
            "pie": False,
            "relro": "none",         # none | partial | full
            "stack_canary": False,
            "fortify": False,
            "stripped": True,        # assume stripped until we see a symtab
            "static": False,
        }

        try:
            # Program headers: NX (GNU_STACK not executable), RELRO segment, interp (dynamic)
            prog = subprocess.run(
                [self.readelf_path, "-l", str(file_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout
            has_gnu_stack = False
            for line in prog.split("\n"):
                if "GNU_STACK" in line:
                    has_gnu_stack = True
                    # Executable stack shows an 'E' in the flags column (RWE)
                    security["nx"] = " E " not in line and not line.rstrip().endswith("E")
            if not has_gnu_stack:
                # No GNU_STACK usually means NX is enforced by default
                security["nx"] = True
            partial_relro = "GNU_RELRO" in prog
            # A dynamically-linked executable has an INTERP/program interpreter.
            security["static"] = "INTERP" not in prog and "program interpreter" not in prog

            # ELF type: PIE is type DYN *with* an interpreter (a bare .so is DYN too,
            # but we only triage executables here).
            hdr = subprocess.run(
                [self.readelf_path, "-h", str(file_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout
            is_dyn = "DYN" in hdr
            security["pie"] = is_dyn and not security["static"]

            # Dynamic section: BIND_NOW => Full RELRO (combined with GNU_RELRO segment)
            dyn = subprocess.run(
                [self.readelf_path, "-d", str(file_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout
            bind_now = "BIND_NOW" in dyn or "FLAGS_1" in dyn and "NOW" in dyn
            if bind_now and partial_relro:
                security["relro"] = "full"
            elif partial_relro:
                security["relro"] = "partial"
            else:
                security["relro"] = "none"

            # Symbols: canary, FORTIFY, stripped
            syms = subprocess.run(
                [self.readelf_path, "-s", str(file_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout
            if "__stack_chk_fail" in syms:
                security["stack_canary"] = True
            if "_chk" in syms:
                security["fortify"] = True
            security["stripped"] = ".symtab" not in subprocess.run(
                [self.readelf_path, "-S", str(file_path)],
                capture_output=True, text=True, timeout=10,
            ).stdout

        except Exception as e:
            logger.warning(f"Failed to check security features: {e}")

        return security
    
    def _get_formatted_output(self, file_path: Path) -> str:
        """Get formatted readelf output for human readability"""
        cmd = [self.readelf_path, "-a", str(file_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                return result.stdout
        
        except subprocess.TimeoutExpired:
            logger.warning("Formatted output generation timed out")
        
        return ""
    
    def get_supported_types(self) -> Set[str]:
        """Get supported file types"""
        return {"elf", "elf32", "elf64"}
