"""
PE Analyzer - Windows Portable Executable analysis
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class PEAnalyzer(BaseAnalyzer):
    """
    Analyze Windows PE (Portable Executable) files
    
    Features:
    - PE header analysis
    - Section analysis
    - Import/Export tables
    - Resources
    - Digital signatures
    - Packer detection (DIE)
    - Compiler detection
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PE analyzer
        
        Args:
            config: Configuration dictionary with:
                - use_pefile: Use pefile library (default: True)
                - use_die: Use Detect It Easy (default: True)
                - die_path: Path to DIE executable
                - extract_resources: Extract resource info (default: True)
        """
        super().__init__("pe_analyzer", config)
        
        self.use_pefile = self.config.get("use_pefile", True) and PEFILE_AVAILABLE
        self.use_die = self.config.get("use_die", True)
        self.die_path = self.config.get("die_path", "diec")
        self.extract_resources = self.config.get("extract_resources", True)
        
        if not self.use_pefile:
            logger.warning("pefile is not available. Install with: pip install pefile")
        
        # Check DIE availability
        if self.use_die:
            self._check_die_availability()
        
        if not self.use_pefile and not self.use_die:
            logger.warning("No PE analysis methods available")
            self.enabled = False
    
    def _check_die_availability(self) -> None:
        """Check if Detect It Easy is available"""
        try:
            result = subprocess.run(
                [self.die_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("Detect It Easy is available")
            else:
                self.use_die = False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("Detect It Easy is not available")
            self.use_die = False
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """Check if file is a PE executable"""
        if not self.enabled:
            return False
        
        # Check file type
        if file_info.file_type:
            pe_indicators = ["pe32", "pe64", "pe", "executable", "dll"]
            return any(indicator in file_info.file_type.lower() for indicator in pe_indicators)
        
        return True
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Analyze PE file
        
        Args:
            file_path: Path to PE file
            file_data: Optional file data (if already read)
            
        Returns:
            AnalysisResult with PE analysis
        """
        if not self.enabled:
            return self._create_result(
                status=AnalysisStatus.SKIPPED,
                error="PE analyzer is not available"
            )
        
        results = {}
        errors = []
        
        try:
            # Analyze with pefile
            if self.use_pefile:
                try:
                    pefile_results = self._analyze_with_pefile(file_path, file_data)
                    results["pefile"] = pefile_results
                except Exception as e:
                    logger.warning(f"pefile analysis failed: {e}")
                    errors.append(f"pefile: {str(e)}")
            
            # Analyze with DIE
            if self.use_die:
                try:
                    die_results = self._analyze_with_die(file_path)
                    results["die"] = die_results
                except Exception as e:
                    logger.warning(f"DIE analysis failed: {e}")
                    errors.append(f"DIE: {str(e)}")
            
            # Determine status
            if results:
                status = AnalysisStatus.PARTIAL_SUCCESS if errors else AnalysisStatus.SUCCESS
            else:
                status = AnalysisStatus.FAILURE
            
            return self._create_result(
                status=status,
                results=results,
                error="\n".join(errors) if errors else None
            )
        
        except Exception as e:
            logger.exception(f"PE analysis failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"PE analysis failed: {str(e)}"
            )
    
    def _analyze_with_pefile(self, file_path: Path, file_data: Optional[bytes] = None) -> Dict[str, Any]:
        """Analyze PE file with pefile library"""
        # Read file data if not provided
        if file_data is None:
            file_data = file_path.read_bytes()
        
        pe = pefile.PE(data=file_data)
        
        results = {
            "machine": self._get_machine_type(pe),
            "subsystem": self._get_subsystem(pe),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": pe.FILE_HEADER.Characteristics,
            "sections": self._extract_sections(pe),
            "imports": self._extract_imports(pe),
            "exports": self._extract_exports(pe),
        }
        
        # Extract resources if enabled
        if self.extract_resources and hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            results["resources"] = self._extract_resources(pe)
        
        # Check for digital signature
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            results["signed"] = True
        else:
            results["signed"] = False
        
        # Extract version info
        if hasattr(pe, "VS_VERSIONINFO"):
            results["version_info"] = self._extract_version_info(pe)
        
        # Calculate entropy for sections
        results["entropy"] = self._calculate_section_entropy(pe)
        
        pe.close()
        
        return results
    
    def _get_machine_type(self, pe: "pefile.PE") -> str:
        """Get machine type from PE"""
        machine_types = {
            0x14c: "i386",
            0x8664: "x64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
        }
        return machine_types.get(pe.FILE_HEADER.Machine, f"Unknown (0x{pe.FILE_HEADER.Machine:x})")
    
    def _get_subsystem(self, pe: "pefile.PE") -> str:
        """Get subsystem from PE"""
        subsystems = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows CUI",
            7: "POSIX CUI",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "XBOX",
        }
        subsystem_value = pe.OPTIONAL_HEADER.Subsystem
        return subsystems.get(subsystem_value, f"Unknown ({subsystem_value})")
    
    def _extract_sections(self, pe: "pefile.PE") -> List[Dict[str, Any]]:
        """Extract section information"""
        sections = []
        
        for section in pe.sections:
            sections.append({
                "name": section.Name.decode().rstrip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
                "characteristics": hex(section.Characteristics),
            })
        
        return sections
    
    def _extract_imports(self, pe: "pefile.PE") -> Dict[str, List[str]]:
        """Extract import table"""
        imports = {}
        
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                functions = []
                
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode())
                    else:
                        functions.append(f"Ordinal_{imp.ordinal}")
                
                imports[dll_name] = functions
        
        return imports
    
    def _extract_exports(self, pe: "pefile.PE") -> List[str]:
        """Extract export table"""
        exports = []
        
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode())
        
        return exports
    
    def _extract_resources(self, pe: "pefile.PE") -> List[Dict[str, Any]]:
        """Extract resource information"""
        resources = []
        
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    data = pe.get_data(
                        resource_lang.data.struct.OffsetToData,
                        resource_lang.data.struct.Size
                    )
                    
                    resources.append({
                        "type": pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "Unknown"),
                        "id": resource_id.struct.Id,
                        "lang": resource_lang.struct.Id,
                        "size": resource_lang.data.struct.Size,
                    })
        
        return resources
    
    def _extract_version_info(self, pe: "pefile.PE") -> Dict[str, str]:
        """Extract version information"""
        version_info = {}
        
        for file_info in pe.FileInfo:
            for entry in file_info:
                if hasattr(entry, "StringTable"):
                    for st in entry.StringTable:
                        for key, value in st.entries.items():
                            version_info[key.decode()] = value.decode()
        
        return version_info
    
    def _calculate_section_entropy(self, pe: "pefile.PE") -> Dict[str, float]:
        """Calculate entropy for each section"""
        entropy = {}
        
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00')
            entropy[name] = section.get_entropy()
        
        return entropy
    
    def _analyze_with_die(self, file_path: Path) -> Dict[str, Any]:
        """Analyze PE file with Detect It Easy"""
        cmd = [self.die_path, "-j", str(file_path)]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"DIE failed: {result.stderr}")
        
        # Parse JSON output
        die_output = json.loads(result.stdout)
        
        return {
            "detects": die_output.get("detects", []),
            "packer": self._extract_packer(die_output),
            "compiler": self._extract_compiler(die_output),
        }
    
    def _extract_packer(self, die_output: Dict[str, Any]) -> Optional[str]:
        """Extract packer information from DIE output"""
        for detect in die_output.get("detects", []):
            if detect.get("type") == "Packer":
                return detect.get("name")
        return None
    
    def _extract_compiler(self, die_output: Dict[str, Any]) -> Optional[str]:
        """Extract compiler information from DIE output"""
        for detect in die_output.get("detects", []):
            if detect.get("type") == "Compiler":
                return detect.get("name")
        return None
    
    def get_supported_types(self) -> Set[str]:
        """Get supported file types"""
        return {"pe", "pe32", "pe64", "dll", "exe"}
