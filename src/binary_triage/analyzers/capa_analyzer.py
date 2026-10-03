"""
CAPA Analyzer - Malware capability detection and MITRE ATT&CK mapping
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class CapaAnalyzer(BaseAnalyzer):
    """
    CAPA-based malware capability detection
    
    Features:
    - Detect malware capabilities
    - Map to MITRE ATT&CK framework
    - Identify behavioral patterns
    - Support for PE and ELF files
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize CAPA analyzer
        
        Args:
            config: Configuration dictionary with:
                - capa_path: Path to capa executable
                - rules_path: Path to CAPA rules
                - timeout: Analysis timeout in seconds
                - verbose: Enable verbose output
        """
        super().__init__("capa_analyzer", config)
        
        self.capa_path = self.config.get("capa_path", "capa")
        self.rules_path = self.config.get("rules_path")
        self.timeout = self.config.get("timeout", 120)
        self.verbose = self.config.get("verbose", False)
        
        # Check if CAPA is available
        self._check_capa_availability()
    
    def _check_capa_availability(self) -> None:
        """Check if CAPA is installed and available"""
        try:
            result = subprocess.run(
                [self.capa_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"CAPA is available: {result.stdout.strip()}")
            else:
                logger.warning("CAPA is not available")
                self.enabled = False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"CAPA is not available: {e}")
            self.enabled = False
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """Check if CAPA can analyze the file"""
        if not self.enabled:
            return False
        
        # CAPA supports PE and ELF files
        supported_types = {"pe", "elf", "pe32", "pe64"}
        if file_info.file_type:
            return any(t in file_info.file_type.lower() for t in supported_types)
        
        return True
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Analyze file with CAPA
        
        Args:
            file_path: Path to file to analyze
            file_data: Optional file data (not used by CAPA)
            
        Returns:
            AnalysisResult with CAPA capabilities and MITRE ATT&CK mapping
        """
        if not self.enabled:
            return self._create_result(
                status=AnalysisStatus.SKIPPED,
                error="CAPA is not available"
            )
        
        try:
            # Build CAPA command
            cmd = [self.capa_path, str(file_path), "-j"]
            
            if self.rules_path:
                cmd.extend(["-r", str(self.rules_path)])
            
            if self.verbose:
                cmd.append("-v")
            
            # Run CAPA
            logger.info(f"Running CAPA: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Check for errors
            if result.returncode != 0:
                error_msg = result.stderr or "CAPA analysis failed"
                
                # Check for specific error patterns
                if "unsupported architecture" in error_msg.lower():
                    return self._create_result(
                        status=AnalysisStatus.SKIPPED,
                        error="Unsupported architecture (CAPA only supports x86/x64)"
                    )
                
                return self._create_result(
                    status=AnalysisStatus.FAILURE,
                    error=error_msg
                )
            
            # Parse JSON output
            try:
                capa_output = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                return self._create_result(
                    status=AnalysisStatus.FAILURE,
                    error=f"Failed to parse CAPA output: {e}"
                )
            
            # Extract results
            results = self._parse_capa_output(capa_output)
            
            status = AnalysisStatus.SUCCESS if results["rules"] else AnalysisStatus.NO_RESULTS
            
            return self._create_result(
                status=status,
                results=results,
                metadata={
                    "capa_version": capa_output.get("meta", {}).get("version"),
                    "analysis_time": self.timeout,
                }
            )
        
        except subprocess.TimeoutExpired:
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"CAPA analysis timed out after {self.timeout} seconds"
            )
        
        except Exception as e:
            logger.exception(f"CAPA analysis failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"CAPA analysis failed: {str(e)}"
            )
    
    def _parse_capa_output(self, capa_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse CAPA JSON output and extract relevant information
        
        Args:
            capa_output: CAPA JSON output
            
        Returns:
            Parsed results dictionary
        """
        results = {
            "rules": [],
            "capabilities": [],
            "mitre_attack": [],
            "mbc": [],
            "namespaces": {},
        }
        
        # Extract rules
        rules = capa_output.get("rules", {})
        
        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})
            
            # Add rule to list
            results["rules"].append(rule_name)
            
            # Extract capabilities
            if namespace := meta.get("namespace"):
                if namespace not in results["namespaces"]:
                    results["namespaces"][namespace] = []
                results["namespaces"][namespace].append(rule_name)
                
                # Add to capabilities list
                if rule_name not in results["capabilities"]:
                    results["capabilities"].append(rule_name)
            
            # Extract MITRE ATT&CK techniques
            for attack in meta.get("attack", []):
                attack_entry = {
                    "id": attack.get("id"),
                    "tactic": attack.get("tactic"),
                    "technique": attack.get("technique"),
                }
                
                # Add subtechnique if present
                if subtechnique := attack.get("subtechnique"):
                    attack_entry["subtechnique"] = subtechnique
                
                if attack_entry not in results["mitre_attack"]:
                    results["mitre_attack"].append(attack_entry)
            
            # Extract MBC (Malware Behavior Catalog)
            for mbc in meta.get("mbc", []):
                mbc_entry = {
                    "id": mbc.get("id"),
                    "objective": mbc.get("objective"),
                    "behavior": mbc.get("behavior"),
                }
                
                if mbc_entry not in results["mbc"]:
                    results["mbc"].append(mbc_entry)
        
        return results
    
    def get_supported_types(self) -> Set[str]:
        """Get supported file types"""
        return {"pe", "elf", "pe32", "pe64"}
