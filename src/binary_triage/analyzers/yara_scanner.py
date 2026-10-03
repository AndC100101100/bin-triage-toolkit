"""
YARA Scanner - Pattern matching and malware detection
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class YaraMatch:
    """Represents a YARA rule match"""
    
    def __init__(self, rule: str, namespace: str = "", tags: List[str] = None, meta: Dict[str, Any] = None):
        self.rule = rule
        self.namespace = namespace
        self.tags = tags or []
        self.meta = meta or {}
        self.strings = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary"""
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "strings": self.strings,
        }
    
    @property
    def family(self) -> Optional[str]:
        """Extract malware family from metadata"""
        return self.meta.get("family") or self.meta.get("malware_family")
    
    @property
    def description(self) -> Optional[str]:
        """Extract description from metadata"""
        return self.meta.get("description") or self.meta.get("desc")


class YaraScanner(BaseAnalyzer):
    """
    YARA-based pattern matching and malware detection
    
    Features:
    - Load rules from files or directories
    - Compile and cache rules
    - Fast pattern matching
    - Extract metadata from matches
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize YARA scanner
        
        Args:
            config: Configuration dictionary with:
                - rules_path: Path to YARA rules (file or directory)
                - compiled_rules: Path to compiled rules file
                - timeout: Scan timeout in seconds
                - fast_mode: Enable fast scanning
        """
        super().__init__("yara_scanner", config)
        
        if not YARA_AVAILABLE:
            logger.error("YARA is not available. Install with: pip install yara-python")
            self.enabled = False
            return
        
        self.rules_path = self.config.get("rules_path")
        self.compiled_rules_path = self.config.get("compiled_rules")
        self.timeout = self.config.get("timeout", 60)
        self.fast_mode = self.config.get("fast_mode", False)
        
        self.rules = None
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load and compile YARA rules"""
        try:
            # Try to load compiled rules first
            if self.compiled_rules_path and Path(self.compiled_rules_path).exists():
                logger.info(f"Loading compiled YARA rules from {self.compiled_rules_path}")
                self.rules = yara.load(str(self.compiled_rules_path))
                return
            
            # Load from source rules
            if self.rules_path:
                rules_path = Path(self.rules_path)
                
                if rules_path.is_file():
                    logger.info(f"Loading YARA rules from file: {rules_path}")
                    self.rules = yara.compile(filepath=str(rules_path))
                
                elif rules_path.is_dir():
                    logger.info(f"Loading YARA rules from directory: {rules_path}")
                    # Collect all .yar and .yara files
                    rule_files = {}
                    for ext in ["*.yar", "*.yara"]:
                        for rule_file in rules_path.rglob(ext):
                            namespace = rule_file.stem
                            rule_files[namespace] = str(rule_file)
                    
                    if rule_files:
                        self.rules = yara.compile(filepaths=rule_files)
                        logger.info(f"Loaded {len(rule_files)} YARA rule files")
                    else:
                        logger.warning(f"No YARA rules found in {rules_path}")
                else:
                    logger.warning(f"YARA rules path does not exist: {rules_path}")
            
            # Save compiled rules if path is specified
            if self.rules and self.compiled_rules_path:
                logger.info(f"Saving compiled rules to {self.compiled_rules_path}")
                self.rules.save(str(self.compiled_rules_path))
        
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.enabled = False
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """Check if YARA scanner can analyze the file"""
        return self.enabled and self.rules is not None
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Scan file with YARA rules
        
        Args:
            file_path: Path to file to scan
            file_data: Optional file data (if already read)
            
        Returns:
            AnalysisResult with YARA matches
        """
        if not self.enabled or not self.rules:
            return self._create_result(
                status=AnalysisStatus.SKIPPED,
                error="YARA scanner is not available or rules not loaded"
            )
        
        try:
            # Read file data if not provided
            if file_data is None:
                file_data = file_path.read_bytes()
            
            # Scan with YARA
            matches = self.rules.match(
                data=file_data,
                timeout=self.timeout,
                fast=self.fast_mode
            )
            
            # Process matches
            yara_matches = []
            families = set()
            tags = set()
            
            for match in matches:
                yara_match = YaraMatch(
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta)
                )
                
                # Extract string matches
                for string_match in match.strings:
                    yara_match.strings.append({
                        "identifier": string_match.identifier,
                        "instances": len(string_match.instances),
                    })
                
                yara_matches.append(yara_match)
                
                # Collect families and tags
                if yara_match.family:
                    families.add(yara_match.family)
                tags.update(yara_match.tags)
            
            # Build results
            results = {
                "matches": [m.to_dict() for m in yara_matches],
                "match_count": len(yara_matches),
                "rules": [m.rule for m in yara_matches],
                "families": list(families),
                "tags": list(tags),
            }
            
            status = AnalysisStatus.SUCCESS if yara_matches else AnalysisStatus.NO_RESULTS
            
            return self._create_result(
                status=status,
                results=results,
                metadata={
                    "scan_time": self.timeout,
                    "fast_mode": self.fast_mode,
                }
            )
        
        except yara.TimeoutError:
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"YARA scan timed out after {self.timeout} seconds"
            )
        
        except Exception as e:
            logger.exception(f"YARA scan failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"YARA scan failed: {str(e)}"
            )
    
    def get_supported_types(self) -> Set[str]:
        """YARA can scan any file type"""
        return {"*"}
