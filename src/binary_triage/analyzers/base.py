"""
Base analyzer class and common data structures
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class AnalysisStatus(str, Enum):
    """Status of an analysis operation"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    NO_RESULTS = "no_results"
    SKIPPED = "skipped"


@dataclass
class AnalysisResult:
    """Base class for analysis results"""
    analyzer: str
    status: AnalysisStatus
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "analyzer": self.analyzer,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "results": self.results,
            "error": self.error,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }
    
    def is_successful(self) -> bool:
        """Check if analysis was successful"""
        return self.status in [AnalysisStatus.SUCCESS, AnalysisStatus.PARTIAL_SUCCESS]


@dataclass
class FileInfo:
    """Information about the file being analyzed"""
    path: Path
    name: str
    size: int
    sha256: str
    md5: str
    sha1: str
    file_type: Optional[str] = None
    mime_type: Optional[str] = None
    magic: Optional[str] = None
    
    @classmethod
    def from_path(cls, file_path: Path) -> "FileInfo":
        """Create FileInfo from a file path"""
        import hashlib
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file data
        data = file_path.read_bytes()
        
        # Calculate hashes
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        
        return cls(
            path=file_path,
            name=file_path.name,
            size=len(data),
            sha256=sha256,
            md5=md5,
            sha1=sha1,
        )


class BaseAnalyzer(ABC):
    """Base class for all analyzers"""
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize analyzer
        
        Args:
            name: Name of the analyzer
            config: Optional configuration dictionary
        """
        self.name = name
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
    
    @abstractmethod
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Analyze a file
        
        Args:
            file_path: Path to the file to analyze
            file_data: Optional file data (if already read)
            
        Returns:
            AnalysisResult object with analysis results
        """
        pass
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """
        Check if this analyzer can analyze the given file
        
        Args:
            file_info: Information about the file
            
        Returns:
            True if analyzer can process this file
        """
        return True
    
    def get_supported_types(self) -> Set[str]:
        """
        Get set of supported file types
        
        Returns:
            Set of supported file type identifiers
        """
        return set()
    
    def _create_result(
        self,
        status: AnalysisStatus,
        results: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        warnings: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """
        Helper method to create an AnalysisResult
        
        Args:
            status: Analysis status
            results: Analysis results dictionary
            error: Optional error message
            warnings: Optional list of warnings
            metadata: Optional metadata dictionary
            
        Returns:
            AnalysisResult object
        """
        return AnalysisResult(
            analyzer=self.name,
            status=status,
            results=results or {},
            error=error,
            warnings=warnings or [],
            metadata=metadata or {},
        )
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name='{self.name}', enabled={self.enabled})"
