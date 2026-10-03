"""
File Identifier - Identify file types using magic numbers and AI
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Set

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    from magika import Magika
    MAGIKA_AVAILABLE = True
except ImportError:
    MAGIKA_AVAILABLE = False

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class FileIdentifier(BaseAnalyzer):
    """
    Identify file types using multiple methods
    
    Features:
    - Magic number detection (libmagic)
    - AI-powered detection (Magika)
    - MIME type detection
    - File extension validation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize file identifier
        
        Args:
            config: Configuration dictionary with:
                - use_magic: Use libmagic (default: True)
                - use_magika: Use Magika AI (default: True)
                - mime: Return MIME type (default: True)
        """
        super().__init__("file_identifier", config)
        
        self.use_magic = self.config.get("use_magic", True) and MAGIC_AVAILABLE
        self.use_magika = self.config.get("use_magika", True) and MAGIKA_AVAILABLE
        self.mime = self.config.get("mime", True)
        
        # Initialize Magika if available
        self.magika = None
        if self.use_magika:
            try:
                self.magika = Magika()
                logger.info("Magika initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Magika: {e}")
                self.use_magika = False
        
        if not self.use_magic and not self.use_magika:
            logger.warning("No file identification methods available")
            self.enabled = False
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """File identification works on any file"""
        return self.enabled
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Identify file type
        
        Args:
            file_path: Path to file to identify
            file_data: Optional file data (if already read)
            
        Returns:
            AnalysisResult with file type information
        """
        if not self.enabled:
            return self._create_result(
                status=AnalysisStatus.SKIPPED,
                error="No file identification methods available"
            )
        
        try:
            # Read file data if not provided
            if file_data is None:
                file_data = file_path.read_bytes()
            
            results = {
                "filename": file_path.name,
                "extension": file_path.suffix.lower() if file_path.suffix else None,
                "size": len(file_data),
            }
            
            # Use libmagic
            if self.use_magic:
                magic_results = self._identify_with_magic(file_path, file_data)
                results.update(magic_results)
            
            # Use Magika
            if self.use_magika and self.magika:
                magika_results = self._identify_with_magika(file_data)
                results["magika"] = magika_results
            
            # Determine primary file type
            results["file_type"] = self._determine_file_type(results)
            
            status = AnalysisStatus.SUCCESS if results.get("file_type") else AnalysisStatus.NO_RESULTS
            
            return self._create_result(
                status=status,
                results=results,
                metadata={
                    "methods_used": {
                        "magic": self.use_magic,
                        "magika": self.use_magika,
                    }
                }
            )
        
        except Exception as e:
            logger.exception(f"File identification failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"File identification failed: {str(e)}"
            )
    
    def _identify_with_magic(self, file_path: Path, file_data: bytes) -> Dict[str, Any]:
        """Identify file using libmagic"""
        results = {}
        
        try:
            # Get file type description
            results["magic_type"] = magic.from_buffer(file_data)
            
            # Get MIME type if requested
            if self.mime:
                results["mime_type"] = magic.from_buffer(file_data, mime=True)
            
            # Parse magic type for common formats
            magic_lower = results["magic_type"].lower()
            
            if "pe32" in magic_lower or "pe64" in magic_lower:
                results["format"] = "pe"
                if "32" in magic_lower:
                    results["architecture"] = "x86"
                elif "64" in magic_lower:
                    results["architecture"] = "x64"
            
            elif "elf" in magic_lower:
                results["format"] = "elf"
                if "32-bit" in magic_lower:
                    results["architecture"] = "x86"
                elif "64-bit" in magic_lower:
                    results["architecture"] = "x64"
            
            elif "mach-o" in magic_lower:
                results["format"] = "macho"
            
            elif "microsoft office" in magic_lower or "ooxml" in magic_lower:
                results["format"] = "office"
            
            elif "ole" in magic_lower:
                results["format"] = "ole"
            
            elif "pdf" in magic_lower:
                results["format"] = "pdf"
            
            elif "zip" in magic_lower or "archive" in magic_lower:
                results["format"] = "archive"
        
        except Exception as e:
            logger.warning(f"Magic identification failed: {e}")
        
        return results
    
    def _identify_with_magika(self, file_data: bytes) -> Dict[str, Any]:
        """Identify file using Magika AI"""
        results = {}
        
        try:
            magika_result = self.magika.identify_bytes(file_data)
            output = magika_result.output
            
            results = {
                "label": output.ct_label,
                "score": output.score,
                "group": output.group,
                "mime_type": output.mime_type,
                "description": output.description,
            }
        
        except Exception as e:
            logger.warning(f"Magika identification failed: {e}")
        
        return results
    
    def _determine_file_type(self, results: Dict[str, Any]) -> str:
        """
        Determine primary file type from all identification results
        
        Args:
            results: Combined results from all identification methods
            
        Returns:
            Primary file type identifier
        """
        # Priority: format from magic > magika label > mime type
        
        if "format" in results:
            return results["format"]
        
        if "magika" in results and results["magika"].get("label"):
            return results["magika"]["label"]
        
        if "mime_type" in results:
            mime = results["mime_type"]
            # Map common MIME types to file types
            mime_map = {
                "application/x-dosexec": "pe",
                "application/x-executable": "elf",
                "application/x-mach-binary": "macho",
                "application/pdf": "pdf",
                "application/zip": "zip",
                "application/x-7z-compressed": "7z",
                "application/x-rar": "rar",
            }
            
            for mime_prefix, file_type in mime_map.items():
                if mime.startswith(mime_prefix):
                    return file_type
        
        if "magic_type" in results:
            return results["magic_type"].split(",")[0].lower()
        
        return "unknown"
    
    def get_supported_types(self) -> Set[str]:
        """File identification works on any file type"""
        return {"*"}
