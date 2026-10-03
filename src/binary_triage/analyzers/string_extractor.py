"""
String and IOC Extractor - Extract strings and indicators of compromise from binaries
"""

import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .base import BaseAnalyzer, AnalysisResult, AnalysisStatus, FileInfo

logger = logging.getLogger(__name__)


class StringExtractor(BaseAnalyzer):
    """
    Extract strings and IOCs from binary files
    
    Features:
    - ASCII and Unicode string extraction
    - URL, IP, domain, email extraction
    - File path detection
    - Registry key detection
    - Delphi string extraction
    - Base64 detection
    - Hex pattern detection
    """
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        "ipv4": re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        "ipv6": re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        "url": re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        ),
        "domain": re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        "email": re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        "windows_path": re.compile(
            r'[A-Za-z]:\\(?:[^\x00-\x1f<>:"|?*\\]+\\)*[^\x00-\x1f<>:"|?*\\]*'
        ),
        "unix_path": re.compile(
            r'/(?:[^/\x00]+/)*[^/\x00]*'
        ),
        "registry_key": re.compile(
            r'HKEY_[A-Z_]+\\[^\x00\n\r]+',
            re.IGNORECASE
        ),
        "base64": re.compile(
            r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        ),
        "hex_pattern": re.compile(
            r'\b(?:0x)?[0-9a-fA-F]{8,}\b'
        ),
        "pdb_path": re.compile(
            r'[A-Za-z]:\\[^:*?"<>|\r\n]+\.pdb',
            re.IGNORECASE
        ),
        "mutex": re.compile(
            r'(?:Global\\|Local\\)[A-Za-z0-9_\-]+',
            re.IGNORECASE
        ),
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize string extractor
        
        Args:
            config: Configuration dictionary with:
                - min_length: Minimum string length (default: 4)
                - max_strings: Maximum strings to extract (default: 10000)
                - extract_unicode: Extract Unicode strings (default: True)
                - extract_iocs: Extract IOCs (default: True)
                - context_size: Context size around IOCs (default: 50)
        """
        super().__init__("string_extractor", config)
        
        self.min_length = self.config.get("min_length", 4)
        self.max_strings = self.config.get("max_strings", 10000)
        self.extract_unicode = self.config.get("extract_unicode", True)
        self.extract_iocs = self.config.get("extract_iocs", True)
        # A&D mode: surface pwn-relevant strings (flag paths, /bin/sh, format
        # specifiers, secrets) instead of / alongside malware IOCs.
        self.extract_ad = self.config.get("extract_ad", True)
        self.context_size = self.config.get("context_size", 50)

    # Attack & Defense relevant string patterns (service binaries, not malware)
    AD_PATTERNS = {
        "flag_paths": re.compile(r'(?:/[\w./-]*)?flag[\w.]*', re.IGNORECASE),
        "shell": re.compile(r'/bin/(?:sh|bash|dash)\b'),
        "format_specifiers": re.compile(r'%(?:\d+\$)?[ -+#0]*\d*(?:\.\d+)?[hljztL]*[diouxXeEfFgGaAcspn]'),
        "secrets": re.compile(r'(?i)(?:secret|token|passwd|password|api[_-]?key|private[_-]?key)[\w./=+-]*'),
        "cmds": re.compile(r'\b(?:system|popen|execve|/usr/bin/\w+)\b'),
    }
    
    def can_analyze(self, file_info: FileInfo) -> bool:
        """String extraction works on any file"""
        return True
    
    def analyze(self, file_path: Path, file_data: Optional[bytes] = None) -> AnalysisResult:
        """
        Extract strings and IOCs from file
        
        Args:
            file_path: Path to file to analyze
            file_data: Optional file data (if already read)
            
        Returns:
            AnalysisResult with extracted strings and IOCs
        """
        try:
            # Read file data if not provided
            if file_data is None:
                file_data = file_path.read_bytes()
            
            # Extract strings
            ascii_strings = self._extract_ascii_strings(file_data)
            unicode_strings = []
            
            if self.extract_unicode:
                unicode_strings = self._extract_unicode_strings(file_data)
            
            # Combine all strings
            all_strings = ascii_strings + unicode_strings
            
            # Extract IOCs if enabled (malware framing; off in the A&D profile)
            iocs = {}
            if self.extract_iocs:
                iocs = self._extract_iocs(all_strings, file_data)

            # Extract A&D-relevant strings (pwn framing)
            ad_strings = {}
            if self.extract_ad:
                ad_strings = self._extract_ad_strings(all_strings)

            # Extract Delphi strings
            delphi_strings = self._extract_delphi_strings(file_data)

            # Build results
            results = {
                "ascii_strings": ascii_strings[:self.max_strings],
                "unicode_strings": unicode_strings[:self.max_strings],
                "delphi_strings": delphi_strings,
                "string_count": {
                    "ascii": len(ascii_strings),
                    "unicode": len(unicode_strings),
                    "delphi": len(delphi_strings),
                    "total": len(all_strings),
                },
                "iocs": iocs,
                "ad_strings": ad_strings,
            }
            
            status = AnalysisStatus.SUCCESS if all_strings or iocs else AnalysisStatus.NO_RESULTS
            
            return self._create_result(
                status=status,
                results=results,
                metadata={
                    "min_length": self.min_length,
                    "truncated": len(all_strings) > self.max_strings,
                }
            )
        
        except Exception as e:
            logger.exception(f"String extraction failed: {e}")
            return self._create_result(
                status=AnalysisStatus.FAILURE,
                error=f"String extraction failed: {str(e)}"
            )
    
    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """Extract ASCII strings from binary data"""
        ascii_pattern = re.compile(rb'[\x20-\x7E]{%d,}' % self.min_length)
        strings = []
        
        for match in ascii_pattern.finditer(data):
            try:
                string = match.group().decode('ascii')
                strings.append(string)
            except UnicodeDecodeError:
                continue
        
        return strings
    
    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """Extract Unicode (UTF-16LE) strings from binary data"""
        unicode_pattern = re.compile(
            rb'(?:[\x20-\x7E]\x00){%d,}' % self.min_length
        )
        strings = []
        
        for match in unicode_pattern.finditer(data):
            try:
                string = match.group().decode('utf-16le')
                strings.append(string)
            except UnicodeDecodeError:
                continue
        
        return strings
    
    def _extract_delphi_strings(self, data: bytes) -> List[str]:
        """Extract Delphi strings (length-prefixed Unicode strings)"""
        delphi_strings = []
        
        # Delphi string pattern: \xb0\x04\x02\x00\xff\xff\xff\xff + 4 bytes length
        pattern = rb'\xb0\x04\x02\x00\xff\xff\xff\xff.{4}'
        
        for match in re.finditer(pattern, data):
            start_offset = match.start()
            end_offset = match.end()
            
            # Extract length
            try:
                length = int.from_bytes(data[start_offset + 8:end_offset], "little")
                
                if length >= 4 and end_offset + length * 2 <= len(data):
                    string_data = data[end_offset:end_offset + length * 2]
                    string = string_data.decode("utf-16le")
                    delphi_strings.append(string)
            except (ValueError, UnicodeDecodeError):
                continue
        
        return delphi_strings
    
    def _extract_iocs(self, strings: List[str], data: bytes) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract IOCs from strings
        
        Args:
            strings: List of extracted strings
            data: Original binary data for context
            
        Returns:
            Dictionary of IOC categories and matches
        """
        iocs = {
            "urls": [],
            "ips": [],
            "domains": [],
            "emails": [],
            "file_paths": [],
            "registry_keys": [],
            "pdb_paths": [],
            "mutexes": [],
        }
        
        # Combine all strings for searching
        text = "\n".join(strings)
        
        # Extract URLs
        for match in self.PATTERNS["url"].finditer(text):
            url = match.group()
            context = self._get_context(text, match.start(), match.end())
            iocs["urls"].append({"value": url, "context": context})
        
        # Extract IPs
        for match in self.PATTERNS["ipv4"].finditer(text):
            ip = match.group()
            # Filter out common false positives
            if not self._is_valid_ip(ip):
                continue
            context = self._get_context(text, match.start(), match.end())
            iocs["ips"].append({"value": ip, "context": context})
        
        # Extract domains (excluding IPs)
        for match in self.PATTERNS["domain"].finditer(text):
            domain = match.group()
            # Skip if it's an IP or common false positive
            if self.PATTERNS["ipv4"].match(domain) or not self._is_valid_domain(domain):
                continue
            context = self._get_context(text, match.start(), match.end())
            iocs["domains"].append({"value": domain, "context": context})
        
        # Extract emails
        for match in self.PATTERNS["email"].finditer(text):
            email = match.group()
            context = self._get_context(text, match.start(), match.end())
            iocs["emails"].append({"value": email, "context": context})
        
        # Extract file paths
        for pattern_name in ["windows_path", "unix_path"]:
            for match in self.PATTERNS[pattern_name].finditer(text):
                path = match.group()
                if len(path) > 3:  # Filter very short paths
                    context = self._get_context(text, match.start(), match.end())
                    iocs["file_paths"].append({"value": path, "context": context})
        
        # Extract registry keys
        for match in self.PATTERNS["registry_key"].finditer(text):
            key = match.group()
            context = self._get_context(text, match.start(), match.end())
            iocs["registry_keys"].append({"value": key, "context": context})
        
        # Extract PDB paths
        for match in self.PATTERNS["pdb_path"].finditer(text):
            pdb = match.group()
            context = self._get_context(text, match.start(), match.end())
            iocs["pdb_paths"].append({"value": pdb, "context": context})
        
        # Extract mutexes
        for match in self.PATTERNS["mutex"].finditer(text):
            mutex = match.group()
            context = self._get_context(text, match.start(), match.end())
            iocs["mutexes"].append({"value": mutex, "context": context})
        
        # Remove duplicates
        for category in iocs:
            seen = set()
            unique = []
            for item in iocs[category]:
                if item["value"] not in seen:
                    seen.add(item["value"])
                    unique.append(item)
            iocs[category] = unique
        
        return iocs
    
    def _extract_ad_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Surface Attack & Defense relevant strings from a service binary."""
        text = "\n".join(strings)
        out: Dict[str, List[str]] = {}
        for name, pat in self.AD_PATTERNS.items():
            seen, vals = set(), []
            for m in pat.finditer(text):
                v = m.group()
                if len(v) < 3 or v in seen:
                    continue
                seen.add(v)
                vals.append(v)
                if len(vals) >= 100:
                    break
            if vals:
                out[name] = vals
        return out

    def _get_context(self, text: str, start: int, end: int) -> str:
        """Get context around a match"""
        context_start = max(0, start - self.context_size)
        context_end = min(len(text), end + self.context_size)
        return text[context_start:context_end]
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid (not a version number or other false positive)"""
        parts = ip.split('.')
        
        # Filter common false positives
        if parts[0] == '0' or parts[0] == '255':
            return False
        
        # Check for version-like patterns (e.g., 1.0.0.0)
        if all(int(p) < 10 for p in parts):
            return False
        
        return True
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid (not a false positive)"""
        # Filter common false positives
        invalid_tlds = {'local', 'test', 'example', 'invalid', 'localhost'}
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        tld = parts[-1].lower()
        if tld in invalid_tlds:
            return False
        
        # Check if it looks like a file extension
        if len(tld) <= 4 and tld in {'exe', 'dll', 'sys', 'txt', 'log', 'dat'}:
            return False
        
        return True
    
    def get_supported_types(self) -> Set[str]:
        """String extraction works on any file type"""
        return {"*"}
