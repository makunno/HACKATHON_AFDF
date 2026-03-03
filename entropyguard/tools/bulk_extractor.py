"""Bulk extractor - artifact scanner for disk images"""
import re
from pathlib import Path
from typing import List, Dict, Set
from dataclasses import dataclass, field


@dataclass
class Artifact:
    """A discovered forensic artifact"""
    artifact_type: str
    offset: int
    data: str
    context: str
    confidence: float
    
    def to_dict(self) -> Dict:
        return {
            "type": self.artifact_type,
            "offset": self.offset,
            "data": self.data,
            "context": self.context,
            "confidence": self.confidence,
        }


@dataclass
class BulkExtractorResult:
    """Results from bulk extraction"""
    artifacts: List[Artifact] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "statistics": self.statistics,
        }


class BulkExtractor:
    """
    Extract various forensic artifacts from disk images.
    Includes patterns for: emails, URLs, IP addresses, credit cards, etc.
    """
    
    PATTERNS = {
        "email": re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "url": re.compile(rb'https?://[^\s<>"{}|\\^`\[\]]+'),
        "ipv4": re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "mac_address": re.compile(rb'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})'),
        "credit_card": re.compile(rb'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        "phone_us": re.compile(rb'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
        "ssn": re.compile(rb'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
        "hex_pattern": re.compile(rb'0x[0-9a-fA-F]+'),
        "base64": re.compile(rb'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    }
    
    def __init__(self, max_findings: int = 10000):
        self.max_findings = max_findings
    
    def extract(
        self,
        disk_path: str | Path,
        patterns: List[str] = None,
        max_scan_size: int = 100 * 1024 * 1024
    ) -> BulkExtractorResult:
        """
        Extract artifacts from disk image.
        
        Args:
            disk_path: Path to disk image
            patterns: List of pattern names to search (None = all)
            max_scan_size: Maximum bytes to scan
            
        Returns:
            BulkExtractorResult with artifacts
        """
        disk_path = Path(disk_path)
        
        if patterns is None:
            patterns = list(self.PATTERNS.keys())
        
        artifacts = []
        statistics = {p: 0 for p in patterns}
        statistics["total_artifacts"] = 0
        
        try:
            with open(disk_path, 'rb') as f:
                offset = 0
                chunk_size = 1024 * 1024  # 1MB chunks
                
                while offset < max_scan_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    for pattern_name in patterns:
                        if pattern_name not in self.PATTERNS:
                            continue
                        
                        pattern = self.PATTERNS[pattern_name]
                        
                        for match in pattern.finditer(chunk):
                            if len(artifacts) >= self.max_findings:
                                break
                            
                            data = match.group().decode('utf-8', errors='replace')
                            match_offset = offset + match.start()
                            
                            # Get context (50 bytes before and after)
                            start_ctx = max(0, match.start() - 25)
                            end_ctx = min(len(chunk), match.end() + 25)
                            context = chunk[start_ctx:end_ctx].decode('utf-8', errors='replace')
                            
                            # Calculate confidence
                            confidence = self._calculate_confidence(pattern_name, data)
                            
                            artifacts.append(Artifact(
                                artifact_type=pattern_name,
                                offset=match_offset,
                                data=data[:200],  # Truncate long matches
                                context=context[:100],
                                confidence=confidence,
                            ))
                            
                            statistics[pattern_name] += 1
                    
                    offset += chunk_size
                    statistics["total_artifacts"] = len(artifacts)
        
        except Exception as e:
            statistics["error"] = str(e)
        
        return BulkExtractorResult(artifacts=artifacts, statistics=statistics)
    
    def _calculate_confidence(self, pattern_type: str, data: str) -> float:
        """Calculate confidence score for a match"""
        if pattern_type == "credit_card":
            # Luhn algorithm check
            if self._luhn_check(data):
                return 95.0
            return 50.0
        
        if pattern_type == "email":
            if "@" in data and "." in data.split("@")[1]:
                return 90.0
        
        if pattern_type == "ipv4":
            parts = data.split(".")
            if len(parts) == 4:
                try:
                    if all(0 <= int(p) <= 255 for p in parts):
                        return 90.0
                except:
                    pass
        
        if pattern_type == "ssn":
            if re.match(r'^\d{3}-\d{2}-\d{4}$', data):
                return 95.0
        
        return 75.0  # Default confidence
    
    def _luhn_check(self, number: str) -> bool:
        """Validate credit card number with Luhn algorithm"""
        digits = [int(c) for c in re.sub(r'\D', '', number)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        
        return checksum % 10 == 0
    
    def extract_carved_files(
        self,
        disk_path: str | Path,
        output_dir: Path,
        max_carve_size: int = 10 * 1024 * 1024
    ) -> List[Path]:
        """
        Attempt to carve files based on magic bytes.
        
        Args:
            disk_path: Path to disk image
            output_dir: Directory to save carved files
            max_carve_size: Maximum size to carve
            
        Returns:
            List of carved file paths
        """
        # File signatures for common types
        MAGIC_BYTES = {
            b'\xFF\xD8\xFF': ('jpg', 'JPEG Image'),
            b'\x89PNG\r\n\x1a\n': ('png', 'PNG Image'),
            b'%PDF': ('pdf', 'PDF Document'),
            b'PK\x03\x04': ('zip', 'ZIP Archive'),
            b'Rar!': ('rar', 'RAR Archive'),
            b'GIF87a': ('gif', 'GIF Image'),
            b'GIF89a': ('gif', 'GIF Image'),
            b'\xD0\xCF\x11\xE0': ('doc', 'MS Office Document'),
            b'EVF\x09\x0D\x0A\xFF': ('e01', 'EnCase Evidence File'),
        }
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        carved = []
        
        try:
            with open(disk_path, 'rb') as f:
                offset = 0
                
                while offset < max_carve_size:
                    f.seek(offset)
                    header = f.read(16)
                    
                    found = False
                    for magic, (ext, desc) in MAGIC_BYTES.items():
                        if header.startswith(magic):
                            # Found a file - try to determine size
                            size = self._estimate_size(f, ext, offset)
                            size = min(size, max_carve_size - offset)
                            
                            if size > 0 and size < max_carve_size:
                                # Carve the file
                                f.seek(offset)
                                data = f.read(size)
                                
                                out_path = output_dir / f"carved_{offset:08X}.{ext}"
                                out_path.write_bytes(data)
                                carved.append(out_path)
                            
                            offset += max(1, size)
                            found = True
                            break
                    
                    if not found:
                        offset += 512  # Skip uninteresting sectors
        
        except Exception as e:
            print(f"Error carving files: {e}")
        
        return carved
    
    def _estimate_size(self, f, file_type: str, start_offset: int) -> int:
        """Estimate file size based on type"""
        # This is a simplified estimation
        return 4096  # Default to one cluster
    
    def export_json(self, result: BulkExtractorResult, output_path: Path) -> Path:
        """Export results to JSON"""
        import json
        output_path.write_text(json.dumps(result.to_dict(), indent=2))
        return output_path


@dataclass
class FileValidationResult:
    """Result of file type validation"""
    file_type: str
    extension: str
    magic_bytes: str
    is_valid: bool
    validation_message: str
    sha256_hash: str
    md5_hash: str
    
    def to_dict(self) -> Dict:
        return {
            "file_type": self.file_type,
            "extension": self.extension,
            "magic_bytes": self.magic_bytes,
            "is_valid": self.is_valid,
            "validation_message": self.validation_message,
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
        }


FILE_SIGNATURES = {
    b'EVF\x09\x0D\x0A\xFF': {
        'type': 'E01',
        'name': 'EnCase Evidence File',
        'data_offset': 0x1000,
    },
    b'\xFF\xD8\xFF': {'type': 'JPEG', 'name': 'JPEG Image', 'data_offset': 0},
    b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'name': 'PNG Image', 'data_offset': 0},
    b'%PDF': {'type': 'PDF', 'name': 'PDF Document', 'data_offset': 0},
    b'PK\x03\x04': {'type': 'ZIP', 'name': 'ZIP Archive', 'data_offset': 0},
    b'Rar!': {'type': 'RAR', 'name': 'RAR Archive', 'data_offset': 0},
    b'GIF87a': {'type': 'GIF', 'name': 'GIF Image', 'data_offset': 0},
    b'GIF89a': {'type': 'GIF', 'name': 'GIF Image', 'data_offset': 0},
    b'\xD0\xCF\x11\xE0': {'type': 'OLE', 'name': 'MS Office Document', 'data_offset': 0},
}


def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """
    Calculate MD5 and SHA256 hashes of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary with 'md5' and 'sha256' hash values
    """
    import hashlib
    
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return {
        'md5': md5_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest(),
    }


def validate_file_type(file_path: Path) -> FileValidationResult:
    """
    Validate file type by checking magic bytes against extension.
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        FileValidationResult with validation status and hashes
    """
    file_path = Path(file_path)
    extension = file_path.suffix.upper()
    
    hashes = calculate_hashes(file_path)
    
    with open(file_path, 'rb') as f:
        header = f.read(16)
    
    detected_type = None
    detected_name = None
    
    for magic, info in FILE_SIGNATURES.items():
        if header.startswith(magic):
            detected_type = info['type']
            detected_name = info['name']
            break
    
    if detected_type is None:
        return FileValidationResult(
            file_type='Unknown',
            extension=extension,
            magic_bytes=header[:8].hex(),
            is_valid=False,
            validation_message='Unknown file type - no matching magic bytes',
            sha256_hash=hashes['sha256'],
            md5_hash=hashes['md5'],
        )
    
    expected_ext_map = {
        'E01': '.E01',
        'JPEG': '.JPG',
        'PNG': '.PNG',
        'PDF': '.PDF',
        'ZIP': '.ZIP',
        'RAR': '.RAR',
        'GIF': '.GIF',
        'OLE': '.DOC',
    }
    
    expected_ext = expected_ext_map.get(detected_type, '')
    is_valid = extension == expected_ext
    
    validation_message = (
        f"VALID (extension matches magic bytes)" if is_valid
        else f"INVALID (extension {extension} does not match expected {expected_ext})"
    )
    
    return FileValidationResult(
        file_type=detected_type,
        extension=extension,
        magic_bytes=header[:8].hex(),
        is_valid=is_valid,
        validation_message=validation_message,
        sha256_hash=hashes['sha256'],
        md5_hash=hashes['md5'],
    )


def get_evidence_data_offset(file_path: Path) -> int:
    """
    Get the offset where the actual evidence data starts within the container.
    
    For EnCase Evidence Files (E01), the raw disk data typically starts at offset 0x1000.
    
    Args:
        file_path: Path to the evidence file
        
    Returns:
        Byte offset where the embedded data starts
    """
    file_path = Path(file_path)
    
    with open(file_path, 'rb') as f:
        header = f.read(16)
    
    for magic, info in FILE_SIGNATURES.items():
        if header.startswith(magic):
            return info.get('data_offset', 0)
    
    return 0


def detect_embedded_filesystem(file_path: Path) -> Dict:
    """
    Detect filesystem type from embedded disk image within a container file.
    
    For E01 files, reads the filesystem signature from offset 0x1000 where the
    raw disk data begins. Also searches for filesystem signatures within 
    compressed evidence files.
    
    Args:
        file_path: Path to the container file (e.g., E01)
        
    Returns:
        Dictionary with filesystem information
    """
    file_path = Path(file_path)
    
    data_offset = 0
    container_type = None
    
    with open(file_path, 'rb') as f:
        header = f.read(16)
        
        for magic, info in FILE_SIGNATURES.items():
            if header.startswith(magic):
                data_offset = info.get('data_offset', 0)
                container_type = info.get('type')
                break
        
        if data_offset == 0:
            return {
                'detected': False,
                'filesystem_type': 'Unknown',
                'message': 'Could not determine data offset for container type',
            }
        
        f.seek(data_offset)
        boot_sector = f.read(512)
    
    fs_signatures = {
        b'NTFS': ('NTFS', 'NTFS filesystem detected'),
        b'\x45\x4E\x54\x46': ('NTFS', 'NTFS filesystem detected (backup boot sector)'),
        b'\xEB\x3C\x90': ('FAT12', 'FAT12 filesystem detected'),
        b'\xEB\x58\x90': ('FAT32', 'FAT32 filesystem detected'),
        b'\xEB\x52\x90': ('FAT32', 'FAT32 filesystem detected (alternative)'),
        b'\x53\xEF': ('EXT2/3/4', 'EXT2/3/4 filesystem detected'),
        b'\x45\x58\x46\x41\x54': ('exFAT', 'exFAT filesystem detected'),
        b'\x48\x2B\x04\x00': ('HFS', 'HFS filesystem detected'),
        b'\x41\x50\x46\x53': ('APFS', 'APFS filesystem detected'),
    }
    
    for sig, (fs_type, message) in fs_signatures.items():
        if boot_sector[:len(sig)] == sig:
            return {
                'detected': True,
                'filesystem_type': fs_type,
                'data_offset': data_offset,
                'container_type': container_type,
                'message': message,
                'magic_bytes': sig.hex(),
            }
    
    # For compressed evidence files (E01), search for filesystem signatures
    # within the file data as they may be embedded in compressed blocks
    if container_type == 'E01':
        with open(file_path, 'rb') as f:
            file_data = f.read(min(file_path.stat().st_size, 50 * 1024 * 1024))
        
        for sig, (fs_type, message) in fs_signatures.items():
            pos = file_data.find(sig)
            if pos != -1 and pos > data_offset:
                return {
                    'detected': True,
                    'filesystem_type': fs_type,
                    'data_offset': data_offset,
                    'container_type': container_type,
                    'message': f'{message} (found at offset 0x{pos:X} within compressed data)',
                    'magic_bytes': sig.hex(),
                    'note': 'Filesystem found within compressed E01 data - decompression required for full analysis',
                }
        
        return {
            'detected': False,
            'filesystem_type': 'Unknown',
            'data_offset': data_offset,
            'container_type': container_type,
            'message': 'E01 evidence file uses compression - filesystem may be inside compressed blocks',
            'boot_sector_preview': boot_sector[:64].hex(),
            'note': 'To analyze the embedded filesystem, decompress the E01 file using EnCase or ewfacquire',
        }
    
    return {
        'detected': False,
        'filesystem_type': 'Unknown',
        'data_offset': data_offset,
        'container_type': container_type,
        'message': 'No recognized filesystem signature found',
        'boot_sector_preview': boot_sector[:64].hex(),
    }
