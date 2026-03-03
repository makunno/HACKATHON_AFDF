"""
Wipe Pattern Detector Module

Runs blkls to extract unallocated disk space and scans for wipe signatures:
- Zero-fill patterns (0x00)
- FF-fill patterns (0xFF)  
- Random-like data (high entropy)
- DoD 5220.22-M patterns (3-pass and 7-pass)
- Gutmann 35-pass patterns
"""

import os
import json
import subprocess
import math
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict


# DoD 5220.22-M patterns
DOD_PATTERNS = {
    'DOD_3PASS': [
        bytes([0x00] * 512),      # Pass 1: All zeros
        bytes([0xFF] * 512),      # Pass 2: All ones
    ],
    'DOD_7PASS': [
        bytes([0x00] * 512),      # Pass 1: All zeros
        bytes([0xFF] * 512),      # Pass 2: All ones
        None,                      # Pass 3: Random (detected by high entropy)
        bytes([0x00] * 512),      # Pass 4: All zeros
        bytes([0xFF] * 512),      # Pass 5: All ones
        None,                      # Pass 6: Random
        None,                      # Pass 7: Random
    ],
    'DOD_5220_22_M': [  # Original 3-pass
        bytes([0x00] * 512),
        bytes([0xFF] * 512),
    ],
    'DOD_5220_22_M_ECE': [  # Enhanced 7-pass
        bytes([0x00] * 512),
        bytes([0xFF] * 512),
        bytes([0x00] * 512),
        bytes([0xFF] * 512),
        bytes([0x00] * 512),
        bytes([0xFF] * 512),
        bytes([0x00] * 512),
    ],
}

# Gutmann 35-pass patterns (specific byte sequences)
GUTMANN_PATTERNS = [
    bytes([0x55] * 512),           # Pass 1: 0x55
    bytes([0xAA] * 512),           # Pass 2: 0xAA
    bytes([0x92, 0x49] * 256),    # Pass 3: 0x92 0x49
    bytes([0x49, 0x24] * 256),    # Pass 4: 0x49 0x24
    bytes([0x24, 0x00] * 256),     # Pass 5: 0x24 0x00
    bytes([0x00] * 512),           # Pass 6: All zeros
    bytes([0x11] * 512),          # Pass 7: 0x11
    bytes([0x22] * 512),          # Pass 8: 0x22
    bytes([0x33] * 512),          # Pass 9: 0x33
    bytes([0x44] * 512),          # Pass 10: 0x44
    bytes([0x55] * 512),          # Pass 11: 0x55
    bytes([0x66] * 512),          # Pass 12: 0x66
    bytes([0x77] * 512),          # Pass 13: 0x77
    bytes([0x88] * 512),          # Pass 14: 0x88
    bytes([0x99] * 512),          # Pass 15: 0x99
    bytes([0xAA] * 512),          # Pass 16: 0xAA
    bytes([0xBB] * 512),          # Pass 17: 0xBB
    bytes([0xCC] * 512),          # Pass 18: 0xCC
    bytes([0xDD] * 512),          # Pass 19: 0xDD
    bytes([0xEE] * 512),          # Pass 20: 0xEE
    bytes([0xFF] * 512),          # Pass 21: 0xFF
    bytes([0x92, 0x49] * 256),    # Pass 22: 0x92 0x49
    bytes([0x49, 0x24] * 256),    # Pass 23: 0x49 0x24
    bytes([0x24, 0x6D] * 256),    # Pass 24: 0x24 0x6D
    bytes([0x6D, 0xB6] * 256),    # Pass 25: 0x6D 0xB6
    bytes([0xB6, 0xDB] * 256),    # Pass 26: 0xB6 0xDB
    bytes([0xDB, 0x6D] * 256),    # Pass 27: 0xDB 0x6D
    bytes([0x6D, 0xB6] * 256),    # Pass 28: 0x6D 0xB6
    bytes([0xB6, 0x92] * 256),    # Pass 29: 0xB6 0x92
    bytes([0x92, 0x49] * 256),    # Pass 30: 0x92 0x49
    bytes([0x49, 0x24] * 256),    # Pass 31: 0x49 0x24
    # Passes 32-35: Random (detected by high entropy)
]

# Common wipe software signatures
WIPE_SOFTWARE_SIGNATURES = {
    'DBAN': [b'DBAN', b'dban', b'Blanking'],
    'BleachBit': [b'BleachBit', b'bleachbit'],
    'Shred': [b'shred', b'SHRED'],
    'Wipe': [b'wipe', b'WIPE'],
    'SecureDelete': [b'sdelete', b'SecureDelete'],
    'Eraser': [b'Eraser', b'eraser'],
    'CCleaner': [b'CCleaner', b'ccleaner'],
    'TrueCrypt': [b'TrueCrypt', b'TRUECRYPT'],
    'VeraCrypt': [b'VeraCrypt', b'VERACRYPT'],
}


@dataclass
class WipeChunk:
    """Represents a single 1MB chunk analysis result."""
    chunk_index: int
    offset_bytes: int
    zero_ratio: float
    ff_ratio: float
    entropy: float
    wipe_type: str  # 'ZERO_FILL', 'FF_FILL', 'RANDOM_LIKE', 'DOD_5220_22', 'GUTMANN', 'NORMAL'
    dod_matches: int = 0
    gutmann_matches: int = 0
    wipe_software: Optional[str] = None


@dataclass
class WipeRegion:
    """Represents a merged region of adjacent suspicious chunks."""
    start_offset: int
    end_offset: int
    wipe_type: str
    chunk_count: int
    
    def to_dict(self) -> Dict:
        return {
            "start": self.start_offset,
            "end": self.end_offset,
            "type": self.wipe_type,
            "chunk_count": self.chunk_count
        }


@dataclass
class WipeMetrics:
    """Aggregated wipe scan metrics."""
    image_path: str
    start_sector: int
    unalloc_path: str
    unalloc_size_bytes: int
    wipe_zero_bytes_total: int
    wipe_ff_bytes_total: int
    wipe_randomlike_bytes_total: int
    wipe_dod_bytes_total: int
    wipe_gutmann_bytes_total: int
    wipe_suspect_chunk_count: int
    scanned_bytes_total: int
    regions: List[Dict]
    detected_wipe_software: List[str]
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.detected_wipe_software is None:
            self.detected_wipe_software = []
    
    def to_dict(self) -> Dict:
        result = {
            "image_path": self.image_path,
            "start_sector": self.start_sector,
            "unalloc_path": self.unalloc_path,
            "unalloc_size_bytes": self.unalloc_size_bytes,
            "metrics": {
                "wipe_zero_bytes_total": self.wipe_zero_bytes_total,
                "wipe_ff_bytes_total": self.wipe_ff_bytes_total,
                "wipe_randomlike_bytes_total": self.wipe_randomlike_bytes_total,
                "wipe_dod_bytes_total": self.wipe_dod_bytes_total,
                "wipe_gutmann_bytes_total": self.wipe_gutmann_bytes_total,
                "wipe_suspect_chunk_count": self.wipe_suspect_chunk_count,
                "scanned_bytes_total": self.scanned_bytes_total,
                "detected_wipe_software": self.detected_wipe_software,
            },
            "regions": self.regions[:200]  # Cap to first 200
        }
        if self.error:
            result["error"] = self.error
        return result


def _compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy of byte data (0-8 bits)."""
    if len(data) == 0:
        return 0.0
    
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    for count in freq:
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy


def _detect_dod_pattern(data: bytes) -> Tuple[bool, int]:
    """
    Detect DoD 5220.22 wipe patterns.
    
    Returns:
        Tuple of (is_dod_pattern, match_count)
    """
    if len(data) < 512:
        return False, 0
    
    # Check for alternating zero/FF patterns (DoD signature)
    match_count = 0
    chunk_size = 512
    
    # Sample multiple chunks to detect DoD patterns
    for i in range(0, min(len(data), 10 * 512), chunk_size):
        chunk = data[i:i + chunk_size]
        
        # Check for all-zero chunk
        if chunk == bytes([0x00] * 512):
            match_count += 1
        # Check for all-FF chunk
        elif chunk == bytes([0xFF] * 512):
            match_count += 1
    
    # If we find alternating zero/FF patterns, likely DoD wipe
    return match_count >= 3, match_count


def _detect_gutmann_pattern(data: bytes) -> Tuple[bool, int]:
    """
    Detect Gutmann 35-pass wipe patterns.
    
    Returns:
        Tuple of (is_gutmann_pattern, match_count)
    """
    if len(data) < 512:
        return False, 0
    
    match_count = 0
    chunk_size = 512
    
    # Check for known Gutmann patterns
    known_patterns = [
        bytes([0x55] * 512),
        bytes([0xAA] * 512),
        bytes([0x92, 0x49] * 256),
        bytes([0x49, 0x24] * 256),
        bytes([0x24, 0x6D] * 256),
        bytes([0x6D, 0xB6] * 256),
        bytes([0xB6, 0xDB] * 256),
        bytes([0xDB, 0x6D] * 256),
    ]
    
    # Sample chunks and check for patterns
    for i in range(0, min(len(data), 20 * 512), chunk_size):
        chunk = data[i:i + chunk_size]
        
        for pattern in known_patterns:
            if chunk == pattern:
                match_count += 1
                break
    
    # Gutmann patterns are more distinctive - fewer matches needed
    return match_count >= 2, match_count


def _detect_wipe_software(data: bytes) -> Optional[str]:
    """
    Detect wipe software signatures in data.
    
    Returns:
        Name of detected wipe software or None
    """
    search_data = data[:min(len(data), 1024)]  # Search first KB
    
    for software, signatures in WIPE_SOFTWARE_SIGNATURES.items():
        for sig in signatures:
            if sig in search_data:
                return software
    
    return None


def _analyze_chunk(data: bytes, chunk_index: int, offset_bytes: int) -> WipeChunk:
    """Analyze a single 1MB chunk for wipe patterns."""
    if len(data) == 0:
        return WipeChunk(chunk_index, offset_bytes, 0.0, 0.0, 0.0, 'NORMAL')
    
    zero_count = data.count(0x00)
    ff_count = data.count(0xFF)
    
    zero_ratio = zero_count / len(data)
    ff_ratio = ff_count / len(data)
    entropy = _compute_entropy(data)
    
    # Check for DoD 5220.22 patterns first (highest priority)
    is_dod, dod_matches = _detect_dod_pattern(data)
    is_gutmann, gutmann_matches = _detect_gutmann_pattern(data)
    wipe_software = _detect_wipe_software(data)
    
    # Detection rules (in order of priority)
    if is_gutmann and gutmann_matches >= 2:
        wipe_type = 'GUTMANN'
    elif is_dod and dod_matches >= 3:
        wipe_type = 'DOD_5220_22'
    elif zero_ratio >= 0.98:
        wipe_type = 'ZERO_FILL'
    elif ff_ratio >= 0.98:
        wipe_type = 'FF_FILL'
    elif entropy >= 7.6:
        wipe_type = 'RANDOM_LIKE'
    else:
        wipe_type = 'NORMAL'
    
    return WipeChunk(
        chunk_index, offset_bytes, zero_ratio, ff_ratio, entropy, 
        wipe_type, dod_matches, gutmann_matches, wipe_software
    )


def _merge_regions(chunks: List[WipeChunk]) -> List[WipeRegion]:
    """Merge adjacent chunks with the same wipe type into regions."""
    if not chunks:
        return []
    
    regions = []
    current_type = chunks[0].wipe_type
    start_offset = chunks[0].offset_bytes
    chunk_count = 0
    
    for chunk in chunks:
        if chunk.wipe_type == current_type and chunk.wipe_type != 'NORMAL':
            chunk_count += 1
        else:
            if chunk_count > 0 and current_type != 'NORMAL':
                regions.append(WipeRegion(
                    start_offset=start_offset,
                    end_offset=chunks[chunk_count - 1].offset_bytes + 1048576,  # 1MB
                    wipe_type=current_type,
                    chunk_count=chunk_count
                ))
            current_type = chunk.wipe_type
            start_offset = chunk.offset_bytes
            chunk_count = 1 if chunk.wipe_type != 'NORMAL' else 0
    
    # Don't forget the last region
    if chunk_count > 0 and current_type != 'NORMAL':
        regions.append(WipeRegion(
            start_offset=start_offset,
            end_offset=chunks[-1].offset_bytes + 1048576,
            wipe_type=current_type,
            chunk_count=chunk_count
        ))
    
    return regions


def run_wipe_scan(image_path: str, start_sector: int, out_dir: str) -> Dict:
    """
    Run wipe pattern detection on unallocated disk space.
    
    Args:
        image_path: Path to the disk image file
        start_sector: Starting sector for the primary filesystem (from mmls)
        out_dir: Output directory for results
    
    Returns:
        Dict with wipe scan results including:
        - image_path, start_sector, unalloc_path, unalloc_size_bytes
        - metrics: wipe_zero_bytes_total, wipe_ff_bytes_total, wipe_randomlike_bytes_total,
                   wipe_suspect_chunk_count, scanned_bytes_total
        - regions: list of {start, end, type, chunk_count} (capped to 200)
        - error: optional error string if blkls missing/failed
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    unalloc_file = out_path / 'unalloc.bin'
    output_json = out_path / 'wipe_metrics.json'
    
    sector_size = 512
    start_byte = start_sector * sector_size
    
    # Step 1: Extract unallocated space using blkls
    try:
        result = subprocess.run(
            ['blkls', '-s', '-o', str(start_sector), str(image_path)],
            capture_output=True,
            timeout=300
        )
        
        if result.returncode != 0:
            error_msg = f"blkls failed: {result.stderr.decode('utf-8', errors='ignore')}"
            metrics = WipeMetrics(
                image_path=str(image_path),
                start_sector=start_sector,
                unalloc_path=str(unalloc_file),
                unalloc_size_bytes=0,
                wipe_zero_bytes_total=0,
                wipe_ff_bytes_total=0,
                wipe_randomlike_bytes_total=0,
                wipe_dod_bytes_total=0,
                wipe_gutmann_bytes_total=0,
                wipe_suspect_chunk_count=0,
                scanned_bytes_total=0,
                regions=[],
                detected_wipe_software=[],
                error=error_msg
            )
            with open(output_json, 'w') as f:
                json.dump(metrics.to_dict(), f, indent=2)
            return metrics.to_dict()
        
        unalloc_data = result.stdout
        
    except FileNotFoundError:
        error_msg = "blkls not found - ensure The Sleuth Kit is installed"
        metrics = WipeMetrics(
            image_path=str(image_path),
            start_sector=start_sector,
            unalloc_path=str(unalloc_file),
            unalloc_size_bytes=0,
            wipe_zero_bytes_total=0,
            wipe_ff_bytes_total=0,
            wipe_randomlike_bytes_total=0,
            wipe_dod_bytes_total=0,
            wipe_gutmann_bytes_total=0,
            wipe_suspect_chunk_count=0,
            scanned_bytes_total=0,
            regions=[],
            detected_wipe_software=[],
            error=error_msg
        )
        with open(output_json, 'w') as f:
            json.dump(metrics.to_dict(), f, indent=2)
        return metrics.to_dict()
    except subprocess.TimeoutExpired:
        error_msg = "blkls timed out after 300 seconds"
        metrics = WipeMetrics(
            image_path=str(image_path),
            start_sector=start_sector,
            unalloc_path=str(unalloc_file),
            unalloc_size_bytes=0,
            wipe_zero_bytes_total=0,
            wipe_ff_bytes_total=0,
            wipe_randomlike_bytes_total=0,
            wipe_dod_bytes_total=0,
            wipe_gutmann_bytes_total=0,
            wipe_suspect_chunk_count=0,
            scanned_bytes_total=0,
            regions=[],
            detected_wipe_software=[],
            error=error_msg
        )
        with open(output_json, 'w') as f:
            json.dump(metrics.to_dict(), f, indent=2)
        return metrics.to_dict()
    
    # Save unallocated data
    with open(unalloc_file, 'wb') as f:
        f.write(unalloc_data)
    
    unalloc_size = len(unalloc_data)
    
    # Handle empty unallocated data
    if unalloc_size == 0:
        metrics = WipeMetrics(
            image_path=str(image_path),
            start_sector=start_sector,
            unalloc_path=str(unalloc_file),
            unalloc_size_bytes=0,
            wipe_zero_bytes_total=0,
            wipe_ff_bytes_total=0,
            wipe_randomlike_bytes_total=0,
            wipe_dod_bytes_total=0,
            wipe_gutmann_bytes_total=0,
            wipe_suspect_chunk_count=0,
            scanned_bytes_total=0,
            regions=[],
            detected_wipe_software=[],
            error=None
        )
        with open(output_json, 'w') as f:
            json.dump(metrics.to_dict(), f, indent=2)
        return metrics.to_dict()
    
    # Step 2: Scan in 1MB chunks
    chunk_size = 1048576  # 1MB
    chunks = []
    zero_bytes = 0
    ff_bytes = 0
    randomlike_bytes = 0
    dod_bytes = 0
    gutmann_bytes = 0
    detected_software = set()
    
    for i in range(0, unalloc_size, chunk_size):
        chunk_data = unalloc_data[i:i + chunk_size]
        offset = start_byte + i
        
        chunk = _analyze_chunk(chunk_data, i // chunk_size, offset)
        chunks.append(chunk)
        
        # Aggregate totals
        chunk_len = len(chunk_data)
        if chunk.wipe_type == 'ZERO_FILL':
            zero_bytes += chunk_len
        elif chunk.wipe_type == 'FF_FILL':
            ff_bytes += chunk_len
        elif chunk.wipe_type == 'RANDOM_LIKE':
            randomlike_bytes += chunk_len
        elif chunk.wipe_type == 'DOD_5220_22':
            dod_bytes += chunk_len
        elif chunk.wipe_type == 'GUTMANN':
            gutmann_bytes += chunk_len
        
        # Track detected wipe software
        if chunk.wipe_software:
            detected_software.add(chunk.wipe_software)
    
    # Step 3: Merge into regions
    regions = _merge_regions(chunks)
    suspect_chunks = [c for c in chunks if c.wipe_type != 'NORMAL']
    suspect_count = len(suspect_chunks)
    
    # Build regions output
    regions_output = [r.to_dict() for r in regions]
    
    # Sort regions by size descending
    regions_output.sort(key=lambda x: x.get('end', 0) - x.get('start', 0), reverse=True)
    
    # Build metrics
    metrics = WipeMetrics(
        image_path=str(image_path),
        start_sector=start_sector,
        unalloc_path=str(unalloc_file),
        unalloc_size_bytes=unalloc_size,
        wipe_zero_bytes_total=zero_bytes,
        wipe_ff_bytes_total=ff_bytes,
        wipe_randomlike_bytes_total=randomlike_bytes,
        wipe_dod_bytes_total=dod_bytes,
        wipe_gutmann_bytes_total=gutmann_bytes,
        wipe_suspect_chunk_count=suspect_count,
        scanned_bytes_total=unalloc_size,
        regions=regions_output,
        detected_wipe_software=list(detected_software)
    )
    
    # Save JSON output
    with open(output_json, 'w') as f:
        json.dump(metrics.to_dict(), f, indent=2)
    
    return metrics.to_dict()


def calculate_wipe_score(wipe_metrics: Dict) -> Tuple[int, Dict]:
    """
    Calculate wipe signature score based on suspect ratio.
    
    Thresholds:
      >0.30 => deduction 35
      >0.10 => deduction 20
      >0.03 => deduction 10
      else 0
    
    Also detects DoD 5220.22 and Gutmann patterns for higher severity.
    
    Returns:
        Tuple of (score, details_dict)
    """
    if not wipe_metrics:
        return 0, {"error": "No wipe metrics provided"}
    
    if wipe_metrics.get("error"):
        return 0, {"error": wipe_metrics["error"]}
    
    metrics = wipe_metrics.get("metrics", {})
    scanned = metrics.get("scanned_bytes_total", 0)
    
    if scanned == 0:
        return 0, {"reason": "No unallocated data scanned"}
    
    zero = metrics.get("wipe_zero_bytes_total", 0)
    ff = metrics.get("wipe_ff_bytes_total", 0)
    randomlike = metrics.get("wipe_randomlike_bytes_total", 0)
    dod = metrics.get("wipe_dod_bytes_total", 0)
    gutmann = metrics.get("wipe_gutmann_bytes_total", 0)
    detected_software = metrics.get("detected_wipe_software", [])
    
    # Check for DoD or Gutmann patterns (higher severity)
    wipe_method_detected = None
    if dod > 0:
        wipe_method_detected = "DoD 5220.22"
    if gutmann > 0:
        wipe_method_detected = "Gutmann"
    
    suspect_bytes = zero + ff + randomlike + dod + gutmann
    suspect_ratio = suspect_bytes / scanned
    
    # Apply thresholds - higher for DoD/Gutmann
    base_score = 0
    if suspect_ratio > 0.30:
        base_score = 35
    elif suspect_ratio > 0.10:
        base_score = 20
    elif suspect_ratio > 0.03:
        base_score = 10
    else:
        base_score = 0
    
    # Add bonus for detected wipe methods
    bonus = 0
    if wipe_method_detected:
        bonus = 10  # Extra points for recognized wipe method
    if detected_software:
        bonus += 5 * len(detected_software)
    
    score = min(base_score + bonus, 50)  # Cap at 50
    
    details = {
        "suspect_ratio": round(suspect_ratio, 4),
        "suspect_ratio_percent": round(suspect_ratio * 100, 2),
        "zero_bytes": zero,
        "ff_bytes": ff,
        "randomlike_bytes": randomlike,
        "dod_bytes": dod,
        "gutmann_bytes": gutmann,
        "suspect_bytes_total": suspect_bytes,
        "scanned_bytes": scanned,
        "wipe_method_detected": wipe_method_detected,
        "detected_wipe_software": detected_software,
        "score": score,
        "max_score": 50
    }
    
    return score, details


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python wipe_scan.py <image_path> <start_sector> <out_dir>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    start_sector = int(sys.argv[2])
    out_dir = sys.argv[3]
    
    result = run_wipe_scan(image_path, start_sector, out_dir)
    print(json.dumps(result, indent=2))
    
    # Also print score
    score, details = calculate_wipe_score(result)
    print(f"\nWipe Score: {score}")
    print(json.dumps(details, indent=2))
