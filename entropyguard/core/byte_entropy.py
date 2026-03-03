"""Byte-level entropy scanning with sliding window"""
import numpy as np
from typing import Iterator, Tuple
from dataclasses import dataclass


@dataclass
class ByteEntropyRegion:
    """A region of high entropy detected at byte level"""
    start_offset: int
    end_offset: int
    size: int
    mean_entropy: float
    max_entropy: float
    score: float  # Anomaly score 0-100
    
    def to_dict(self):
        return {
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.size,
            "mean_entropy": self.mean_entropy,
            "max_entropy": self.max_entropy,
            "score": self.score,
        }


class ByteLevelEntropyScanner:
    """
    Byte-level entropy scanning using sliding window.
    Provides more granular detection than block-level analysis.
    """
    
    def __init__(
        self,
        window_size: int = 256,
        step_size: int = 64,
        entropy_threshold: float = 7.5,
        min_region_size: int = 512
    ):
        """
        Initialize byte-level entropy scanner.
        
        Args:
            window_size: Size of sliding window (default 256 bytes)
            step_size: Step between windows (default 64 bytes)
            entropy_threshold: Entropy above this indicates anomaly
            min_region_size: Minimum size for a suspicious region
        """
        self.window_size = window_size
        self.step_size = step_size
        self.entropy_threshold = entropy_threshold
        self.min_region_size = min_region_size
    
    def _calculate_window_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a window"""
        if len(data) < self.window_size:
            return 0.0
        
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        import math
        length = len(data)
        entropy = 0.0
        for count in frequency:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def scan_bytes(self, data: bytes, base_offset: int = 0) -> Iterator[Tuple[int, float]]:
        """
        Scan data bytes and yield entropy values.
        
        Args:
            data: Bytes to scan
            base_offset: Starting offset in disk
            
        Yields:
            Tuples of (offset, entropy)
        """
        if len(data) < self.window_size:
            return
        
        for i in range(0, len(data) - self.window_size + 1, self.step_size):
            window = data[i:i + self.window_size]
            entropy = self._calculate_window_entropy(window)
            yield (base_offset + i, entropy)
    
    def find_high_entropy_regions(
        self,
        entropy_values: list[Tuple[int, float]]
    ) -> list[ByteEntropyRegion]:
        """
        Find contiguous regions of high entropy.
        
        Args:
            List of (offset, entropy) tuples
            
        Returns:
            List of high-entropy regions
        """
        if not entropy_values:
            return []
        
        regions = []
        in_region = False
        region_start = 0
        region_offsets = []
        region_entropies = []
        
        for offset, entropy in entropy_values:
            if entropy >= self.entropy_threshold:
                if not in_region:
                    region_start = offset
                    region_offsets = [offset]
                    region_entropies = [entropy]
                    in_region = True
                else:
                    region_offsets.append(offset)
                    region_entropies.append(entropy)
            else:
                if in_region:
                    # End of region - check if large enough
                    region_size = region_offsets[-1] - region_offsets[0] + self.window_size
                    if region_size >= self.min_region_size:
                        mean_ent = sum(region_entropies) / len(region_entropies)
                        max_ent = max(region_entropies)
                        
                        # Calculate anomaly score
                        score = self._calculate_region_score(mean_ent, max_ent, region_size)
                        
                        regions.append(ByteEntropyRegion(
                            start_offset=region_offsets[0],
                            end_offset=region_offsets[-1] + self.window_size,
                            size=region_size,
                            mean_entropy=mean_ent,
                            max_entropy=max_ent,
                            score=score,
                        ))
                    in_region = False
        
        # Handle region at end of data
        if in_region:
            region_size = region_offsets[-1] - region_offsets[0] + self.window_size
            if region_size >= self.min_region_size:
                mean_ent = sum(region_entropies) / len(region_entropies)
                max_ent = max(region_entropies)
                score = self._calculate_region_score(mean_ent, max_ent, region_size)
                
                regions.append(ByteEntropyRegion(
                    start_offset=region_offsets[0],
                    end_offset=region_offsets[-1] + self.window_size,
                    size=region_size,
                    mean_entropy=mean_ent,
                    max_entropy=max_ent,
                    score=score,
                ))
        
        return regions
    
    def _calculate_region_score(
        self,
        mean_entropy: float,
        max_entropy: float,
        size: int
    ) -> float:
        """
        Calculate anomaly score for a region.
        
        Score factors:
        - Higher entropy = higher score
        - Larger region = slightly lower score (could be compressed data)
        - Max entropy close to 8 = higher score
        """
        # Entropy score (0-50)
        entropy_score = ((mean_entropy - 5.0) / 3.0) * 50
        entropy_score = max(0, min(50, entropy_score))
        
        # Randomness bonus for max entropy close to 8
        if max_entropy > 7.8:
            randomness_bonus = 30
        elif max_entropy > 7.5:
            randomness_bonus = 20
        elif max_entropy > 7.0:
            randomness_bonus = 10
        else:
            randomness_bonus = 0
        
        # Size penalty (very large high-entropy could be compressed)
        if size > 1024 * 1024:  # > 1MB
            size_penalty = -10
        elif size > 100 * 1024:  # > 100KB
            size_penalty = -5
        else:
            size_penalty = 0
        
        score = entropy_score + randomness_bonus + size_penalty
        return max(0, min(100, score))
    
    def scan_disk_image(self, disk_path: str, max_scan_size: int = 100 * 1024 * 1024) -> list[ByteEntropyRegion]:
        """
        Scan an entire disk image for high-entropy regions.
        
        Args:
            disk_path: Path to disk image
            max_scan_size: Maximum bytes to scan (default 100MB)
            
        Returns:
            List of suspicious high-entropy regions
        """
        from pathlib import Path
        
        entropy_values = []
        
        with open(disk_path, 'rb') as f:
            offset = 0
            while True:
                chunk = f.read(self.window_size)
                if not chunk or offset > max_scan_size:
                    break
                
                if len(chunk) == self.window_size:
                    entropy = self._calculate_window_entropy(chunk)
                    entropy_values.append((offset, entropy))
                
                offset += self.step_size
        
        return self.find_high_entropy_regions(entropy_values)
