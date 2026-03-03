"""
Entropy calculations - Shannon entropy, chi-square, byte frequency distribution,
serial correlation coefficient, compression ratio estimate
"""
import math
import zlib
import numpy as np
from typing import Dict, Tuple
from dataclasses import dataclass


@dataclass
class BlockFeatures:
    """Features extracted from a block of data"""
    offset: int
    size: int
    shannon_entropy: float
    chi_square: float
    byte_frequencies: np.ndarray
    serial_correlation: float
    compression_ratio: float
    mean_byte: float
    std_byte: float
    null_ratio: float
    
    def to_dict(self) -> Dict:
        return {
            "offset": self.offset,
            "size": self.size,
            "shannon_entropy": self.shannon_entropy,
            "chi_square": self.chi_square,
            "serial_correlation": self.serial_correlation,
            "compression_ratio": self.compression_ratio,
            "mean_byte": self.mean_byte,
            "std_byte": self.std_byte,
            "null_ratio": self.null_ratio,
        }


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    Entropy close to 8.0 indicates high randomness (encrypted/compressed).
    Entropy close to 0.0 indicates uniform data (nulls/repeating patterns).
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Entropy value between 0 and 8
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    frequency = [0] * 256
    for byte in data:
        frequency[byte] += 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    
    for count in frequency:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy


def calculate_chi_square(data: bytes) -> float:
    """
    Calculate chi-square randomness test.
    
    Lower values indicate more uniform distribution.
    Higher values indicate non-random patterns.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Chi-square statistic
    """
    if not data:
        return 0.0
    
    n = len(data)
    if n == 0:
        return 0.0
    
    # Count byte frequencies
    observed = [0] * 256
    for byte in data:
        observed[byte] += 1
    
    # Expected frequency for uniform distribution
    expected = n / 256.0
    
    # Chi-square calculation
    chi_square = 0.0
    for obs in observed:
        chi_square += ((obs - expected) ** 2) / expected
    
    return chi_square


def calculate_byte_frequencies(data: bytes) -> np.ndarray:
    """
    Calculate byte frequency distribution.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        numpy array of 256 frequencies (normalized)
    """
    if not data:
        return np.zeros(256, dtype=np.float32)
    
    frequency = np.zeros(256, dtype=np.float32)
    for byte in data:
        frequency[byte] += 1
    
    # Normalize by data length
    frequency /= len(data)
    
    return frequency


def calculate_serial_correlation(data: bytes) -> float:
    """
    Calculate serial correlation coefficient.
    
    Measures how well each byte predicts the next byte.
    Encrypted data typically has near-zero correlation.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Correlation coefficient between -1 and 1
    """
    if len(data) < 2:
        return 0.0
    
    n = len(data)
    
    # Convert to integers for calculation
    x = np.array(list(data[:-1]), dtype=np.float32)
    y = np.array(list(data[1:]), dtype=np.float32)
    
    # Calculate correlation
    x_mean = np.mean(x)
    y_mean = np.mean(y)
    
    numerator = np.sum((x - x_mean) * (y - y_mean))
    denominator = np.sqrt(np.sum((x - x_mean) ** 2) * np.sum((y - y_mean) ** 2))
    
    if denominator == 0:
        return 0.0
    
    return float(numerator / denominator)


def calculate_compression_ratio(data: bytes) -> float:
    """
    Estimate compression ratio using zlib.
    
    Highly random/encrypted data cannot be compressed (ratio ~1.0).
    Compressible data has ratio < 1.0.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Compression ratio (compressed_size / original_size)
    """
    if not data:
        return 1.0
    
    try:
        compressed = zlib.compress(data, level=9)
        return len(compressed) / len(data)
    except Exception:
        return 1.0


def calculate_statistics(data: bytes) -> Tuple[float, float]:
    """
    Calculate mean and standard deviation of byte values.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Tuple of (mean, std_dev)
    """
    if not data:
        return (0.0, 0.0)
    
    arr = np.array(list(data), dtype=np.float32)
    return (float(np.mean(arr)), float(np.std(arr)))


def calculate_null_ratio(data: bytes) -> float:
    """
    Calculate ratio of null (0x00) bytes.
    
    Args:
        data: Raw bytes to analyze
        
    Returns:
        Ratio of null bytes (0.0 to 1.0)
    """
    if not data:
        return 0.0
    
    return sum(1 for b in data if b == 0) / len(data)


def extract_all_features(data: bytes, offset: int = 0) -> BlockFeatures:
    """
    Extract all statistical features from a block of data.
    
    Args:
        data: Raw bytes to analyze
        offset: Disk offset of this block
        
    Returns:
        BlockFeatures object with all calculated features
    """
    return BlockFeatures(
        offset=offset,
        size=len(data),
        shannon_entropy=calculate_shannon_entropy(data),
        chi_square=calculate_chi_square(data),
        byte_frequencies=calculate_byte_frequencies(data),
        serial_correlation=calculate_serial_correlation(data),
        compression_ratio=calculate_compression_ratio(data),
        mean_byte=calculate_statistics(data)[0],
        std_byte=calculate_statistics(data)[1],
        null_ratio=calculate_null_ratio(data),
    )


def calculate_histogram(data: bytes, bins: int = 16) -> np.ndarray:
    """
    Calculate byte histogram with specified number of bins.
    
    Args:
        data: Raw bytes to analyze
        bins: Number of histogram bins
        
    Returns:
        Histogram array
    """
    if not data:
        return np.zeros(bins)
    
    arr = np.array(list(data))
    hist, _ = np.histogram(arr, bins=bins, range=(0, 256))
    return hist.astype(np.float32) / len(data)


class EntropyAnalyzer:
    """High-level entropy analysis with caching and statistics"""
    
    def __init__(self, block_size: int = 4096):
        self.block_size = block_size
        self._results: list[BlockFeatures] = []
    
    def analyze_block(self, data: bytes, offset: int) -> BlockFeatures:
        """Analyze a single block"""
        return extract_all_features(data, offset)
    
    def analyze_blocks(self, blocks: list[tuple[int, bytes]]) -> list[BlockFeatures]:
        """Analyze multiple blocks"""
        results = []
        for offset, data in blocks:
            results.append(self.analyze_block(data, offset))
        self._results.extend(results)
        return results
    
    @property
    def mean_entropy(self) -> float:
        """Average entropy across all analyzed blocks"""
        if not self._results:
            return 0.0
        return sum(r.shannon_entropy for r in self._results) / len(self._results)
    
    @property
    def max_entropy(self) -> float:
        """Maximum entropy across all analyzed blocks"""
        if not self._results:
            return 0.0
        return max(r.shannon_entropy for r in self._results)
    
    @property
    def high_entropy_blocks(self) -> list[BlockFeatures]:
        """Blocks with entropy > 7.5 (likely encrypted)"""
        return [r for r in self._results if r.shannon_entropy > 7.5]
