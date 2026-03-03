"""
EntropyGuard: AI-Powered Hidden Volume & High-Entropy Region Detector

A production-grade digital forensics tool for detecting anomalous high-entropy
regions in disk images that may indicate hidden encrypted volumes.
"""

__version__ = "1.0.0"
__author__ = "EntropyGuard Team"
__license__ = "MIT"

from entropyguard.core.disk_reader import DiskReader
from entropyguard.core.entropy import calculate_shannon_entropy, calculate_chi_square
from entropyguard.pipeline.scanner import EntropyScanner

__all__ = [
    "DiskReader",
    "calculate_shannon_entropy", 
    "calculate_chi_square",
    "EntropyScanner",
]
