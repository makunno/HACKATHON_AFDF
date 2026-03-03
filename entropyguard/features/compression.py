"""Compression-based feature analysis"""
import zlib
import lzma
import bz2
import numpy as np
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class CompressionAnalysis:
    """Results of compression analysis"""
    offset: int
    zlib_ratio: float
    lzma_ratio: float
    bz2_ratio: float
    overall_score: float
    
    def to_dict(self) -> Dict:
        return {
            "offset": self.offset,
            "zlib_ratio": self.zlib_ratio,
            "lzma_ratio": self.lzma_ratio,
            "bz2_ratio": self.bz2_ratio,
            "overall_score": self.overall_score,
        }


class CompressionAnalyzer:
    """
    Analyze data compressibility to detect encrypted/hidden content.
    
    Encrypted data has near-1.0 compression ratio (cannot be compressed).
    Compressible data has lower ratios.
    """
    
    def __init__(self, threshold: float = 0.95):
        """
        Initialize compression analyzer.
        
        Args:
            threshold: Compression ratio above this indicates potential encryption
        """
        self.threshold = threshold
    
    def analyze(self, data: bytes, offset: int = 0) -> CompressionAnalysis:
        """
        Analyze a block of data.
        
        Args:
            data: Bytes to analyze
            offset: Disk offset
            
        Returns:
            CompressionAnalysis result
        """
        if not data:
            return CompressionAnalysis(
                offset=offset, zlib_ratio=1.0, lzma_ratio=1.0, 
                bz2_ratio=1.0, overall_score=0.0
            )
        
        try:
            zlib_compressed = zlib.compress(data, level=9)
            zlib_ratio = len(zlib_compressed) / len(data)
        except Exception:
            zlib_ratio = 1.0
        
        try:
            lzma_compressed = lzma.compress(data, preset=1)
            lzma_ratio = len(lzma_compressed) / len(data)
        except Exception:
            lzma_ratio = 1.0
        
        try:
            bz2_compressed = bz2.compress(data, compresslevel=9)
            bz2_ratio = len(bz2_compressed) / len(data)
        except Exception:
            bz2_ratio = 1.0
        
        avg_ratio = (zlib_ratio + lzma_ratio + bz2_ratio) / 3
        
        if avg_ratio >= self.threshold:
            score = min(100, ((avg_ratio - self.threshold) / (1 - self.threshold)) * 100)
        else:
            score = 0
        
        return CompressionAnalysis(
            offset=offset,
            zlib_ratio=zlib_ratio,
            lzma_ratio=lzma_ratio,
            bz2_ratio=bz2_ratio,
            overall_score=score,
        )
    
    def analyze_batch(self, blocks: List[tuple[int, bytes]]) -> List[CompressionAnalysis]:
        return [self.analyze(data, offset) for offset, data in blocks]
    
    def find_encrypted_regions(self, analyses: List[CompressionAnalysis]) -> List[Dict]:
        regions = []
        in_region = False
        region_start = 0
        region_scores = []
        
        for analysis in analyses:
            if analysis.overall_score > 50:
                if not in_region:
                    region_start = analysis.offset
                    region_scores = [analysis.overall_score]
                    in_region = True
                else:
                    region_scores.append(analysis.overall_score)
            else:
                if in_region:
                    if len(region_scores) >= 3:
                        regions.append({
                            "start_offset": region_start,
                            "end_offset": analysis.offset,
                            "size": analysis.offset - region_start,
                            "mean_score": float(np.mean(region_scores)),
                            "max_score": max(region_scores),
                        })
                    in_region = False
        
        if in_region and len(region_scores) >= 3:
            regions.append({
                "start_offset": region_start,
                "end_offset": analyses[-1].offset,
                "size": analyses[-1].offset - region_start,
                "mean_score": float(np.mean(region_scores)),
                "max_score": max(region_scores),
            })
        
        return regions
