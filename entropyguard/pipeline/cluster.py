"""Region clustering for merging adjacent anomalous blocks"""
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class SuspiciousRegion:
    """A suspicious region of consecutive anomalous blocks"""
    start_offset: int
    end_offset: int
    size: int
    block_count: int
    mean_entropy: float
    max_entropy: float
    mean_anomaly_score: float
    max_anomaly_score: float
    
    def to_dict(self) -> Dict:
        return {
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.size,
            "block_count": self.block_count,
            "mean_entropy": round(self.mean_entropy, 4),
            "max_entropy": round(self.max_entropy, 4),
            "mean_anomaly_score": round(self.mean_anomaly_score, 2),
            "max_anomaly_score": round(self.max_anomaly_score, 2),
        }


class RegionCluster:
    """
    Cluster consecutive anomalous blocks into regions.
    """
    
    def __init__(
        self,
        min_blocks: int = 3,
        gap_threshold: int = 1
    ):
        """
        Initialize region cluster.
        
        Args:
            min_blocks: Minimum number of blocks to form a region
            gap_threshold: Max gap between blocks to still consider contiguous
        """
        self.min_blocks = min_blocks
        self.gap_threshold = gap_threshold
    
    def cluster(
        self,
        blocks: List[Dict],
        block_size: int = 4096
    ) -> List[SuspiciousRegion]:
        """
        Cluster anomalous blocks into regions.
        
        Args:
            blocks: List of block dictionaries with offset, entropy, anomaly_score
            block_size: Size of each block
            
        Returns:
            List of SuspiciousRegion objects
        """
        if not blocks:
            return []
        
        # Filter anomalous blocks
        anomalous = [
            b for b in blocks
            if b.get("is_anomalous", b.get("anomaly_score", 0) > 50)
        ]
        
        if not anomalous:
            return []
        
        # Sort by offset
        anomalous.sort(key=lambda x: x.get("offset", 0))
        
        # Cluster contiguous blocks
        regions = []
        current_region = [anomalous[0]]
        
        for i in range(1, len(anomalous)):
            current = anomalous[i]
            previous = current_region[-1]
            
            prev_offset = previous.get("offset", 0)
            curr_offset = current.get("offset", 0)
            
            # Check if contiguous (within gap threshold)
            if curr_offset - prev_offset <= block_size * (self.gap_threshold + 1):
                current_region.append(current)
            else:
                # End current region, start new one
                if len(current_region) >= self.min_blocks:
                    regions.append(self._create_region(current_region, block_size))
                current_region = [current]
        
        # Handle last region
        if len(current_region) >= self.min_blocks:
            regions.append(self._create_region(current_region, block_size))
        
        return regions
    
    def _create_region(
        self,
        blocks: List[Dict],
        block_size: int
    ) -> SuspiciousRegion:
        """Create a SuspiciousRegion from a list of blocks"""
        start_offset = blocks[0].get("offset", 0)
        end_offset = blocks[-1].get("offset", 0) + block_size
        
        entropies = [b.get("shannon_entropy", 0) for b in blocks]
        scores = [b.get("anomaly_score", 0) for b in blocks]
        
        return SuspiciousRegion(
            start_offset=start_offset,
            end_offset=end_offset,
            size=end_offset - start_offset,
            block_count=len(blocks),
            mean_entropy=sum(entropies) / len(entropies),
            max_entropy=max(entropies),
            mean_anomaly_score=sum(scores) / len(scores),
            max_anomaly_score=max(scores),
        )
    
    def cluster_by_entropy(
        self,
        blocks: List[Dict],
        entropy_threshold: float = 7.0,
        block_size: int = 4096
    ) -> List[SuspiciousRegion]:
        """
        Cluster blocks by entropy threshold (simpler method).
        
        Args:
            blocks: List of block dictionaries
            entropy_threshold: Entropy above this indicates suspicious
            block_size: Size of each block
            
        Returns:
            List of high-entropy regions
        """
        # Filter high-entropy blocks
        high_entropy = [
            b for b in blocks
            if b.get("shannon_entropy", 0) >= entropy_threshold
        ]
        
        if not high_entropy:
            return []
        
        # Sort by offset
        high_entropy.sort(key=lambda x: x.get("offset", 0))
        
        # Cluster
        regions = []
        current = [high_entropy[0]]
        
        for i in range(1, len(high_entropy)):
            prev_offset = current[-1].get("offset", 0)
            curr_offset = high_entropy[i].get("offset", 0)
            
            if curr_offset - prev_offset <= block_size * 2:
                current.append(high_entropy[i])
            else:
                if len(current) >= self.min_blocks:
                    regions.append(self._create_region(current, block_size))
                current = [high_entropy[i]]
        
        if len(current) >= self.min_blocks:
            regions.append(self._create_region(current, block_size))
        
        return regions
