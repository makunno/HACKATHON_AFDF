"""Block processor for parallel processing"""
import multiprocessing as mp
from typing import List, Dict, Iterator, Callable
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProcessingResult:
    """Result of block processing"""
    block_num: int
    offset: int
    features: Dict
    anomaly_score: float = 0.0
    is_anomalous: bool = False


class BlockProcessor:
    """
    Multi-process block processor for disk analysis.
    """
    
    def __init__(
        self,
        num_workers: int = None,
        chunk_size: int = 100
    ):
        """
        Initialize block processor.
        
        Args:
            num_workers: Number of worker processes (default: CPU count)
            chunk_size: Number of blocks to process per batch
        """
        self.num_workers = num_workers or mp.cpu_count()
        self.chunk_size = chunk_size
    
    def process_blocks(
        self,
        blocks: Iterator[tuple[int, bytes]],
        feature_extractor: Callable,
        anomaly_detector: Callable = None
    ) -> List[ProcessingResult]:
        """
        Process blocks in parallel.
        
        Args:
            blocks: Iterator of (offset, data) tuples
            feature_extractor: Function to extract features from block
            anomaly_detector: Optional anomaly detector
            
        Returns:
            List of ProcessingResult
        """
        # Convert to list for multiprocessing
        block_list = list(blocks)
        
        if not block_list:
            return []
        
        logger.info(f"Processing {len(block_list)} blocks with {self.num_workers} workers")
        
        # For small datasets, process sequentially
        if len(block_list) < self.num_workers * 10:
            return self._process_sequential(
                block_list, feature_extractor, anomaly_detector
            )
        
        # Split into chunks
        chunks = [
            block_list[i:i + self.chunk_size]
            for i in range(0, len(block_list), self.chunk_size)
        ]
        
        # Process with multiprocessing pool
        with mp.Pool(processes=self.num_workers) as pool:
            results = []
            for chunk_results in pool.imap(
                _process_chunk,
                [(chunk, feature_extractor, anomaly_detector) for chunk in chunks]
            ):
                results.extend(chunk_results)
        
        return results
    
    def _process_sequential(
        self,
        blocks: List[tuple[int, bytes]],
        feature_extractor: Callable,
        anomaly_detector: Callable = None
    ) -> List[ProcessingResult]:
        """Sequential processing for small datasets"""
        results = []
        
        for i, (offset, data) in enumerate(blocks):
            features = feature_extractor(data, offset)
            
            anomaly_score = 0.0
            is_anomalous = False
            
            if anomaly_detector:
                result = anomaly_detector.predict(features)
                anomaly_score = result.get("anomaly_score", 0)
                is_anomalous = result.get("is_anomalous", False)
            
            results.append(ProcessingResult(
                block_num=i,
                offset=offset,
                features=features,
                anomaly_score=anomaly_score,
                is_anomalous=is_anomalous
            ))
        
        return results


def _process_chunk(args):
    """Worker function for processing a chunk of blocks"""
    chunk, feature_extractor, anomaly_detector = args
    
    # Import here to avoid pickling issues
    from entropyguard.core.entropy import extract_all_features
    
    results = []
    
    for i, (offset, data) in enumerate(chunk):
        # Get features using provided extractor or default
        if callable(feature_extractor):
            features = feature_extractor(data, offset)
        else:
            features = extract_all_features(data, offset).to_dict()
        
        anomaly_score = 0.0
        is_anomalous = False
        
        if anomaly_detector:
            try:
                result = anomaly_detector.predict(features)
                anomaly_score = result.get("anomaly_score", 0)
                is_anomalous = result.get("is_anomalous", False)
            except Exception:
                pass
        
        results.append(ProcessingResult(
            block_num=i,
            offset=offset,
            features=features,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous
        ))
    
    return results
