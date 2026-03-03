"""Main EntropyScanner - orchestrates the entire scanning pipeline"""
import json
import logging
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Iterator
from dataclasses import dataclass, asdict
from datetime import datetime
import pandas as pd

from entropyguard.core.disk_reader import DiskReader
from entropyguard.core.entropy import extract_all_features
from entropyguard.features.statistical import ZScoreDetector
from entropyguard.models import IsolationForestDetector, LOFDetector, AutoencoderDetector
from entropyguard.pipeline.processor import BlockProcessor
from entropyguard.pipeline.cluster import RegionCluster

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a scan"""
    block_size: int = 4096
    num_workers: int = 4
    methods: List[str] = None  # zscore, isolation_forest, lof, autoencoder
    
    def __post_init__(self):
        if self.methods is None:
            self.methods = ["zscore", "isolation_forest"]


@dataclass
class ScanResult:
    """Result of a complete scan"""
    scan_id: str
    disk_path: str
    disk_size: int
    block_size: int
    total_blocks: int
    anomalous_blocks: int
    suspicious_regions: List[Dict]
    block_results: List[Dict]
    statistics: Dict
    scan_time: str
    methods_used: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class EntropyScanner:
    """
    Main scanner that orchestrates the entire analysis pipeline.
    """
    
    def __init__(
        self,
        config: Optional[ScanConfig] = None,
        models_dir: Optional[Path] = None
    ):
        self.config = config or ScanConfig()
        self.models_dir = models_dir or Path("models")
        
        # Initialize components
        self.processor = BlockProcessor(num_workers=self.config.num_workers)
        self.zscore_detector = ZScoreDetector()
        self.region_cluster = RegionCluster()
        
        # ML models (loaded on demand)
        self.isolation_forest: Optional[IsolationForestDetector] = None
        self.lof: Optional[LOFDetector] = None
        self.autoencoder: Optional[AutoencoderDetector] = None
        
        # State
        self._current_scan_id: Optional[str] = None
        self._results: Optional[ScanResult] = None
    
    def load_models(self) -> bool:
        """Load trained ML models"""
        loaded = []
        
        if_path = self.models_dir / "isolation_forest.joblib"
        if if_path.exists():
            self.isolation_forest = IsolationForestDetector()
            self.isolation_forest.load(if_path)
            loaded.append("isolation_forest")
        
        lof_path = self.models_dir / "lof.joblib"
        if lof_path.exists():
            self.lof = LOFDetector()
            self.lof.load(lof_path)
            loaded.append("lof")
        
        ae_path = self.models_dir / "autoencoder.pt"
        if ae_path.exists():
            self.autoencoder = AutoencoderDetector()
            self.autoencoder.load(ae_path)
            loaded.append("autoencoder")
        
        logger.info(f"Loaded models: {loaded}")
        return len(loaded) > 0
    
    def scan(
        self,
        disk_path: str | Path,
        output_path: Optional[Path] = None,
        save_parquet: bool = True,
        progress_callback: Optional[callable] = None
    ) -> ScanResult:
        """
        Perform a complete scan of a disk image.
        
        Args:
            disk_path: Path to disk image
            output_path: Optional path to save results
            save_parquet: Whether to save block results as Parquet
            progress_callback: Optional callback for progress updates
            
        Returns:
            ScanResult with all findings
        """
        start_time = datetime.now()
        disk_path = Path(disk_path)
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        self._current_scan_id = scan_id
        
        logger.info(f"Starting scan {scan_id} on {disk_path}")
        
        # Try to load trained ML models
        self.load_models()
        
        # Open disk reader
        with DiskReader(disk_path, block_size=self.config.block_size) as reader:
            total_blocks = reader.total_blocks
            disk_size = reader.file_size
            
            logger.info(f"Disk size: {disk_size} bytes, {total_blocks} blocks")
            
            # Phase 1: Feature extraction
            if progress_callback:
                progress_callback(0, "Extracting features...")
            
            all_features = []
            block_results = []
            
            for i, block in enumerate(reader.read_all_blocks()):
                features = extract_all_features(block.data, block.offset)
                features_dict = features.to_dict()
                all_features.append(features_dict)
                
                # Progress update
                if i % 1000 == 0:
                    progress = int(i / total_blocks * 50)
                    if progress_callback:
                        progress_callback(progress, f"Processed {i}/{total_blocks} blocks")
            
            logger.info(f"Extracted features from {len(all_features)} blocks")
            
            # Phase 2: Fit Z-score detector on data
            if progress_callback:
                progress_callback(50, "Detecting anomalies...")
            
            self.zscore_detector.fit(all_features)
            
            # Phase 3: Anomaly detection
            methods_used = []
            anomaly_scores = []
            
            for features in all_features:
                # Z-score detection
                zscore_result = self.zscore_detector.predict(features)
                features["zscore_score"] = zscore_result.anomaly_score
                features["zscore_anomaly"] = zscore_result.is_anomalous
                
                # ML detection (if models loaded)
                ml_scores = []
                
                if "isolation_forest" in self.config.methods and self.isolation_forest:
                    if_result = self.isolation_forest.predict(features)
                    features["if_score"] = if_result["anomaly_score"]
                    ml_scores.append(if_result["anomaly_score"])
                    if "isolation_forest" not in methods_used:
                        methods_used.append("isolation_forest")
                
                if "lof" in self.config.methods and self.lof:
                    lof_result = self.lof.predict(features)
                    features["lof_score"] = lof_result["anomaly_score"]
                    ml_scores.append(lof_result["anomaly_score"])
                    if "lof" not in methods_used:
                        methods_used.append("lof")
                
                if "autoencoder" in self.config.methods and self.autoencoder:
                    ae_result = self.autoencoder.predict(features)
                    features["ae_score"] = ae_result["anomaly_score"]
                    ml_scores.append(ae_result["anomaly_score"])
                    if "autoencoder" not in methods_used:
                        methods_used.append("autoencoder")
                
                # Combine scores
                if ml_scores:
                    avg_score = sum(ml_scores) / len(ml_scores)
                else:
                    avg_score = zscore_result.anomaly_score
                
                features["anomaly_score"] = avg_score
                features["is_anomalous"] = avg_score > 50
                anomaly_scores.append(avg_score)
                
                block_results.append(features)
            
            methods_used.insert(0, "zscore")
            
            # Phase 4: Region clustering
            if progress_callback:
                progress_callback(80, "Clustering regions...")
            
            suspicious_regions = self.region_cluster.cluster(
                block_results,
                block_size=self.config.block_size
            )
            regions_dict = [r.to_dict() for r in suspicious_regions]
            
            # Calculate statistics
            anomalous_count = sum(1 for b in block_results if b.get("is_anomalous"))
            
            statistics = {
                "total_blocks": len(block_results),
                "anomalous_blocks": anomalous_count,
                "anomaly_rate": anomalous_count / len(block_results) if block_results else 0,
                "mean_entropy": sum(b.get("shannon_entropy", 0) for b in block_results) / len(block_results),
                "max_entropy": max(b.get("shannon_entropy", 0) for b in block_results),
                "mean_anomaly_score": sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0,
                "regions_found": len(regions_dict),
            }
            
            # Create result
            result = ScanResult(
                scan_id=scan_id,
                disk_path=str(disk_path),
                disk_size=disk_size,
                block_size=self.config.block_size,
                total_blocks=total_blocks,
                anomalous_blocks=anomalous_count,
                suspicious_regions=regions_dict,
                block_results=block_results,
                statistics=statistics,
                scan_time=start_time.isoformat(),
                methods_used=methods_used
            )
            
            self._results = result
            
            # Save outputs
            if output_path:
                output_path = Path(output_path)
                output_path.mkdir(parents=True, exist_ok=True)
                
                # Save JSON
                json_path = output_path / f"scan_{scan_id}.json"
                with open(json_path, "w") as f:
                    json.dump(result.to_dict(), f, indent=2)
                
                # Save parquet
                if save_parquet:
                    df = pd.DataFrame(block_results)
                    parquet_path = output_path / f"blocks_{scan_id}.parquet"
                    df.to_parquet(parquet_path)
                
                logger.info(f"Results saved to {output_path}")
            
            if progress_callback:
                progress_callback(100, "Scan complete!")
            
            return result
    
    def get_result(self) -> Optional[ScanResult]:
        """Get current scan result"""
        return self._results
    
    def resume_scan(self, scan_path: Path) -> ScanResult:
        """Resume a scan from saved parquet"""
        # Load parquet
        df = pd.read_parquet(scan_path)
        block_results = df.to_dict("records")
        
        # Re-cluster
        suspicious_regions = self.region_cluster.cluster(
            block_results,
            block_size=self.config.block_size
        )
        
        # Create result
        result = ScanResult(
            scan_id=scan_path.stem,
            disk_path="",
            disk_size=0,
            block_size=self.config.block_size,
            total_blocks=len(block_results),
            anomalous_blocks=sum(1 for b in block_results if b.get("is_anomalous")),
            suspicious_regions=[r.to_dict() for r in suspicious_regions],
            block_results=block_results,
            statistics={},
            scan_time="",
            methods_used=[]
        )
        
        self._results = result
        return result
