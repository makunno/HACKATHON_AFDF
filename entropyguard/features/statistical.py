"""Statistical analysis for anomaly detection"""
import numpy as np
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a block"""
    offset: int
    anomaly_score: float  # 0-100
    confidence: float  # 0-100
    is_anomalous: bool
    method: str
    details: Dict
    
    def to_dict(self) -> Dict:
        return {
            "offset": self.offset,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "is_anomalous": self.is_anomalous,
            "method": self.method,
            "details": self.details,
        }


class StatisticalAnalyzer:
    """Statistical analysis of entropy distribution"""
    
    def __init__(self):
        self.entropies: List[float] = []
        self.chi_squares: List[float] = []
        self.correlations: List[float] = []
        self.compression_ratios: List[float] = []
    
    def add_block_features(self, features: Dict):
        """Add block features to the analyzer"""
        self.entropies.append(features.get("shannon_entropy", 0))
        self.chi_squares.append(features.get("chi_square", 0))
        self.correlations.append(features.get("serial_correlation", 0))
        self.compression_ratios.append(features.get("compression_ratio", 1))
    
    def compute_statistics(self) -> Dict:
        """Compute overall statistics"""
        if not self.entropies:
            return {}
        
        return {
            "mean_entropy": np.mean(self.entropies),
            "std_entropy": np.std(self.entropies),
            "min_entropy": np.min(self.entropies),
            "max_entropy": np.max(self.entropies),
            "median_entropy": np.median(self.entropies),
            "mean_chi_square": np.mean(self.chi_squares),
            "mean_correlation": np.mean(np.abs(self.correlations)),
            "mean_compression_ratio": np.mean(self.compression_ratios),
            "total_blocks": len(self.entropies),
        }


class ZScoreDetector:
    """
    Z-score based anomaly detection.
    
    Detects blocks with statistical features far from the mean.
    """
    
    def __init__(
        self,
        entropy_threshold: float = 3.0,
        entropy_weight: float = 0.4,
        chi_square_weight: float = 0.3,
        correlation_weight: float = 0.15,
        compression_weight: float = 0.15
    ):
        """
        Initialize Z-score detector.
        
        Args:
            entropy_threshold: Z-score above this is anomalous
            weights: Feature weights for combined score
        """
        self.entropy_threshold = entropy_threshold
        self.weights = {
            "entropy": entropy_weight,
            "chi_square": chi_square_weight,
            "correlation": correlation_weight,
            "compression": compression_weight,
        }
        self._means: Dict[str, float] = {}
        self._stds: Dict[str, float] = {}
        self._fitted = False
    
    def fit(self, features: List[Dict]):
        """
        Fit the detector on normal data to learn baseline statistics.
        
        Args:
            features: List of block feature dictionaries
        """
        entropies = [f.get("shannon_entropy", 0) for f in features]
        chi_squares = [f.get("chi_square", 0) for f in features]
        correlations = [abs(f.get("serial_correlation", 0)) for f in features]
        compression = [f.get("compression_ratio", 1) for f in features]
        
        self._means = {
            "entropy": float(np.mean(entropies)),
            "chi_square": float(np.mean(chi_squares)),
            "correlation": float(np.mean(correlations)),
            "compression": float(np.mean(compression)),
        }
        
        self._stds = {
            "entropy": float(max(np.std(entropies), 0.001)),
            "chi_square": float(max(np.std(chi_squares), 0.001)),
            "correlation": float(max(np.std(correlations), 0.001)),
            "compression": float(max(np.std(compression), 0.001)),
        }
        
        self._fitted = True
    
    def predict(self, features: Dict) -> AnomalyResult:
        """
        Detect anomaly in a single block.
        
        Args:
            features: Block feature dictionary
            
        Returns:
            AnomalyResult with score and confidence
        """
        if not self._fitted:
            # Use default thresholds if not fitted
            entropy = features.get("shannon_entropy", 0)
            is_anomaly = entropy > 7.5
            score = min(100, (entropy / 8.0) * 100) if entropy > 5 else 0
            
            return AnomalyResult(
                offset=features.get("offset", 0),
                anomaly_score=score,
                confidence=50.0,
                is_anomalous=is_anomaly,
                method="zscore_default",
                details={"entropy": entropy},
            )
        
        # Calculate z-scores
        z_entropy = abs(
            (features.get("shannon_entropy", 0) - self._means["entropy"]) 
            / self._stds["entropy"]
        )
        z_chi = abs(
            (features.get("chi_square", 0) - self._means["chi_square"]) 
            / self._stds["chi_square"]
        )
        z_corr = abs(
            (abs(features.get("serial_correlation", 0)) - self._means["correlation"]) 
            / self._stds["correlation"]
        )
        z_comp = abs(
            (features.get("compression_ratio", 1) - self._means["compression"]) 
            / self._stds["compression"]
        )
        
        # Calculate weighted anomaly score
        raw_score = (
            z_entropy * self.weights["entropy"] +
            z_chi * self.weights["chi_square"] +
            z_corr * self.weights["correlation"] +
            z_comp * self.weights["compression"]
        )
        
        # Normalize to 0-100
        anomaly_score = min(100, raw_score * 20)
        
        # Confidence based on how extreme the z-score is
        max_z = max(z_entropy, z_chi, z_corr, z_comp)
        confidence = min(100, max_z * 25)
        
        is_anomalous = anomaly_score > 50
        
        return AnomalyResult(
            offset=features.get("offset", 0),
            anomaly_score=anomaly_score,
            confidence=confidence,
            is_anomalous=is_anomalous,
            method="zscore",
            details={
                "z_entropy": z_entropy,
                "z_chi_square": z_chi,
                "z_correlation": z_corr,
                "z_compression": z_comp,
            },
        )
    
    def predict_batch(self, features: List[Dict]) -> List[AnomalyResult]:
        """Predict anomalies for multiple blocks"""
        return [self.predict(f) for f in features]
