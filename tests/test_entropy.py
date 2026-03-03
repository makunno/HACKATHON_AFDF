"""Tests for entropy calculations"""
import pytest
import os
import tempfile
from pathlib import Path

from entropyguard.core.entropy import (
    calculate_shannon_entropy,
    calculate_chi_square,
    calculate_byte_frequencies,
    calculate_serial_correlation,
    calculate_compression_ratio,
    extract_all_features
)


class TestEntropy:
    """Test entropy calculation functions"""
    
    def test_shannon_entropy_zero(self):
        """Test entropy of all zeros"""
        data = b'\x00' * 1000
        entropy = calculate_shannon_entropy(data)
        assert entropy == 0.0
    
    def test_shannon_entropy_uniform(self):
        """Test entropy of uniform distribution"""
        data = bytes(range(256)) * 4  # Each byte appears once
        entropy = calculate_shannon_entropy(data)
        assert 7.9 < entropy < 8.1  # Should be close to 8
    
    def test_shannon_entropy_empty(self):
        """Test entropy of empty data"""
        entropy = calculate_shannon_entropy(b'')
        assert entropy == 0.0
    
    def test_chi_square_random(self):
        """Test chi-square on random data"""
        import random
        data = bytes(random.randint(0, 255) for _ in range(10000))
        chi = calculate_chi_square(data)
        assert 200 < chi < 300  # Expected for uniform
    
    def test_chi_square_zeros(self):
        """Test chi-square on zeros"""
        data = b'\x00' * 1000
        chi = calculate_chi_square(data)
        assert chi > 255  # Very non-uniform
    
    def test_serial_correlation(self):
        """Test serial correlation"""
        data = b'\x01\x02\x03\x04' * 1000
        corr = calculate_serial_correlation(data)
        assert abs(corr) > 0.9  # Highly correlated
    
    def test_serial_correlation_random(self):
        """Test serial correlation on random data"""
        import random
        data = bytes(random.randint(0, 255) for _ in range(1000))
        corr = calculate_serial_correlation(data)
        assert abs(corr) < 0.3  # Low correlation
    
    def test_compression_ratio(self):
        """Test compression ratio"""
        # Repeatable data compresses well
        data = b'ABC' * 10000
        ratio = calculate_compression_ratio(data)
        assert ratio < 0.5  # Good compression
        
        # Random data doesn't compress
        import random
        data = bytes(random.randint(0, 255) for _ in range(10000))
        ratio = calculate_compression_ratio(data)
        assert ratio > 0.9  # Poor compression
    
    def test_extract_all_features(self):
        """Test feature extraction"""
        data = b'Hello World!' * 100
        features = extract_all_features(data, offset=0)
        
        assert features.offset == 0
        assert features.size == len(data)
        assert 0 <= features.shannon_entropy <= 8
        assert features.chi_square >= 0
        assert len(features.byte_frequencies) == 256
        assert -1 <= features.serial_correlation <= 1
        assert 0 <= features.compression_ratio <= 1


class TestDiskReader:
    """Test disk reader"""
    
    def test_read_block(self):
        """Test reading a block"""
        from entropyguard.core.disk_reader import DiskReader
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0' * 8192)
            temp_path = f.name
        
        try:
            reader = DiskReader(temp_path, block_size=4096)
            with reader:
                block = reader.read_block(0)
                assert block.offset == 0
                assert len(block.data) == 4096
        finally:
            os.unlink(temp_path)
    
    def test_total_blocks(self):
        """Test total blocks calculation"""
        from entropyguard.core.disk_reader import DiskReader
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0' * 10000)
            temp_path = f.name
        
        try:
            reader = DiskReader(temp_path, block_size=4096)
            with reader:
                assert reader.total_blocks == 3  # ceil(10000/4096)
        finally:
            os.unlink(temp_path)


class TestAnomalyDetection:
    """Test anomaly detection"""
    
    def test_zscore_detector(self):
        """Test Z-score anomaly detection"""
        from entropyguard.features.statistical import ZScoreDetector
        
        # Create test features
        normal_features = [
            {"offset": i, "shannon_entropy": 3.0 + (i % 10) * 0.1, 
             "chi_square": 250, "serial_correlation": 0.5,
             "compression_ratio": 0.5, "mean_byte": 100, "std_byte": 50, "null_ratio": 0.1}
            for i in range(100)
        ]
        
        detector = ZScoreDetector()
        detector.fit(normal_features)
        
        # Test on anomalous data
        anomaly = {"offset": 1000, "shannon_entropy": 7.9, 
                   "chi_square": 500, "serial_correlation": 0.01,
                   "compression_ratio": 0.98, "mean_byte": 128, "std_byte": 70, "null_ratio": 0.0}
        
        result = detector.predict(anomaly)
        
        assert result.anomaly_score > 50
        assert result.is_anomalous


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
