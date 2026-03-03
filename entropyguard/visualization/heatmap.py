"""Heatmap visualization generator"""
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional


class HeatmapGenerator:
    """
    Generate entropy heatmap visualizations.
    """
    
    def __init__(self):
        self._matplotlib = None
        self._try_import()
    
    def _try_import(self):
        """Try to import matplotlib"""
        try:
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
            import matplotlib.pyplot as plt
            import matplotlib.cm as cm
            self._matplotlib = plt
            self._cm = cm
        except ImportError:
            self._matplotlib = None
    
    def generate_entropy_heatmap(
        self,
        blocks: List[Dict],
        output_path: Path,
        width: int = 1000,
        height: int = 800,
        dpi: int = 100
    ) -> Path:
        """
        Generate PNG heatmap of entropy distribution.
        
        Args:
            blocks: List of block dictionaries with entropy
            output_path: Output file path
            width: Image width
            height: Image height
            dpi: DPI for image
            
        Returns:
            Path to generated image
        """
        if self._matplotlib is None:
            raise ImportError("matplotlib not installed")
        
        plt = self._matplotlib
        cm = self._cm
        
        # Extract entropy values
        entropies = [b.get("shannon_entropy", 0) for b in blocks]
        
        if not entropies:
            raise ValueError("No entropy data to plot")
        
        # Create grid
        n_blocks = len(entropies)
        cols = min(1000, n_blocks)
        rows = (n_blocks + cols - 1) // cols
        
        # Create entropy matrix
        matrix = np.zeros((rows, cols))
        for i, ent in enumerate(entropies):
            row = i // cols
            col = i % cols
            matrix[row, col] = ent
        
        # Create figure
        fig, ax = plt.subplots(figsize=(width/dpi, height/dpi), dpi=dpi)
        
        # Plot heatmap
        im = ax.imshow(matrix, cmap='hot', aspect='auto', vmin=0, vmax=8)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Shannon Entropy (bits)', fontsize=12)
        
        # Labels
        ax.set_title('EntropyGuard - Disk Entropy Heatmap', fontsize=16)
        ax.set_xlabel('Block Position (modulo)', fontsize=12)
        ax.set_ylabel('Block Row', fontsize=12)
        
        # Add annotations for high-entropy regions
        threshold = 7.5
        for i, ent in enumerate(entropies):
            if ent > threshold:
                row = i // cols
                col = i % cols
                ax.plot(col, row, 'co', markersize=1)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=dpi)
        plt.close()
        
        return output_path
    
    def generate_anomaly_heatmap(
        self,
        blocks: List[Dict],
        output_path: Path,
        width: int = 1000,
        height: int = 800
    ) -> Path:
        """Generate heatmap showing anomaly scores"""
        if self._matplotlib is None:
            raise ImportError("matplotlib not installed")
        
        plt = self._matplotlib
        
        scores = [b.get("anomaly_score", 0) for b in blocks]
        
        n_blocks = len(scores)
        cols = min(1000, n_blocks)
        rows = (n_blocks + cols - 1) // cols
        
        matrix = np.zeros((rows, cols))
        for i, score in enumerate(scores):
            row = i // cols
            col = i % cols
            matrix[row, col] = score
        
        fig, ax = plt.subplots(figsize=(width/100, height/100))
        
        im = ax.imshow(matrix, cmap='Reds', aspect='auto', vmin=0, vmax=100)
        
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Anomaly Score', fontsize=12)
        
        ax.set_title('EntropyGuard - Anomaly Score Heatmap', fontsize=16)
        ax.set_xlabel('Block Position', fontsize=12)
        ax.set_ylabel('Block Row', fontsize=12)
        
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        
        return output_path
    
    def generate_combined_plot(
        self,
        blocks: List[Dict],
        output_path: Path,
        regions: List[Dict] = None
    ) -> Path:
        """Generate combined visualization with multiple panels"""
        if self._matplotlib is None:
            raise ImportError("matplotlib not installed")
        
        plt = self._matplotlib
        
        entropies = [b.get("shannon_entropy", 0) for b in blocks]
        scores = [b.get("anomaly_score", 0) for b in blocks]
        
        fig, axes = plt.subplots(3, 1, figsize=(14, 12))
        
        # Panel 1: Entropy over blocks
        axes[0].plot(entropies, 'b-', linewidth=0.5)
        axes[0].axhline(y=7.5, color='r', linestyle='--', label='Encryption threshold')
        axes[0].set_ylabel('Shannon Entropy')
        axes[0].set_title('Entropy Distribution')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # Panel 2: Anomaly scores
        axes[1].plot(scores, 'r-', linewidth=0.5)
        axes[1].axhline(y=50, color='orange', linestyle='--', label='Anomaly threshold')
        axes[1].set_ylabel('Anomaly Score')
        axes[1].set_title('Anomaly Scores')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        # Panel 3: Regions
        if regions:
            for region in regions:
                start = region.get("start_offset", 0) // 4096
                end = region.get("end_offset", 0) // 4096
                score = region.get("mean_anomaly_score", 0)
                axes[2].axvspan(start, end, alpha=0.3, color='red', label=f'Region (score:{score:.0f})')
        
        axes[2].set_ylabel('Blocks')
        axes[2].set_xlabel('Block Number')
        axes[2].set_title('Suspicious Regions')
        axes[2].set_xlim(0, len(blocks))
        
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        
        return output_path
