"""Configuration module"""
from pathlib import Path
from typing import List
from dataclasses import dataclass


@dataclass
class Config:
    """EntropyGuard configuration"""
    block_size: int = 4096
    num_workers: int = 4
    models_dir: Path = Path("models")
    output_dir: Path = Path("output")
    default_methods: List[str] = None
    
    def __post_init__(self):
        if self.default_methods is None:
            self.default_methods = ["zscore", "isolation_forest"]
    
    @classmethod
    def from_file(cls, path: Path):
        """Load config from YAML file"""
        # Simple YAML parser
        import yaml
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
            return cls(**data)
        return cls()
    
    def to_dict(self):
        return {
            "block_size": self.block_size,
            "num_workers": self.num_workers,
            "models_dir": str(self.models_dir),
            "output_dir": str(self.output_dir),
            "default_methods": self.default_methods,
        }


DEFAULT_CONFIG = Config()
