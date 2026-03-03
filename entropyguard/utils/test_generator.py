"""Synthetic test disk generator for testing EntropyGuard"""
import os
import random
import struct
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class InjectedRegion:
    """A region to inject into the test disk"""
    offset: int
    size: int
    type: str  # 'encrypted', 'zero', 'random', 'text', 'compressed'
    entropy_hint: float


class SyntheticDiskGenerator:
    """
    Generate synthetic disk images for testing EntropyGuard.
    Supports various data types with known entropy signatures.
    """
    
    # Common filesystem magic signatures
    MBR_SIGNATURE = b'\x55\xaa'
    NTFS_MAGIC = b'NTFS'
    FAT_MAGIC = b'\xeb\x3c\x90'
    EXT_MAGIC = b'\x53\xef'
    
    def __init__(self, block_size: int = 4096):
        self.block_size = block_size
    
    def generate(
        self,
        output_path: str | Path,
        size_mb: int = 10,
        inject_regions: Optional[List[InjectedRegion]] = None,
        add_mbr: bool = True,
        add_partition_table: bool = True,
        seed: Optional[int] = None
    ) -> Path:
        """
        Generate a synthetic disk image.
        
        Args:
            output_path: Path to save the disk image
            size_mb: Size of the disk in MB
            inject_regions: List of regions to inject
            add_mbr: Add MBR signature
            add_partition_table: Add fake partition table
            seed: Random seed for reproducibility
            
        Returns:
            Path to the generated disk
        """
        output_path = Path(output_path)
        
        if seed is not None:
            random.seed(seed)
        
        total_size = size_mb * 1024 * 1024
        
        # Default: fill with random-ish but low entropy data
        with open(output_path, 'wb') as f:
            # Generate base disk with mixed content
            pos = 0
            
            # Add MBR if requested
            if add_mbr:
                mbr = self._generate_mbr(total_size)
                f.write(mbr)
                pos = 512
            
            # Fill rest with various content types
            while pos < total_size:
                remaining = total_size - pos
                block = self._generate_block(remaining)
                f.write(block)
                pos += len(block)
            
            # Inject special regions
            if inject_regions:
                self._inject_regions(output_path, inject_regions)
        
        return output_path
    
    def _generate_mbr(self, disk_size: int) -> bytes:
        """Generate a fake MBR"""
        mbr = bytearray(512)
        
        # Boot signature
        mbr[510:512] = self.MBR_SIGNATURE
        
        # Fake partition table entry (single partition)
        # Partition 1: Start at sector 2048 (1MB offset)
        partition_offset = 2048 * 512  # 1MB
        partition_size = (disk_size - partition_offset) // 512
        
        # Partition entry at offset 446
        # Boot flag (1 byte)
        mbr[446] = 0x80  # Bootable
        
        # CHS start (3 bytes) - 0xFF 0xFE 0xFF
        mbr[447:450] = b'\xff\xfe\xff'
        
        # Type code (1 byte) - 0x07 = NTFS
        mbr[450] = 0x07
        
        # CHS end (3 bytes)
        mbr[451:454] = b'\xff\xfe\xff'
        
        # Starting sector (4 bytes, little endian)
        struct.pack_into('<I', mbr, 454, partition_offset // 512)
        
        # Size in sectors (4 bytes, little endian)
        struct.pack_into('<I', mbr, 458, partition_size)
        
        return bytes(mbr)
    
    def _generate_block(self, size: int) -> bytes:
        """Generate a block of data with variable entropy"""
        # Random choice of content type
        content_type = random.choices(
            ['text', 'repeating', 'semi_random', 'binary'],
            weights=[0.3, 0.2, 0.3, 0.2]
        )[0]
        
        if content_type == 'text':
            # Low entropy - readable text
            return self._generate_text(min(size, self.block_size))
        elif content_type == 'repeating':
            # Very low entropy - repeating pattern
            return self._generate_repeating(min(size, self.block_size))
        elif content_type == 'semi_random':
            # Medium entropy - typical binary data
            return self._generate_binary(min(size, self.block_size))
        else:
            # Binary executable-like
            return self._generate_executable(min(size, self.block_size))
    
    def _generate_text(self, size: int) -> bytes:
        """Generate low-entropy text data"""
        words = [
            b'The quick brown fox jumps over the lazy dog. ',
            b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ',
            b'Lorem ipsum dolor sit amet, consectetur. ',
            b'1234567890ABCDEF0123456789ABCDEF0. ',
            b'Windows System32 Config SAM. ',
            b'User Documents Report 2024. ',
        ]
        data = b''
        while len(data) < size:
            data += random.choice(words)
        return data[:size]
    
    def _generate_repeating(self, size: int) -> bytes:
        """Generate very low entropy repeating data"""
        patterns = [
            b'\x00' * 16,
            b'\xff' * 16,
            b'\xaa\x55' * 8,
            b'\x00\x01\x02\x03' * 4,
            b'AAAA' * 4,
        ]
        pattern = random.choice(patterns)
        repeats = (size // len(pattern)) + 1
        return (pattern * repeats)[:size]
    
    def _generate_binary(self, size: int) -> bytes:
        """Generate medium entropy binary data"""
        # Some patterns, some random
        data = bytearray(size)
        for i in range(0, size, 16):
            if random.random() < 0.3:
                # Insert a pattern
                pattern = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
                data[i:i+16] = pattern
            else:
                # Random but biased
                for j in range(min(16, size - i)):
                    data[i + j] = random.randint(0, 200)
        return bytes(data)
    
    def _generate_executable(self, size: int) -> bytes:
        """Generate executable-like data with moderate entropy"""
        # Typical PE header patterns
        data = bytearray(size)
        
        # MZ header stub
        data[0:2] = b'MZ'
        
        # Some nulls and some random bytes
        for i in range(2, size):
            if random.random() < 0.4:
                data[i] = 0
            else:
                data[i] = random.randint(0, 255)
        
        return bytes(data)
    
    def _inject_regions(self, disk_path: Path, regions: List[InjectedRegion]) -> None:
        """Inject special regions into the disk"""
        for region in regions:
            with open(disk_path, 'r+b') as f:
                f.seek(region.offset)
                
                if region.type == 'encrypted':
                    # High entropy - encrypted-like data
                    data = self._generate_encrypted(region.size)
                elif region.type == 'zero':
                    # Very low entropy - zeros
                    data = b'\x00' * region.size
                elif region.type == 'random':
                    # Maximum entropy - random data
                    data = self._generate_random(region.size)
                elif region.type == 'compressed':
                    # High entropy - compressed-like
                    data = self._generate_compressed(region.size)
                else:
                    data = b'\x00' * region.size
                
                f.write(data)
    
    def _generate_encrypted(self, size: int) -> bytes:
        """Generate high entropy encrypted-like data"""
        return bytes(random.randint(0, 255) for _ in range(size))
    
    def _generate_random(self, size: int) -> bytes:
        """Generate random data"""
        return os.urandom(size)
    
    def _generate_compressed(self, size: int) -> bytes:
        """Generate compressed-like data"""
        # zlib-like compressed data header
        data = bytearray(size)
        data[0:2] = b'\x78\x9c'  # zlib header
        for i in range(2, size):
            data[i] = random.randint(0, 255)
        return bytes(data)
    
    def create_test_disk_with_hidden_volume(
        self,
        output_path: str | Path,
        disk_size_mb: int = 50,
        hidden_volume_size_mb: int = 10,
        hidden_volume_offset_mb: int = 20,
        seed: Optional[int] = 42
    ) -> dict:
        """
        Create a test disk with a hidden encrypted volume.
        
        This simulates a VeraCrypt hidden volume scenario.
        """
        regions = [
            InjectedRegion(
                offset=hidden_volume_offset_mb * 1024 * 1024,
                size=hidden_volume_size_mb * 1024 * 1024,
                type='encrypted',
                entropy_hint=7.9
            )
        ]
        
        self.generate(
            output_path=output_path,
            size_mb=disk_size_mb,
            inject_regions=regions,
            add_mbr=True,
            seed=seed
        )
        
        return {
            'disk_size_mb': disk_size_mb,
            'hidden_volume': {
                'offset_mb': hidden_volume_offset_mb,
                'size_mb': hidden_volume_size_mb,
                'entropy_hint': 7.9
            }
        }
    
    def create_test_disk_wipe_signature(
        self,
        output_path: str | Path,
        disk_size_mb: int = 50,
        wipe_regions: List[Tuple[int, int]] = None,  # (offset_mb, size_mb)
        seed: Optional[int] = 42
    ) -> dict:
        """
        Create a test disk with wipe signatures.
        """
        if wipe_regions is None:
            wipe_regions = [(10, 5), (30, 3)]  # Default wipe regions
        
        regions = [
            InjectedRegion(
                offset=offset * 1024 * 1024,
                size=size * 1024 * 1024,
                type='zero',
                entropy_hint=0.0
            )
            for offset, size in wipe_regions
        ]
        
        self.generate(
            output_path=output_path,
            size_mb=disk_size_mb,
            inject_regions=regions,
            add_mbr=True,
            seed=seed
        )
        
        return {
            'disk_size_mb': disk_size_mb,
            'wipe_regions': [{'offset_mb': o, 'size_mb': s} for o, s in wipe_regions]
        }


def generate_standard_test_disk(output_path: str, disk_size_mb: int = 50) -> Path:
    """Convenience function to generate a standard test disk"""
    gen = SyntheticDiskGenerator()
    
    # Inject some encrypted regions
    regions = [
        InjectedRegion(
            offset=10 * 1024 * 1024,  # 10MB
            size=5 * 1024 * 1024,     # 5MB
            type='encrypted',
            entropy_hint=7.9
        ),
        InjectedRegion(
            offset=25 * 1024 * 1024,  # 25MB
            size=3 * 1024 * 1024,     # 3MB  
            type='encrypted',
            entropy_hint=7.8
        ),
    ]
    
    return gen.generate(
        output_path=output_path,
        size_mb=disk_size_mb,
        inject_regions=regions,
        add_mbr=True,
        seed=12345
    )


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m entropyguard.utils.test_generator <output_path> [size_mb]")
        sys.exit(1)
    
    output = sys.argv[1]
    size = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    print(f"Generating test disk: {output} ({size}MB)")
    path = generate_standard_test_disk(output, size)
    print(f"Created: {path}")
