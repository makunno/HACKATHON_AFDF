"""Synthetic disk generator for testing"""
import os
import random
from pathlib import Path
from typing import Optional


class SyntheticDiskGenerator:
    """
    Generate synthetic disk images for testing.
    Creates fake disks with normal and encrypted regions.
    """
    
    def __init__(self, block_size: int = 4096):
        self.block_size = block_size
    
    def generate(
        self,
        output_path: str | Path,
        total_size: int = 10 * 1024 * 1024,
        normal_entropy: float = 3.0,
        encrypted_entropy: float = 7.9,
        encrypted_regions: list = None,
        add_partition_table: bool = True
    ) -> Path:
        """
        Generate a synthetic disk image.
        
        Args:
            output_path: Output file path
            total_size: Total disk size in bytes
            normal_entropy: Target entropy for normal regions
            encrypted_entropy: Target entropy for encrypted regions
            encrypted_regions: List of (start, size) tuples for encrypted regions
            add_partition_table: Add MBR partition table
            
        Returns:
            Path to generated disk image
        """
        output_path = Path(output_path)
        
        if encrypted_regions is None:
            # Default: add encrypted region in middle
            mid = total_size // 2
            encrypted_regions = [(mid, 1024 * 1024)]  # 1MB encrypted
        
        with open(output_path, 'wb') as f:
            # Write partition table if requested
            if add_partition_table:
                mbr = self._generate_mbr(total_size)
                f.write(mbr)
                f.write(b'\x00' * (self.block_size - len(mbr)))
            else:
                f.seek(self.block_size)
            
            remaining = total_size - f.tell()
            
            # Generate data
            pos = f.tell()
            
            while pos < total_size:
                # Check if in encrypted region
                is_encrypted = False
                for start, size in encrypted_regions:
                    if start <= pos < start + size:
                        is_encrypted = True
                        break
                
                # Generate block
                if is_encrypted:
                    data = self._generate_high_entropy(encrypted_entropy)
                else:
                    data = self._generate_normal_entropy(normal_entropy)
                
                f.write(data)
                pos += len(data)
        
        return output_path
    
    def _generate_mbr(self, disk_size: int) -> bytes:
        """Generate a basic MBR with single partition"""
        mbr = bytearray(512)
        
        # Boot signature
        mbr[510] = 0x55
        mbr[511] = 0xAA
        
        # Partition 1: Linux partition
        mbr[446] = 0x80  # Bootable
        mbr[447] = 0xFE  # CHS start
        mbr[448] = 0xFF
        mbr[449] = 0xFF
        mbr[450] = 0x83  # Linux partition type
        mbr[451] = 0xFE  # CHS end
        mbr[452] = 0xFF
        mbr[453] = 0xFF
        
        # LBA start (sector 2048)
        lba_start = 2048
        mbr[454:458] = lba_start.to_bytes(4, 'little')
        
        # Partition size (in sectors)
        partition_sectors = (disk_size // 512) - lba_start
        mbr[458:462] = partition_sectors.to_bytes(4, 'little')
        
        return bytes(mbr)
    
    def _generate_normal_entropy(self, target_entropy: float) -> bytes:
        """Generate data with specific entropy"""
        if target_entropy < 2:
            # Very low - mostly zeros
            return bytes(self.block_size)
        
        elif target_entropy < 4:
            # Low - mostly repeated patterns
            pattern = bytes([i % 256 for i in range(256)])
            repeats = self.block_size // 256 + 1
            data = pattern * repeats
            return data[:self.block_size]
        
        elif target_entropy < 6:
            # Medium - some structure
            data = bytearray(self.block_size)
            for i in range(0, self.block_size, 64):
                data[i:i+16] = b'This is a test '
            return bytes(data)
        
        else:
            # Higher entropy - random-like but structured
            data = bytearray(self.block_size)
            random.seed()
            for i in range(0, self.block_size, 4):
                val = random.randint(0, 255)
                data[i] = val
            return bytes(data)
    
    def _generate_high_entropy(self, target_entropy: float) -> bytes:
        """Generate high-entropy (encrypted-like) data"""
        if target_entropy >= 7.8:
            # True random - like encryption
            return bytes(random.randint(0, 255) for _ in range(self.block_size))
        
        # Near-random
        data = bytearray(self.block_size)
        for i in range(self.block_size):
            if random.random() < 0.95:
                data[i] = random.randint(0, 255)
        return bytes(data)
    
    def generate_with_hidden_volume(
        self,
        output_path: str | Path,
        disk_size: int = 50 * 1024 * 1024,
        hidden_start: int = 20 * 1024 * 1024,
        hidden_size: int = 5 * 1024 * 1024
    ) -> Path:
        """Generate disk with simulated hidden VeraCrypt volume"""
        
        regions = [(hidden_start, hidden_size)]
        
        return self.generate(
            output_path=output_path,
            total_size=disk_size,
            encrypted_regions=regions,
            add_partition_table=True
        )


if __name__ == "__main__":
    gen = SyntheticDiskGenerator()
    
    # Generate test disk
    disk = gen.generate_with_hidden_volume("test_disk.dd")
    print(f"Generated: {disk}")
