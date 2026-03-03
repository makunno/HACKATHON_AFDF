"""
Disk Reader - Streaming disk/image reader with configurable block sizes
Never loads full disk into memory
"""
import os
import mmap
import logging
from pathlib import Path
from typing import Iterator, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Block:
    """Represents a block of data from disk"""
    offset: int
    data: bytes
    size: int
    
    @property
    def is_full_block(self) -> bool:
        return self.size == self._expected_size
    
    def __post_init__(self):
        self._expected_size = len(self.data)


class DiskReader:
    """
    Stream-based disk image reader.
    Reads disk images in configurable block sizes without loading entire file into memory.
    """
    
    def __init__(
        self,
        path: str | Path,
        block_size: int = 4096,
        overlap: int = 0
    ):
        """
        Initialize disk reader.
        
        Args:
            path: Path to disk image file
            block_size: Size of each block to read (default: 4096 bytes)
            overlap: Optional overlap between blocks for context
        """
        self.path = Path(path)
        self.block_size = block_size
        self.overlap = overlap
        
        if not self.path.exists():
            raise FileNotFoundError(f"Disk image not found: {self.path}")
        
        self._file_size = self.path.stat().st_size
        self._file = None
        self._mmap = None
        
        logger.info(f"DiskReader initialized: {self.path} ({self._file_size} bytes, block_size={block_size})")
    
    @property
    def file_size(self) -> int:
        """Get total size of disk image"""
        return self._file_size
    
    @property
    def total_blocks(self) -> int:
        """Calculate total number of blocks"""
        return (self._file_size + self.block_size - 1) // self.block_size
    
    def __enter__(self):
        """Context manager entry"""
        self._file = open(self.path, 'rb')
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    def close(self):
        """Close the disk image file"""
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None
    
    def read_block(self, offset: int) -> Block:
        """
        Read a single block at the given offset.
        
        Args:
            offset: Byte offset to read from
            
        Returns:
            Block object containing data and metadata
        """
        if self._file is None:
            raise RuntimeError("DiskReader not opened. Use 'with' statement or call open()")
        
        self._file.seek(offset)
        data = self._file.read(self.block_size)
        size = len(data)
        
        return Block(offset=offset, data=data, size=size)
    
    def read_blocks(
        self, 
        start_block: int = 0, 
        end_block: Optional[int] = None
    ) -> Iterator[Block]:
        """
        Iterate over blocks in a range.
        
        Args:
            start_block: Starting block number
            end_block: Ending block number (None = read to end)
            
        Yields:
            Tuples of (block_number, data, size)
        """
        if end_block is None:
            end_block = self.total_blocks
        
        for block_num in range(start_block, end_block):
            offset = block_num * self.block_size
            if offset >= self._file_size:
                break
            
            yield self.read_block(offset)
    
    def read_all_blocks(self) -> Iterator[Block]:
        """
        Iterate over all blocks in the disk image.
        
        Yields:
            Block objects sequentially
        """
        offset = 0
        while offset < self._file_size:
            yield self.read_block(offset)
            offset += self.block_size
    
    def get_block_offsets(self) -> list[int]:
        """Get list of all block offsets"""
        return list(range(0, self._file_size, self.block_size))
    
    def read_range(self, start: int, length: int) -> bytes:
        """
        Read a specific range of bytes from disk.
        
        Args:
            start: Starting byte offset
            length: Number of bytes to read
            
        Returns:
            Raw bytes (may be less than requested if EOF)
        """
        if self._file is None:
            raise RuntimeError("DiskReader not opened")
        
        self._file.seek(start)
        return self._file.read(min(length, self._file_size - start))
    
    def use_mmap(self, readonly: bool = True) -> 'DiskReader':
        """
        Enable memory-mapped file access for faster random access.
        
        Args:
            readonly: Open in read-only mode
            
        Returns:
            Self for method chaining
        """
        self._file = open(self.path, 'rb' if readonly else 'r+b')
        if readonly:
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        else:
            self._mmap = mmap.mmap(self._file.fileno(), 0)
        return self
    
    def read_block_mmap(self, offset: int) -> Block:
        """Read block using memory-mapped file"""
        if self._mmap is None:
            raise RuntimeError("Memory map not enabled. Call use_mmap() first")
        
        end = offset + self.block_size
        if offset >= self._file_size:
            return Block(offset=offset, data=b'', size=0)
        
        data = self._mmap[offset:end]
        return Block(offset=offset, data=bytes(data), size=len(data))


class MultiVolumeReader:
    """Handle multiple volume images (e.g., split .001, .002 files)"""
    
    def __init__(self, base_path: str | Path, block_size: int = 4096):
        self.base_path = Path(base_path)
        self.block_size = block_size
        self._readers: list[DiskReader] = []
        self._volume_offsets: list[int] = []
        
        self._discover_volumes()
    
    def _discover_volumes(self):
        """Find all split volume files"""
        base = self.base_path.stem
        ext = self.base_path.suffix
        parent = self.base_path.parent
        
        # Look for numbered files: image.001, image.002, etc.
        volumes = []
        for i in range(1, 1000):
            vol_path = parent / f"{base}{i:03d}"
            if not vol_path.exists():
                # Try alternative naming: image.part1, image.part2
                vol_path = parent / f"{base}.part{i}"
                if not vol_path.exists():
                    break
            volumes.append(vol_path)
        
        if not volumes and self.base_path.exists():
            volumes = [self.base_path]
        
        # Create readers and calculate offsets
        offset = 0
        for vol_path in volumes:
            reader = DiskReader(vol_path, self.block_size)
            self._readers.append(reader)
            self._volume_offsets.append(offset)
            offset += reader.file_size
        
        logger.info(f"MultiVolumeReader: found {len(self._readers)} volumes")
    
    def __enter__(self):
        for reader in self._readers:
            reader.__enter__()
        return self
    
    def __exit__(self, *args):
        for reader in self._readers:
            reader.close()
    
    @property
    def file_size(self) -> int:
        return sum(r.file_size for r in self._readers)
    
    def read_block(self, offset: int) -> Block:
        """Read a block from the appropriate volume"""
        for i, vol_offset in enumerate(self._volume_offsets):
            if offset < vol_offset + self._readers[i].file_size:
                rel_offset = offset - vol_offset
                return self._readers[i].read_block(rel_offset)
        raise EOFError(f"Offset {offset} beyond total size")
    
    def read_all_blocks(self) -> Iterator[Block]:
        """Iterate over all blocks across volumes"""
        for reader in self._readers:
            yield from reader.read_all_blocks()
