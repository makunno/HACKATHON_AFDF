"""Filesystem metadata analyzer - similar to The Sleuth Kit fsstat"""
import struct
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class FilesystemInfo:
    """Filesystem metadata"""
    filesystem_type: str
    label: Optional[str]
    block_size: int
    total_blocks: int
    free_blocks: int
    mount_point: Optional[str]
    last_mounted: Optional[str]
    magic: Optional[str]
    metadata: Dict
    
    def to_dict(self) -> Dict:
        return {
            "filesystem_type": self.filesystem_type,
            "label": self.label,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "free_blocks": self.free_blocks,
            "mount_point": self.mount_point,
            "last_mounted": self.last_mounted,
            "magic": self.magic,
            "metadata": self.metadata,
        }


class FilesystemAnalyzer:
    """
    Analyze filesystem metadata from disk images.
    Supports common filesystems: NTFS, FAT, EXT, exFAT, HFS+
    """
    
    FS_SIGNATURES = {
        b'NTFS': "NTFS",
        b'\x45\x4E\x54\x46': "NTFS",
        b'\xEB\x3C\x90': "FAT",
        b'\xEB\x58\x90': "FAT32",
        b'\x53\xEF': "EXT2/3/4",
        b'\x45\x58\x46\x41\x54': "exFAT",
        b'\x48\x2B\x04\x00': "HFS",
        b'\x41\x50\x46\x53': "APFS",
    }
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size
    
    def analyze(self, disk_path: str | Path, offset: int = 0) -> FilesystemInfo:
        """
        Analyze filesystem at given offset.
        
        Args:
            disk_path: Path to disk image
            offset: Byte offset to check for filesystem
            
        Returns:
            FilesystemInfo with metadata
        """
        disk_path = Path(disk_path)
        
        try:
            with open(disk_path, 'rb') as f:
                f.seek(offset)
                boot_sector = f.read(512)
                
                if len(boot_sector) < 512:
                    return self._unknown_fs()
                
                # Detect filesystem
                fs_type = self._detect_filesystem(boot_sector)
                
                if fs_type == "NTFS":
                    return self._analyze_ntfs(boot_sector, offset)
                elif fs_type in ["FAT", "FAT32"]:
                    return self._analyze_fat(boot_sector, offset)
                elif fs_type == "EXT2/3/4":
                    return self._analyze_ext(boot_sector, offset)
                elif fs_type == "exFAT":
                    return self._analyze_exfat(boot_sector, offset)
                else:
                    return self._unknown_fs()
        
        except Exception as e:
            return FilesystemInfo(
                filesystem_type="Unknown",
                label=None,
                block_size=0,
                total_blocks=0,
                free_blocks=0,
                mount_point=None,
                last_mounted=None,
                magic=None,
                metadata={"error": str(e)},
            )
    
    def _detect_filesystem(self, boot_sector: bytes) -> str:
        """Detect filesystem type from boot sector"""
        # Check for known signatures
        for sig, fs_type in self.FS_SIGNATURES.items():
            if boot_sector[:len(sig)] == sig:
                return fs_type
        
        # Check for FAT by cluster size
        if boot_sector[14:16] != b'\x00\x00':
            reserved = struct.unpack('<H', boot_sector[14:16])[0]
            if 1 <= reserved <= 65535:
                return "FAT"
        
        return "Unknown"
    
    def _analyze_ntfs(self, boot_sector: bytes, offset: int) -> FilesystemInfo:
        """Analyze NTFS filesystem"""
        try:
            bytes_per_sector = struct.unpack('<H', boot_sector[11:13])[0]
            sectors_per_cluster = boot_sector[13]
            total_sectors = struct.unpack('<Q', boot_sector[40:48])[0]
            
            # Try to read MFT
            mft_start = struct.unpack('<Q', boot_sector[48:56])[0]
            
            label = None
            try:
                # Volume label is at offset 0x30 in boot sector (up to 261 chars)
                label = boot_sector[0x30:0x30+261].decode('utf-16le').rstrip('\x00')
                if not label:
                    label = None
            except:
                pass
            
            return FilesystemInfo(
                filesystem_type="NTFS",
                label=label,
                block_size=bytes_per_sector * sectors_per_cluster,
                total_blocks=total_sectors,
                free_blocks=0,
                mount_point=None,
                last_mounted=None,
                magic="NTFS",
                metadata={
                    "bytes_per_sector": bytes_per_sector,
                    "sectors_per_cluster": sectors_per_cluster,
                    "mft_start_cluster": mft_start,
                    "offset": offset,
                },
            )
        except Exception:
            return self._unknown_fs()
    
    def _analyze_fat(self, boot_sector: bytes, offset: int) -> FilesystemInfo:
        """Analyze FAT filesystem"""
        try:
            bytes_per_sector = struct.unpack('<H', boot_sector[11:13])[0]
            sectors_per_cluster = boot_sector[13]
            reserved_sectors = struct.unpack('<H', boot_sector[14:16])[0]
            num_fats = boot_sector[16]
            sectors_per_fat = struct.unpack('<H', boot_sector[22:24])[0]
            
            total_sectors = struct.unpack('<H', boot_sector[19:21])[0]
            if total_sectors == 0:
                total_sectors = struct.unpack('<I', boot_sector[32:36])[0]
            
            fat_size = sectors_per_fat * num_fats
            root_dir_sectors = ((32 * 200) + bytes_per_sector - 1) // bytes_per_sector
            data_sectors = total_sectors - reserved_sectors - (num_fats * sectors_per_fat) - root_dir_sectors
            total_clusters = data_sectors // sectors_per_cluster
            
            fs_type = "FAT32" if sectors_per_fat == 0 else "FAT16" if total_clusters > 65525 else "FAT12"
            
            label = None
            try:
                label = boot_sector[43:54].decode('ascii').rstrip('\x00')
            except:
                pass
            
            return FilesystemInfo(
                filesystem_type=fs_type,
                label=label if label else None,
                block_size=bytes_per_sector * sectors_per_cluster,
                total_blocks=total_sectors,
                free_blocks=0,
                mount_point=None,
                last_mounted=None,
                magic="FAT",
                metadata={
                    "bytes_per_sector": bytes_per_sector,
                    "sectors_per_cluster": sectors_per_cluster,
                    "reserved_sectors": reserved_sectors,
                    "num_fats": num_fats,
                    "fat_size": fat_size,
                    "offset": offset,
                },
            )
        except Exception:
            return self._unknown_fs()
    
    def _analyze_ext(self, boot_sector: bytes, offset: int) -> FilesystemInfo:
        """Analyze EXT filesystem"""
        try:
            # EXT superblock is at offset 1024
            if len(boot_sector) < 1084:
                return self._unknown_fs()
            
            superblock = boot_sector[1024:1084]
            
            inodes = struct.unpack('<I', superblock[0:4])[0]
            block_size = 1024 << struct.unpack('<I', superblock[24:28])[0]
            blocks = struct.unpack('<I', superblock[4:8])[0]
            reserved = struct.unpack('<I', superblock[8:12])[0]
            
            free_blocks = struct.unpack('<I', superblock[12:16])[0]
            free_inodes = struct.unpack('<I', superblock[16:20])[0]
            
            first_data_block = struct.unpack('<I', superblock[20:24])[0]
            
            return FilesystemInfo(
                filesystem_type="EXT4",
                label=None,
                block_size=block_size,
                total_blocks=blocks - reserved,
                free_blocks=free_blocks,
                mount_point=None,
                last_mounted=None,
                magic="EXT",
                metadata={
                    "inodes": inodes,
                    "free_inodes": free_inodes,
                    "first_data_block": first_data_block,
                    "offset": offset,
                },
            )
        except Exception:
            return self._unknown_fs()
    
    def _analyze_exfat(self, boot_sector: bytes, offset: int) -> FilesystemInfo:
        """Analyze exFAT filesystem"""
        try:
            bytes_per_sector_shift = boot_sector[12]
            sectors_per_cluster_shift = boot_sector[13]
            bytes_per_sector = 2 << bytes_per_sector_shift
            sectors_per_cluster = 2 << sectors_per_cluster_shift
            
            fat_offset = struct.unpack('<I', boot_sector[80:84])[0]
            fat_length = struct.unpack('<I', boot_sector[84:88])[0]
            
            total_sectors = struct.unpack('<Q', boot_sector[0x58:0x60])[0]
            
            return FilesystemInfo(
                filesystem_type="exFAT",
                label=None,
                block_size=bytes_per_sector * sectors_per_cluster,
                total_blocks=total_sectors,
                free_blocks=0,
                mount_point=None,
                last_mounted=None,
                magic="exFAT",
                metadata={
                    "fat_offset": fat_offset,
                    "fat_length": fat_length,
                    "offset": offset,
                },
            )
        except Exception:
            return self._unknown_fs()
    
    def _unknown_fs(self) -> FilesystemInfo:
        """Return unknown filesystem"""
        return FilesystemInfo(
            filesystem_type="Unknown",
            label=None,
            block_size=0,
            total_blocks=0,
            free_blocks=0,
            mount_point=None,
            last_mounted=None,
            magic=None,
            metadata={},
        )
