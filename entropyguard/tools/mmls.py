"""Partition table mapper - similar to The Sleuth Kit mmls"""
import struct
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class Partition:
    """A disk partition"""
    slot: int
    start_offset: int
    end_offset: int
    size: int
    description: str
    filesystem_type: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "slot": self.slot,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.size,
            "description": self.description,
            "filesystem_type": self.filesystem_type,
        }


class PartitionMapper:
    """
    Map partition tables from disk images.
    Supports MBR and GPT partitioning schemes.
    """
    
    MBR_SIGNATURE = 0xAA55
    GPT_SIGNATURE = b'EFI PART'
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size
    
    def analyze(self, disk_path: str | Path) -> List[Partition]:
        """
        Analyze disk image for partition tables.
        
        Args:
            disk_path: Path to disk image
            
        Returns:
            List of detected partitions
        """
        disk_path = Path(disk_path)
        
        partitions = []
        
        # Try MBR
        mbr_partitions = self._detect_mbr(disk_path)
        partitions.extend(mbr_partitions)
        
        # Try GPT
        gpt_partitions = self._detect_gpt(disk_path)
        partitions.extend(gpt_partitions)
        
        # If nothing found, try to detect unallocated space
        if not partitions:
            partitions = self._detect_unallocated(disk_path)
        
        return partitions
    
    def _detect_mbr(self, disk_path: Path) -> List[Partition]:
        """Detect MBR partitions"""
        partitions = []
        
        try:
            with open(disk_path, 'rb') as f:
                # Read MBR
                f.seek(0)
                mbr = f.read(512)
                
                # Check signature
                if len(mbr) < 512:
                    return []
                
                signature = struct.unpack('<H', mbr[510:512])[0]
                if signature != self.MBR_SIGNATURE:
                    return []
                
                # Parse partition entries (64 bytes starting at offset 446)
                for i in range(4):
                    offset = 446 + (i * 16)
                    entry = mbr[offset:offset + 16]
                    
                    if entry[4] == 0:  # Empty entry
                        continue
                    
                    start_sector = struct.unpack('<I', entry[8:12])[0]
                    sectors = struct.unpack('<I', entry[12:16])[0]
                    
                    if sectors == 0:
                        continue
                    
                    fs_type = self._get_fs_type(entry[4])
                    
                    partitions.append(Partition(
                        slot=i,
                        start_offset=start_sector * self.sector_size,
                        end_offset=(start_sector + sectors) * self.sector_size,
                        size=sectors * self.sector_size,
                        description=f"MBR Partition {i+1}",
                        filesystem_type=fs_type,
                    ))
        
        except Exception:
            pass
        
        return partitions
    
    def _detect_gpt(self, disk_path: Path) -> List[Partition]:
        """Detect GPT partitions"""
        partitions = []
        
        try:
            with open(disk_path, 'rb') as f:
                # Read GPT header (LBA 1)
                f.seek(self.sector_size)
                header = f.read(self.sector_size)
                
                # Check GPT signature
                if len(header) < 92 or header[:8] != self.GPT_SIGNATURE:
                    return []
                
                # Get partition entries info
                partition_entries_lba = struct.unpack('<Q', header[72:80])[0]
                num_partitions = struct.unpack('<I', header[80:84])[0]
                partition_entry_size = struct.unpack('<I', header[84:88])[0]
                
                # Read partition entries
                f.seek(partition_entries_lba * self.sector_size)
                
                for i in range(min(num_partitions, 128)):
                    entry = f.read(partition_entry_size)
                    
                    if len(entry) < 128:
                        break
                    
                    # Check if entry exists (first 16 bytes are GUID)
                    if entry[:16] == b'\x00' * 16:
                        continue
                    
                    # Parse GPT partition entry
                    start_lba = struct.unpack('<Q', entry[32:40])[0]
                    end_lba = struct.unpack('<Q', entry[40:48])[0]
                    
                    # Get name (UTF-16le, 72 bytes)
                    name = entry[56:128].decode('utf-16le').rstrip('\x00')
                    
                    if end_lba >= start_lba:
                        partitions.append(Partition(
                            slot=i,
                            start_offset=start_lba * self.sector_size,
                            end_offset=(end_lba + 1) * self.sector_size,
                            size=(end_lba - start_lba + 1) * self.sector_size,
                            description=name or f"GPT Partition {i+1}",
                            filesystem_type=self._guess_fs_from_name(name),
                        ))
        
        except Exception:
            pass
        
        return partitions
    
    def _detect_unallocated(self, disk_path: Path) -> List[Partition]:
        """Detect unallocated space as single partition"""
        try:
            size = disk_path.stat().st_size
            return [Partition(
                slot=0,
                start_offset=0,
                end_offset=size,
                size=size,
                description="Whole Disk (Unallocated)",
                filesystem_type=None,
            )]
        except Exception:
            return []
    
    def _get_fs_type(self, type_code: int) -> str:
        """Get filesystem type from MBR type code"""
        fs_types = {
            0x01: "FAT12",
            0x04: "FAT16",
            0x05: "Extended",
            0x06: "FAT16",
            0x07: "NTFS/HPFS",
            0x0B: "FAT32",
            0x0C: "FAT32 (LBA)",
            0x0E: "FAT16 (LBA)",
            0x0F: "Extended (LBA)",
            0x11: "Hidden FAT12",
            0x14: "Hidden FAT16",
            0x16: "Hidden FAT16",
            0x1B: "Hidden FAT32",
            0x1C: "Hidden FAT32 (LBA)",
            0x1E: "Hidden FAT16 (LBA)",
            0x82: "Linux Swap",
            0x83: "Linux",
            0x85: "Linux Extended",
            0x8E: "Linux LVM",
            0xEE: "GPT Protective",
            0xEF: "EFI System",
            0xFD: "Linux RAID",
        }
        return fs_types.get(type_code, f"Unknown (0x{type_code:02X})")
    
    def _guess_fs_from_name(self, name: str) -> str:
        """Guess filesystem type from partition name"""
        name_lower = name.lower()
        if "ntfs" in name_lower:
            return "NTFS"
        elif "fat" in name_lower:
            return "FAT"
        elif "ext" in name_lower:
            return "EXT"
        elif "linux" in name_lower:
            return "Linux"
        elif "swap" in name_lower:
            return "Swap"
        elif "recovery" in name_lower:
            return "Recovery"
        elif "esp" in name_lower:
            return "EFI"
        elif "microsoft" in name_lower:
            return "Microsoft"
        return "Unknown"
    
    def export_json(self, partitions: List[Partition], output_path: Path) -> Path:
        """Export partition table to JSON"""
        import json
        data = [p.to_dict() for p in partitions]
        output_path.write_text(json.dumps(data, indent=2))
        return output_path
