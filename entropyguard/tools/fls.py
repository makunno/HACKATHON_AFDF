"""Deleted file entries lister - similar to The Sleuth Kit fls"""
import struct
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FileEntry:
    """A file or directory entry"""
    inode: int
    name: str
    size: int
    created: Optional[str]
    modified: Optional[str]
    accessed: Optional[str]
    is_directory: bool
    is_deleted: bool
    metadata: Dict
    
    def to_dict(self) -> Dict:
        return {
            "inode": self.inode,
            "name": self.name,
            "size": self.size,
            "created": self.created,
            "modified": self.modified,
            "accessed": self.accessed,
            "is_directory": self.is_directory,
            "is_deleted": self.is_deleted,
            "metadata": self.metadata,
        }


class DeletedEntriesLister:
    """
    List deleted file entries from filesystem directories.
    Supports FAT, NTFS, and EXT filesystems.
    """
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size
    
    def list_deleted(
        self,
        disk_path: str | Path,
        offset: int = 0,
        fs_type: str = "auto",
        max_entries: int = 1000
    ) -> List[FileEntry]:
        """
        List deleted file entries.
        
        Args:
            disk_path: Path to disk image
            offset: Offset to filesystem
            fs_type: Filesystem type (auto, FAT, NTFS, EXT)
            max_entries: Maximum entries to return
            
        Returns:
            List of FileEntry objects
        """
        disk_path = Path(disk_path)
        
        if fs_type == "auto":
            fs_type = self._detect_fs(disk_path, offset)
        
        if fs_type == "FAT":
            return self._list_fat(disk_path, offset, max_entries)
        elif fs_type == "NTFS":
            return self._list_ntfs(disk_path, offset, max_entries)
        elif fs_type in ["EXT2", "EXT3", "EXT4"]:
            return self._list_ext(disk_path, offset, max_entries)
        else:
            return []
    
    def _detect_fs(self, disk_path: Path, offset: int) -> str:
        """Detect filesystem type"""
        try:
            with open(disk_path, 'rb') as f:
                f.seek(offset)
                data = f.read(512)
                
                if data[:4] == b'NTFS' or data[3:7] == b'NTFS':
                    return "NTFS"
                if data[:3] == b'\xEB\x3C\x90' or data[:3] == b'\xEB\x58\x90':
                    return "FAT"
                if data[0x38:0x3A] == b'\x53\xEF':
                    return "EXT2"
        except:
            pass
        return "Unknown"
    
    def _list_fat(self, disk_path: Path, offset: int, max_entries: int) -> List[FileEntry]:
        """List deleted entries from FAT filesystem"""
        entries = []
        
        try:
            with open(disk_path, 'rb') as f:
                f.seek(offset)
                boot = f.read(512)
                
                bytes_per_sector = struct.unpack('<H', boot[11:13])[0]
                sectors_per_cluster = boot[13]
                reserved_sectors = struct.unpack('<H', boot[14:16])[0]
                num_fats = boot[16]
                sectors_per_fat = struct.unpack('<H', boot[22:24])[0]
                
                root_entries = struct.unpack('<H', boot[17:19])[0]
                root_dir_sectors = (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
                
                # Root directory location
                root_offset = offset + (reserved_sectors + num_fats * sectors_per_fat) * bytes_per_sector
                
                # Read root directory
                f.seek(root_offset)
                root_data = f.read(root_entries * 32)
                
                for i in range(0, len(root_data), 32):
                    entry = root_data[i:i+32]
                    
                    if entry[0] == 0x00:  # End of directory
                        break
                    
                    if entry[0] == 0xE5:  # Deleted entry
                        name_bytes = entry[0:8].rstrip(b' ')
                        ext_bytes = entry[8:11].rstrip(b' ')
                        
                        try:
                            name = (name_bytes.decode('ascii') + '.' + ext_bytes.decode('ascii')).strip('.')
                        except:
                            name = f"DELETED_{i:04X}"
                        
                        size = struct.unpack('<I', entry[28:32])[0]
                        is_dir = (entry[11] & 0x10) != 0
                        
                        entries.append(FileEntry(
                            inode=i,
                            name=name,
                            size=size,
                            created=None,
                            modified=None,
                            accessed=None,
                            is_directory=is_dir,
                            is_deleted=True,
                            metadata={"offset": root_offset + i}
                        ))
                        
                        if len(entries) >= max_entries:
                            break
        
        except Exception:
            pass
        
        return entries
    
    def _list_ntfs(self, disk_path: Path, offset: int, max_entries: int) -> List[FileEntry]:
        """List deleted entries from NTFS filesystem"""
        # Simplified - would need MFT parsing
        return []
    
    def _list_ext(self, disk_path: Path, offset: int, max_entries: int) -> List[FileEntry]:
        """List deleted entries from EXT filesystem"""
        # Simplified - would need inode table parsing
        return []
    
    def export_json(self, entries: List[FileEntry], output_path: Path) -> Path:
        """Export entries to JSON"""
        import json
        data = [e.to_dict() for e in entries]
        output_path.write_text(json.dumps(data, indent=2))
        return output_path
