"""EXIF metadata extraction from image files"""
import os
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class EXIFData:
    """EXIF metadata from an image file"""
    filename: str
    file_path: str
    file_size: int
    file_modified: str
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    date_taken: Optional[str] = None
    date_modified: Optional[str] = None
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    image_width: Optional[int] = None
    image_height: Optional[int] = None
    orientation: Optional[int] = None
    iso: Optional[int] = None
    aperture: Optional[str] = None
    shutter_speed: Optional[str] = None
    focal_length: Optional[str] = None
    flash: Optional[str] = None
    software: Optional[str] = None
    copyright: Optional[str] = None
    artist: Optional[str] = None
    description: Optional[str] = None
    raw_tags: Dict = None
    
    def __post_init__(self):
        if self.raw_tags is None:
            self.raw_tags = {}
    
    def to_dict(self) -> Dict:
        return asdict(self)


class EXIFExtractor:
    """
    Extract EXIF metadata from image files.
    Supports JPEG, TIFF, PNG, and other formats.
    """
    
    def __init__(self):
        self._exif_lib = None
        self._load_library()
    
    def _load_library(self):
        """Try to load EXIF library"""
        try:
            from exif import Image
            self._exif_lib = "exif"
        except ImportError:
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS
                self._exif_lib = "PIL"
                self._pil_tags = TAGS
            except ImportError:
                self._exif_lib = None
    
    def extract(self, file_path: str | Path) -> Optional[EXIFData]:
        """
        Extract EXIF data from a single file.
        
        Args:
            file_path: Path to image file
            
        Returns:
            EXIFData object or None if extraction failed
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return None
        
        # Get basic file info
        stat = file_path.stat()
        
        exif_data = EXIFData(
            filename=file_path.name,
            file_path=str(file_path),
            file_size=stat.st_size,
            file_modified=datetime.fromtimestamp(stat.st_mtime).isoformat(),
        )
        
        if self._exif_lib is None:
            exif_data.raw_tags = {"error": "No EXIF library available"}
            return exif_data
        
        try:
            if self._exif_lib == "exif":
                return self._extract_with_exif(exif_data, file_path)
            elif self._exif_lib == "PIL":
                return self._extract_with_pil(exif_data, file_path)
        except Exception as e:
            exif_data.raw_tags = {"error": str(e)}
        
        return exif_data
    
    def _extract_with_exif(self, exif_data: EXIFData, file_path: Path) -> EXIFData:
        """Extract using exif library"""
        from exif import Image
        
        with open(file_path, 'rb') as f:
            image = Image(f)
            
            # Get all EXIF tags
            raw_tags = {}
            for tag, value in image.items():
                raw_tags[str(tag)] = str(value)
            exif_data.raw_tags = raw_tags
            
            # Extract common fields
            exif_data.camera_make = str(image.get("Image Make", ""))
            exif_data.camera_model = str(image.get("Image Model", ""))
            exif_data.software = str(image.get("Image Software", ""))
            exif_data.artist = str(image.get("Image Artist", ""))
            exif_data.copyright = str(image.get("Image Copyright", ""))
            exif_data.description = str(image.get("Image ImageDescription", ""))
            
            # Date/Time
            date_orig = image.get("EXIF DateTimeOriginal")
            if date_orig:
                exif_data.date_taken = str(date_orig)
            
            # Image dimensions
            width = image.get("EXIF ExifImageWidth")
            height = image.get("EXIF ExifImageLength")
            if width:
                exif_data.image_width = int(str(width))
            if height:
                exif_data.image_height = int(str(height))
            
            # GPS
            lat = image.get("GPS GPSLatitude")
            lat_ref = image.get("GPS GPSLatitudeRef")
            lon = image.get("GPS GPSLongitude")
            lon_ref = image.get("GPS GPSLongitudeRef")
            
            if lat and lat_ref and lon and lon_ref:
                try:
                    exif_data.gps_latitude = self._convert_gps(lat, lat_ref)
                    exif_data.gps_longitude = self._convert_gps(lon, lon_ref)
                except:
                    pass
        
        return exif_data
    
    def _extract_with_pil(self, exif_data: EXIFData, file_path: Path) -> EXIFData:
        """Extract using PIL"""
        from PIL import Image, ExifTags
        
        with Image.open(file_path) as img:
            # Get EXIF data
            exif = img.getexif()
            
            if exif:
                raw_tags = {}
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    raw_tags[str(tag)] = str(value)
                exif_data.raw_tags = raw_tags
                
                # Common tags
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, "")
                    
                    if tag == "Make":
                        exif_data.camera_make = str(value)
                    elif tag == "Model":
                        exif_data.camera_model = str(value)
                    elif tag == "Software":
                        exif_data.software = str(value)
                    elif tag == "Artist":
                        exif_data.artist = str(value)
                    elif tag == "Copyright":
                        exif_data.copyright = str(value)
                    elif tag == "ImageDescription":
                        exif_data.description = str(value)
                    elif tag == "DateTimeOriginal":
                        exif_data.date_taken = str(value)
                    elif tag == "DateTime":
                        exif_data.date_modified = str(value)
                
                # Image dimensions
                exif_data.image_width = img.width
                exif_data.image_height = img.height
            
            # GPS (in different location for PIL)
            gps_info = img.get("GPSInfo")
            if gps_info:
                for key, val in gps_info.items():
                    tag = ExifTags.GPSTAGS.get(key, key)
                    if tag == "Latitude":
                        exif_data.gps_latitude = val
                    elif tag == "Longitude":
                        exif_data.gps_longitude = val
        
        return exif_data
    
    def _convert_gps(self, coord, ref) -> float:
        """Convert GPS coordinates to decimal degrees"""
        degrees = float(coord[0])
        minutes = float(coord[1])
        seconds = float(coord[2])
        
        decimal = degrees + (minutes / 60) + (seconds / 3600)
        
        if str(ref) in ['S', 'W']:
            decimal = -decimal
        
        return decimal
    
    def extract_directory(
        self,
        directory: str | Path,
        extensions: List[str] = None
    ) -> List[EXIFData]:
        """
        Extract EXIF from all images in a directory.
        
        Args:
            directory: Directory to scan
            extensions: List of file extensions to process
            
        Returns:
            List of EXIFData objects
        """
        if extensions is None:
            extensions = ['.jpg', '.jpeg', '.tiff', '.tif', '.png', '.webp', '.heic', '.heif']
        
        directory = Path(directory)
        results = []
        
        for ext in extensions:
            for file_path in directory.glob(f"*{ext}"):
                exif_data = self.extract(file_path)
                if exif_data:
                    results.append(exif_data)
            
            # Case insensitive
            for file_path in directory.glob(f"*{ext.upper()}"):
                if file_path not in [r.file_path for r in results]:
                    exif_data = self.extract(file_path)
                    if exif_data:
                        results.append(exif_data)
        
        return results
    
    def extract_from_disk_image(
        self,
        disk_path: str | Path,
        max_files: int = 100
    ) -> List[EXIFData]:
        """
        Extract files from disk image and get EXIF.
        Note: This is a simplified version - real implementation
        would use sleuthkit or similar.
        
        Args:
            disk_path: Path to disk image
            max_files: Maximum number of files to extract
            
        Returns:
            List of EXIFData from extracted files
        """
        # This would require file carving - placeholder
        return []
    
    def export_json(self, exif_list: List[EXIFData], output_path: Path) -> Path:
        """Export EXIF data to JSON"""
        data = [e.to_dict() for e in exif_list]
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        
        return output_path
    
    def export_csv(self, exif_list: List[EXIFData], output_path: Path) -> Path:
        """Export EXIF data to CSV"""
        import csv
        
        if not exif_list:
            return output_path
        
        fieldnames = [
            "filename", "file_path", "file_size", "file_modified",
            "camera_make", "camera_model", "date_taken", "gps_latitude",
            "gps_longitude", "image_width", "image_height", "software"
        ]
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for exif in exif_list:
                row = {k: getattr(exif, k, None) for k in fieldnames}
                writer.writerow(row)
        
        return output_path
