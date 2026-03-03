"""API routes for EntropyGuard"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, Dict, List
from pathlib import Path
import uuid
import json
import threading

from entropyguard.pipeline.scanner import EntropyScanner, ScanConfig
from entropyguard.forensics.reporter import ForensicReporter
from entropyguard.tools.mmls import PartitionMapper
from entropyguard.tools.fsstat import FilesystemAnalyzer
from entropyguard.tools.bulk_extractor import BulkExtractor

router = APIRouter()

# In-memory scan storage
scans: Dict[str, dict] = {}
scan_threads: Dict[str, threading.Thread] = {}


class ScanRequest(BaseModel):
    disk_path: str
    block_size: Optional[int] = 4096
    methods: Optional[List[str]] = None
    num_workers: Optional[int] = 4


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@router.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new disk scan"""
    scan_id = str(uuid.uuid4())[:8]
    
    config = ScanConfig(
        block_size=request.block_size,
        num_workers=request.num_workers,
        methods=request.methods or ["zscore", "isolation_forest"]
    )
    
    scans[scan_id] = {
        "status": "pending",
        "config": config.__dict__,
        "disk_path": request.disk_path,
    }
    
    def run_scan():
        try:
            scanner = EntropyScanner(config=config)
            result = scanner.scan(request.disk_path)
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["result"] = result.to_dict()
        except Exception as e:
            scans[scan_id]["status"] = "failed"
            scans[scan_id]["error"] = str(e)
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    scan_threads[scan_id] = thread
    
    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Scan started for {request.disk_path}"
    )


@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scans[scan_id]


@router.get("/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get scan results"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans[scan_id]
    if scan["status"] != "completed":
        return {"status": scan["status"], "message": "Scan not yet completed"}
    
    return scan["result"]


@router.post("/mmls")
async def run_mmls(disk_path: str):
    """Run partition map analysis"""
    mapper = PartitionMapper()
    partitions = mapper.analyze(disk_path)
    return {"partitions": [p.to_dict() for p in partitions]}


@router.post("/fsstat")
async def run_fsstat(disk_path: str, offset: int = 0):
    """Run filesystem analysis"""
    analyzer = FilesystemAnalyzer()
    fs_info = analyzer.analyze(disk_path, offset)
    return fs_info.to_dict()


@router.post("/bulk_extract")
async def run_bulk_extract(disk_path: str, max_size: int = 10*1024*1024):
    """Run bulk artifact extraction"""
    extractor = BulkExtractor()
    result = extractor.extract(disk_path, max_scan_size=max_size)
    return result.to_dict()
