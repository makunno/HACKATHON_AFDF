"""CLI commands for EntropyGuard"""
import click
import logging
from pathlib import Path
from typing import Optional
import json
import sys

from entropyguard.pipeline.scanner import EntropyScanner, ScanConfig
from entropyguard.forensics.reporter import ForensicReporter
from entropyguard.visualization.heatmap import HeatmapGenerator
from entropyguard.visualization.html_map import HTMLMapGenerator
from entropyguard.tools.mmls import PartitionMapper
from entropyguard.tools.fsstat import FilesystemAnalyzer
from entropyguard.tools.fls import DeletedEntriesLister
from entropyguard.tools.bulk_extractor import BulkExtractor, validate_file_type, detect_embedded_filesystem
from entropyguard.models.trainer import ModelTrainer
from entropyguard.analysis.wipe_scan import run_wipe_scan, calculate_wipe_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """EntropyGuard - AI-Powered Hidden Volume & High-Entropy Region Detector"""
    pass


@cli.command()
@click.argument("disk_path", type=click.Path(exists=True))
@click.option("--block-size", default=4096, help="Block size in bytes (default: 4096)")
@click.option("--output", "-o", default="output", help="Output directory")
@click.option("--methods", default="zscore,isolation_forest", help="Detection methods (comma-separated: zscore,isolation_forest,lof,autoencoder)")
@click.option("--workers", default=8, help="Number of worker processes (default: 8)")
@click.option("--visualize/--no-visualize", default=True, help="Generate visualizations")
@click.option("--reports/--no-reports", default=True, help="Generate reports")
def scan(
    disk_path: str,
    block_size: int,
    output: str,
    methods: str,
    workers: int,
    visualize: bool,
    reports: bool
):
    """Scan a disk image for hidden volumes and high-entropy regions"""
    
    disk_path = Path(disk_path)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Scanning {disk_path}")
    logger.info(f"Block size: {block_size}, Workers: {workers}")
    
    # Configure scanner
    config = ScanConfig(
        block_size=block_size,
        num_workers=workers,
        methods=methods.split(",")
    )
    
    scanner = EntropyScanner(config=config)
    
    # File validation and filesystem detection
    click.echo("\n=== File Validation ===")
    validation_result = validate_file_type(disk_path)
    click.echo(f"File Type: {validation_result.file_type}")
    click.echo(f"Magic Bytes: {validation_result.magic_bytes}")
    click.echo(f"Validation: {validation_result.validation_message}")
    click.echo(f"MD5: {validation_result.md5_hash}")
    click.echo(f"SHA256: {validation_result.sha256_hash}")
    
    fs_result = detect_embedded_filesystem(disk_path)
    click.echo(f"Filesystem: {fs_result.get('filesystem_type', 'Unknown')}")
    
    # Progress callback
    def progress_callback(pct: int, message: str):
        click.echo(f"[{pct}%] {message}")
    
    # Run scan
    result = scanner.scan(
        disk_path=disk_path,
        output_path=output_path,
        progress_callback=progress_callback
    )
    
    click.echo(f"\nScan complete: {result.scan_id}")
    click.echo(f"Total blocks: {result.total_blocks}")
    click.echo(f"Anomalous blocks: {result.anomalous_blocks}")
    click.echo(f"Suspicious regions: {len(result.suspicious_regions)}")
    
    # Run wipe pattern detection on unallocated space
    click.echo("\n=== Wipe Pattern Detection ===")
    try:
        mapper = PartitionMapper()
        partitions = mapper.analyze(disk_path)
        
        # Get primary filesystem start sector (largest partition)
        if partitions:
            primary_partition = max(partitions, key=lambda p: p.size)
            start_sector = primary_partition.start_offset // 512
            
            click.echo(f"Primary partition start sector: {start_sector}")
            
            # Run wipe scan
            wipe_output_dir = output_path / "wipe_scan"
            wipe_result = run_wipe_scan(str(disk_path), start_sector, str(wipe_output_dir))
            
            # Add wipe metrics to result
            result_dict = result.to_dict()
            
            # Add file validation and filesystem detection
            result_dict["file_validation"] = validation_result.to_dict()
            result_dict["filesystem_detection"] = fs_result
            
            result_dict["wipe_metrics"] = wipe_result
            
            # Calculate and add wipe score
            wipe_score, wipe_details = calculate_wipe_score(wipe_result)
            result_dict["wipe_score"] = wipe_score
            result_dict["wipe_score_details"] = wipe_details
            
            click.echo(f"Wipe scan: {wipe_result.get('metrics', {}).get('wipe_suspect_chunk_count', 0)} suspicious chunks")
            click.echo(f"Wipe score: {wipe_score}/35")
            
            # Update result for reporting
            result_for_report = result_dict
        else:
            click.echo("No partitions found, skipping wipe scan")
            result_for_report = result.to_dict()
            result_for_report["wipe_metrics"] = None
            result_for_report["wipe_score"] = 0
            
    except Exception as e:
        click.echo(f"Wipe scan error (non-fatal): {e}")
        result_for_report = result.to_dict()
        result_for_report["wipe_metrics"] = {"error": str(e)}
        result_for_report["wipe_score"] = 0
    
    # Ensure file validation is in result for report (for branches that skip wipe scan)
    if "file_validation" not in result_for_report:
        result_for_report["file_validation"] = validation_result.to_dict()
        result_for_report["filesystem_detection"] = fs_result
    
    # Generate reports
    if reports:
        reporter = ForensicReporter(output_path)
        paths = reporter.save_all_reports(result_for_report)
        click.echo(f"\nReports saved to {output_path}")
    
    # Generate visualizations
    if visualize:
        try:
            heatmap = HeatmapGenerator()
            heatmap_path = output_path / f"heatmap_{result.scan_id}.png"
            heatmap.generate_entropy_heatmap(
                result.block_results,
                heatmap_path
            )
            click.echo(f"Heatmap: {heatmap_path}")
            
            # HTML map
            html_gen = HTMLMapGenerator()
            html_path = output_path / f"map_{result.scan_id}.html"
            html_gen.generate(
                result.block_results,
                result.suspicious_regions,
                html_path
            )
            click.echo(f"Interactive map: {html_path}")
        except Exception as e:
            click.echo(f"Visualization error: {e}")


@cli.command()
@click.argument("disk_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="output", help="Output directory")
@click.option("--type", "analysis_type", default="all",
              type=click.Choice(["all", "mmls", "fsstat", "fls", "bulk"]))
def analyze(disk_path: str, output: str, analysis_type: str):
    """Run forensics analysis tools on disk image"""
    
    disk_path = Path(disk_path)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    if analysis_type in ["all", "mmls"]:
        click.echo("\n=== Partition Map (mmls) ===")
        mapper = PartitionMapper()
        partitions = mapper.analyze(disk_path)
        for p in partitions:
            click.echo(f"  Slot {p.slot}: {p.description}")
            click.echo(f"    Offset: 0x{p.start_offset:X} - 0x{p.end_offset:X}")
            click.echo(f"    Size: {p.size:,} bytes")
        
        mapper.export_json(partitions, output_path / "partitions.json")
    
    if analysis_type in ["all", "fsstat"]:
        click.echo("\n=== Filesystem Analysis (fsstat) ===")
        analyzer = FilesystemAnalyzer()
        fs_info = analyzer.analyze(disk_path)
        click.echo(f"  Filesystem: {fs_info.filesystem_type}")
        click.echo(f"  Block size: {fs_info.block_size}")
        click.echo(f"  Total blocks: {fs_info.total_blocks}")
    
    if analysis_type in ["all", "fls"]:
        click.echo("\n=== Deleted Entries (fls) ===")
        lister = DeletedEntriesLister()
        entries = lister.list_deleted(disk_path)
        click.echo(f"  Found {len(entries)} deleted entries")
        for e in entries[:10]:
            click.echo(f"    {e.name} ({e.size} bytes)")
    
    if analysis_type in ["all", "bulk"]:
        click.echo("\n=== Bulk Extractor ===")
        extractor = BulkExtractor()
        result = extractor.extract(disk_path, max_scan_size=10*1024*1024)
        click.echo(f"  Total artifacts: {result.statistics.get('total_artifacts', 0)}")
        for ptype, count in result.statistics.items():
            if count > 0 and ptype != "total_artifacts":
                click.echo(f"    {ptype}: {count}")


@cli.command()
@click.argument("disk_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="models", help="Models directory")
@click.option("--epochs", default=50, help="Autoencoder epochs")
def train(disk_path: str, output: str, epochs: int):
    """Train ML models on a clean disk image"""
    
    disk_path = Path(disk_path)
    models_dir = Path(output)
    
    click.echo("Extracting features from disk...")
    
    from entropyguard.core.disk_reader import DiskReader
    from entropyguard.core.entropy import extract_all_features
    
    features = []
    with DiskReader(disk_path, block_size=4096) as reader:
        for block in reader.read_all_blocks():
            feat = extract_all_features(block.data, block.offset)
            features.append(feat.to_dict())
    
    click.echo(f"Extracted {len(features)} block features")
    
    click.echo("Training models...")
    trainer = ModelTrainer(models_dir)
    results = trainer.train_all(features, autoencoder_epochs=epochs)
    
    click.echo("Models trained:")
    for name, path in results.items():
        click.echo(f"  {name}: {path}")


@cli.command()
@click.argument("disk_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="output", help="Output directory")
def exif(disk_path: str, output: str):
    """Extract EXIF metadata from image files in disk"""
    
    from entropyguard.forensics.exif_extractor import EXIFExtractor
    
    click.echo("Scanning for image files...")
    
    extractor = EXIFExtractor()
    # Note: This would need file carving first
    click.echo("Note: EXIF extraction requires file carving first")


@cli.command()
@click.argument("disk_path", type=click.Path(exists=True))
@click.option("--output", "-o", default="output", help="Output directory")
@click.option("--examiner-name", prompt=True, help="Examiner full name")
@click.option("--examiner-title", prompt=True, help="Examiner title/role")
@click.option("--examiner-org", prompt=True, help="Examiner organization")
@click.option("--examiner-qual", help="Examiner qualifications (comma-separated)")
@click.option("--case-number", prompt=True, help="Case number")
@click.option("--case-name", help="Case name")
@click.option("--legal-authority", help="Legal authority for examination")
@click.option("--exhibit-number", help="Evidence exhibit number")
@click.option("--acq-tool", prompt=True, help="Acquisition tool used")
@click.option("--acq-method", prompt=True, help="Acquisition method")
@click.option("--write-blocker", help="Write blocker used")
@click.option("--hash-sha256", help="Original evidence SHA-256 hash")
@click.option("--hash-md5", help="Original evidence MD5 hash")
@click.option("--acq-date", help="Acquisition date (ISO format)")
@click.option("--source-device", help="Original device description")
def court_report(
    disk_path: str,
    output: str,
    examiner_name: str,
    examiner_title: str,
    examiner_org: str,
    examiner_qual: str,
    case_number: str,
    case_name: str,
    legal_authority: str,
    exhibit_number: str,
    acq_tool: str,
    acq_method: str,
    write_blocker: str,
    hash_sha256: str,
    hash_md5: str,
    acq_date: str,
    source_device: str
):
    """Generate a court-admissible forensic report"""
    
    from entropyguard.forensics.reporter import ForensicReporter
    from datetime import datetime
    
    disk_path = Path(disk_path)
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    click.echo("\n" + "="*60)
    click.echo("  COURT-ADMISSIBLE FORENSIC REPORT GENERATOR")
    click.echo("="*60 + "\n")
    
    # Parse qualifications
    qualifications = []
    if examiner_qual:
        qualifications = [q.strip() for q in examiner_qual.split(",")]
    
    # Build examiner info
    examiner_info = {
        "name": examiner_name,
        "title": examiner_title,
        "organization": examiner_org,
        "qualifications": qualifications
    }
    
    # Build case info
    case_info = {
        "case_number": case_number,
        "case_name": case_name,
        "legal_authority": legal_authority,
        "exhibit_number": exhibit_number
    }
    
    # Build acquisition details
    acquisition_details = {
        "acquisition_tool": acq_tool,
        "acquisition_method": acq_method,
        "write_blocker": write_blocker or None,
        "original_hash_sha256": hash_sha256 or None,
        "original_hash_md5": hash_md5 or None,
        "acquisition_date": acq_date or datetime.now().isoformat(),
        "source_device": source_device or None
    }
    
    click.echo("Running forensic analysis...")
    
    # Run the scan
    config = ScanConfig(block_size=4096, num_workers=4, methods=["zscore"])
    scanner = EntropyScanner(config=config)
    
    result = scanner.scan(
        disk_path=disk_path,
        output_path=output_path,
        progress_callback=lambda p, m: click.echo(f"[{p}] {m}")
    )
    
    click.echo("\nGenerating court-admissible report...")
    
    # Generate court report
    reporter = ForensicReporter(output_path)
    report_path = reporter.generate_court_report(
        scan_result=result.to_dict(),
        examiner_info=examiner_info,
        case_info=case_info,
        acquisition_details=acquisition_details,
        forensics_result=None
    )
    
    if report_path:
        click.echo(f"\nCourt-admissible report saved to: {report_path}")
        click.echo("\nReport includes:")
        click.echo("  1. Examiner information and qualifications")
        click.echo("  2. Case identifier and legal authority")
        click.echo("  3. Evidence acquisition details")
        click.echo("  4. Chain of custody log")
        click.echo("  5. Forensic environment details")
        click.echo("  6. Evidence integrity verification")
        click.echo("  7. Detailed methodology")
        click.echo("  8. Filesystem and partition overview")
        click.echo("  9. Artifact-based findings")
        click.echo("  10. Timeline reconstruction")
        click.echo("  11. Anti-forensic technique analysis")
        click.echo("  12. Machine learning output")
        click.echo("  13. Correlation findings")
        click.echo("  14. Limitations and error rates")
        click.echo("  15. Conclusion")
        click.echo("  16. Examiner declaration")
    else:
        click.echo("Error: Could not generate court report (missing pydantic?)")



if __name__ == "__main__":
    cli()
