"""
Simple wrapper for EntropyGuard scan that accepts input via JSON file.
"""

import json
import sys
import os
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from entropyguard.pipeline.scanner import EntropyScanner, ScanConfig
from entropyguard.forensics.reporter import ForensicReporter
from entropyguard.tools.mmls import PartitionMapper
from entropyguard.analysis.wipe_scan import run_wipe_scan, calculate_wipe_score
from entropyguard.tools.bulk_extractor import validate_file_type, detect_embedded_filesystem


def run_scan_from_config(config_path: str):
    """Run scan from JSON config file."""
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    disk_path = config['disk_path']
    output_dir = config['output_dir']
    scan_id = config.get('scan_id', 'unknown')
    
    print(f"Scanning {disk_path}")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # File validation and filesystem detection
    print("Validating file type...")
    validation_result = validate_file_type(disk_path)
    file_validation = validation_result.to_dict()
    
    print("Detecting embedded filesystem...")
    fs_detection = detect_embedded_filesystem(disk_path)
    
    # Get partition info
    mapper = PartitionMapper()
    partitions = mapper.analyze(disk_path)
    
    start_sector = 0
    if partitions:
        primary_partition = max(partitions, key=lambda p: p.size)
        start_sector = primary_partition.start_offset // 512
    
    # Run entropy scan
    scan_config = ScanConfig(
        block_size=config.get('block_size', 4096),
        num_workers=config.get('num_workers', 4),
        methods=config.get('methods', ['zscore'])
    )
    
    scanner = EntropyScanner(config=scan_config)
    result = scanner.scan(
        disk_path=disk_path,
        output_path=output_path,
        progress_callback=lambda p, m: print(f"[{p}] {m}")
    )
    
    result_dict = result.to_dict()
    result_dict['scan_id'] = scan_id
    
    # Add file validation and filesystem detection
    result_dict['file_validation'] = file_validation
    result_dict['filesystem_detection'] = fs_detection
    
    # Run wipe scan
    try:
        wipe_output_dir = output_path / "wipe_scan"
        wipe_result = run_wipe_scan(disk_path, start_sector, str(wipe_output_dir))
        result_dict['wipe_metrics'] = wipe_result
        
        wipe_score, wipe_details = calculate_wipe_score(wipe_result)
        result_dict['wipe_score'] = wipe_score
    except Exception as e:
        print(f"Wipe scan error: {e}")
        result_dict['wipe_metrics'] = {'error': str(e)}
        result_dict['wipe_score'] = 0
    
    # Generate forensic report
    reporter = ForensicReporter(output_path)
    report_path = reporter.generate_json_report(result_dict)
    print(f"Report saved to {report_path}")
    
    # Generate court report if possible
    try:
        court_report_path = reporter.generate_court_report(
            scan_result=result_dict,
            examiner_info=config.get('examiner', {
                'name': 'Examiner',
                'title': 'Forensic Analyst',
                'organization': 'Lab',
                'qualifications': []
            }),
            case_info=config.get('case', {
                'case_number': config.get('case_id', 'UNKNOWN')
            }),
            acquisition_details=config.get('acquisition', {
                'acquisition_tool': 'Unknown',
                'acquisition_method': 'Unknown',
                'acquisition_date': 'Unknown'
            })
        )
        if court_report_path:
            print(f"Court report saved to {court_report_path}")
    except Exception as e:
        print(f"Court report error: {e}")
    
    return result_dict


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python run_scan.py <config.json>")
        sys.exit(1)
    
    run_scan_from_config(sys.argv[1])
