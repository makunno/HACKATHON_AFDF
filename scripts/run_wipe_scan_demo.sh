#!/bin/bash
# Demo script for Wipe Pattern Detection
# 
# This script demonstrates the wipe pattern detection feature.
# Usage:
#   ./run_wipe_scan_demo.sh <image_path> <output_dir>
#
# Requirements:
#   - The Sleuth Kit (TSK) must be installed with blkls in PATH
#   - Python 3.8+ with entropyguard installed
#
# If no arguments provided, runs a demo with synthetic data.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "  Wipe Pattern Detection Demo"
echo "========================================"
echo ""

# Check for blkls
if ! command -v blkls &> /dev/null; then
    echo -e "${YELLOW}WARNING: blkls not found in PATH${NC}"
    echo "The Sleuth Kit (TSK) is required for wipe pattern detection."
    echo "Install with: apt-get install sleuthkit"
    echo ""
    echo "Will demonstrate with mock data instead..."
    echo ""
    
    # Run Python demo with mock data
    cd "$PROJECT_DIR"
    python3 -c "
import sys
sys.path.insert(0, '.')
from entropyguard.analysis.wipe_scan import run_wipe_scan, calculate_wipe_score
import json
import tempfile

# Create a small test file with wipe-like patterns
import os

with tempfile.TemporaryDirectory() as tmpdir:
    # Create a test image with wipe patterns
    test_image = os.path.join(tmpdir, 'test.img')
    with open(test_image, 'wb') as f:
        # 2MB of zeros (zero-fill)
        f.write(b'\x00' * (2 * 1024 * 1024))
        # 1MB of FF (FF-fill)
        f.write(b'\xff' * (1 * 1024 * 1024))
        # 1MB of random-like data
        import random
        f.write(bytes([random.randint(0, 255) for _ in range(1024 * 1024)]))
    
    # Run wipe scan (will fail without blkls but shows expected output)
    print('Expected wipe_scan output structure:')
    print(json.dumps({
        'image_path': test_image,
        'start_sector': 0,
        'unalloc_path': '<out_dir>/unalloc.bin',
        'unalloc_size_bytes': '<size>',
        'metrics': {
            'wipe_zero_bytes_total': 2097152,
            'wipe_ff_bytes_total': 1048576,
            'wipe_randomlike_bytes_total': 1048576,
            'wipe_suspect_chunk_count': 4,
            'scanned_bytes_total': 4194304
        },
        'regions': [
            {'start': 0, 'end': 2097152, 'type': 'ZERO_FILL', 'chunk_count': 2},
            {'start': 2097152, 'end': 3145728, 'type': 'FF_FILL', 'chunk_count': 1},
            {'start': 3145728, 'end': 4194304, 'type': 'RANDOM_LIKE', 'chunk_count': 1}
        ]
    }, indent=2))
    
    print('')
    print('Scoring thresholds:')
    print('  suspect_ratio > 0.30 => 35 points')
    print('  suspect_ratio > 0.10 => 20 points')
    print('  suspect_ratio > 0.03 => 10 points')
    print('  otherwise => 0 points')
    
    print('')
    print('For example:')
    print('  4MB scanned, 4MB suspect => ratio 1.0 => 35 points')
    print('  10MB scanned, 2MB suspect => ratio 0.2 => 20 points')
    print('  100MB scanned, 2MB suspect => ratio 0.02 => 0 points')
    
    # Test scoring
    test_metrics = {
        'metrics': {
            'wipe_zero_bytes_total': 2000000,
            'wipe_ff_bytes_total': 1000000,
            'wipe_randomlike_bytes_total': 500000,
            'scanned_bytes_total': 10000000
        }
    }
    score, details = calculate_wipe_score(test_metrics)
    print(f'')
    print(f'Test scoring:')
    print(f'  Zero: 2MB, FF: 1MB, Random: 0.5MB / 10MB scanned')
    print(f'  Suspect ratio: {details[\"suspect_ratio_percent\"]}%')
    print(f'  Score: {score}/35')
"

    echo ""
    echo -e "${GREEN}Demo complete!${NC}"
    exit 0
fi

# If blkls is available, run the full demo
IMAGE_PATH="${1:-test_disk.dd}"
OUTPUT_DIR="${2:-output/wipe_demo}"

echo "Image path: $IMAGE_PATH"
echo "Output dir: $OUTPUT_DIR"
echo ""

# Check if image exists
if [ ! -f "$IMAGE_PATH" ]; then
    echo -e "${RED}Error: Image file not found: $IMAGE_PATH${NC}"
    exit 1
fi

# Run wipe scan
echo -e "${GREEN}Running wipe pattern detection...${NC}"
echo ""

cd "$PROJECT_DIR"

python3 -c "
import sys
sys.path.insert(0, '.')
from entropyguard.analysis.wipe_scan import run_wipe_scan, calculate_wipe_score
from entropyguard.tools.mmls import PartitionMapper
import json
import os

# Get primary partition start sector
mapper = PartitionMapper()
partitions = mapper.analyze('$IMAGE_PATH')

if not partitions:
    print('No partitions found, using sector 0')
    start_sector = 0
else:
    # Get largest partition
    primary = max(partitions, key=lambda p: p.size)
    start_sector = primary.start_offset // 512
    print(f'Primary partition: slot {primary.slot}, start sector: {start_sector}')

# Run wipe scan
os.makedirs('$OUTPUT_DIR', exist_ok=True)
result = run_wipe_scan('$IMAGE_PATH', start_sector, '$OUTPUT_DIR')

print('')
print('Wipe Metrics:')
print(json.dumps(result, indent=2))

# Calculate score
score, details = calculate_wipe_score(result)
print('')
print(f'Wipe Score: {score}/35')
print(json.dumps(details, indent=2))

print('')
print(f'Results saved to: $OUTPUT_DIR/wipe_metrics.json')
print(f'Unallocated data saved to: $OUTPUT_DIR/unalloc.bin')
"

echo ""
echo -e "${GREEN}Wipe scan complete!${NC}"
