# AFDF - Anti-Forensic Detection Framework

## Technical Methodology Document

**Version: 2.0.0**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Architecture](#2-system-architecture)
3. [Analysis Pipeline](#3-analysis-pipeline)
4. [Feature Extraction Methods](#4-feature-extraction-methods)
5. [Machine Learning Components](#5-machine-learning-components)
6. [Wipe Pattern Detection](#6-wipe-pattern-detection)
7. [Forensics Tools Integration](#7-forensics-tools-integration)
8. [File Validation and Hashing](#8-file-validation-and-hashing)
9. [Filesystem Detection](#9-filesystem-detection)
10. [Report Generation](#10-report-generation)
11. [API Specification](#11-api-specification)
12. [Supported Formats](#12-supported-formats)
13. [Limitations and Considerations](#13-limitations-and-considerations)
14. [Security Considerations](#14-security-considerations)

---

## 1. Introduction

AFDF (Anti-Forensic Detection Framework) is a comprehensive digital forensics platform designed to detect various anti-forensic techniques in disk images. This document provides detailed technical methodology for forensic analysts, investigators, and developers.

### Purpose

The framework addresses four primary forensic challenges:

1. **Hidden Volume Detection**: Identifying encrypted containers and hidden volumes within disk images
2. **Wipe Pattern Recognition**: Detecting evidence of secure deletion attempts in allocated AND unallocated space
3. **Evidence Integrity Verification**: Ensuring the analyzed evidence matches original acquisition hashes
4. **Anti-Forensic Tool Detection**: Identifying use of tools like DBAN, SDelete, BleachBit

### Scope

AFDF is designed for:
- Law enforcement digital forensics
- Corporate incident response
- Academic research in digital forensics
- Security auditing and penetration testing

---

## 2. System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (Port 5173/8080)                           │
│  ┌──────────┐    ┌───────────┐    ┌────────────┐    ┌─────────────┐      │
│  │  Upload  │───▶│ Analysis  │───▶│ Dashboard  │───▶│ Report Page │      │
│  │   Page   │    │   View    │    │   View     │    │  (22 sec)   │      │
│  └──────────┘    └───────────┘    └────────────┘    └─────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP/HTTPS
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     NODE.JS EXPRESS SERVER (Port 3001)                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                    API ENDPOINTS                                 │       │
│  │  POST /api/analyze  -  Upload & orchestrate full analysis      │       │
│  │  GET  /api/result/:id -  Retrieve analysis results             │       │
│  │  GET  /api/health   -  Server health check                      │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐            │
│         │                          │                          │             │
│         ▼                          ▼                          ▼             │
│  ┌─────────────┐          ┌──────────────┐          ┌───────────┐         │
│  │   Python   │          │   Rust      │          │   ML API  │         │
│  │   Entropy  │          │  Analyzer   │          │  (Port    │         │
│  │   Scanner  │          │  (Fast)     │          │   3002)   │         │
│  └─────────────┘          └──────────────┘          └───────────┘         │
│         │                          │                          │             │
│         └──────────────────────────┼──────────────────────────┘             │
│                                    │                                        │
│                                    ▼                                        │
│                      ┌────────────────────────────┐                        │
│                      │   Results Aggregation       │                        │
│                      │   & Report Generation      │                        │
│                      └────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | React + TypeScript | User interface, visualization |
| API Server | Node.js + Express | Request handling, orchestration |
| Entropy Scanner | Python (NumPy) | Statistical analysis of disk blocks |
| Wipe Detector | Python | Pattern recognition in unallocated space |
| Rust Analyzer | Rust | Fast file signature, anti-forensic tool detection |
| ML API | Python (scikit-learn) | Ensemble classification (RF + Isolation Forest) |
| Forensics | Python + The Sleuth Kit | Filesystem and artifact analysis |

### Data Flow

1. **Upload** → Server validates file, calculates hashes
2. **Python Analysis** → Entropy scan, wipe detection in unallocated space
3. **Rust Analysis** → Fast signature detection, anti-forensic tool detection
4. **Feature Extraction** → Combine features from all sources
5. **ML Classification** → Ensemble RF + Isolation Forest prediction
6. **Report** → Generate 22-section court-admissible report

---

## 3. Analysis Pipeline

### Complete Analysis Flow

```
┌────────────────────────────────────────────────────────────────────┐
│ STEP 1: FILE UPLOAD AND VALIDATION                                │
│                                                                     │
│  1.1 User uploads disk image via web interface                    │
│  1.2 Server calculates MD5, SHA1, and SHA-256 hashes            │
│  1.3 Magic bytes analysis for file type detection                 │
│  1.4 Filesystem signature detection                               │
│  1.5 Generate unique analysis ID                                  │
│  1.6 Store in unique results directory                            │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 2: PYTHON ENTROPY SCANNING                                  │
│                                                                     │
│  2.1 Read disk image in 4KB blocks                                │
│  2.2 For each block calculate:                                     │
│      - Shannon entropy                                             │
│      - Chi-square distribution                                    │
│      - Mean byte value                                            │
│      - Serial correlation                                         │
│      - Null byte ratio                                            │
│  2.3 Identify high-entropy regions (>7.5)                        │
│  2.4 Cluster adjacent anomalous blocks into regions             │
│  2.5 Save results to unique output directory                     │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 3: WIPE PATTERN DETECTION (Unallocated Space)                │
│                                                                     │
│  3.1 Extract unallocated space using blkls                        │
│  3.2 Divide into 1MB chunks                                       │
│  3.3 For each chunk classify as:                                   │
│      - ZERO_FILL (0x00 ratio ≥ 0.98)                             │
│      - FF_FILL (0xFF ratio ≥ 0.98)                                │
│      - RANDOM_LIKE (entropy ≥ 7.6)                                │
│      - DOD_PATTERN (specific 3-pass pattern)                       │
│      - GUTMANN_PATTERN (35-pass pattern)                          │
│      - NORMAL                                                      │
│  3.4 Merge adjacent suspicious chunks into regions                │
│  3.5 Calculate metrics:                                           │
│      - Total bytes wiped by each method                           │
│      - Percentage of suspicious space                              │
│      - Wipe score (0-1)                                           │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 4: RUST ANALYZER (Fast Analysis)                            │
│                                                                     │
│  4.1 Read entire file into memory                                  │
│  4.2 File signature detection (NTFS, FAT, ext, etc.)              │
│  4.3 Anti-forensic tool detection:                                 │
│      - DBAN signatures                                            │
│      - SDelete signatures                                          │
│      - BleachBit signatures                                        │
│  4.4 Timestamp anomaly detection                                   │
│  4.5 Hidden data detection in slack space                         │
│  4.6 Repeating pattern analysis                                    │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 5: FORENSICS TOOLS EXECUTION                                 │
│                                                                     │
│  5.1 mmls - Partition table parsing                               │
│      - Detect MBR and GPT partition tables                        │
│      - Extract partition boundaries                                │
│      - Identify partition types                                    │
│                                                                     │
│  5.2 fsstat - Filesystem metadata analysis                        │
│      - Determine filesystem type                                   │
│      - Extract cluster/block size                                  │
│      - Get total sectors and free space                            │
│                                                                     │
│  5.3 fls - Deleted file entry listing                             │
│      - Extract metadata entries                                    │
│      - Identify deleted file names                                  │
│      - Recover timestamps                                          │
│                                                                     │
│  5.4 bulk_extractor - Artifact scanning                          │
│      - Extract email addresses                                    │
│      - Find URLs and web links                                     │
│      - Identify IP addresses                                       │
│      - Detect phone numbers                                        │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 6: MACHINE LEARNING CLASSIFICATION (Ensemble)                │
│                                                                     │
│  6.1 Feature extraction (18 features):                            │
│      - Basic: entropy, null_ratio, repeating_chunks               │
│      - Anomaly: timestamp_anomalies, has_wiping                   │
│      - Security: has_anti_forensic_tool, has_hidden_data         │
│      - Classification: high_entropy, unknown_filesystem           │
│      - Size: file_size, sector_alignment                          │
│      - Unallocated: unallocated_space_bytes, suspicious_regions   │
│      - Wipe: zero_filled_regions, random_filled_regions          │
│      - Files: deleted_file_entries, wipe_pattern_score            │
│                                                                     │
│  6.2 Random Forest classification:                                 │
│      - AUTHENTIC: Normal disk appearance                          │
│      - QUESTIONABLE: Some anomalies detected                      │
│      - TAMPERED: Strong indicators of manipulation                │
│                                                                     │
│  6.3 Isolation Forest anomaly detection                           │
│                                                                     │
│  6.4 Ensemble voting (60% RF, 40% IF)                             │
│                                                                     │
│  6.5 Confidence scoring                                            │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│ STEP 7: REPORT GENERATION                                          │
│                                                                     │
│  7.1 Compile all analysis results                                  │
│  7.2 Generate findings and correlations                           │
│  7.3 Calculate integrity score                                    │
│  7.4 Format 22-section court-admissible report                   │
│  7.5 Include limitations and declarations                         │
└────────────────────────────────────────────────────────────────────┘
```

---

## 4. Feature Extraction Methods

### 4.1 Shannon Entropy

**Formula**: H(X) = -Σ P(xᵢ) × log₂(P(xᵢ))

**Implementation**:
```python
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    
    return entropy
```

**Interpretation**:
| Entropy Range | Likely Content |
|---------------|----------------|
| 0.0 - 2.0 | Padding, zeros |
| 2.0 - 4.0 | Plain text, code |
| 4.0 - 6.0 | Mixed content |
| 6.0 - 7.0 | Compressed data |
| 7.0 - 8.0 | Encrypted/random data |

### 4.2 Chi-Square Test

**Purpose**: Detect deviations from uniform byte distribution

**Formula**: χ² = Σ (observed - expected)² / expected

**Interpretation**:
- Low chi-square (< 256): Uniform distribution (encrypted/compressed)
- High chi-square (> 256): Non-uniform distribution (text/structure)

### 4.3 Serial Correlation

**Purpose**: Measure byte-to-byte dependency

**Formula**: r = Σ(xᵢ - x̄)(xᵢ₊₁ - x̄) / Σ(xᵢ - x̄)²

**Interpretation**:
- High positive correlation: Structured data
- Near zero: Random/encrypted data

### 4.4 Byte Frequency Analysis

**Purpose**: Identify characteristic patterns

**Implementation**:
- Calculate frequency distribution for all 256 byte values
- Compare against known signatures
- Detect non-standard distributions

---

## 5. Machine Learning Components

### 5.1 Ensemble Architecture

AFDF uses an **ensemble approach** combining two models:

```
                    ┌─────────────────┐
                    │  Feature Input  │
                    │   (18 features) │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐
│ Random Forest   │  │ Isolation       │  │  Rule-Based  │
│ Classifier      │  │ Forest          │  │  Fallback    │
│ (100 trees)     │  │ (100 trees)     │  │              │
└────────┬────────┘  └────────┬────────┘  └──────────────┘
         │                   │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ Ensemble Voting │
                   │ RF: 60%         │
                   │ IF: 40%         │
                   └────────┬────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ Final Prediction│
                   │ AUTHENTIC /     │
                   │ QUESTIONABLE /  │
                   │ TAMPERED        │
                   └─────────────────┘
```

### 5.2 Input Features (18 Total)

| Feature | Type | Description | Source |
|---------|------|-------------|--------|
| entropy | float | Mean Shannon entropy (0-8) | Python |
| null_ratio | float | Ratio of zero bytes (0-1) | Python |
| repeating_chunks | int | Count of repeated patterns | Rust |
| timestamp_anomalies | int | Invalid timestamps detected | Rust |
| has_wiping | bool | Wipe patterns detected | Python |
| file_size | int | Total file size in bytes | Server |
| sector_alignment | bool | Size multiple of 512 | Server |
| has_anti_forensic_tool | bool | DBAN/SDelete/BleachBit | Rust |
| has_hidden_data | bool | Data in slack space | Rust |
| high_entropy | bool | Mean entropy > 7.5 | Python |
| unknown_filesystem | bool | No filesystem detected | Server |
| unallocated_space_bytes | int | Free space size | Python |
| suspicious_unallocated_regions | int | Anomalies in free space | Python |
| zero_filled_regions | int | Zero-wipe pattern count | Python |
| random_filled_regions | int | Random-wipe pattern count | Python |
| wipe_pattern_score | float | Overall wipe score (0-1) | Python |
| deleted_file_entries | int | Count of deleted files | Python |

### 5.3 Random Forest Classifier

**Model Configuration**:
- Number of trees: 100
- Max depth: 10
- Min samples split: 5
- Min samples leaf: 2
- Random state: 42

**Classification**:
- 0 = AUTHENTIC
- 1 = TAMPERED  
- 2 = QUESTIONABLE

### 5.4 Isolation Forest

**Model Configuration**:
- Number of trees: 100
- Contamination: 'auto'
- Random state: 42

**Output**:
- 1 = Normal (AUTHENTIC)
- -1 = Anomaly (TAMPERED)
- Anomaly score: 0-1 (higher = more anomalous)

### 5.5 Ensemble Combination

```python
# Weighted ensemble
rf_weight = 0.6
iso_weight = 0.4

# Score mapping
rf_score = {"AUTHENTIC": 0, "QUESTIONABLE": 1, "TAMPERED": 2}
iso_score = {"AUTHENTIC": 0, "TAMPERED": 2}

ensemble_score = rf_weight * rf_score + iso_weight * iso_score

# Final prediction
if ensemble_score < 0.5: prediction = "AUTHENTIC"
elif ensemble_score < 1.5: prediction = "QUESTIONABLE"
else: prediction = "TAMPERED"
```

### 5.6 Classification Output

| Class | Description | Confidence Threshold |
|-------|-------------|---------------------|
| AUTHENTIC | No significant anomalies detected | > 0.7 |
| QUESTIONABLE | Some anomalies, unclear | 0.4 - 0.7 |
| TAMPERED | Strong indicators of manipulation | < 0.4 |

---

## 6. Wipe Pattern Detection

### 6.1 Detection Methods

| Method | Pattern | Detection Criteria |
|--------|---------|-------------------|
| ZERO_FILL | `00 00 00...` | 0x00 ratio ≥ 98% |
| FF_FILL | `FF FF FF...` | 0xFF ratio ≥ 98% |
| RANDOM_LIKE | Random bytes | Entropy ≥ 7.6 |
| DOD_5220 | 3-pass overwrite | Specific byte sequence |
| GUTMANN | 35-pass overwrite | Specific 35-pass pattern |

### 6.2 Unallocated Space Analysis

The key improvement in AFDF v2.0 is analyzing **unallocated space** (free disk space):

```
Disk Structure:
┌─────────────────────────────────────────────┐
│           ALLOCATED SPACE                   │
│  (Active files, filesystem metadata)       │
├─────────────────────────────────────────────┤
│         UNALLOCATED (FREE) SPACE            │  ◄── Critical for forensics
│  - Previously deleted file data             │
│  - Potential wipe patterns                  │
│  - Hidden evidence traces                   │
└─────────────────────────────────────────────┘
```

**Why Unallocated Space Matters**:
1. Secure deletion tools primarily overwrite this space
2. Wipe patterns are most visible here
3. Hidden volumes may leave traces
4. Deleted but unrecoverable files leave evidence

### 6.3 Process Flow

```
Unallocated Space Extraction (blkls)
                │
                ▼
        Divide into 1MB chunks
                │
                ▼
    ┌───────────────────┐
    │  For each chunk:  │
    │  1. Count bytes  │
    │  2. Calculate    │
    │     entropy      │
    │  3. Match        │
    │     patterns     │
    └───────────────────┘
                │
                ▼
        Classify chunk type
                │
                ▼
    Merge adjacent suspicious
    chunks into regions
                │
                ▼
    Calculate wipe metrics
                │
                ▼
    Calculate overall wipe score
```

### 6.4 Output Metrics

- `wipe_zero_bytes_total`: Total bytes in zero-fill regions
- `wipe_ff_bytes_total`: Total bytes in FF-fill regions
- `wipe_randomlike_bytes_total`: Total bytes with random patterns
- `wipe_dod_bytes_total`: Total bytes with DoD pattern
- `wipe_gutmann_bytes_total`: Total bytes with Gutmann pattern
- `wipe_suspect_chunk_count`: Number of suspicious chunks
- `wipe_score`: Overall wipe score (0-1)

---

## 7. Forensics Tools Integration

### 7.1 The Sleuth Kit (TSK)

AFDF integrates industry-standard tools from The Sleuth Kit:

| Tool | Purpose | Output |
|------|---------|--------|
| mmls | Partition table parsing | Start/end offsets, types |
| fsstat | Filesystem metadata | FS type, cluster size, usage |
| fls | Deleted file entries | File names, metadata |
| blkls | Unallocated space | Raw byte data |
| icat | File content extraction | File data by inode |

### 7.2 Implementation

```python
# Example: Running mmls
import subprocess

def get_partitions(disk_path: str) -> List[dict]:
    result = subprocess.run(
        ['mmls', disk_path],
        capture_output=True,
        text=True
    )
    # Parse output into partition list
    return parse_mmls_output(result.stdout)
```

### 7.3 Output Parsing

Partitions are parsed into structured data:
```json
{
  "partitions": [
    {
      "slot": 0,
      "startOffset": 2048,
      "size": 102400000,
      "description": "NTFS/FAT32"
    }
  ]
}
```

---

## 8. File Validation and Hashing

### 8.1 Hash Calculation

Upon file upload, the server calculates cryptographic hashes:

```python
import hashlib

def calculate_hashes(file_path: str) -> dict:
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }
```

### 8.2 Magic Bytes Detection

File type is validated by reading the first bytes:

| Magic Bytes | File Type |
|-------------|-----------|
| `EVF\x09\x0D\x0A\xFF` | EnCase Evidence (E01) |
| `FF D8 FF` | JPEG Image |
| `89 50 4E 47` | PNG Image |
| `25 50 44 46` | PDF Document |
| `50 4B 03 04` | ZIP Archive |

### 8.3 Validation Result

```json
{
  "fileValidation": {
    "fileType": "E01",
    "fileTypeName": "EnCase Evidence File",
    "declaredExtension": ".E01",
    "magicBytes": "455646090d0aff00",
    "isValid": true,
    "validationMessage": "VALID (extension matches magic bytes)"
  }
}
```

---

## 9. Filesystem Detection

### 9.1 Detection Process

1. Check magic bytes at offset 0 (for raw images)
2. Search within container files (for E01, etc.)
3. Parse partition table for filesystem signatures
4. Extract filesystem metadata via fsstat

### 9.2 Filesystem Signatures

| Signature | Filesystem | Offset |
|-----------|------------|--------|
| `4E 54 53 53` | NTFS | 0x0 (boot sector) |
| `EB xx 90` | FAT12/FAT32 | 0x0 |
| `53 EF` | EXT2/3/4 | 0x38C |
| `45 58 46 41 54` | exFAT | 0x0 |
| `48 2B 04 00` | HFS+ | 0x0 |
| `41 50 46 53` | APFS | 0x0 |

### 9.3 Output

```json
{
  "filesystem": {
    "detected": true,
    "filesystemType": "FAT32",
    "name": "FAT32 Filesystem",
    "method": "Magic bytes analysis",
    "confidence": 95,
    "details": {
      "message": "FAT32 detected at offset 0x0",
      "magicBytes": "eb5890"
    }
  }
}
```

---

## 10. Report Generation

### 10.1 Report Structure

The court-admissible report contains **22 sections**:

1. **Examiner Information** - Name, title, organization, certifications
2. **Case Information** - Case number, legal authority, court case number
3. **Evidence Acquisition Details** - File name, size, acquisition tool
4. **File Integrity Verification** - MD5, SHA1, SHA256 hashes
5. **File Type Verification** - Magic bytes, extension validation
6. **Filesystem Identification** - Detected filesystem, cluster size
7. **Chain of Custody Log** - Timestamp, action, personnel
8. **Forensic Environment** - Analysis system, timezone, tools
9. **Evidence Integrity (Entropy)** - Mean/max entropy, anomalous blocks
10. **Filesystem Overview** - Partition details, cluster size
11. **Suspicious Regions Analysis** - Offset locations, sizes, entropy scores
12. **Artifact Findings** - File paths, timestamps, interpretations
13. **Timeline Reconstruction** - Event timeline, sources
14. **Deleted Files Analysis** - Deleted file entries
15. **Artifact Scan Results** - Emails, URLs, IPs found
16. **Wipe Detection Results** - Zero/FF/Random fill regions
17. **Anti-Forensic Technique Analysis** - Encryption, wipe patterns, tools
18. **Machine Learning Analysis** - Ensemble model, features, prediction
19. **Correlation Analysis** - ML-to-artifact correlation
20. **Unallocated Space Analysis** - Free space, suspicious regions
21. **Limitations** - Known limitations, false positive rates
22. **Declaration** - Examiner statement, signature

---

## 11. API Specification

### POST /api/analyze

**Purpose**: Upload and analyze a disk image

**Request**:
- Content-Type: multipart/form-data
- Body: Binary file data

**Response**:
```json
{
  "id": "uuid-string",
  "fileName": "disk.E01",
  "fileSize": 309818835,
  "analyzedAt": "2026-03-03T12:00:00.000Z",
  "hashes": {
    "md5": "4193cc3bc7111ddf8be7a00677f2a2f4",
    "sha1": "abc123...",
    "sha256": "6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5"
  },
  "fileValidation": {
    "fileType": "E01",
    "fileTypeName": "EnCase Evidence File",
    "magicBytes": "455646090d0aff00",
    "isValid": true
  },
  "filesystem": {
    "detected": true,
    "filesystemType": "FAT32"
  },
  "statistics": {
    "mean_entropy": 7.9223,
    "max_entropy": 7.9699,
    "anomalous_blocks": 513,
    "total_blocks": 75640
  },
  "suspicious_regions": [...],
  "wipeMetrics": {
    "zero_filled_blocks": 100,
    "random_filled_blocks": 50,
    "wipe_score": 0.75
  },
  "forensics": {
    "partitions": [...],
    "deletedFiles": [...],
    "artifacts": {...}
  },
  "mlAnalysis": {
    "modelName": "AFDF Ensemble (Random Forest + Isolation Forest) v2.0",
    "prediction": "TAMPERED",
    "confidence": 0.85,
    "tamperProbability": 0.82,
    "ensemble_details": {
      "random_forest": {...},
      "isolation_forest": {...}
    }
  }
}
```

### GET /api/result/:id

**Purpose**: Retrieve analysis results by ID

**Response**: Full analysis result JSON

### ML API Endpoints (Port 3002)

#### POST /analyze
**Purpose**: ML classification with ensemble

**Request**:
```json
{
  "entropy": 7.5,
  "null_ratio": 0.05,
  "repeating_chunks": 50,
  "timestamp_anomalies": 5,
  "has_wiping": true,
  "file_size": 31000000,
  "sector_alignment": true,
  "has_anti_forensic_tool": false,
  "has_hidden_data": false,
  "high_entropy": true,
  "unknown_filesystem": false,
  "unallocated_space_bytes": 5000000,
  "suspicious_unallocated_regions": 20,
  "zero_filled_regions": 10,
  "random_filled_regions": 5,
  "wipe_pattern_score": 0.75,
  "deleted_file_entries": 100
}
```

**Response**:
```json
{
  "model_name": "AFDF Ensemble (Random Forest + Isolation Forest) v2.0",
  "prediction": "TAMPERED",
  "confidence": 0.85,
  "tamper_probability": 0.82,
  "anomaly_score": 0.78,
  "accuracy": 0.923,
  "precision": 0.89,
  "recall": 0.91,
  "f1_score": 0.90,
  "ensemble_details": {
    "random_forest": {
      "prediction": "TAMPERED",
      "confidence": 0.88,
      "tamper_probability": 0.85
    },
    "isolation_forest": {
      "prediction": "TAMPERED",
      "anomaly_score": 0.72,
      "confidence": 0.80
    }
  }
}
```

---

## 12. Supported Formats

| Format | Extension | Support |
|--------|-----------|---------|
| Raw DD | .dd, .raw | Full |
| EnCase | .E01 | Full (compressed) |
| Logical Image | .img | Full |
| Split RAW | .001, .002 | Partial |
| AFF | .aff | Via external tools |

---

## 13. Limitations and Considerations

### Known Limitations

1. **Encrypted Volumes**: Cannot analyze contents of encrypted volumes without the decryption key

2. **Overwritten Data**: Cannot recover data that has been overwritten

3. **Steganography**: May not detect all steganographic techniques

4. **Time-Based Attacks**: Cannot detect time-based anti-forensic techniques

5. **Cloud Storage**: Limited analysis of cloud-synchronized data

6. **E01 Compression**: Some compressed E01 files may not fully decompress

### False Positive Considerations

- Compressed files may appear as encrypted
- Wipe patterns in swap files
- Normal high-entropy regions (graphics, archives)
- Large deleted file counts in active systems

### Recommendations

- Always verify findings manually
- Use multiple analysis methods
- Document chain of custody
- Cross-reference with other evidence

---

## 14. Security Considerations

### Evidence Handling

- All processing should occur on isolated systems
- Use write blockers during acquisition
- Maintain immutable backup of original evidence
- Document all access and handling

### Network Security

- AFDF can run completely offline
- No data is sent to external servers
- All analysis is local

### File Cleanup

- Temporary files are deleted after analysis
- Each analysis has unique output directory
- Server should be run in secure environment
- Clear results directory periodically

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| Entropy | Measure of data randomness |
| Disk Image | Exact copy of disk contents |
| Anti-Forensic | Techniques to hide evidence |
| Chain of Custody | Documented evidence handling |
| Magic Bytes | File type signature |
| Wipe Pattern | Secure deletion pattern |
| Hidden Volume | Encrypted container |
| Unallocated Space | Free disk space |
| Ensemble Learning | Combining multiple models |

---

## Appendix B: References

1. Carrier, B. (2005). "File System Forensic Analysis"
2. The Sleuth Kit Documentation: https://www.sleuthkit.org/
3. Carrier, B. & Spij, E. (2005). "Defining Digital Forensics"
4. NIST SP 800-86: Guide to Integrating Forensic Techniques
5. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). "Isolation Forest"

---

*Document Version: 2.0.0*
*Last Updated: 2026*
*AFDF - Anti-Forensic Detection Framework*
