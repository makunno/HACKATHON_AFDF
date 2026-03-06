# AFDF - Anti-Forensic Detection Framework

## Complete Beginner's Guide

**Version: 2.0.0**

---

## Table of Contents

1. [What is AFDF?](#what-is-afdf)
2. [Why Does This Tool Exist?](#why-does-this-tool-exist)
3. [How It Works - High Level Overview](#how-it-works---high-level-overview)
4. [Key Concepts Explained](#key-concepts-explained)
5. [Features](#features)
6. [Prerequisites](#prerequisites)
7. [Installation](#installation)
8. [Running the Application](#running-the-application)
9. [Using the Web Interface](#using-the-web-interface)
10. [Understanding the Report](#understanding-the-report)
11. [Technical Details](#technical-details)
12. [Troubleshooting](#troubleshooting)

---

## What is AFDF?

AFDF (Anti-Forensic Detection Framework) is a **digital forensics tool** that helps investigators analyze disk images to find:

1. **Hidden encrypted volumes** - Areas that might contain secret encrypted data
2. **Wipe patterns** - Signs that data was deliberately destroyed
3. **Evidence tampering** - Modifications to the original data
4. **Deleted files** - Files that were removed but might still be recoverable
5. **Unallocated space anomalies** - Suspicious patterns in free disk space

Think of it like a **medical scanner for hard drives** - it looks deep inside to find things that aren't visible to the naked eye.

---

## Why Does This Tool Exist?

### The Problem

When investigators (like police or forensic experts) get a computer as evidence, they often work with a **disk image** - an exact copy of everything on the hard drive. Criminals often try to hide evidence by:

- **Encrypting** hidden volumes with special software (like VeraCrypt)
- **Securely deleting** files to make them unrecoverable
- **Wiping** entire drives to destroy evidence
- **Using anti-forensic tools** like DBAN, SDelete, or BleachBit

### The Solution

AFDF analyzes the patterns in a disk image to detect these anti-forensic techniques. It uses:

- **Statistical analysis** - Finding unusual patterns in the data
- **Machine learning** - Ensemble of Random Forest + Isolation Forest for classification
- **Forensics tools** - Industry-standard tools from The Sleuth Kit
- **Unallocated space analysis** - Detecting wipe patterns in free disk space

---

## How It Works - High Level Overview

Here's what happens when you upload a disk image:

```
1. UPLOAD
   You upload a disk image file (.dd, .E01, .img, .raw)
            │
            ▼
2. FILE VALIDATION
   System calculates hashes (MD5, SHA256, SHA1) for integrity
   Detects file type using magic bytes
   Identifies embedded filesystem
            │
            ▼
3. RUST ANALYZER
   Fast analysis of file signatures
   Anti-forensic tool detection (DBAN, SDelete, BleachBit)
   Timestamp anomaly detection
   Hidden data detection
            │
            ▼
4. PYTHON ENTROPY & WIPE SCAN
   Reads disk in small 4KB blocks
   Calculates Shannon entropy for each block
   Identifies high-entropy regions
   Analyzes unallocated space for wipe patterns
            │
            ▼
5. MACHINE LEARNING (Ensemble)
   Random Forest + Isolation Forest classification
   Analyzes 18 features including unallocated space
   Outputs: AUTHENTIC / QUESTIONABLE / TAMPERED
            │
            ▼
6. FORENSICS TOOLS
   Parses partition tables (mmls)
   Analyzes filesystem metadata (fsstat)
   Finds deleted file entries (fls)
   Extracts artifacts (bulk_extractor)
            │
            ▼
7. REPORT GENERATION
   Creates comprehensive forensic report
   Includes all findings, evidence, limitations
   Ready for court proceedings
```

---

## Key Concepts Explained

### What is Entropy?

**Entropy** is a measure of how random or unpredictable data is. Think of it like this:

| Data Type | Entropy | Example |
|----------|---------|---------|
| **Zero (all zeros)** | 0.0 | `00 00 00 00 00` |
| **Text (repetitive)** | 2-4 | `hello hello hello` |
| **Compressed** | 6-7 | ZIP files, images |
| **Encrypted** | 7.5-8.0 | Random-looking data |
| **Fully Random** | 8.0 | `A9 F3 7C 2B 1E...` |

AFDF flags regions with **high entropy** because they might contain hidden encrypted volumes.

### What is a Disk Image?

A **disk image** is an exact copy of an entire hard drive, including:
- All files (even deleted ones)
- Deleted disk
- The data still on the filesystem structure
- Empty space
- Unallocated (free) space

Common formats:
- `.dd` or `.raw` - Raw binary copy
- `.E01` - EnCase format (compressed)
- `.img` - Generic disk image

### What are Wipe Patterns?

When someone wants to permanently delete data, they might "wipe" the drive by overwriting it with:
- **Zeros** - `00 00 00 00`
- **All FFs** - `FF FF FF FF`
- **Random data** - `A3 7F 2B 9C...`
- **DoD 5220.22** - Specific overwrite patterns
- **Gutmann** - 35-pass overwrite

AFDF detects these patterns, especially in **unallocated space**, to identify evidence destruction.

### What is Chain of Custody?

**Chain of custody** documents everyone who touched the evidence and when. It's critical for court cases to prove the evidence wasn't tampered with.

### Unallocated Space

**Unallocated space** is the free space on a disk where deleted files can sometimes be recovered. This is a critical area for forensic analysis because:
- Secure deletion tools often overwrite this space
- Hidden volumes may leave traces here
- Wipe patterns are most visible in unallocated regions

---

## Features

### 1. Entropy Analysis
- Shannon entropy calculation per 4KB block
- Chi-square distribution testing
- Byte frequency analysis
- Serial correlation detection
- High-entropy region identification

### 2. Machine Learning (Ensemble)
- **Random Forest Classifier** - Classification into AUTHENTIC/QUESTIONABLE/TAMPERED
- **Isolation Forest** - Anomaly detection in disk features
- 18 features including unallocated space analysis
- Confidence scoring and tamper probability

### 3. Wipe Pattern Detection
- Zero-fill detection
- FF-fill detection
- Random-wipe detection
- DoD 5220.22 and Gutmann patterns
- Unallocated space analysis

### 4. Rust Analyzer (Fast Analysis)
- File signature detection
- Anti-forensic tool detection (DBAN, SDelete, BleachBit)
- Timestamp anomaly detection
- Hidden data detection in slack space

### 5. Forensics Tools Integration
- **mmls** - Partition table mapping (MBR/GPT)
- **fsstat** - Filesystem metadata analysis
- **fls** - Deleted file listing
- **blkls** - Unallocated space extraction
- **bulk_extractor** - Email, URL, IP extraction

### 6. File Validation
- Magic bytes detection
- Hash calculation (MD5, SHA1, SHA256)
- Filesystem identification (NTFS, FAT32, ext2/3/4, exFAT, HFS+, APFS)

### 7. Court-Admissible Reports
- 22-section comprehensive reports
- Customizable examiner information
- Professional formatting

---

## Prerequisites

Before you begin, you need:

1. **Python 3.10 or higher** - Download from python.org
2. **Node.js 18 or higher** - Download from nodejs.org
3. **The Sleuth Kit (TSK)** - For forensics tools
   - Windows: Download from sleuthkit.org
   - Mac: `brew install sleuthkit`
   - Linux: `sudo apt-get install sleuthkit`
4. **8GB RAM minimum** (16GB recommended for large images)

### Python Dependencies
```
pip install -r requirements.txt
```

### Node.js Dependencies
```bash
cd server
npm install
```

### ML API Dependencies
```bash
cd server/ml-api
pip install -r requirements.txt
```

---

## Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd AFDF-updated_updated_more

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Node.js dependencies
cd server
npm install
cd ..

# 4. Install ML API dependencies
cd server/ml-api
pip install -r requirements.txt
cd ../..
```

---

## Running the Application

### The Easy Way (One-Click Start)
For Windows users, simply double-click the **`Start_AFDF.bat`** file in the root directory. 
This shortcut will instantly boot up the Frontend, the Node.js Backend, and the Machine Learning API simultaneously in a single terminal.

If you don't want to use the `.bat` file, you can run the same command manually:
```bash
npm run start:all
```
*Wait a few seconds for the services to boot up, then navigate to **http://localhost:8081**.*

---

### The Manual Way (Three Terminals)

If you prefer to see the logs separated into individual windows or need to restart one service independently:

**Terminal 1 - ML API (Port 3002):**
```bash
cd server/ml-api
python -m uvicorn main:app --port 3002
```

**Terminal 2 - Backend Server (Port 3001):**
```bash
cd server
npm start
```

**Terminal 3 - Frontend (Port 8081):**
```bash
npm run dev
```

---

## Using the Web Interface

### Step 1: Open the Application
Navigate to http://localhost:5173 in your web browser.

### Step 2: Upload a Disk Image
Click the upload area and select your disk image file.
- Supported formats: .dd, .E01, .img, .raw, .E01

### Step 3: Wait for Analysis
The system will:
- Calculate file hashes (MD5, SHA1, SHA256)
- Run Rust analyzer for fast signature detection
- Analyze entropy patterns in 4KB blocks
- Detect wipe patterns in unallocated space
- Run forensics tools (partitions, filesystem, deleted files)
- Run ML ensemble classification (Random Forest + Isolation Forest)

### Step 4: View Results
Click on any analysis to see:
- Dashboard - Overview of findings with severity ratings
- Full Report - Detailed 22-section report

### Step 5: Customize and Download Report
1. Fill in examiner information
2. Add case details
3. Review all sections
4. Download the final report

---

## Understanding the Report

The AFDF report contains 22 sections:

### 1. Examiner Information
Your name, title, organization, and qualifications.

### 2. Case Information
Case number, legal authority, court case number.

### 3. Evidence Acquisition Details
- File name and size
- Acquisition tool used
- Write blocker information
- Original hash values (for integrity verification)

### 4. File Integrity Verification
- MD5, SHA1, and SHA-256 hashes calculated from the uploaded file
- These can be compared with original evidence hashes

### 5. File Type Verification
- Detected file type (using magic bytes)
- Whether extension matches actual content
- Validation status

### 6. Filesystem Identification
- Detected filesystem type (NTFS, FAT32, exFAT, etc.)
- Cluster/block size
- Partition information

### 7. Chain of Custody Log
Timeline of evidence handling from acquisition to analysis.

### 8. Forensic Environment
- Analysis system details
- Tool versions used
- Timezone of analysis

### 9. Evidence Integrity (Entropy)
- Mean entropy value
- Maximum entropy found
- Number of anomalous blocks

### 10. Filesystem and Partition Overview
Detailed partition information including:
- Start offsets
- Sizes
- Partition types

### 11. Suspicious Regions Analysis
Regions with unusual entropy that warrant further investigation:
- Offset locations
- Size
- Entropy scores
- Anomaly scores

### 12. Artifact Findings
Detailed findings from forensic analysis:
- Deleted files
- Email addresses found
- URLs discovered
- IP addresses

### 13. Timeline Reconstruction
Events extracted from filesystem metadata.

### 14. Deleted Files Analysis
List of files that were deleted but may still be recoverable.

### 15. Artifact Scan Results
Summary of emails, URLs, IPs, and phone numbers found.

### 16. Wipe Detection Results
Analysis of unallocated space for wipe patterns:
- Zero-fill regions
- FF-fill regions
- Random-wipe regions
- Wipe score calculation

### 17. Anti-Forensic Technique Analysis
Detected anti-forensic techniques:
- Encryption presence
- Wipe patterns
- Anti-forensic tool signatures (DBAN, SDelete, BleachBit)
- Metadata inconsistencies

### 18. Machine Learning Analysis
- Ensemble model details (Random Forest + Isolation Forest)
- Features analyzed (18 total including unallocated space)
- Accuracy metrics
- Prediction result (AUTHENTIC/QUESTIONABLE/TAMPERED)
- Confidence score
- Ensemble breakdown

### 19. Correlation Analysis
How ML findings correlate with forensic artifacts.

### 20. Unallocated Space Analysis
Detailed analysis of free disk space:
- Total unallocated bytes
- Suspicious regions count
- Wipe pattern distribution

### 21. Limitations
Known limitations of the analysis:
- Encrypted volumes without keys
- Overwritten data
- False positive rates

### 22. Examiner Declaration
Statement certifying the analysis was performed properly.

---

## Technical Details

### Analysis Pipeline

```
User Upload
    │
    ▼
┌─────────────────────────────────────────┐
│ 1. File Validation                      │
│    - Hash calculation (MD5/SHA1/SHA256)│
│    - Magic bytes detection              │
│    - Filesystem identification          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 2. Rust Analyzer (Fast)                 │
│    - File signature detection           │
│    - Anti-forensic tool detection       │
│    - Timestamp anomaly detection         │
│    - Hidden data detection              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 3. Python Entropy Scan                  │
│    - Read disk in 4KB blocks           │
│    - Calculate Shannon entropy          │
│    - Chi-square testing                │
│    - Identify high-entropy regions     │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 4. Wipe Detection                      │
│    - Extract unallocated space          │
│    - Scan for wipe patterns            │
│    - Zero/FF/Random classification     │
│    - Calculate wipe score              │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 5. Forensics Tools                     │
│    - mmls: Partition tables             │
│    - fsstat: Filesystem metadata        │
│    - fls: Deleted files                 │
│    - bulk_extractor: Artifacts          │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 6. Machine Learning (Ensemble)          │
│    - 18 features extracted             │
│    - Random Forest classification       │
│    - Isolation Forest anomaly detection │
│    - Ensemble voting                    │
│    - Confidence scoring                 │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ 7. Report Generation                    │
│    - Combine all findings               │
│    - Format for court                  │
│    - Include limitations                │
└─────────────────────────────────────────┘
```

### Machine Learning Features (18 Total)

The ML ensemble analyzes these features:
1. **Entropy score** - Shannon entropy
2. **Null ratio** - Percentage of null bytes
3. **Repeating chunks** - Repeated data patterns
4. **Timestamp anomalies** - Invalid timestamps
5. **Wiping detected** - Wipe patterns found
6. **Anti-forensic tool** - Tool signatures detected
7. **Hidden data** - Data in slack space
8. **High entropy** - Above 7.5 threshold
9. **Unknown filesystem** - No FS detected
10. **File size** - Disk image size in GB
11. **Sector alignment** - 512-byte alignment
12. **Unallocated space bytes** - Free space size
13. **Suspicious unallocated regions** - Anomalies in free space
14. **Zero-filled regions** - Zero-wipe patterns
15. **Random-filled regions** - Random-wipe patterns
16. **Wipe pattern score** - Overall wipe score
17. **Deleted file entries** - Count of deleted files

### Ensemble Model Details

- **Random Forest**: 100 trees, classifies into AUTHENTIC/QUESTIONABLE/TAMPERED
- **Isolation Forest**: 100 trees, anomaly detection
- **Weights**: 60% Random Forest, 40% Isolation Forest
- **Training**: Synthetic forensic data (can be retrained with real data)

### Scoring System

| Category | Score | Description |
|----------|-------|-------------|
| Wipe Detection >30% | 35 | Strong evidence of wiping |
| Wipe Detection >10% | 20 | Moderate wiping evidence |
| Wipe Detection >3% | 10 | Some wiping detected |
| No Anomalies | 0 | Normal findings |

---

## Troubleshooting

### Common Issues

**Q: Server won't start**
- Make sure port 3001 is not in use
- Make sure port 3002 (ML API) is not in use
- Check that Node.js is installed: `node --version`
- Check that Python is installed: `python --version`

**Q: ML API shows "Random Forest model not found, using default"**
- This is normal on first run - models will be trained automatically
- Models will be saved to `server/ml-api/models/` for future use

**Q: Analysis takes too long**
- Larger files take more time
- The timeout is set to 10 minutes for Python analysis
- Try reducing block size in configuration

**Q: No suspicious regions found**
- This could mean the disk is clean
- Or the file might be encrypted/compressed
- Check if high entropy regions exist

**Q: Can't detect filesystem**
- For encrypted containers, filesystem is inside encrypted data
- E01 files may need decompression first
- Check if disk is raw or has known filesystem

**Q: All disk images show same results**
- This was a bug that has been fixed
- Each analysis now uses unique output directories
- Restart the server to apply fixes

---

## License

MIT License - See LICENSE file for details

---

## Support

For issues and questions, please open an issue on GitHub.

---

*Document Version: 2.0.0*
*AFDF - Anti-Forensic Detection Framework*
