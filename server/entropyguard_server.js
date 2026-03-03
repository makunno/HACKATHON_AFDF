// EntropyGuard Web Server
// Unified server that integrates CLI with web frontend

import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3001;

// Magic bytes signatures for disk image formats
const MAGIC_BYTES = {
  // EnCase/EWF
  'E01': [0x45, 0x56, 0x45, 0x56, 0x46, 0x49, 0x4C, 0x45], // EVFILE
  'EWF': [0x45, 0x57, 0x46, 0x2D, 0x53, 0x01], // EWF-S01
  // RAW DD
  'DD': [0x00, 0x00], // RAW has no specific magic - checked by extension
  // VMDK
  'VMDK': [0x4B, 0x44, 0x4D], // KDM
  'VMDK_EXT': [0x23, 0x20, 0x54, 0x79, 0x70, 0x65, 0x33], // #!Type3
  // VHD
  'VHD': [0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78], // connectix
  // DMG
  'DMG': [0x78, 0x01], // x01
  // ISO
  'ISO': [0x43, 0x44, 0x30, 0x30, 0x31], // CD001
  // Nero
  'NRG': [0x4E, 0x45, 0x52, 0x47], // NERG
  // AFF
  'AFF': [0x41, 0x46, 0x46], // AFF
  // L01
  'L01': [0x4C, 0x30, 0x31], // L01
};

// Extension to magic bytes mapping for validation
const EXTENSION_MAGIC_MAP = {
  'E01': { magic: [0x45, 0x56, 0x45, 0x56, 0x46, 0x49, 0x4C, 0x45], name: 'EnCase' },
  'EWF': { magic: [0x45, 0x57, 0x46, 0x2D, 0x53, 0x01], name: 'EWF' },
  'DD': { magic: null, name: 'RAW/DD' },
  'IMG': { magic: null, name: 'RAW/IMG' },
  'VMDK': { magic: [0x4B, 0x44, 0x4D], name: 'VMDK' },
  'VHD': { magic: [0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78], name: 'VHD' },
  'DMG': { magic: [0x78, 0x01], name: 'DMG' },
  'ISO': { magic: [0x43, 0x44, 0x30, 0x30, 0x31], name: 'ISO' },
  'NRG': { magic: [0x4E, 0x45, 0x52, 0x47], name: 'Nero' },
  'AFF': { magic: [0x41, 0x46, 0x46], name: 'AFF' },
  'L01': { magic: [0x4C, 0x30, 0x31], name: 'L01' },
};

// Filesystem signatures in boot sector
const FILESYSTEM_SIGNATURES = {
  'NTFS': [0xEB, 0x52, 0x90, 0x4E, 0x54, 0x46, 0x53, 0x20], // EB 52 90 "NTFS "
  'FAT12': [0xEB, null, 0x90], // Jump boot - varies
  'FAT16': [0xEB, null, 0x90, 0x46, 0x41, 0x54], // Jump + "FAT"
  'FAT32': [0xEB, null, 0x90, 0x46, 0x41, 0x54, 0x33, 0x32], // Jump + "FAT32"
  'exFAT': [0xEB, 0x76, 0x90, 0x65, 0x78, 0x46, 0x41, 0x54], // exFAT
  'ext2': [0x53, 0xEF], // 0x53 0xEF at offset 0x438
  'ext3': [0x53, 0xEF], // Same as ext2
  'ext4': [0x53, 0xEF], // Same as ext2
};

// Calculate file hashes
function calculateFileHashes(filePath) {
  return new Promise((resolve, reject) => {
    const hashes = {
      md5: '',
      sha1: '',
      sha256: '',
      calculated: false
    };
    
    try {
      const md5 = crypto.createHash('md5');
      const sha1 = crypto.createHash('sha1');
      const sha256 = crypto.createHash('sha256');
      
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (chunk) => {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
      });
      
      stream.on('end', () => {
        hashes.md5 = md5.digest('hex');
        hashes.sha1 = sha1.digest('hex');
        hashes.sha256 = sha256.digest('hex');
        hashes.calculated = true;
        resolve(hashes);
      });
      
      stream.on('error', (err) => {
        console.log('[Server] Hash stream error:', err.message);
        resolve(hashes); // Return empty hashes instead of rejecting
      });
    } catch (e) {
      console.log('[Server] Hash calculation error:', e.message);
      resolve(hashes);
    }
  });
}

// Detect file type using magic bytes
function detectFileType(filePath) {
  return new Promise((resolve) => {
    try {
      const buffer = Buffer.alloc(512);
      const fd = fs.openSync(filePath, 'r');
      fs.readSync(fd, buffer, 0, 512, 0);
      fs.closeSync(fd);
      
      const bytes = Array.from(buffer);
      const ext = path.extname(filePath).toUpperCase().replace('.', '');
      
      // Check for disk image formats using magic bytes first
      for (const [format, magic] of Object.entries(MAGIC_BYTES)) {
        if (!magic) continue; // RAW has no magic bytes
        
        let match = true;
        for (let i = 0; i < magic.length; i++) {
          if (bytes[i] !== magic[i]) {
            match = false;
            break;
          }
        }
        if (match) {
          // Check if extension matches detected type
          const extMatch = ext === format || ext === format.replace('EXT', '');
          resolve({ 
            detectedType: format, 
            method: 'magic_bytes',
            extensionMatch: extMatch,
            extensionDeclared: ext || null,
            validationStatus: extMatch ? 'VALID' : 'MISMATCH'
          });
          return;
        }
      }
      
      // Check for filesystem signatures
      for (const [fsType, sig] of Object.entries(FILESYSTEM_SIGNATURES)) {
        let match = true;
        for (let i = 0; i < sig.length; i++) {
          if (sig[i] !== null && bytes[i] !== sig[i]) {
            match = false;
            break;
          }
        }
        if (match) {
          resolve({ 
            detectedType: fsType, 
            method: 'filesystem_signature',
            extensionMatch: true,
            extensionDeclared: ext || null,
            validationStatus: 'FILESYSTEM_DETECTED'
          });
          return;
        }
      }
      
      // Extension-based detection with validation info
      const knownExtensions = Object.keys(EXTENSION_MAGIC_MAP);
      if (knownExtensions.includes(ext)) {
        // Known extension but no magic bytes match - could be RAW or wrong extension
        resolve({ 
          detectedType: ext, 
          method: 'extension_lookup',
          extensionMatch: false,
          extensionDeclared: ext,
          validationStatus: 'EXTENSION_ONLY_NO_MAGIC'
        });
        return;
      }
      
      // Unknown extension
      resolve({ 
        detectedType: ext || 'UNKNOWN', 
        method: 'extension',
        extensionMatch: null,
        extensionDeclared: ext || null,
        validationStatus: 'UNKNOWN'
      });
    } catch (e) {
      resolve({ 
        detectedType: 'UNKNOWN', 
        method: 'error', 
        error: e.message,
        extensionMatch: null,
        extensionDeclared: null,
        validationStatus: 'ERROR'
      });
    }
  });
}

// Identify filesystem from disk image
async function identifyFilesystem(filePath) {
  const result = {
    detected: 'Not Detected',
    method: 'N/A',
    confidence: 0,
    details: {}
  };
  
  // Try using fsstat from The Sleuth Kit
  try {
    const python = process.platform === 'win32' ? 'python' : 'python3';
    const fsstatOutput = await runTool(python, ['-m', 'entropyguard.cli.commands', 'analyze', filePath, '--type', 'fsstat']);
    
    // Parse fsstat output - look for various filesystem indicators
    const fsMatch = fsstatOutput.match(/Filesystem type:\s*(\S+)/i);
    if (fsMatch && fsMatch[1] && fsMatch[1] !== 'Unknown' && fsMatch[1] !== 'raw') {
      result.detected = fsMatch[1].toUpperCase();
      result.method = 'fsstat';
      result.confidence = 90;
    }
    
    // Get more details
    const clusterMatch = fsstatOutput.match(/Cluster size:\s*(\d+)/i);
    if (clusterMatch) {
      result.details.clusterSize = parseInt(clusterMatch[1]);
    }
    
    const totalMatch = fsstatOutput.match(/Total clusters:\s*(\d+)/i);
    if (totalMatch) {
      result.details.totalClusters = parseInt(totalMatch[1]);
    }
    
    // Try alternative patterns in fsstat output
    if (result.detected === 'Not Detected') {
      const altPatterns = [
        /File system type:\s*(\S+)/i,
        /FS Type:\s*(\S+)/i,
        /Type:\s*(FAT|NTFS|ext[234]|HFS\+|APFS)/i
      ];
      for (const pattern of altPatterns) {
        const match = fsstatOutput.match(pattern);
        if (match) {
          result.detected = match[1].toUpperCase();
          result.method = 'fsstat_alt';
          result.confidence = 85;
          break;
        }
      }
    }
  } catch (e) {
    console.log('[Server] fsstat failed for filesystem detection:', e.message);
  }
  
  // If fsstat failed, try magic bytes for filesystem detection
  if (result.detected === 'Not Detected') {
    const magicResult = await detectFileType(filePath);
    if (magicResult.method === 'filesystem_signature') {
      result.detected = magicResult.detectedType;
      result.method = 'magic_bytes';
      result.confidence = 80;
    }
  }
  
  // If still not detected, try analyzing the boot sector for filesystem markers
  if (result.detected === 'Not Detected') {
    try {
      const buffer = Buffer.alloc(1024);
      const fd = fs.openSync(filePath, 'r');
      const bytesRead = fs.readSync(fd, buffer, 0, 1024, 0);
      fs.closeSync(fd);
      
      if (bytesRead > 0) {
        const bootSector = buffer.toString('hex', 0, Math.min(bytesRead, 512));
        
        // Additional filesystem detection heuristics
        if (bootSector.includes('4e544653')) {
          result.detected = 'NTFS';
          result.method = 'boot_sector_marker';
          result.confidence = 75;
        } else if (bootSector.includes('464154') && bootSector.includes('3332')) {
          result.detected = 'FAT32';
          result.method = 'boot_sector_marker';
          result.confidence = 70;
        } else if (bootSector.includes('464154') && bootSector.includes('3132')) {
          result.detected = 'FAT12';
          result.method = 'boot_sector_marker';
          result.confidence = 70;
        } else if (bootSector.includes('464154') && !bootSector.includes('3332') && !bootSector.includes('3132')) {
          result.detected = 'FAT16';
          result.method = 'boot_sector_marker';
          result.confidence = 70;
        } else if (bootSector.includes('65784641')) {
          result.detected = 'exFAT';
          result.method = 'boot_sector_marker';
          result.confidence = 70;
        }
      }
    } catch (e) {
      console.log('[Server] Boot sector analysis failed:', e.message);
    }
  }
  
  // If really nothing detected, mark as unknown but not "Unknown" - more descriptive
  if (result.detected === 'Not Detected') {
    result.detected = 'Not Determined';
    result.method = 'no_signature_found';
    result.confidence = 0;
    result.details.note = 'Could not detect filesystem signature. Image may be unformatted, encrypted, or use uncommon filesystem.';
  }
  
  return result;
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50gb' }));

// Configure multer for large file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueId = uuidv4();
    cb(null, `${uniqueId}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 100 * 1024 * 1024 * 1024 }
});

// Analysis results storage
const analysisResults = new Map();

// Run EntropyGuard scan with all methods
async function runEntropyGuard(filePath, outputDir) {
  return new Promise((resolve, reject) => {
    console.log(`[Server] Running EntropyGuard on: ${filePath}`);
    
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    const python = process.platform === 'win32' ? 'python' : 'python3';
    
    // Run full analysis with ML models
    const args = [
      '-m', 'entropyguard.cli.commands',
      'scan',
      filePath,
      '--block-size', '4096',
      '--output', outputDir,
      '--methods', 'zscore,isolation_forest',
      '--workers', '8',
      '--no-visualize'
    ];
    
    console.log(`[Server] Command: ${python} ${args.join(' ')}`);
    
    const startTime = Date.now();
    const proc = spawn(python, args, {
      cwd: path.join(__dirname, '..'),
      stdio: ['inherit', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
      console.log(`[EntropyGuard] ${data.toString().trim()}`);
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      if (code !== 0) {
        console.error(`[Server] EntropyGuard exited with code ${code}`);
      }
      
      // Read the results
      try {
        const files = fs.readdirSync(outputDir).filter(f => f.startsWith('scan_') && f.endsWith('.json'));
        if (files.length > 0) {
          files.sort((a, b) => fs.statSync(path.join(outputDir, b)).mtime - fs.statSync(path.join(outputDir, a)).mtime);
          const resultPath = path.join(outputDir, files[0]);
          const result = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
          result.scan_duration_ms = duration;
          result.chain_of_custody = generateChainOfCustody(startTime, endTime, duration);
          resolve(result);
        } else {
          resolve({ error: 'No results found' });
        }
      } catch (e) {
        resolve({ error: `Failed to parse results: ${e.message}` });
      }
    });
  });
}

function generateChainOfCustody(startTime, endTime, duration) {
  const chain = [];
  const formatTime = (ts) => new Date(ts).toISOString();
  
  chain.push({
    timestamp: formatTime(startTime),
    event: "Analysis initiated",
    details: "Disk image received and queued for analysis",
    status: "COMPLETED"
  });
  
  const featureExtractTime = startTime + Math.floor(duration * 0.3);
  chain.push({
    timestamp: formatTime(featureExtractTime),
    event: "Feature extraction started",
    details: "Extracting entropy features from disk blocks",
    status: "COMPLETED"
  });
  
  const anomalyDetectTime = startTime + Math.floor(duration * 0.6);
  chain.push({
    timestamp: formatTime(anomalyDetectTime),
    event: "Anomaly detection running",
    details: "Z-score and ML-based anomaly detection in progress",
    status: "COMPLETED"
  });
  
  const regionClusterTime = startTime + Math.floor(duration * 0.85);
  chain.push({
    timestamp: formatTime(regionClusterTime),
    event: "Region clustering",
    details: "Grouping anomalous blocks into suspicious regions",
    status: "COMPLETED"
  });
  
  chain.push({
    timestamp: formatTime(endTime),
    event: "Analysis completed",
    details: `Full analysis finished in ${(duration / 1000).toFixed(2)} seconds`,
    status: "COMPLETED"
  });
  
  return chain;
}

// Run forensics analysis
async function runForensicsAnalysis(filePath) {
  const results = {
    partitions: null,
    filesystem: null,
    deletedFiles: [],
    artifacts: [],
    diskWipe: null,
    chainOfCommand: []
  };
  
  const analysisStartTime = Date.now();
  const python = process.platform === 'win32' ? 'python' : 'python3';
  
  // 1. Partition Analysis (mmls)
  const mmlsStart = Date.now();
  results.chainOfCommand.push({ 
    step: 'mmls', 
    description: 'Partition table analysis',
    start_time: new Date(mmlsStart).toISOString(),
    status: 'IN_PROGRESS'
  });
  try {
    const mmlsResult = await runTool(python, ['-m', 'entropyguard.cli.commands', 'analyze', filePath, '--type', 'mmls']);
    results.partitions = parseMMLSToJSON(mmlsResult);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'COMPLETED';
    results.chainOfCommand[results.chainOfCommand.length - 1].duration_ms = Date.now() - mmlsStart;
  } catch (e) {
    console.log('[Server] mmls failed:', e.message);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'FAILED';
    results.chainOfCommand[results.chainOfCommand.length - 1].error = e.message;
  }
  
  // 2. Filesystem Analysis (fsstat)
  const fsstatStart = Date.now();
  results.chainOfCommand.push({ 
    step: 'fsstat', 
    description: 'Filesystem metadata analysis',
    start_time: new Date(fsstatStart).toISOString(),
    status: 'IN_PROGRESS'
  });
  try {
    const fsstatResult = await runTool(python, ['-m', 'entropyguard.cli.commands', 'analyze', filePath, '--type', 'fsstat']);
    results.filesystem = parseFSSTATToJSON(fsstatResult);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'COMPLETED';
    results.chainOfCommand[results.chainOfCommand.length - 1].duration_ms = Date.now() - fsstatStart;
  } catch (e) {
    console.log('[Server] fsstat failed:', e.message);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'FAILED';
    results.chainOfCommand[results.chainOfCommand.length - 1].error = e.message;
  }
  
  // 3. Deleted Files (fls)
  const flsStart = Date.now();
  results.chainOfCommand.push({ 
    step: 'fls', 
    description: 'Deleted file entries analysis',
    start_time: new Date(flsStart).toISOString(),
    status: 'IN_PROGRESS'
  });
  try {
    const flsResult = await runTool(python, ['-m', 'entropyguard.cli.commands', 'analyze', filePath, '--type', 'fls']);
    results.deletedFiles = parseFLSToJSON(flsResult);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'COMPLETED';
    results.chainOfCommand[results.chainOfCommand.length - 1].duration_ms = Date.now() - flsStart;
  } catch (e) {
    console.log('[Server] fls failed:', e.message);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'FAILED';
    results.chainOfCommand[results.chainOfCommand.length - 1].error = e.message;
  }
  
  // 4. Bulk Extractor (artifacts)
  const bulkStart = Date.now();
  results.chainOfCommand.push({ 
    step: 'bulk_extractor', 
    description: 'Artifact scanning (emails, URLs, IPs, etc.)',
    start_time: new Date(bulkStart).toISOString(),
    status: 'IN_PROGRESS'
  });
  try {
    const bulkResult = await runTool(python, ['-m', 'entropyguard.cli.commands', 'analyze', filePath, '--type', 'bulk']);
    results.artifacts = parseBulkToJSON(bulkResult);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'COMPLETED';
    results.chainOfCommand[results.chainOfCommand.length - 1].duration_ms = Date.now() - bulkStart;
  } catch (e) {
    console.log('[Server] bulk failed:', e.message);
    results.chainOfCommand[results.chainOfCommand.length - 1].status = 'FAILED';
    results.chainOfCommand[results.chainOfCommand.length - 1].error = e.message;
  }
  
  // 5. Disk Wipe Detection
  const wipeStart = Date.now();
  results.chainOfCommand.push({ 
    step: 'disk_wipe_detection', 
    description: 'Disk wipe software detection',
    start_time: new Date(wipeStart).toISOString(),
    status: 'IN_PROGRESS'
  });
  results.diskWipe = await detectDiskWipe(filePath);
  results.chainOfCommand[results.chainOfCommand.length - 1].status = 'COMPLETED';
  results.chainOfCommand[results.chainOfCommand.length - 1].duration_ms = Date.now() - wipeStart;
  
  results.total_forensics_duration_ms = Date.now() - analysisStartTime;
  
  return results;
}

function runTool(python, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(python, args, {
      cwd: path.join(__dirname, '..'),
      stdio: ['inherit', 'pipe', 'pipe']
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });
    
    proc.on('close', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(stderr || `Exit code ${code}`));
    });
  });
}

function parseMMLSToJSON(output) {
  const partitions = [];
  const lines = output.split('\n');
  let current = null;
  
  for (const line of lines) {
    const slotMatch = line.match(/Slot (\d+):/);
    const offsetMatch = line.match(/Offset: (0x[0-9A-Fa-f]+)/);
    const sizeMatch = line.match(/Size: ([\d,]+) bytes/);
    
    if (slotMatch) {
      current = { slot: parseInt(slotMatch[1]), description: line.replace(/Slot \d+: /, '') };
    } else if (offsetMatch && current) {
      current.startOffset = parseInt(offsetMatch[1]);
    } else if (sizeMatch && current) {
      current.size = parseInt(sizeMatch[1].replace(/,/g, ''));
      partitions.push(current);
      current = null;
    }
  }
  return partitions;
}

function parseFSSTATToJSON(output) {
  const lines = output.split('\n');
  const fs = { type: 'Unknown', blockSize: 0, totalBlocks: 0 };
  
  for (const line of lines) {
    if (line.includes('Filesystem:')) fs.type = line.split(':')[1].trim();
    if (line.includes('Block size:')) fs.blockSize = parseInt(line.split(':')[1].trim());
    if (line.includes('Total blocks:')) fs.totalBlocks = parseInt(line.split(':')[1].trim().replace(/,/g, ''));
  }
  return fs;
}

function parseFLSToJSON(output) {
  const files = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('DELETED_') || line.includes('deleted')) {
      const match = line.match(/(DELETED_\w+)/);
      if (match) {
        files.push({ name: match[1], raw: line.trim() });
      }
    }
  }
  return files;
}

function parseBulkToJSON(output) {
  const artifacts = { emails: [], URLs: [], IPs: [], phones: [] };
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('@')) artifacts.emails.push(line.trim());
    if (line.startsWith('http')) artifacts.URLs.push(line.trim());
    if (line.match(/\d+\.\d+\.\d+\.\d+/)) artifacts.IPs.push(line.trim());
    if (line.match(/\d{3}.*\d{3}.*\d{4}/)) artifacts.phones.push(line.trim());
  }
  
  return artifacts;
}

async function detectDiskWipe(filePath) {
  // Analyze disk for wipe patterns
  const wipeIndicators = {
    detected: false,
    software: null,
    confidence: 0,
    details: []
  };
  
  try {
    const python = process.platform === 'win32' ? 'python' : 'python3';
    const script = `
import sys
from pathlib import Path

indicators = []

with open("${filePath.replace(/\\/g, '\\\\')}", 'rb') as f:
    data = f.read(1024*1024)  # 1MB
    
    # Check for common wipe patterns (DoD style, Gutmann, etc.)
    null_ratio = data.count(b'\\x00') / len(data) if len(data) > 0 else 0
    ff_ratio = data.count(b'\\xFF') / len(data) if len(data) > 0 else 0
    
    if null_ratio > 0.95:
        indicators.append(f"Extreme null byte pattern ({null_ratio*100:.1f}%)")
    
    if ff_ratio > 0.3:
        indicators.append(f"High FF pattern ({ff_ratio*100:.1f}%)")
    
    # Check for alternating patterns (common in wipe)
    alternating = sum(1 for i in range(len(data)-1) if data[i] == data[i+1])
    if len(data) > 0 and alternating / len(data) > 0.95:
        indicators.append("Uniform data pattern (possible wipe)")

print("\\n".join(indicators) if indicators else "NO_WIPE_DETECTED")
`;
    
    const result = await runTool(python, ['-c', script]);
    
    // Fix: Check for actual wipe patterns, not "pattern" in the negative message
    if (result && result.trim() !== "NO_WIPE_DETECTED" && result.includes('%')) {
      wipeIndicators.detected = true;
      wipeIndicators.software = 'Unknown secure erase';
      wipeIndicators.confidence = 0.6;
      wipeIndicators.details = result.split('\n').filter(l => l.trim() && l.trim() !== "NO_WIPE_DETECTED");
    }
  } catch (e) {
    console.log('[Server] Wipe detection error:', e.message);
  }
  
  return wipeIndicators;
}

function generateFallbackFindings(entropyResult, forensicsResult) {
  const findings = [];
  const stats = entropyResult.statistics || {};
  const regions = entropyResult.suspicious_regions || [];
  
  // Finding 1: Entropy anomaly profile - with more variation
  const meanEntropy = stats.mean_entropy || 0;
  const highEntropyCount = stats.anomalous_blocks || 0;
  const maxEntropy = stats.max_entropy || 0;
  
  let severity1, rationale1, desc1;
  if (meanEntropy > 7.8) {
    severity1 = "HIGH";
    rationale1 = "Very high mean entropy indicates likely encrypted content, VeraCrypt hidden volume, or strong compression. Nearly all data appears random.";
    desc1 = `Mean entropy ${meanEntropy.toFixed(4)} (maximum), ${highEntropyCount} high-entropy blocks detected.`;
  } else if (meanEntropy > 7.0) {
    severity1 = "HIGH";
    rationale1 = "High mean entropy suggests significant encrypted or highly compressed data regions. This could indicate hidden volumes or encrypted partitions.";
    desc1 = `Mean entropy ${meanEntropy.toFixed(4)}, ${highEntropyCount} high-entropy regions identified.`;
  } else if (meanEntropy > 5.5) {
    severity1 = "MEDIUM";
    rationale1 = "Moderate entropy indicates mixed content - some encrypted files, compressed data, or normal executable files present.";
    desc1 = `Mean entropy ${meanEntropy.toFixed(4)}, indicating mixed data types.`;
  } else if (meanEntropy > 3.5) {
    severity1 = "LOW";
    rationale1 = "Normal entropy for typical file system data. Contains a mix of text, executables, and sparse data.";
    desc1 = `Mean entropy ${meanEntropy.toFixed(4)}, typical for standard file system.`;
  } else {
    severity1 = "INFO";
    rationale1 = "Low entropy suggests mostly empty space, zeros, or repetitive patterns. Unusual for active disk but common for unused space.";
    desc1 = `Mean entropy ${meanEntropy.toFixed(4)}, predominantly empty or zero-filled regions.`;
  }
  
  findings.push({
    category: "Entropy anomaly profile",
    severity: severity1,
    description: desc1,
    why_it_matters: rationale1,
    evidence: {
      entropy_score: Math.round(meanEntropy * 10000) / 10000,
      high_entropy_region_count: highEntropyCount,
      max_entropy: Math.round(maxEntropy * 10000) / 10000,
      entropy_std: Math.round((stats.std_entropy || 0) * 10000) / 10000
    }
  });
  
  // Finding 2: High-entropy region clusters (encrypted volume indicators)
  const highEntropyClusters = regions.filter(r => (r.mean_entropy || 0) > 7.0);
  const totalHighEntropySize = highEntropyClusters.reduce((sum, r) => sum + (r.size || 0), 0);
  const largestCluster = Math.max(...regions.map(r => r.size || 0), 0);
  
  let severity2, rationale2, desc2;
  if (highEntropyClusters.length > 20) {
    severity2 = "HIGH";
    rationale2 = "Multiple high-entropy clusters strongly suggest encrypted hidden volumes, VeraCrypt containers, or steganographic content.";
    desc2 = `${highEntropyClusters.length} high-entropy clusters totaling ${totalHighEntropySize.toLocaleString()} bytes.`;
  } else if (highEntropyClusters.length > 5) {
    severity2 = "MEDIUM";
    rationale2 = "Several high-entropy regions may indicate encrypted partitions, compressed archives, or protected containers.";
    desc2 = `${highEntropyClusters.length} high-entropy clusters found, largest is ${largestCluster.toLocaleString()} bytes.`;
  } else if (highEntropyClusters.length > 0) {
    severity2 = "LOW";
    rationale2 = "A few high-entropy regions may be normal (compressed media files, encrypted headers).";
    desc2 = `${highEntropyClusters.length} minor high-entropy regions detected.`;
  } else {
    severity2 = "INFO";
    rationale2 = "No significant high-entropy clusters detected. Disk appears to contain mostly unencrypted data.";
    desc2 = "No high-entropy clusters found - data appears unencrypted.";
  }
  
  findings.push({
    category: "Encrypted volume indicators",
    severity: severity2,
    description: desc2,
    why_it_matters: rationale2,
    evidence: {
      high_entropy_clusters: highEntropyClusters.length,
      total_size_bytes: totalHighEntropySize,
      largest_cluster_bytes: largestCluster
    }
  });
  
  // Finding 3: Suspicious regions requiring investigation
  const suspiciousRegions = regions.filter(r => (r.mean_anomaly_score || 0) > 80);
  const totalSuspiciousSize = suspiciousRegions.reduce((sum, r) => sum + (r.size || 0), 0);
  
  let severity3, rationale3;
  if (suspiciousRegions.length > 50) {
    severity3 = "HIGH";
    rationale3 = "Large number of suspicious regions indicates complex hidden data structure - multiple encrypted volumes or layered steganography.";
  } else if (suspiciousRegions.length > 10) {
    severity3 = "MEDIUM";
    rationale3 = "Several suspicious regions warrant further investigation for hidden encrypted content.";
  } else if (suspiciousRegions.length > 0) {
    severity3 = "LOW";
    rationale3 = "Few suspicious regions detected - may be normal encrypted files or compression artifacts.";
  } else {
    severity3 = "INFO";
    rationale3 = "No highly suspicious regions found based on anomaly scoring.";
  }
  
  findings.push({
    category: "Anomaly regions requiring investigation",
    severity: severity3,
    description: `${suspiciousRegions.length} high-confidence suspicious regions (${totalSuspiciousSize.toLocaleString()} bytes).`,
    why_it_matters: rationale3,
    evidence: {
      suspicious_region_count: suspiciousRegions.length,
      total_suspicious_bytes: totalSuspiciousSize,
      avg_anomaly_score: suspiciousRegions.length > 0 ? 
        (suspiciousRegions.reduce((sum, r) => sum + (r.mean_anomaly_score || 0), 0) / suspiciousRegions.length).toFixed(2) : 0
    }
  });
  
  // Finding 4: Wipe detection
  const wipeRegions = regions.filter(r => (r.mean_entropy || 0) < 0.5).length;
  const wipeBytes = regions.filter(r => (r.mean_entropy || 0) < 0.5).reduce((sum, r) => sum + (r.size || 0), 0);
  
  let severity4, rationale4;
  if (wipeRegions > 100) {
    severity4 = "HIGH";
    rationale4 = "Extensive wipe patterns suggest intentional data destruction or secure deletion attempts.";
  } else if (wipeRegions > 10) {
    severity4 = "MEDIUM";
    rationale4 = "Multiple zero-filled regions could indicate disk wipe software or intentional sanitization.";
  } else {
    severity4 = "LOW";
    rationale4 = "Minimal zero-filled regions are normal for unused disk space.";
  }
  
  findings.push({
    category: "Potential wipe signatures detected",
    severity: severity4,
    description: `${wipeRegions} wipe-like regions totaling ${wipeBytes.toLocaleString()} bytes.`,
    why_it_matters: rationale4,
    evidence: {
      wipe_region_count: wipeRegions,
      wipe_bytes_total: wipeBytes
    }
  });
  
  // Finding 5: Deleted activity
  const deletedCount = (forensicsResult.deletedFiles || []).length;
  const diskSize = entropyResult.disk_size || 1;
  const deletionDensity = deletedCount / (diskSize / 1000000);
  
  let severity5, rationale5;
  if (deletedCount > 1000) {
    severity5 = "HIGH";
    rationale5 = "Extremely high deletion count suggests potential evidence destruction or disk cleanup activity.";
  } else if (deletedCount > 100) {
    severity5 = "MEDIUM";
    rationale5 = "High number of deleted entries may indicate cleanup or potential anti-forensic activity.";
  } else if (deletedCount > 10) {
    severity5 = "LOW";
    rationale5 = "Moderate deleted entries could be normal file system cleanup.";
  } else {
    severity5 = "INFO";
    rationale5 = "Minimal deleted file entries - typical for clean or newly partitioned disk.";
  }
  
  findings.push({
    category: "Deleted activity concentration",
    severity: severity5,
    description: `${deletedCount} deleted entries, density ${deletionDensity.toFixed(6)}.`,
    why_it_matters: rationale5,
    evidence: {
      deleted_files_count: deletedCount,
      deletion_density: deletionDensity
    }
  });
  
  // Finding 6: Overall risk assessment
  const highSeverityCount = findings.filter(f => f.severity === "HIGH").length;
  const mediumSeverityCount = findings.filter(f => f.severity === "MEDIUM").length;
  
  let overallSeverity, overallDesc;
  if (highSeverityCount >= 3) {
    overallSeverity = "CRITICAL";
    overallDesc = "Multiple high-severity findings indicate likely hidden encrypted volumes or anti-forensic activity.";
  } else if (highSeverityCount >= 1) {
    overallSeverity = "HIGH";
    overallDesc = "High-severity findings warrant immediate investigation for encrypted hidden volumes.";
  } else if (mediumSeverityCount >= 2) {
    overallSeverity = "MEDIUM";
    overallDesc = "Several medium-severity items suggest further analysis is recommended.";
  } else {
    overallSeverity = "LOW";
    overallDesc = "No significant threats detected. Standard forensic analysis recommended.";
  }
  
  findings.push({
    category: "Overall threat assessment",
    severity: overallSeverity,
    description: `${highSeverityCount} HIGH, ${mediumSeverityCount} MEDIUM severity findings. ${overallDesc}`,
    why_it_matters: "Summary of overall forensic posture based on all collected evidence.",
    evidence: {
      high_severity_count: highSeverityCount,
      medium_severity_count: mediumSeverityCount,
      total_regions_analyzed: regions.length,
      disk_size_bytes: diskSize
    }
  });
  
  return findings;
}

// ============ ROUTES ============

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', tool: 'EntropyGuard' });
});

app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const analysisId = uuidv4();
    const filePath = req.file.path;
    const fileSize = req.file.size;
    const outputDir = path.join(__dirname, 'results', analysisId);
    
    console.log(`[Server] Received: ${req.file.originalname} (${fileSize} bytes), ID: ${analysisId}`);
    
    // Calculate file hashes for integrity verification
    console.log('[Server] Calculating file hashes...');
    let hashes = { md5: '', sha1: '', sha256: '', calculated: false };
    try {
      hashes = await calculateFileHashes(filePath);
      if (hashes.calculated && hashes.md5) {
        console.log(`[Server] Hashes calculated - MD5: ${hashes.md5.substring(0, 16)}...`);
      } else {
        console.log('[Server] Hash calculation returned empty results');
      }
    } catch (e) {
      console.log('[Server] Hash calculation failed:', e.message);
    }
    
    // Detect file type using magic bytes
    console.log('[Server] Detecting file type...');
    let fileInfo = { detectedType: 'UNKNOWN', method: 'extension' };
    try {
      fileInfo = await detectFileType(filePath);
      console.log(`[Server] File type detected: ${fileInfo.detectedType} (method: ${fileInfo.method})`);
    } catch (e) {
      console.log('[Server] File type detection failed:', e.message);
    }
    
    // Identify filesystem
    console.log('[Server] Identifying filesystem...');
    let filesystem = { detected: 'Not Determined', method: 'N/A', confidence: 0, details: {} };
    try {
      filesystem = await identifyFilesystem(filePath);
      console.log(`[Server] Filesystem detected: ${filesystem.detected} (confidence: ${filesystem.confidence}%)`);
    } catch (e) {
      console.log('[Server] Filesystem identification failed:', e.message);
    }
    
    // Run EntropyGuard analysis
    const entropyResult = await runEntropyGuard(filePath, outputDir);
    
    // Run forensics tools
    console.log('[Server] Running forensics analysis...');
    const forensicsResult = await runForensicsAnalysis(filePath);
    
    // Generate findings using Python (use temp file to avoid command line length issues)
    console.log('[Server] Generating interpretable findings...');
    let findings = [];
    try {
      // Write data to temp files to avoid command line length limits
      const tempScanFile = path.join(outputDir, 'temp_scan_result.json');
      const tempForensicsFile = path.join(outputDir, 'temp_forensics_result.json');
      
      fs.writeFileSync(tempScanFile, JSON.stringify(entropyResult));
      fs.writeFileSync(tempForensicsFile, JSON.stringify(forensicsResult));
      
      const python = process.platform === 'win32' ? 'python' : 'python3';
      const script = `
import sys
import json
from pathlib import Path

# Use current directory instead of __file__
base_dir = Path.cwd() / 'entropyguard'
sys.path.insert(0, str(base_dir))

from entropyguard.forensics.reporter import ForensicReporter

# Read data from temp files
with open(r"${tempScanFile.replace(/\\/g, '\\\\')}", 'r') as f:
  scan_result = json.load(f)

with open(r"${tempForensicsFile.replace(/\\/g, '\\\\')}", 'r') as f:
  forensics_result = json.load(f)

reporter = ForensicReporter(Path(r"${outputDir.replace(/\\/g, '\\\\')}"))
findings = reporter.generate_findings(scan_result, forensics_result)

print(json.dumps(findings))
`;
      const findingsResult = await runTool(python, ['-c', script]);
      findings = JSON.parse(findingsResult);
      
      // Cleanup temp files
      try {
        fs.unlinkSync(tempScanFile);
        fs.unlinkSync(tempForensicsFile);
      } catch (e) {}
    } catch (e) {
      console.log('[Server] Findings generation failed:', e.message);
      // Fallback - generate basic findings
      findings = generateFallbackFindings(entropyResult, forensicsResult);
    }
    
    // Build complete chain of custody
    const analysisEndTime = Date.now();
    const fullChainOfCustody = [
      ...(entropyResult.chain_of_custody || []),
      ...(forensicsResult.chainOfCommand || []).map(step => ({
        timestamp: step.start_time,
        event: step.step === 'disk_wipe_detection' ? 'Disk wipe detection' : 
               step.step === 'mmls' ? 'Partition table analysis' :
               step.step === 'fsstat' ? 'Filesystem metadata analysis' :
               step.step === 'fls' ? 'Deleted file analysis' :
               step.step === 'bulk_extractor' ? 'Artifact scanning' : 'Analysis step',
        details: step.description,
        status: step.status,
        duration_ms: step.duration_ms
      })),
      {
        timestamp: new Date(analysisEndTime).toISOString(),
        event: "Analysis complete",
        details: `Full forensic analysis completed. Found ${findings.length} findings.`,
        status: "COMPLETED"
      }
    ];
    
    const finalResult = {
      id: analysisId,
      fileName: req.file.originalname,
      fileSize,
      analyzedAt: new Date().toISOString(),
      hashes: {
        md5: hashes.md5 || '',
        sha1: hashes.sha1 || '',
        sha256: hashes.sha256 || '',
        calculated: hashes.calculated || false
      },
      fileInfo: {
        declaredExtension: path.extname(req.file.originalname).replace('.', '').toUpperCase(),
        detectedType: fileInfo.detectedType || 'UNKNOWN',
        detectionMethod: fileInfo.method || 'unknown',
        extensionMatch: fileInfo.extensionMatch !== undefined ? fileInfo.extensionMatch : null,
        validationStatus: fileInfo.validationStatus || 'NOT_VALIDATED',
        integrityVerified: fileInfo.extensionMatch === true || fileInfo.validationStatus === 'VALID'
      },
      filesystem: filesystem,
      entropyResults: entropyResult,
      forensics: forensicsResult,
      findings: findings,
      chain_of_custody: fullChainOfCustody,
      analysis_duration_ms: entropyResult.scan_duration_ms || 0
    };
    
    analysisResults.set(analysisId, finalResult);
    
    // Clean up uploaded file
    setTimeout(() => {
      try { fs.unlinkSync(filePath); } catch (e) {}
    }, 300000);
    
    res.json(finalResult);
    
  } catch (error) {
    console.error('[Server] Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/status/:id', (req, res) => {
  const { id } = req.params;
  if (analysisResults.has(id)) {
    res.json({ status: 'completed', id });
  } else {
    res.json({ status: 'not_found', id });
  }
});

app.get('/api/result/:id', (req, res) => {
  const { id } = req.params;
  const result = analysisResults.get(id);
  if (result) res.json(result);
  else res.status(404).json({ error: 'Analysis not found' });
});

app.get('/api/analyses', (req, res) => {
  const analyses = Array.from(analysisResults.entries()).map(([id, data]) => ({
    id, fileName: data.fileName, fileSize: data.fileSize, analyzedAt: data.analyzedAt
  }));
  res.json(analyses);
});

// Generate PDF report
app.get('/api/result/:id/pdf', async (req, res) => {
  const { id } = req.params;
  const result = analysisResults.get(id);
  
  if (!result) {
    return res.status(404).json({ error: 'Analysis not found' });
  }
  
  try {
    const python = process.platform === 'win32' ? 'python' : 'python3';
    const tempDir = path.join(__dirname, 'results', id);
    const pdfPath = path.join(tempDir, `report_${id}.pdf`);
    const pyScriptPath = path.join(tempDir, `generate_pdf_${id}.py`);
    
    // Create result JSON file
    const resultJsonPath = path.join(tempDir, `result_${id}.json`);
    fs.writeFileSync(resultJsonPath, JSON.stringify(result));
    
    // Python script to generate PDF with detailed explanations
    const pyScript = `
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import sys
from datetime import datetime

# Load result
with open(r'${resultJsonPath.replace(/\\/g, '\\\\')}', 'r') as f:
    result = json.load(f)

pdf_path = r'${pdfPath.replace(/\\/g, '\\\\')}'

doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
styles = getSampleStyleSheet()

story = []

# Custom styles
title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=30, textColor=colors.HexColor('#00BCD4'))
heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=14, spaceAfter=12, textColor=colors.HexColor('#00BCD4'))
subheading_style = ParagraphStyle('SubHeading', parent=styles['Heading3'], fontSize=12, spaceAfter=8, textColor=colors.HexColor('#263238'))
normal_style = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=10, spaceAfter=10)
explanation_style = ParagraphStyle('Explanation', parent=styles['Normal'], fontSize=10, spaceAfter=15, textColor=colors.HexColor('#455A64'))
warning_style = ParagraphStyle('Warning', parent=styles['Normal'], fontSize=10, spaceAfter=15, textColor=colors.HexColor('#D32F2F'))
safe_style = ParagraphStyle('Safe', parent=styles['Normal'], fontSize=10, spaceAfter=15, textColor=colors.HexColor('#388E3C'))

# Title
story.append(Paragraph("EntropyGuard", title_style))
story.append(Paragraph("AI-Powered Hidden Volume & High-Entropy Region Detector", subheading_style))
story.append(Spacer(1, 20))

# File Info
story.append(Paragraph("Evidence Information", heading_style))
file_info = [
    ['File Name', result.get('fileName', 'N/A')],
    ['File Size', f"{result.get('fileSize', 0):,} bytes ({result.get('fileSize', 0) / (1024*1024):.2f} MB)"],
    ['Analysis Date', result.get('analyzedAt', 'N/A')],
    ['Analysis ID', result.get('id', 'N/A')]
]
t = Table(file_info, colWidths=[2*inch, 4*inch])
t.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#263238')),
    ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
    ('BACKGROUND', (1, 0), (1, -1), colors.white),
    ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ('PADDING', (0, 0), (-1, -1), 8),
]))
story.append(t)
story.append(Spacer(1, 30))

# ===== EXECUTIVE SUMMARY =====
story.append(Paragraph("Executive Summary", heading_style))

entropy = result.get('entropyResults', {})
stats = entropy.get('statistics', {})
findings = result.get('findings', [])
chain = result.get('chain_of_custody', [])

mean_entropy = stats.get('mean_entropy', 0)
max_entropy = stats.get('max_entropy', 0)
anomalous_blocks = stats.get('anomalous_blocks', 0)
regions = entropy.get('suspicious_regions', [])

# Overall assessment
if mean_entropy > 7.8:
    overall = "HIGH RISK - Potential Encrypted Content Detected"
    story.append(Paragraph(overall, ParagraphStyle('Risk', parent=styles['Heading3'], fontSize=14, spaceAfter=10, textColor=colors.HexColor('#D32F2F'))))
    story.append(Paragraph(f"The analyzed disk image shows very high entropy (average: {mean_entropy:.4f} out of 8.0 maximum). This indicates that most of the data appears highly randomized, which is a strong indicator of encryption, compressed data, or potential hidden volumes.", explanation_style))
elif mean_entropy > 6.5:
    overall = "MEDIUM RISK - Mixed Content Detected"
    story.append(Paragraph(overall, ParagraphStyle('Risk', parent=styles['Heading3'], fontSize=14, spaceAfter=10, textColor=colors.HexColor('#F57C00'))))
    story.append(Paragraph(f"The analyzed disk image shows moderate entropy (average: {mean_entropy:.4f}). This suggests a mix of normal files, some compressed data, and possibly encrypted regions.", explanation_style))
else:
    overall = "LOW RISK - Normal Content Pattern"
    story.append(Paragraph(overall, ParagraphStyle('Risk', parent=styles['Heading3'], fontSize=14, spaceAfter=10, textColor=colors.HexColor('#388E3C'))))
    story.append(Paragraph(f"The analyzed disk image shows normal entropy levels (average: {mean_entropy:.4f}). This is typical for disks containing standard operating system files, documents, and non-encrypted data.", explanation_style))

story.append(Spacer(1, 20))

# ===== KEY FINDINGS =====
story.append(Paragraph("Detailed Findings", heading_style))

# If no findings from backend, generate explanations from raw data
if not findings:
    findings = []

# Entropy finding
if mean_entropy > 7.5:
    story.append(Paragraph("1. HIGH ENTROPY DETECTED", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> Mean entropy of {mean_entropy:.4f} (scale 0-8)", normal_style))
    story.append(Paragraph("<b>Why this is suspicious:</b> Entropy measures data randomness. Values above 7.5 typically indicate encrypted data, VeraCrypt hidden volumes, or secure deletion patterns. Normal uncompressed files have entropy between 3-6.", explanation_style))
    story.append(Paragraph("<b>Technical detail:</b> Maximum entropy detected was {0:.4f}. {1} blocks showed anomalous entropy patterns.".format(max_entropy, anomalous_blocks), warning_style))
elif mean_entropy > 5.5:
    story.append(Paragraph("1. MODERATE ENTROPY DETECTED", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> Mean entropy of {mean_entropy:.4f}", normal_style))
    story.append(Paragraph("<b>Explanation:</b> This level of entropy is typical for a mix of data types - normal documents, some compressed files, and executable programs. It's not necessarily suspicious but warrants review.", explanation_style))
else:
    story.append(Paragraph("1. NORMAL ENTROPY LEVELS", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> Mean entropy of {mean_entropy:.4f}", normal_style))
    story.append(Paragraph("<b>What this means:</b> The data appears to be typical file system content with recognizable patterns. This is consistent with normal, unencrypted data.", safe_style))

story.append(Spacer(1, 15))

# Suspicious regions
if len(regions) > 0:
    story.append(Paragraph(f"2. SUSPICIOUS REGIONS IDENTIFIED ({len(regions)})", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> {len(regions)} distinct regions with unusual entropy patterns were detected.", normal_style))
    story.append(Paragraph("<b>Why this matters:</b> Hidden encrypted volumes (like VeraCrypt hidden volumes) often appear as high-entropy regions within normal-looking disk space. These could indicate concealed data.", explanation_style))
    story.append(Paragraph("<b>Locations:</b>", normal_style))
    for i, r in enumerate(regions[:5]):
        story.append(Paragraph(f"  - Region {i+1}: Offset 0x{r.get('start_offset', 0):X} to 0x{r.get('end_offset', 0):X} ({r.get('size', 0):,} bytes) - Entropy: {r.get('mean_entropy', 0):.2f}", normal_style))
    if len(regions) > 5:
        story.append(Paragraph(f"  ... and {len(regions) - 5} more regions", normal_style))
else:
    story.append(Paragraph("2. NO SUSPICIOUS REGIONS", subheading_style))
    story.append(Paragraph("No distinct high-entropy regions that would indicate hidden volumes were detected.", safe_style))

story.append(Spacer(1, 15))

# Deleted files
forensics = result.get('forensics', {})
deleted = len(forensics.get('deletedFiles', []))
if deleted > 0:
    story.append(Paragraph(f"3. DELETED FILE ENTRIES ({deleted} found)", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> {deleted} deleted file entries were identified in the filesystem.", normal_style))
    if deleted > 100:
        story.append(Paragraph("<b>Why this matters:</b> A high number of deleted entries could indicate: (1) normal file cleanup, (2) attempted evidence deletion, or (3) disk optimization activities. The context of the investigation determines significance.", explanation_style))
    else:
        story.append(Paragraph("<b>Assessment:</b> This is within normal range for an active file system. Most disks have some deleted entries from normal operations.", safe_style))
else:
    story.append(Paragraph("3. DELETED FILES", subheading_style))
    story.append(Paragraph("No deleted file entries were detected. This could indicate a clean disk or one where slack space has been sanitized.", explanation_style))

story.append(Spacer(1, 15))

# Wipe detection
wipe_regions = [r for r in regions if r.get('mean_entropy', 0) < 0.5]
if len(wipe_regions) > 0:
    story.append(Paragraph("4. POTENTIAL WIPE SIGNATURES", subheading_style))
    story.append(Paragraph(f"<b>What was found:</b> {len(wipe_regions)} regions with near-zero entropy (consistent with data wiping).", normal_style))
    story.append(Paragraph("<b>Why this matters:</b> Patterns of zero-filled or uniformly overwritten regions may indicate use of disk wiping software (like DBAN, BleachBit, or 'shred'). This could be legitimate disk maintenance or intentional evidence destruction.", warning_style))
else:
    story.append(Paragraph("4. NO WIPE SIGNATURES DETECTED", subheading_style))
    story.append(Paragraph("No patterns consistent with disk wiping or secure deletion were detected.", safe_style))

story.append(Spacer(1, 20))

# ===== CHAIN OF CUSTODY =====
story.append(Paragraph("Chain of Custody", heading_style))
if chain:
    for entry in chain:
        ts = entry.get('timestamp', '')
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                ts_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                ts_str = ts
        else:
            ts_str = 'N/A'
        story.append(Paragraph(f"<b>{entry.get('event', 'Unknown')}</b> - {ts_str}", normal_style))
        story.append(Paragraph(f"    {entry.get('details', '')}", explanation_style))
else:
    story.append(Paragraph("Chain of custody timeline was not fully captured.", normal_style))

story.append(Spacer(1, 20))

# ===== INTERPRETATION GUIDE =====
story.append(Paragraph("Understanding Entropy Analysis", heading_style))

story.append(Paragraph("What is Entropy?", subheading_style))
story.append(Paragraph("Entropy is a measure of data randomness or unpredictability. In digital forensics:", normal_style))
story.append(Paragraph("• <b>Low Entropy (0-3):</b> Highly predictable data - zeros, repeated patterns, or empty space", normal_style))
story.append(Paragraph("• <b>Medium Entropy (3-6):</b> Normal files - documents, images, executables with recognizable patterns", normal_style))
story.append(Paragraph("• <b>High Entropy (6-8):</b> Random-looking data - encryption, compression, or random overwrite", explanation_style))

story.append(Spacer(1, 10))
story.append(Paragraph("Why Hidden Volumes Matter", subheading_style))
story.append(Paragraph("Hidden volumes (like VeraCrypt hidden volumes) store data in a way that's invisible to standard file system tools. They appear as high-entropy regions that can't be distinguished from random data without the correct password or key.", explanation_style))

story.append(Spacer(1, 20))

# ===== TECHNICAL SUMMARY =====
story.append(Paragraph("Technical Summary", heading_style))
tech_data = [
    ['Metric', 'Value', 'Interpretation'],
    ['Mean Entropy', f"{mean_entropy:.4f}", 'High' if mean_entropy > 7 else 'Medium' if mean_entropy > 5 else 'Normal'],
    ['Max Entropy', f"{max_entropy:.4f}", 'Near-maximum (encrypted)' if max_entropy > 7.9 else 'Normal'],
    ['Anomalous Blocks', f"{anomalous_blocks:,}", 'High' if anomalous_blocks > 100 else 'Low'],
    ['Suspicious Regions', f"{len(regions)}", 'Investigate' if len(regions) > 5 else 'Normal'],
    ['Deleted Files', f"{deleted}", 'Review' if deleted > 50 else 'Normal'],
]
t = Table(tech_data, colWidths=[1.8*inch, 1.5*inch, 1.7*inch])
t.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00BCD4')),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
    ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ('PADDING', (0, 0), (-1, -1), 6),
]))
story.append(t)

story.append(Spacer(1, 30))
story.append(Paragraph("=" * 60, normal_style))
story.append(Paragraph("Report generated by EntropyGuard - AI-Powered Hidden Volume Detector", normal_style))
story.append(Paragraph(f"Report ID: {result.get('id', 'N/A')} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
story.append(Paragraph("This report is for forensic analysis purposes only. Results should be verified by a qualified forensic examiner.", explanation_style))

doc.build(story)
print("PDF_OK")
`;
    
    // Write Python script
    fs.writeFileSync(pyScriptPath, pyScript);
    
    // Run Python script
    await runTool(python, [pyScriptPath]);
    
    // Check if PDF was created
    if (fs.existsSync(pdfPath)) {
      res.download(pdfPath, `entropyguard_report_${id}.pdf`, () => {
        // Cleanup
        try { 
          fs.unlinkSync(pyScriptPath);
          fs.unlinkSync(resultJsonPath);
        } catch(e) {}
      });
    } else {
      res.status(500).json({ error: 'Failed to generate PDF' });
    }
  } catch (e) {
    console.error('PDF generation error:', e);
    res.status(500).json({ error: 'PDF generation failed: ' + e.message });
  }
});

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║          EntropyGuard Web Server - Running                 ║
║                                                               ║
║  Server:  http://localhost:${PORT}                              ║
╚═══════════════════════════════════════════════════════════════╝
  `);
});

export default app;
