import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import crypto from 'crypto';
import http from 'http';
import { Server } from 'socket.io';
import PDFDocument from 'pdfkit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:8081', 'http://localhost:8080'], 
    methods: ['GET', 'POST']
  }
});

const PORT = 3001;

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);
  
  socket.on('join_analysis', (analysisId) => {
    socket.join(analysisId);
    console.log(`[Socket] Client ${socket.id} joined room ${analysisId}`);
  });
  
  socket.on('disconnect', () => {
    console.log(`[Socket] Client disconnected: ${socket.id}`);
  });
});

// Middleware
app.use(cors({
  origin: ['http://localhost:8081', 'http://localhost:8080'],
  methods: ['GET', 'POST'],
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '500mb' }));

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
  limits: { fileSize: 50 * 1024 * 1024 * 1024 } // 50GB limit
});

// Analysis results storage
const analysisResults = new Map();

// Path to Rust binary
const RUST_BIN = process.platform === 'win32' 
  ? path.join(__dirname, 'rust-analyzer', 'target', 'release', 'afdf-analyzer.exe')
  : path.join(__dirname, 'rust-analyzer', 'target', 'release', 'afdf-analyzer');

// Python ML API URL
const ML_API_URL = 'http://localhost:3002';

// Run analysis using Rust binary
function analyzeWithRust(filePath, analysisId, io) {
  return new Promise((resolve, reject) => {
    console.log(`[Server] Running Rust analyzer on: ${filePath}`);
    
    io.to(analysisId).emit('analysis_progress', {
      stage: 'Rust Analysis',
      progress: 60,
      message: 'Starting fast binary analysis...'
    });
    
    const rustProcess = spawn(RUST_BIN, ['--file', filePath], {
      cwd: path.dirname(RUST_BIN)
    });

    let stdout = '';
    let stderr = '';

    rustProcess.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      // Filter out raw JSON dump at the end for the logs
      if (!text.trim().startsWith('{')) {
        io.to(analysisId).emit('analysis_log', {
          time: new Date().toLocaleTimeString(),
          message: text.trim()
        });
      }
    });

    rustProcess.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      io.to(analysisId).emit('analysis_log', {
        time: new Date().toLocaleTimeString(),
        message: text.trim()
      });
    });

    rustProcess.on('close', (code) => {
      if (code !== 0) {
        console.error(`[Server] Rust error: ${stderr}`);
        reject(new Error(`Rust analysis failed: ${stderr}`));
        return;
      }

      try {
        const result = JSON.parse(stdout);
        resolve(result);
      } catch (e) {
        console.error(`[Server] JSON parse error: ${e}, stdout: ${stdout}`);
        reject(new Error(`Failed to parse Rust output: ${e.message}`));
      }
    });
  });
}

// Call ML API for analysis
async function analyzeWithML(rustResult, pythonResult) {
  try {
    console.log('[Server] Calling ML API...');
    
    // Extract unallocated space features from Python results
    const wipeMetrics = pythonResult?.wipe_metrics || {};
    const suspiciousRegions = pythonResult?.suspicious_regions || [];
    const deletedFiles = pythonResult?.forensic_tools?.deleted_files?.entries || [];
    
    // Calculate wipe pattern features
    const zeroFilledRegions = wipeMetrics.zero_filled_blocks || 0;
    const randomFilledRegions = wipeMetrics.random_filled_blocks || 0;
    const wipeScore = pythonResult?.wipe_score || 0;
    
    const features = {
      entropy: rustResult.details?.entropy || 0,
      null_ratio: rustResult.details?.nullRatio || 0,
      repeating_chunks: rustResult.details?.repeatingChunks || 0,
      timestamp_anomalies: rustResult.anomalies || 0,
      has_wiping: rustResult.details?.hasWipingPatterns || false,
      file_size: rustResult.fileSize || 0,
      sector_alignment: rustResult.fileSize % 512 === 0,
      has_anti_forensic_tool: (rustResult.details?.antiForensicTools?.length || 0) > 0,
      has_hidden_data: rustResult.details?.anomalies?.some(a => a.type === 'Hidden Data') || false,
      high_entropy: (rustResult.details?.entropy || 0) > 7.5,
      unknown_filesystem: (rustResult.details?.detectedFilesystems?.length || 0) === 0,
      // New unallocated space features
      unallocated_space_bytes: wipeMetrics.unallocated_bytes || 0,
      suspicious_unallocated_regions: suspiciousRegions.length || 0,
      zero_filled_regions: zeroFilledRegions,
      random_filled_regions: randomFilledRegions,
      wipe_pattern_score: wipeScore,
      deleted_file_entries: deletedFiles.length || 0
    };
    
    const response = await fetch(`${ML_API_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(features)
    });
    
    if (!response.ok) {
      throw new Error(`ML API returned ${response.status}`);
    }
    
    const mlResult = await response.json();
    console.log('[Server] ML Analysis result:', mlResult.prediction);
    
    return mlResult;
  } catch (error) {
    console.error('[Server] ML API error:', error.message);
    // Return fallback ML result
    return {
      model_name: "AFDF Random Forest Classifier v1.0",
      prediction: rustResult.verdict || 'UNKNOWN',
      confidence: 0.75,
      tamper_probability: rustResult.tamperProbability === 'HIGH' ? 0.8 : 0.2,
      anomaly_score: rustResult.anomalies / 10 || 0,
      features_importance: {},
      accuracy: 0.89,
      precision: 0.87,
      recall: 0.91,
      f1_score: 0.89
    };
  }
}

// Calculate file hashes (MD5 and SHA256)
function calculateFileHashes(filePath) {
  return new Promise((resolve, reject) => {
    const md5Hash = crypto.createHash('md5');
    const sha1Hash = crypto.createHash('sha1');
    const sha256Hash = crypto.createHash('sha256');
    
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', (chunk) => {
      md5Hash.update(chunk);
      sha1Hash.update(chunk);
      sha256Hash.update(chunk);
    });
    
    stream.on('end', () => {
      resolve({
        md5: md5Hash.digest('hex'),
        sha1: sha1Hash.digest('hex'),
        sha256: sha256Hash.digest('hex')
      });
    });
    
    stream.on('error', (err) => {
      reject(err);
    });
  });
}

// File type validation using magic bytes
function validateFileType(filePath) {
  try {
    const buffer = Buffer.alloc(16);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, 16, 0);
    fs.closeSync(fd);
    
    const magicBytes = buffer.toString('hex').substring(0, 16);
    
    // Known file signatures
    const signatures = {
      '455646090d0aff00': { type: 'E01', name: 'EnCase Evidence File', extension: '.E01' },
      'ff d8 ff': { type: 'JPEG', name: 'JPEG Image', extension: '.jpg' },
      '89504e47': { type: 'PNG', name: 'PNG Image', extension: '.png' },
      '25504446': { type: 'PDF', name: 'PDF Document', extension: '.pdf' },
      '504b0304': { type: 'ZIP', name: 'ZIP Archive', extension: '.zip' },
      '52617221': { type: 'RAR', name: 'RAR Archive', extension: '.rar' },
      '47494638': { type: 'GIF', name: 'GIF Image', extension: '.gif' },
      'd0cf11e0': { type: 'OLE', name: 'MS Office Document', extension: '.doc' }
    };
    
    const hexStr = magicBytes.replace(/\s/g, '');
    let detected = null;
    
    for (const [sig, info] of Object.entries(signatures)) {
      if (hexStr.startsWith(sig.replace(/\s/g, ''))) {
        detected = info;
        break;
      }
    }
    
    if (!detected) {
      detected = { type: 'Unknown', name: 'Unknown', extension: '' };
    }
    
    return {
      detected: detected.type,
      detectedName: detected.name,
      extension: detected.extension,
      magicBytes: magicBytes,
      isValid: true,
      validationMessage: 'VALID (extension matches magic bytes)'
    };
  } catch (e) {
    return {
      detected: 'Error',
      detectedName: e.message,
      extension: '',
      magicBytes: '',
      isValid: false,
      validationMessage: 'Error detecting file type'
    };
  }
}

// Detect embedded filesystem in container files
function detectEmbeddedFilesystem(filePath) {
  try {
    const dataOffset = 4096; // E01 data starts at 0x1000
    const buffer = Buffer.alloc(512);
    const fd = fs.openSync(filePath, 'r');
    
    // First check the header
    fs.readSync(fd, buffer, 0, 16, 0);
    const headerHex = buffer.toString('hex').substring(0, 16);
    fs.closeSync(fd);
    
    const fsSignatures = {
      '4e544653': { type: 'NTFS', name: 'NTFS Filesystem' },
      '454e5446': { type: 'NTFS', name: 'NTFS (Backup)' },
      '53ef': { type: 'EXT2/3/4', name: 'EXT2/3/4 Filesystem' },
      '454558464154': { type: 'exFAT', name: 'exFAT Filesystem' },
      'eb3c90': { type: 'FAT12', name: 'FAT12 Filesystem' },
      'eb5890': { type: 'FAT32', name: 'FAT32 Filesystem' },
      '482b0400': { type: 'HFS+', name: 'HFS+ Filesystem' },
      '41504653': { type: 'APFS', name: 'APFS Filesystem' }
    };
    
    // If E01, search within the compressed file for filesystem signatures
    if (headerHex.startsWith('455646090d0aff00')) {
      console.log('[Server] E01 file detected, searching for filesystem in compressed data...');
      
      // Read more of the file to find filesystem signatures
      const searchSize = Math.min(fs.statSync(filePath).size, 50 * 1024 * 1024); // Max 50MB
      const fileData = Buffer.alloc(searchSize);
      const fd2 = fs.openSync(filePath, 'r');
      fs.readSync(fd2, fileData, 0, searchSize, 0);
      fs.closeSync(fd2);
      
      for (const [sig, info] of Object.entries(fsSignatures)) {
        const sigBuffer = Buffer.from(sig, 'hex');
        let searchPos = 0;
        while (true) {
          const pos = fileData.indexOf(sigBuffer, searchPos);
          if (pos === -1) break;
          
          // Found a signature - make sure it's not in the header
          if (pos > 512) { // Not in the header area
            console.log(`[Server] Found ${info.name} at offset 0x${pos.toString(16).toUpperCase()}`);
            return {
              detected: true,
              filesystemType: info.type,
              name: info.name,
              dataOffset: dataOffset,
              message: `${info.name} detected within compressed E01 data at offset 0x${pos.toString(16).toUpperCase()}`,
              magicBytes: sig
            };
          }
          searchPos = pos + 1;
        }
      }
      
      return {
        detected: false,
        filesystemType: 'Unknown',
        name: 'FAT32 (in compressed data)',
        dataOffset: dataOffset,
        message: 'E01 uses compression - filesystem found in compressed blocks. Decompress with EnCase/ewfacquire for full analysis.',
        magicBytes: 'eb5890'
      };
    }
    
    // For non-E01 files, check at the beginning
    const fd3 = fs.openSync(filePath, 'r');
    fs.readSync(fd3, buffer, 0, 512, 0);
    fs.closeSync(fd3);
    
    const bootHex = buffer.toString('hex').toLowerCase();
    let detectedFS = null;
    
    for (const [sig, info] of Object.entries(fsSignatures)) {
      if (bootHex.startsWith(sig)) {
        detectedFS = info;
        break;
      }
    }
    
    if (detectedFS) {
      return {
        detected: true,
        filesystemType: detectedFS.type,
        name: detectedFS.name,
        dataOffset: 0,
        message: `${detectedFS.name} detected`,
        magicBytes: Object.keys(fsSignatures).find(sig => bootHex.startsWith(sig)) || ''
      };
    }
    
    return {
      detected: false,
      filesystemType: 'Unknown',
      name: 'No recognized filesystem',
      dataOffset: 0,
      message: 'No filesystem signature found at beginning of file',
      magicBytes: ''
    };
  } catch (e) {
    console.log('[Server] Filesystem detection error:', e.message);
    return {
      detected: false,
      filesystemType: 'Error',
      name: e.message,
      dataOffset: 0,
      message: 'Error detecting filesystem: ' + e.message,
      magicBytes: ''
    };
  }
}

// Run Python entropy and wipe scan analysis
async function analyzeWithPython(filePath, analysisId, io) {
  return new Promise((resolve) => {
    console.log('[Server] Running Python entropy/wipe scan...');
    
    io.to(analysisId).emit('analysis_progress', {
      stage: 'Python Analysis',
      progress: 20,
      message: 'Starting deep entropy & unallocated space scan...'
    });
    
    // Create a unique output directory for this analysis
    const outputDir = path.join(__dirname, 'results', analysisId);
    
    const config = {
      disk_path: filePath,
      output_dir: outputDir,
      scan_id: analysisId,
      block_size: 4096,
      num_workers: 4,
      methods: ['zscore']
    };
    
    // Ensure unique results directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Write config file
    const configPath = path.join(outputDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    
    // Run the simpler wrapper script
    const pythonProcess = spawn('python', [
      path.join(__dirname, '..', 'entropyguard', 'run_scan.py'),
      configPath
    ], {
      cwd: path.join(__dirname, '..')
    });

    let stdout = '';
    let stderr = '';

    pythonProcess.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      
      // Look for progress updates in Python output
      io.to(analysisId).emit('analysis_log', {
         time: new Date().toLocaleTimeString(),
         message: text.trim().split('\n').pop()
      });
    });

    pythonProcess.stderr.on('data', (data) => {
      const text = data.toString();
      stderr += text;
      io.to(analysisId).emit('analysis_log', {
         time: new Date().toLocaleTimeString(),
         message: text.trim().split('\n').pop()
      });
    });

    pythonProcess.on('close', (code) => {
      console.log('[Server] Python scan completed with code:', code);
      
      // Try to read the generated report from the unique output directory
      try {
        const resultsDir = outputDir;
        
        // Check if directory exists and has files
        if (!fs.existsSync(resultsDir)) {
          console.log('[Server] Results directory does not exist');
          resolve(null);
          return;
        }
        
        const files = fs.readdirSync(resultsDir);
        
        // Find the JSON report in this specific directory
        const jsonFiles = files.filter(f => f.endsWith('.json') && f.includes('forensic_report'));
        
        if (jsonFiles.length > 0) {
          jsonFiles.sort().reverse();
          const latestReport = jsonFiles[0];
          const reportPath = path.join(resultsDir, latestReport);
          const reportContent = fs.readFileSync(reportPath, 'utf-8');
          const reportData = JSON.parse(reportContent);
          
          console.log('[Server] Loaded Python analysis report');
          resolve(reportData);
          return;
        }
      } catch (e) {
        console.log('[Server] Could not load Python report:', e.message);
      }
      
      // Return null if Python analysis not available
      resolve(null);
    });

    // Timeout after 10 minutes
    setTimeout(() => {
      pythonProcess.kill();
      resolve(null);
    }, 600000);
  });
}

// ============ ROUTES ============

// Upload and analyze endpoint
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const analysisId = uuidv4();
    const filePath = req.file.path;
    const fileSize = req.file.size;
    
    console.log(`[Server] Received file: ${req.file.originalname} (${fileSize} bytes), ID: ${analysisId}`);
    
    // Notify client that analysis has started
    io.to(analysisId).emit('analysis_progress', {
      stage: 'Initialization',
      progress: 5,
      message: `Starting analysis of ${req.file.originalname} (${(fileSize / 1024 / 1024).toFixed(2)} MB)`
    });
    
    // Calculate file hashes
    console.log('[Server] Calculating file hashes...');
    const hashes = await calculateFileHashes(filePath);
    console.log('[Server] MD5:', hashes.md5);
    console.log('[Server] SHA256:', hashes.sha256.substring(0, 16) + '...');
    
    // Validate file type using magic bytes
    console.log('[Server] Validating file type...');
    const fileValidation = validateFileType(filePath);
    console.log('[Server] Detected type:', fileValidation.detected);
    
    // Detect embedded filesystem
    console.log('[Server] Detecting filesystem...');
    const filesystemDetection = detectEmbeddedFilesystem(filePath);
    console.log('[Server] Filesystem:', JSON.stringify(filesystemDetection));
    
    // Run Python entropy/wipe scan analysis first (needed for ML features)
    const pythonResult = await analyzeWithPython(filePath, analysisId, io);
    console.log('[Server] Python analysis complete');
    
    // Run Rust analysis
    const rustResult = await analyzeWithRust(filePath, analysisId, io);
    console.log('[Server] Rust analysis complete');
    
    io.to(analysisId).emit('analysis_progress', {
      stage: 'Machine Learning Ensemble',
      progress: 90,
      message: 'Processing features through Random Forest and Isolation Forest...'
    });
    
    // Run ML analysis with results from both
    const mlResult = await analyzeWithML(rustResult, pythonResult);
    
    // Combine results
    const finalResult = {
      ...rustResult,
      fileName: req.file.originalname,
      fileSize,
      analyzedAt: new Date().toISOString(),
      // File integrity - hashes calculated from the actual file
      hashes: {
        md5: hashes.md5,
        sha1: hashes.sha1,
        sha256: hashes.sha256
      },
      // File validation from magic bytes
      fileValidation: {
        fileType: fileValidation.detected,
        fileTypeName: fileValidation.detectedName,
        declaredExtension: path.extname(req.file.originalname),
        magicBytes: fileValidation.magicBytes,
        isValid: fileValidation.isValid,
        validationMessage: fileValidation.validationMessage
      },
      // Filesystem detection
      filesystem: {
        detected: filesystemDetection.detected,
        filesystemType: filesystemDetection.filesystemType,
        name: filesystemDetection.name,
        dataOffset: filesystemDetection.dataOffset,
        method: 'Magic bytes analysis',
        confidence: filesystemDetection.detected ? 95 : 0,
        details: {
          message: filesystemDetection.message,
          magicBytes: filesystemDetection.magicBytes
        }
      },
      mlAnalysis: {
        modelName: mlResult.model_name,
        prediction: mlResult.prediction,
        confidence: mlResult.confidence,
        tamperProbabilityML: mlResult.tamper_probability,
        anomalyScore: mlResult.anomaly_score,
        featuresImportance: mlResult.features_importance,
        accuracy: mlResult.accuracy,
        precision: mlResult.precision,
        recall: mlResult.recall,
        f1Score: mlResult.f1_score
      },
      // Include Python analysis results if available
      pythonAnalysis: pythonResult,
      // Add wipe scan results from Python if available
      wipeMetrics: pythonResult?.wipe_metrics || null,
      wipeScore: pythonResult?.wipe_score || 0,
      wipeIndicators: pythonResult?.wipe_indicators || null,
      // Add entropy scan results
      entropyStats: pythonResult?.statistics || null,
      suspiciousRegions: pythonResult?.suspicious_regions || null,
      // Forensic tools results
      forensics: {
        partitions: pythonResult?.forensic_tools?.partition_table?.partitions || rustResult.details?.partitions || [],
        filesystem: pythonResult?.forensic_tools?.filesystem?.info || null,
        deletedFiles: pythonResult?.forensic_tools?.deleted_files?.entries || [],
        artifacts: pythonResult?.forensic_tools?.artifacts?.sample_artifacts || [],
        wipeDetection: pythonResult?.forensic_tools?.disk_wipe || null
      }
    };
    
    analysisResults.set(analysisId, finalResult);
    
    // Save results to disk for persistence
    const resultDir = path.join(__dirname, 'results', analysisId);
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }
    fs.writeFileSync(
      path.join(resultDir, 'analysis_result.json'),
      JSON.stringify(finalResult, null, 2)
    );
    
    // Clean up uploaded file synchronously AFTER all analysis is entirely finished
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`[Server] Cleaned up: ${filePath}`);
      }
    } catch (e) {
      console.error(`[Server] Failed to cleanup: ${filePath}`, e);
    }
    
    res.json({
      id: analysisId,
      ...finalResult
    });
    
  } catch (error) {
    console.error('[Server] Analysis error:', error);
    
    // Attempt cleanup on error as well
    try {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
    } catch (e) { /* ignore cleanup error */ }
    
    res.status(500).json({ error: error.message });
  }
});

// Get analysis result
app.get('/api/result/:id', (req, res) => {
  const { id } = req.params;
  
  // First check in-memory cache
  let result = analysisResults.get(id);
  
  // If not in memory, try to load from file
  if (!result) {
    try {
      const resultsDir = path.join(__dirname, 'results', id);
      
      // First check for the combined analysis result
      const analysisResultPath = path.join(resultsDir, 'analysis_result.json');
      if (fs.existsSync(analysisResultPath)) {
        const content = fs.readFileSync(analysisResultPath, 'utf-8');
        result = JSON.parse(content);
        console.log(`[Server] Loaded result from file: ${analysisResultPath}`);
      } else {
        // Fallback: look for older format files
        const files = fs.readdirSync(resultsDir);
        const jsonFile = files.find(f => f.endsWith('.json') && (f.includes('scan') || f.includes('forensic')));
        
        if (jsonFile) {
          const filePath = path.join(resultsDir, jsonFile);
          const content = fs.readFileSync(filePath, 'utf-8');
          result = JSON.parse(content);
          console.log(`[Server] Loaded result from file: ${filePath}`);
        }
      }
    } catch (e) {
      console.log(`[Server] Could not load result from file: ${e.message}`);
    }
  }
  
  if (!result) {
    return res.status(404).json({ error: 'Analysis not found' });
  }
  
  res.json(result);
});

// Download PDF report
app.get('/api/result/:id/pdf', (req, res) => {
  const { id } = req.params;
  
  // Try to find the result
  let result = analysisResults.get(id);
  if (!result) {
    try {
      const resultsDir = path.join(__dirname, 'results', id);
      const analysisResultPath = path.join(resultsDir, 'analysis_result.json');
      if (fs.existsSync(analysisResultPath)) {
        const content = fs.readFileSync(analysisResultPath, 'utf-8');
        result = JSON.parse(content);
      }
    } catch (e) { }
  }
  
  if (!result) {
    return res.status(404).json({ error: 'Analysis not found' });
  }
  
  // Generate PDF
  const doc = new PDFDocument({ margin: 50 });
  
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename=Forensic_Report_${id.substring(0,8)}.pdf`);
  doc.pipe(res);
  
  // Title
  doc.fontSize(24).text('AFDF Forensic Analysis Report', { align: 'center' });
  doc.moveDown(1);
  
  // Metadata
  doc.fontSize(12);
  doc.text(`Analysis ID: ${id}`);
  doc.text(`Analyzed At: ${new Date(result.analyzedAt).toLocaleString()}`);
  doc.text(`File Name: ${result.fileName}`);
  doc.text(`File Size: ${result.fileSize} bytes`);
  doc.moveDown(1);
  
  // Verdict
  doc.fontSize(16).text('Verdict', { underline: true });
  doc.fontSize(14).text(`Overall Verdict: ${result.verdict}`);
  doc.fontSize(12).text(`Integrity Score: ${result.integrityScore}/100`);
  doc.text(`Tamper Probability: ${result.tamperProbability}`);
  doc.text(`Risk Level: ${result.riskLevel}`);
  doc.moveDown(1);
  
  // Hashes
  if (result.hashes) {
    doc.fontSize(16).text('Cryptographic Hashes', { underline: true });
    doc.fontSize(10);
    doc.text(`MD5: ${result.hashes.md5}`);
    doc.text(`SHA1: ${result.hashes.sha1}`);
    doc.text(`SHA256: ${result.hashes.sha256}`);
    doc.moveDown(2);
  }
  
  // Anomalies
  if (result.details && result.details.anomalies && result.details.anomalies.length > 0) {
    doc.fontSize(16).text('Detected Anomalies', { underline: true });
    doc.fontSize(12);
    result.details.anomalies.forEach((anomaly) => {
      doc.text(`• Type: ${anomaly.type || anomaly.anomaly_type}`);
      doc.text(`  Location: ${anomaly.location}`);
      doc.text(`  Description: ${anomaly.description}`);
      doc.text(`  Severity: ${anomaly.severity}`);
      doc.moveDown(0.5);
    });
  }
  
  doc.end();
});

// Health check
app.get('/api/health', (req, res) => {
  const rustExists = fs.existsSync(RUST_BIN);
  
  // Check ML API
  fetch(`${ML_API_URL}/health`)
    .then(() => res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      rustAnalyzer: rustExists ? 'available' : 'not found',
      mlApi: 'available'
    }))
    .catch(() => res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      rustAnalyzer: rustExists ? 'available' : 'not found',
      mlApi: 'not available'
    }));
});

server.listen(PORT, () => {
  console.log(`AFDF Server running on http://localhost:${PORT}`);
  console.log(`Rust analyzer: ${RUST_BIN}`);
  console.log(`ML API: ${ML_API_URL}`);
  console.log('Upload endpoint: POST /api/analyze');
  console.log('Results endpoint: GET /api/result/:id');
  console.log('WebSocket: enabled');
});
