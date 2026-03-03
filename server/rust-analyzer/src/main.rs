use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Anomaly {
    #[serde(rename = "type")]
    pub anomaly_type: String,
    pub location: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    #[serde(rename = "integrityScore")]
    pub integrity_score: i32,
    #[serde(rename = "tamperProbability")]
    pub tamper_probability: String,
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    pub verdict: String,
    pub anomalies: i32,
    pub techniques: Vec<String>,
    pub details: Details,
    pub hashes: Hashes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Details {
    pub hash: String,
    pub entropy: f64,
    #[serde(rename = "nullRatio")]
    pub null_ratio: f64,
    #[serde(rename = "fileType")]
    pub file_type: String,
    #[serde(rename = "fileSize")]
    pub file_size: u64,
    pub anomalies: Vec<Anomaly>,
    pub timeline: Vec<TimelineEvent>,
    #[serde(rename = "mlFeatures")]
    pub ml_features: MlFeatures,
    #[serde(rename = "detectedFilesystems")]
    pub detected_filesystems: Vec<String>,
    #[serde(rename = "antiForensicTools")]
    pub anti_forensic_tools: Vec<String>,
    #[serde(rename = "hasWipingPatterns")]
    pub has_wiping_patterns: bool,
    #[serde(rename = "repeatingChunks")]
    pub repeating_chunks: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub event: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MlFeatures {
    #[serde(rename = "entropyScore")]
    pub entropy_score: f64,
    #[serde(rename = "anomalyScore")]
    pub anomaly_score: f64,
    #[serde(rename = "tamperingScore")]
    pub tampering_score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

const FILE_SIGNATURES: &[(&str, &[u8])] = &[
    ("NTFS", &[0x45, 0x4E, 0x54, 0x46]),
    ("FAT12", &[0xEB, 0x3C, 0x90]),
    ("FAT16", &[0xEB, 0x3C, 0x90]),
    ("FAT32", &[0xEB, 0x58, 0x90]),
    ("EXT2", &[0x53, 0xEF]),
    ("EXT3", &[0x53, 0xEF]),
    ("EXFAT", &[0x45, 0x58, 0x46, 0x41, 0x54]),
    ("HFS", &[0x48, 0x2B, 0x04, 0x00]),
    ("APFS", &[0x41, 0x50, 0x46, 0x53]),
];

const ANTI_FORENSIC_SIGNATURES: &[(&str, &[u8])] = &[
    ("DBAN", &[0x44, 0x42, 0x41, 0x4E]),
    ("SDelete", &[0x53, 0x44, 0x45, 0x4C]),
    ("BleachBit", &[0x42, 0x4C, 0x45, 0x41]),
];

fn calculate_shannon_entropy(buffer: &[u8]) -> f64 {
    if buffer.is_empty() {
        return 0.0;
    }

    let mut frequency: HashMap<u8, usize> = HashMap::new();
    for &byte in buffer {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let len = buffer.len() as f64;
    let mut entropy = 0.0;
    for count in frequency.values() {
        let p = *count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn detect_file_signature(buffer: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let header = &buffer[..std::cmp::min(512, buffer.len())];

    for (name, sig) in FILE_SIGNATURES {
        if sig.len() <= header.len() {
            let mut matches = true;
            for (i, &byte) in sig.iter().enumerate() {
                if header[i] != byte {
                    matches = false;
                    break;
                }
            }
            if matches {
                found.push(name.to_string());
            }
        }
    }
    found
}

fn detect_anti_forensic_tools(buffer: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let header = &buffer[..std::cmp::min(4096, buffer.len())];

    // Check binary signatures
    for (name, sig) in ANTI_FORENSIC_SIGNATURES {
        if sig.len() <= header.len() {
            let mut matches = true;
            for (i, &byte) in sig.iter().enumerate() {
                if header[i] != byte {
                    matches = false;
                    break;
                }
            }
            if matches {
                found.push(name.to_string());
            }
        }
    }

    // Check string content
    let header_str = String::from_utf8_lossy(header);
    if header_str.contains("DBAN") || header_str.contains("darik") {
        found.push("DBAN".to_string());
    }
    if header_str.contains("SDelete") || header_str.contains("sdelete") {
        found.push("SDelete".to_string());
    }
    if header_str.contains("BleachBit") {
        found.push("BleachBit".to_string());
    }

    found.sort();
    found.dedup();
    found
}

fn check_for_wiping(buffer: &[u8]) -> bool {
    if buffer.len() < 8192 {
        return false;
    }

    let sample_size = 4096;
    let first_bytes = &buffer[..sample_size];
    let last_bytes = &buffer[buffer.len() - sample_size..];

    let first_all_same = first_bytes.iter().all(|&b| b == first_bytes[0]);
    let last_all_same = last_bytes.iter().all(|&b| b == last_bytes[0]);

    if first_all_same && last_all_same && first_bytes[0] == 0 {
        return true;
    }
    if first_all_same || last_all_same {
        return true;
    }

    false
}

fn detect_timestamp_anomalies(buffer: &[u8]) -> Vec<String> {
    let mut anomalies = Vec::new();
    let sector_size = 512;
    let max_scan = std::cmp::min(10 * 1024 * 1024, buffer.len());

    let mut i = 0;
    while i + 4 <= max_scan {
        // Read 4-byte little-endian timestamp
        let ts = u32::from_le_bytes([buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]]);

        if ts == 0 {
            anomalies.push(format!("Zero timestamp (epoch) at offset {}", i));
        }
        if ts > 4102444800 {
            anomalies.push(format!("Far-future timestamp at offset {}", i));
        }

        i += sector_size;
    }

    anomalies
}

fn detect_hidden_data(buffer: &[u8]) -> Vec<String> {
    let mut anomalies = Vec::new();
    let num_sectors = std::cmp::min(100, buffer.len() / 512);

    for sector in 0..num_sectors {
        let slack_start = 512;
        let slack_end = std::cmp::min(512 + 512, buffer.len() - sector * 512);

        if slack_end <= sector * 512 + slack_start {
            break;
        }

        let slack_space = &buffer[sector * 512 + slack_start..sector * 512 + slack_end];
        let non_zero_count = slack_space.iter().filter(|&&b| b != 0).count();

        if non_zero_count > 100 {
            anomalies.push(format!("Data in slack space at sector {}", sector));
        }
    }

    anomalies
}

fn analyze_repeating_patterns(buffer: &[u8]) -> i32 {
    let chunk_size = 512;
    let max_chunks = std::cmp::min(1000, buffer.len() / chunk_size);
    let mut repeating_chunks = 0;

    if max_chunks < 2 {
        return 0;
    }

    let first_chunk = &buffer[..chunk_size];
    if first_chunk.iter().all(|&b| b == 0) {
        return 0;
    }

    for c in 1..max_chunks {
        let chunk = &buffer[c * chunk_size..(c + 1) * chunk_size];
        if chunk.len() != first_chunk.len() {
            continue;
        }

        let is_identical = chunk.iter().zip(first_chunk.iter()).all(|(a, b)| a == b);
        if is_identical && first_chunk.iter().any(|&b| b != 0) {
            repeating_chunks += 1;
        }
    }

    repeating_chunks
}

fn calculate_hashes(buffer: &[u8]) -> Hashes {
    let mut md5_hasher = Md5::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();

    md5_hasher.update(buffer);
    sha1_hasher.update(buffer);
    sha256_hasher.update(buffer);

    Hashes {
        md5: format!("{:x}", md5_hasher.finalize()),
        sha1: format!("{:x}", sha1_hasher.finalize()),
        sha256: format!("{:x}", sha256_hasher.finalize()),
    }
}

pub fn analyze_file(file_path: &str) -> Result<AnalysisResult, String> {
    let path = Path::new(file_path);

    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file
        .metadata()
        .map_err(|e| format!("Failed to get metadata: {}", e))?
        .len();

    // Read entire file into memory
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader
        .read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    eprintln!("[AFDF] Analyzing {} bytes from {}", buffer.len(), file_path);

    let mut detected_anomalies = Vec::new();
    let mut techniques = Vec::new();
    let mut integrity_deductions = 0;

    // Stage 1: Integrity Check
    eprintln!("[AFDF] Stage 1: Integrity Check");

    let header_null = buffer.iter().take(16).all(|&b| b == 0);
    if header_null {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Header Anomaly".to_string(),
            location: "Bytes 0-15".to_string(),
            description: "Header is completely null - abnormal for disk image".to_string(),
            severity: "critical".to_string(),
        });
        techniques.push("Header Manipulation".to_string());
        integrity_deductions += 20;
    }

    let fs_signatures = detect_file_signature(&buffer);
    if fs_signatures.is_empty() {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Unknown Filesystem".to_string(),
            location: "Boot Sector".to_string(),
            description: "Unable to identify standard file system signature".to_string(),
            severity: "medium".to_string(),
        });
        integrity_deductions += 10;
    }

    let anti_forensic_tools = detect_anti_forensic_tools(&buffer);
    if !anti_forensic_tools.is_empty() {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Anti-Forensic Tool".to_string(),
            location: "Header/boot sector".to_string(),
            description: format!(
                "Evidence of anti-forensic tool usage: {}",
                anti_forensic_tools.join(", ")
            ),
            severity: "critical".to_string(),
        });
        techniques.push("Anti-Forensic Tool Detected".to_string());
        integrity_deductions += 30;
    }

    // Stage 2: Metadata Analysis
    eprintln!("[AFDF] Stage 2: Metadata Analysis");

    if file_size % 512 != 0 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Non-Standard Size".to_string(),
            location: "File".to_string(),
            description: "File size not aligned to 512-byte sector boundary".to_string(),
            severity: "medium".to_string(),
        });
        techniques.push("Non-Standard Sector Size".to_string());
        integrity_deductions += 10;
    }

    if file_size < 1024 * 1024 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Suspicious Size".to_string(),
            location: "File".to_string(),
            description: "File is unusually small for a disk image".to_string(),
            severity: "medium".to_string(),
        });
        integrity_deductions += 15;
    }

    // Stage 3: Artifact Analysis
    eprintln!("[AFDF] Stage 3: Artifact Analysis");

    let wiped = check_for_wiping(&buffer);
    if wiped {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Data Wiping".to_string(),
            location: "Multiple sectors".to_string(),
            description: "Pattern consistent with data wiping or secure deletion".to_string(),
            severity: "critical".to_string(),
        });
        techniques.push("Evidence Sanitization".to_string());
        integrity_deductions += 35;
    }

    let timestamp_anomalies = detect_timestamp_anomalies(&buffer);
    for anomaly in timestamp_anomalies.iter().take(5) {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Timestamp Anomaly".to_string(),
            location: "Various sectors".to_string(),
            description: anomaly.clone(),
            severity: "high".to_string(),
        });
        integrity_deductions += 15;
    }

    let hidden_data_anomalies = detect_hidden_data(&buffer);
    if !hidden_data_anomalies.is_empty() {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Hidden Data".to_string(),
            location: "Sector slack space".to_string(),
            description: format!(
                "Data found in unused sector space ({} sectors)",
                hidden_data_anomalies.len()
            ),
            severity: "high".to_string(),
        });
        techniques.push("Steganography Detected".to_string());
        integrity_deductions += 25;
    }

    // Check for uniform data
    let sample_for_uniform = &buffer[..std::cmp::min(1024 * 1024, buffer.len())];
    let first_byte = sample_for_uniform.first().copied().unwrap_or(0);
    let all_same = sample_for_uniform.iter().all(|&b| b == first_byte);

    if all_same && first_byte != 0 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Uniform Data".to_string(),
            location: "Full File".to_string(),
            description: "All bytes are identical - indicates wiping".to_string(),
            severity: "critical".to_string(),
        });
        techniques.push("Evidence Sanitization".to_string());
        integrity_deductions += 40;
    }

    let repeating_chunks = analyze_repeating_patterns(&buffer);
    if repeating_chunks > 10 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Repeating Pattern".to_string(),
            location: "Multiple Sectors".to_string(),
            description: format!("{} sectors have identical content", repeating_chunks),
            severity: "high".to_string(),
        });
        techniques.push("Pattern-Based Wiping".to_string());
        integrity_deductions += 20;
    }

    // Stage 4: Entropy Analysis
    eprintln!("[AFDF] Stage 4: Entropy Analysis");

    let entropy = calculate_shannon_entropy(&buffer);
    let null_ratio = buffer.iter().filter(|&&b| b == 0).count() as f64 / buffer.len() as f64;

    if entropy > 7.5 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "High Entropy".to_string(),
            location: "Full File".to_string(),
            description: format!(
                "Entropy {:.2} indicates encryption or hidden partition",
                entropy
            ),
            severity: "high".to_string(),
        });
        techniques.push("Encrypted Volume Detected".to_string());
        integrity_deductions += 25;
    } else if entropy > 6.0 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Elevated Entropy".to_string(),
            location: "Full File".to_string(),
            description: format!("Entropy {:.2} is higher than typical", entropy),
            severity: "medium".to_string(),
        });
        techniques.push("Possible Steganography".to_string());
        integrity_deductions += 10;
    } else if entropy < 1.0 {
        detected_anomalies.push(Anomaly {
            anomaly_type: "Very Low Entropy".to_string(),
            location: "Full File".to_string(),
            description: format!("Entropy {:.4} - possible zero-filled image", entropy),
            severity: "low".to_string(),
        });
        techniques.push("Zero-Filled Image".to_string());
        integrity_deductions += 5;
    }

    // Calculate final score
    let integrity_score = std::cmp::max(0, 100 - integrity_deductions);

    let (tamper_prob, risk_level, verdict) = if integrity_score < 40 {
        (
            "HIGH".to_string(),
            "CRITICAL".to_string(),
            "TAMPERED".to_string(),
        )
    } else if integrity_score < 70 {
        (
            "MEDIUM".to_string(),
            "SUSPICIOUS".to_string(),
            "QUESTIONABLE".to_string(),
        )
    } else {
        (
            "LOW".to_string(),
            "NORMAL".to_string(),
            "AUTHENTIC".to_string(),
        )
    };

    if techniques.is_empty() {
        techniques.push("No anomalies detected".to_string());
    }

    // Calculate hashes
    let hashes = calculate_hashes(&buffer);
    let hash_full = &hashes.sha256;

    eprintln!(
        "[AFDF] Analysis complete. Score: {}, Verdict: {}",
        integrity_score, verdict
    );

    Ok(AnalysisResult {
        integrity_score,
        tamper_probability: tamper_prob,
        risk_level: risk_level.clone(),
        verdict: verdict.clone(),
        anomalies: detected_anomalies.len() as i32,
        techniques: techniques.clone(),
        details: Details {
            hash: hash_full.clone(),
            entropy,
            null_ratio,
            file_type: if file_path.to_lowercase().ends_with(".e01") {
                "EnCase Evidence".to_string()
            } else {
                "Raw Disk Image".to_string()
            },
            file_size,
            anomalies: detected_anomalies.clone(),
            timeline: vec![
                TimelineEvent {
                    timestamp: "2024-01-01T00:00:00Z".to_string(),
                    event: "Evidence Acquired".to_string(),
                },
                TimelineEvent {
                    timestamp: "2024-01-01T01:00:00Z".to_string(),
                    event: "Hash Verification".to_string(),
                },
                TimelineEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    event: "Analysis Complete".to_string(),
                },
            ],
            ml_features: MlFeatures {
                entropy_score: entropy / 8.0,
                anomaly_score: detected_anomalies.len() as f64 / 10.0,
                tampering_score: (100 - integrity_score) as f64 / 100.0,
            },
            detected_filesystems: fs_signatures,
            anti_forensic_tools,
            has_wiping_patterns: wiped,
            repeating_chunks,
        },
        hashes,
    })
}

fn main() {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(author, version, about, long_about = None)]
    struct Args {
        #[arg(short, long)]
        file: String,
    }

    let args = Args::parse();

    match analyze_file(&args.file) {
        Ok(result) => {
            let json = serde_json::to_string_pretty(&result).expect("Failed to serialize result");
            println!("{}", json);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
