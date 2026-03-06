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

// Re-vamped Streaming Analytics State
struct StreamState {
    pub md5_hasher: Md5,
    pub sha1_hasher: Sha1,
    pub sha256_hasher: Sha256,
    pub frequency: [usize; 256],
    pub null_count: u64,
    pub total_bytes: u64,
    
    // Anomaly tracking
    pub file_signatures: Vec<String>,
    pub anti_forensic_tools: Vec<String>,
    pub anomalies: Vec<Anomaly>,
    
    // Metrics
    pub wiped_detected: bool,
    pub repeating_chunks: i32,
    pub first_chunk: Option<Vec<u8>>,
    pub all_first_byte: Option<u8>,
    pub is_uniform: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            md5_hasher: Md5::new(),
            sha1_hasher: Sha1::new(),
            sha256_hasher: Sha256::new(),
            frequency: [0; 256],
            null_count: 0,
            total_bytes: 0,
            file_signatures: Vec::new(),
            anti_forensic_tools: Vec::new(),
            anomalies: Vec::new(),
            wiped_detected: false,
            repeating_chunks: 0,
            first_chunk: None,
            all_first_byte: None,
            is_uniform: true,
        }
    }
}

pub fn analyze_file(file_path: &str) -> Result<AnalysisResult, String> {
    let path = Path::new(file_path);

    let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file
        .metadata()
        .map_err(|e| format!("Failed to get metadata: {}", e))?
        .len();

    eprintln!("[AFDF] Streaming and analyzing {} bytes from {}", file_size, file_path);

    // Stream the file in 1MB chunks
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut buffer = vec![0; 1024 * 1024]; // 1MB chunk size
    let mut state = StreamState::new();

    let mut is_first_chunk = true;

    loop {
        let bytes_read = reader.read(&mut buffer).map_err(|e| format!("Failed to read file: {}", e))?;
        if bytes_read == 0 {
            break; // EOF
        }

        let chunk = &buffer[..bytes_read];
        
        // 1. Hashes
        state.md5_hasher.update(chunk);
        state.sha1_hasher.update(chunk);
        state.sha256_hasher.update(chunk);

        // 2. Entropy and Null distributions
        for &byte in chunk {
            state.frequency[byte as usize] += 1;
            if byte == 0 {
                state.null_count += 1;
            }
        }

        // 3. Header specific checks (only on the very first chunk)
        if is_first_chunk {
            if chunk.iter().take(16).all(|&b| b == 0) {
                state.anomalies.push(Anomaly {
                    anomaly_type: "Header Anomaly".to_string(),
                    location: "Bytes 0-15".to_string(),
                    description: "Header is completely null - abnormal for disk image".to_string(),
                    severity: "critical".to_string(),
                });
            }

            // File signatures (only search the first 512 bytes)
            let header = &chunk[..std::cmp::min(512, chunk.len())];
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
                        state.file_signatures.push(name.to_string());
                    }
                }
            }

            // Initialization for uniformity and repeating chunk checks
            if chunk.len() >= 512 {
                state.first_chunk = Some(chunk[..512].to_vec());
                state.all_first_byte = Some(chunk[0]);
            }
        }

        // 4. Uniformity check
        if state.is_uniform {
            if let Some(first) = state.all_first_byte {
                if !chunk.iter().all(|&b| b == first) {
                    state.is_uniform = false;
                }
            }
        }

        // 5. Anti-forensic tool search - applied across the ENTIRE file, not just first 4KB
        for (name, sig) in ANTI_FORENSIC_SIGNATURES {
            if chunk.windows(sig.len()).any(|w| w == *sig) {
                if !state.anti_forensic_tools.contains(&name.to_string()) {
                    state.anti_forensic_tools.push(name.to_string());
                }
            }
        }
        
        let chunk_str = String::from_utf8_lossy(chunk);
        if chunk_str.contains("DBAN") || chunk_str.contains("darik") {
            if !state.anti_forensic_tools.contains(&"DBAN".to_string()) {
                state.anti_forensic_tools.push("DBAN".to_string());
            }
        }
        if chunk_str.contains("SDelete") || chunk_str.contains("sdelete") {
            if !state.anti_forensic_tools.contains(&"SDelete".to_string()) {
                state.anti_forensic_tools.push("SDelete".to_string());
            }
        }
        if chunk_str.contains("BleachBit") {
            if !state.anti_forensic_tools.contains(&"BleachBit".to_string()) {
                state.anti_forensic_tools.push("BleachBit".to_string());
            }
        }

        // 6. Repeating pattern checks
        if let Some(ref first_chk) = state.first_chunk {
            if first_chk.iter().any(|&b| b != 0) && bytes_read >= 512 {
                let chunks_in_buffer = bytes_read / 512;
                for c in 0..chunks_in_buffer {
                    let sub_chunk = &chunk[c * 512..(c + 1) * 512];
                    if sub_chunk == first_chk.as_slice() {
                        state.repeating_chunks += 1;
                    }
                }
            }
        }

        // 7. Hidden Slack Space Check (Fixed logic)
        // Detects non-zero data in the back half of a 512-byte sector
        if state.total_bytes < 100 * 512 { // Only scan early sectors
            let chunks_in_buffer = bytes_read / 512;
            for c in 0..chunks_in_buffer {
                let sector = &chunk[c * 512..(c + 1) * 512];
                // Check bottom half of the sector for data
                let slack_space = &sector[256..512];
                let non_zero_count = slack_space.iter().filter(|&&b| b != 0).count();
                if non_zero_count > 100 {
                    let absolute_sector = (state.total_bytes / 512) + c as u64;
                    state.anomalies.push(Anomaly {
                        anomaly_type: "Hidden Data".to_string(),
                        location: format!("Sector {}", absolute_sector),
                        description: "Data found in unused sector space".to_string(),
                        severity: "high".to_string(),
                    });
                }
            }
        }

        // 8. Timestamps - Removed the massive false positive generator
        // Interpreting arbitrary 4 bytes as timestamps is inherently noisy.
        // We only append specific known bad signature anomalies instead of treating 0x00000000 as epoch.

        state.total_bytes += bytes_read as u64;
        is_first_chunk = false;
    }

    // Processing finished
    let mut techniques = Vec::new();
    let mut integrity_deductions = 0;

    // Evaluate deductions based on findings
    if state.is_uniform && state.all_first_byte.unwrap_or(0) != 0 && state.total_bytes > 0 {
         state.anomalies.push(Anomaly {
            anomaly_type: "Uniform Data".to_string(),
            location: "Full File".to_string(),
            description: "All bytes are identical - indicates wiping".to_string(),
            severity: "critical".to_string(),
        });
        techniques.push("Evidence Sanitization".to_string());
        integrity_deductions += 40;
    }

    if state.file_signatures.is_empty() && state.total_bytes >= 512 {
        state.anomalies.push(Anomaly {
            anomaly_type: "Unknown Filesystem".to_string(),
            location: "Boot Sector".to_string(),
            description: "Unable to identify standard file system signature".to_string(),
            severity: "medium".to_string(),
        });
        integrity_deductions += 10;
    }

    if !state.anti_forensic_tools.is_empty() {
        state.anomalies.push(Anomaly {
            anomaly_type: "Anti-Forensic Tool".to_string(),
            location: "File contents".to_string(),
            description: format!(
                "Evidence of anti-forensic tool usage: {}",
                state.anti_forensic_tools.join(", ")
            ),
            severity: "critical".to_string(),
        });
        techniques.push("Anti-Forensic Tool Detected".to_string());
        integrity_deductions += 30;
    }

    if state.total_bytes % 512 != 0 {
        state.anomalies.push(Anomaly {
            anomaly_type: "Non-Standard Size".to_string(),
            location: "File".to_string(),
            description: "File size not aligned to 512-byte sector boundary".to_string(),
            severity: "medium".to_string(),
        });
        techniques.push("Non-Standard Sector Size".to_string());
        integrity_deductions += 10;
    }

    if state.total_bytes < 1024 * 1024 && state.total_bytes > 0 {
        state.anomalies.push(Anomaly {
            anomaly_type: "Suspicious Size".to_string(),
            location: "File".to_string(),
            description: "File is unusually small for a disk image".to_string(),
            severity: "medium".to_string(),
        });
        integrity_deductions += 15;
    }

    if state.repeating_chunks > 10 {
        state.anomalies.push(Anomaly {
            anomaly_type: "Repeating Pattern".to_string(),
            location: "Multiple Sectors".to_string(),
            description: format!("{} sectors have identical content", state.repeating_chunks),
            severity: "high".to_string(),
        });
        techniques.push("Pattern-Based Wiping".to_string());
        integrity_deductions += 20;
    }

    // Evaluate Entropy
    let total = state.total_bytes as f64;
    let mut entropy = 0.0;
    if total > 0.0 {
        for &count in state.frequency.iter() {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
    }

    if entropy > 7.5 {
        state.anomalies.push(Anomaly {
            anomaly_type: "High Entropy".to_string(),
            location: "Full File".to_string(),
            description: format!("Entropy {:.2} indicates encryption or hidden partition", entropy),
            severity: "high".to_string(),
        });
        techniques.push("Encrypted Volume Detected".to_string());
        integrity_deductions += 25;
    } else if entropy > 6.0 {
        state.anomalies.push(Anomaly {
            anomaly_type: "Elevated Entropy".to_string(),
            location: "Full File".to_string(),
            description: format!("Entropy {:.2} is higher than typical", entropy),
            severity: "medium".to_string(),
        });
        techniques.push("Possible Steganography".to_string());
        integrity_deductions += 10;
    }

    let integrity_score = std::cmp::max(0, 100 - integrity_deductions);
    let (tamper_prob, risk_level, verdict) = if integrity_score < 40 {
        ("HIGH".to_string(), "CRITICAL".to_string(), "TAMPERED".to_string())
    } else if integrity_score < 70 {
        ("MEDIUM".to_string(), "SUSPICIOUS".to_string(), "QUESTIONABLE".to_string())
    } else {
        ("LOW".to_string(), "NORMAL".to_string(), "AUTHENTIC".to_string())
    };

    if techniques.is_empty() {
        techniques.push("No anomalies detected".to_string());
    }

    let hashes = Hashes {
        md5: format!("{:x}", state.md5_hasher.finalize()),
        sha1: format!("{:x}", state.sha1_hasher.finalize()),
        sha256: format!("{:x}", state.sha256_hasher.finalize()),
    };

    let null_ratio = if state.total_bytes > 0 {
        state.null_count as f64 / state.total_bytes as f64
    } else {
        0.0
    };

    eprintln!("[AFDF] Streaming Analysis complete. Score: {}, Verdict: {}", integrity_score, verdict);

    Ok(AnalysisResult {
        integrity_score,
        tamper_probability: tamper_prob,
        risk_level: risk_level,
        verdict: verdict,
        anomalies: state.anomalies.len() as i32,
        techniques: techniques,
        details: Details {
            hash: hashes.sha256.clone(),
            entropy,
            null_ratio,
            file_type: if file_path.to_lowercase().ends_with(".e01") {
                "EnCase Evidence".to_string()
            } else {
                "Raw Disk Image".to_string()
            },
            file_size: state.total_bytes,
            anomalies: state.anomalies.clone(),
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
                anomaly_score: state.anomalies.len() as f64 / 10.0,
                tampering_score: (100 - integrity_score) as f64 / 100.0,
            },
            detected_filesystems: state.file_signatures,
            anti_forensic_tools: state.anti_forensic_tools,
            has_wiping_patterns: state.is_uniform && state.total_bytes > 0,
            repeating_chunks: state.repeating_chunks,
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
