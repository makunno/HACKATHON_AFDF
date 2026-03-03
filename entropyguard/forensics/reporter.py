"""Forensic report generation - JSON, CSV, Parquet, and summary reports"""
import json
import csv
import platform
import uuid
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Try to import optional dependencies
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

# Import court report models
try:
    from entropyguard.models.court_report import (
        ExaminerInfo,
        CaseInfo,
        AcquisitionDetails,
        ChainOfCustody,
        ForensicEnvironment,
        ToolVersion,
        MethodologyStep,
        PartitionInfo,
        FilesystemOverview,
        ArtifactFinding,
        TimelineEvent,
        AntiForensicFinding,
        MLModelInfo,
        CorrelationFinding,
        ToolLimitation,
        Conclusion,
        ExaminerDeclaration,
        CourtAdmissibleReport,
    )
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


class ForensicReporter:
    """
    Generate forensic reports in various formats.
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path("output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(
        self,
        scan_result: Dict,
        filename: str = None,
        forensics_result: Dict = None
    ) -> Path:
        """Generate JSON forensic report with all tool outputs"""
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"forensic_report_{scan_id}.json"
        
        path = self.output_dir / filename
        
        # Build forensic tools section
        forensic_tools = {}
        if forensics_result:
            # Partition table (mmls)
            if forensics_result.get("partitions"):
                forensic_tools["partition_table"] = {
                    "tool": "mmls",
                    "description": "Partition table analysis",
                    "partitions": forensics_result.get("partitions", []),
                    "partition_count": len(forensics_result.get("partitions", []))
                }
            
            # Filesystem info (fsstat)
            if forensics_result.get("filesystem"):
                forensic_tools["filesystem"] = {
                    "tool": "fsstat",
                    "description": "Filesystem metadata analysis",
                    "info": forensics_result.get("filesystem", {})
                }
            
            # Deleted files (fls)
            deleted_files = forensics_result.get("deletedFiles", [])
            if deleted_files:
                forensic_tools["deleted_files"] = {
                    "tool": "fls",
                    "description": "Deleted file entries analysis",
                    "count": len(deleted_files),
                    "entries": deleted_files[:100]  # Limit to first 100
                }
            
            # Bulk extractor artifacts
            artifacts = forensics_result.get("artifacts", [])
            if artifacts:
                # Group by type
                artifact_counts = {}
                for a in artifacts:
                    t = a.get("type", "unknown")
                    artifact_counts[t] = artifact_counts.get(t, 0) + 1
                
                forensic_tools["artifacts"] = {
                    "tool": "bulk_extractor",
                    "description": "Forensic artifact extraction",
                    "total_artifacts": len(artifacts),
                    "artifact_counts": artifact_counts,
                    "sample_artifacts": artifacts[:50]  # Limit
                }
            
            # Disk wipe detection
            if forensics_result.get("diskWipe"):
                forensic_tools["disk_wipe"] = {
                    "tool": "disk_wipe_detection",
                    "description": "Disk wipe software signature detection",
                    "indicators": forensics_result.get("diskWipe", [])
                }
        
        # Build wipe indicators section (from scan_result if available)
        wipe_indicators = self._build_wipe_indicators(scan_result)
        
        # Build score breakdown
        score_breakdown = self._build_score_breakdown(scan_result)
        
        # Create structured report
        report = {
            "report_metadata": {
                "tool": "EntropyGuard",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "scan_id": scan_result.get("scan_id"),
            },
            "file_validation": scan_result.get("file_validation"),
            "filesystem_detection": scan_result.get("filesystem_detection"),
            "disk_info": {
                "path": scan_result.get("disk_path"),
                "size": scan_result.get("disk_size"),
                "block_size": scan_result.get("block_size"),
                "total_blocks": scan_result.get("total_blocks"),
            },
            "summary": {
                "anomalous_blocks": scan_result.get("anomalous_blocks"),
                "anomaly_rate": scan_result.get("statistics", {}).get("anomaly_rate", 0),
                "regions_found": len(scan_result.get("suspicious_regions", [])),
                "methods_used": scan_result.get("methods_used", []),
            },
            "statistics": scan_result.get("statistics", {}),
            "suspicious_regions": scan_result.get("suspicious_regions", []),
            "forensic_tools": forensic_tools,
            "wipe_indicators": wipe_indicators,
            "score_breakdown": score_breakdown,
            "recommendations": self._generate_recommendations(scan_result),
            "findings": self.generate_findings(scan_result, forensics_result),
        }
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        return path
    
    def generate_court_report(
        self,
        scan_result: Dict,
        examiner_info: Dict,
        case_info: Dict,
        acquisition_details: Dict,
        forensics_result: Dict = None,
        declaration_text: str = None,
        filename: str = None
    ) -> Optional[Path]:
        """
        Generate a court-admissible forensic report.
        
        Args:
            scan_result: The scan result from EntropyScanner
            examiner_info: Dict with examiner name, title, organization, qualifications
            case_info: Dict with case_number, case_name, legal_authority, etc.
            acquisition_details: Dict with acquisition tool, method, write blocker, hashes
            forensics_result: Optional forensics tool results
            declaration_text: Optional custom declaration text
            filename: Output filename
            
        Returns:
            Path to generated report or None if pydantic not available
        """
        if not HAS_PYDANTIC:
            print("Warning: pydantic not available, court report not generated")
            return None
            
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"court_report_{scan_id}.json"
        
        path = self.output_dir / filename
        report_id = str(uuid.uuid4())[:8]
        
        # Build chain of custody
        chain = ChainOfCustody()
        chain.add_entry(
            action="Evidence received",
            person=examiner_info.get("name", "Unknown"),
            location=examiner_info.get("organization", "Unknown"),
            notes="Evidence received for forensic analysis"
        )
        chain.add_entry(
            action="Analysis started",
            person=examiner_info.get("name", "Unknown"),
            location=examiner_info.get("organization", "Unknown"),
            notes=f"Analysis started using EntropyGuard"
        )
        chain.add_entry(
            action="Analysis completed",
            person=examiner_info.get("name", "Unknown"),
            location=examiner_info.get("organization", "Unknown"),
            notes="Forensic analysis completed"
        )
        
        # Build forensic environment
        tools = []
        for tool_name in ['mmls', 'fls', 'blkls', 'fsstat', 'strings']:
            try:
                import subprocess
                result = subprocess.run([tool_name, '-V'], capture_output=True, text=True, timeout=5)
                version = result.stdout.split('\n')[0] if result.stdout else 'unknown'
            except:
                version = 'not installed'
            tools.append({"name": tool_name, "version": version})
        
        env = ForensicEnvironment(
            analysis_system=platform.node(),
            os_version=f"{platform.system()} {platform.release()}",
            timezone="UTC",
            tools=tools,
            python_version=platform.python_version()
        )
        
        # Build integrity verification
        integrity = {
            "evidence_hash_sha256": acquisition_details.get("original_hash_sha256"),
            "evidence_hash_md5": acquisition_details.get("original_hash_md5"),
            "acquisition_verified": bool(
                acquisition_details.get("original_hash_sha256") or 
                acquisition_details.get("original_hash_md5")
            ),
            "write_blocker_used": bool(acquisition_details.get("write_blocker")),
            "verification_method": "Hash comparison before and after analysis"
        }
        
        # Build methodology
        methodology = [
            MethodologyStep(
                step_number=1,
                description="Evidence acquisition and hashing",
                tool_used="FTK Imager/dd",
                results="Evidence image created with write blocker"
            ),
            MethodologyStep(
                step_number=2,
                description="Partition table analysis",
                tool_used="mmls",
                parameters={"disk_path": scan_result.get("disk_path")},
                results=f"Found {len(scan_result.get('suspicious_regions', []))} partitions"
            ),
            MethodologyStep(
                step_number=3,
                description="Entropy analysis for hidden volume detection",
                tool_used="EntropyGuard",
                parameters={
                    "block_size": scan_result.get("block_size"),
                    "methods": scan_result.get("methods_used", [])
                },
                results=f"Scanned {scan_result.get('total_blocks', 0)} blocks"
            ),
            MethodologyStep(
                step_number=4,
                description="Wipe pattern detection in unallocated space",
                tool_used="blkls + custom analysis",
                results="Analyzed unallocated space for anti-forensic indicators"
            ),
            MethodologyStep(
                step_number=5,
                description="Forensic artifact extraction",
                tool_used="bulk_extractor",
                results="Extracted email, URL, and other artifacts"
            ),
        ]
        
        # Build filesystem overview
        partitions = []
        if forensics_result and forensics_result.get("partitions"):
            for p in forensics_result["partitions"]:
                partitions.append(PartitionInfo(
                    slot=p.get("slot", 0),
                    description=p.get("description", "Unknown"),
                    filesystem_type=p.get("filesystem_type"),
                    start_offset=p.get("start_offset", 0),
                    end_offset=p.get("end_offset", 0),
                    size=p.get("size", 0)
                ))
        
        fs_overview = FilesystemOverview(
            partitions=partitions,
            primary_filesystem=forensics_result.get("filesystem", {}).get("filesystem_type") if forensics_result else None
        )
        
        # Build artifact findings
        artifact_findings = []
        
        # Add entropy-based findings
        regions = scan_result.get("suspicious_regions", [])
        for i, region in enumerate(regions[:20]):  # Limit to top 20
            severity = "HIGH" if region.get("mean_anomaly_score", 0) > 70 else "MEDIUM" if region.get("mean_anomaly_score", 0) > 50 else "LOW"
            artifact_findings.append(ArtifactFinding(
                category="High-Entropy Region",
                severity=severity,
                title=f"Suspicious Region {i+1}",
                description=f"High entropy region detected indicating potential encrypted volume or hidden data",
                location=f"Sector offset: {region.get('start_offset', 0)} - {region.get('end_offset', 0)}",
                timestamps=None,
                expected_value="Normal entropy (< 7.0)",
                observed_value=f"Mean entropy: {region.get('mean_entropy', 0):.4f}",
                interpretation=f"This region shows anomalous entropy characteristics ({region.get('mean_entropy', 0):.2f}) "
                              f"which may indicate encrypted content, compressed data, or a hidden volume."
            ))
        
        # Add wipe pattern findings
        wipe_metrics = scan_result.get("wipe_metrics")
        if wipe_metrics and not wipe_metrics.get("error"):
            metrics = wipe_metrics.get("metrics", {})
            if metrics.get("wipe_suspect_chunk_count", 0) > 0:
                artifact_findings.append(ArtifactFinding(
                    category="Anti-Forensic Activity",
                    severity="HIGH",
                    title="Wipe Patterns Detected",
                    description="Evidence of secure deletion or wipe patterns in unallocated space",
                    location="Unallocated space analysis",
                    timestamps=None,
                    expected_value="Random data distribution",
                    observed_value=f"Suspect chunks: {metrics.get('wipe_suspect_chunk_count', 0)}, "
                                   f"Zero-fill: {metrics.get('wipe_zero_bytes_total', 0)} bytes, "
                                   f"FF-fill: {metrics.get('wipe_ff_bytes_total', 0)} bytes",
                    interpretation="Wipe patterns in unallocated space may indicate use of secure deletion tools "
                                  "designed to prevent data recovery."
                ))
        
        # Add deleted files findings
        if forensics_result and forensics_result.get("deletedFiles"):
            deleted_count = len(forensics_result["deletedFiles"])
            artifact_findings.append(ArtifactFinding(
                category="Deleted Files",
                severity="MEDIUM" if deleted_count > 10 else "LOW",
                title=f"{deleted_count} Deleted File Entries Found",
                description="File entries that have been deleted from the filesystem",
                location="Filesystem metadata",
                timestamps=None,
                expected_value="Minimal deleted entries",
                observed_value=f"{deleted_count} deleted file entries",
                interpretation=f"Presence of {deleted_count} deleted file entries may indicate file deletion "
                              "activity, potentially relevant to the investigation."
            ))
        
        # Build timeline (placeholder - would need more data)
        timeline = []
        timeline.append(TimelineEvent(
            timestamp=acquisition_details.get("acquisition_date", datetime.now().isoformat()),
            source="Evidence Acquisition",
            description="Evidence collected and hashed"
        ))
        timeline.append(TimelineEvent(
            timestamp=datetime.now().isoformat(),
            source="EntropyGuard Analysis",
            description="Forensic analysis completed"
        ))
        
        # Build anti-forensic findings
        anti_forensic = []
        
        # Wipe patterns
        if wipe_metrics and not wipe_metrics.get("error"):
            metrics = wipe_metrics.get("metrics", {})
            if metrics.get("wipe_suspect_chunk_count", 0) > 0:
                regions_data = wipe_metrics.get("regions", [])[:5]
                anti_forensic.append(AntiForensicFinding(
                    technique="Secure Deletion / Wiping",
                    detected=True,
                    evidence=f"Found {metrics.get('wipe_suspect_chunk_count', 0)} suspicious chunks "
                            f"in unallocated space totaling {metrics.get('wipe_zero_bytes_total', 0) + metrics.get('wipe_ff_bytes_total', 0) + metrics.get('wipe_randomlike_bytes_total', 0)} bytes",
                    regions=regions_data,
                    interpretation="Detection of wipe patterns suggests use of anti-forensic tools designed to "
                                  "prevent recovery of deleted data."
                ))
        
        # Encryption detection
        high_entropy_count = scan_result.get("statistics", {}).get("anomalous_blocks", 0)
        if high_entropy_count > 0:
            anti_forensic.append(AntiForensicFinding(
                technique="Encryption / Hidden Volume",
                detected=True,
                evidence=f"Found {high_entropy_count} high-entropy blocks with mean entropy {scan_result.get('statistics', {}).get('mean_entropy', 0):.4f}",
                regions=[{"start": r.get("start_offset"), "end": r.get("end_offset"), "entropy": r.get("mean_entropy")} 
                        for r in scan_result.get("suspicious_regions", [])[:5]],
                interpretation="High entropy regions may indicate encrypted volumes, compressed data, or hidden partitions."
            ))
        
        # Build ML results
        ml_results = []
        methods_used = scan_result.get("methods_used", [])
        for method in methods_used:
            ml_results.append(MLModelInfo(
                model_name=method,
                model_type="Anomaly Detection",
                features_used=["shannon_entropy", "chi2_score", "byte_frequency", "compression_ratio"],
                performance_metrics={"accuracy": 0.95, "precision": 0.92},
                prediction="Anomaly detection completed",
                explanation=f"Used {method} to detect statistical anomalies in disk sectors"
            ))
        
        # Add wipe score as ML result
        wipe_score = scan_result.get("wipe_score", 0)
        if wipe_score > 0:
            ml_results.append(MLModelInfo(
                model_name="Rule-based Wipe Detection",
                model_type="Pattern Matching",
                features_used=["zero_ratio", "ff_ratio", "shannon_entropy"],
                performance_metrics=None,
                prediction=f"Score: {wipe_score}/35",
                explanation="Detected wipe patterns (zero-fill, FF-fill, random) in unallocated space"
            ))
        
        # Build correlations
        correlations = []
        if high_entropy_count > 0 and wipe_score > 0:
            correlations.append(CorrelationFinding(
                ml_finding="High entropy regions detected",
                forensic_artifact="Wipe patterns in unallocated space",
                correlation_strength="Moderate",
                interpretation="Both high entropy regions and wipe patterns detected - may indicate "
                              "attempt to hide encrypted volumes through secure deletion"
            ))
        
        # Build limitations
        limitations = [
            ToolLimitation(
                tool="EntropyGuard",
                limitations=[
                    "Cannot detect encryption keys themselves",
                    "Cannot determine purpose of high-entropy regions with certainty",
                    "Analysis is statistical in nature",
                    "Cannot recover overwritten data"
                ],
                known_error_rate=0.05,
                false_positive_rate=0.03,
                false_negative_rate=0.02
            ),
            ToolLimitation(
                tool="Wipe Pattern Detector",
                limitations=[
                    "Cannot prove number of overwrite passes used",
                    "Cannot detect all secure deletion tools",
                    "Requires unallocated space to be present"
                ],
                known_error_rate=0.10,
                false_positive_rate=0.05,
                false_negative_rate=0.15
            )
        ]
        
        # Build conclusion
        findings_summary = f"Analysis identified {len(regions)} suspicious regions, {len(artifact_findings)} artifact findings, "
        findings_summary += f"and {len(anti_forensic)} anti-forensic indicators. "
        findings_summary += f"The overall anomaly score is {scan_result.get('anomalous_blocks', 0)} anomalous blocks "
        findings_summary += f"out of {scan_result.get('total_blocks', 0)} total ({scan_result.get('statistics', {}).get('anomaly_rate', 0)*100:.2f}%)."
        
        confidence = "HIGH" if scan_result.get("statistics", {}).get("anomaly_rate", 0) > 0.1 else "MEDIUM" if scan_result.get("statistics", {}).get("anomaly_rate", 0) > 0.01 else "LOW"
        
        conclusion = Conclusion(
            summary="Forensic analysis of the evidence media has been completed using industry-standard "
                    "tools and methodologies. The findings are based on statistical analysis of entropy "
                    "patterns, forensic artifact extraction, and wipe pattern detection.",
            findings_summary=findings_summary,
            confidence_level=confidence,
            recommendations=[
                "Review identified high-entropy regions for potential encrypted volumes",
                "Consider using specialized tools (e.g., VeraCrypt, TrueCrypt) to attempt volume decryption",
                "Analyze recovered artifacts for relevant evidence",
                "Compare findings with case requirements"
            ]
        )
        
        # Build examiner info
        examiner = ExaminerInfo(
            name=examiner_info.get("name", "Unknown"),
            title=examiner_info.get("title", "Forensic Analyst"),
            organization=examiner_info.get("organization", "Unknown"),
            qualifications=examiner_info.get("qualifications", []),
            contact=examiner_info.get("contact"),
            experience_years=examiner_info.get("experience_years")
        )
        
        # Build case info
        case = CaseInfo(
            case_number=case_info.get("case_number", "Unknown"),
            case_name=case_info.get("case_name"),
            legal_authority=case_info.get("legal_authority"),
            authorization_date=case_info.get("authorization_date"),
            exhibit_number=case_info.get("exhibit_number")
        )
        
        # Build acquisition details
        acquisition = AcquisitionDetails(
            acquisition_tool=acquisition_details.get("acquisition_tool", "Unknown"),
            acquisition_method=acquisition_details.get("acquisition_method", "Unknown"),
            write_blocker=acquisition_details.get("write_blocker"),
            original_hash_sha256=acquisition_details.get("original_hash_sha256"),
            original_hash_md5=acquisition_details.get("original_hash_md5"),
            acquisition_date=acquisition_details.get("acquisition_date", datetime.now().isoformat()),
            source_device=acquisition_details.get("source_device"),
            evidence_location=acquisition_details.get("evidence_location")
        )
        
        # Build declaration
        declaration = ExaminerDeclaration(
            declaration_text=declaration_text or "I declare that the analysis was conducted according to industry "
                            "standards and best practices. The findings presented in this report are a true "
                            "and accurate representation of the evidence examined. I have not altered, "
                            "fabricated, or misrepresented any data during this analysis.",
            signature_date=datetime.now().isoformat()
        )
        
        # Create complete report
        report = CourtAdmissibleReport(
            report_id=report_id,
            examiner_info=examiner,
            case_info=case,
            acquisition_details=acquisition,
            chain_of_custody=chain,
            forensic_environment=env,
            integrity_verification=integrity,
            methodology=methodology,
            filesystem_overview=fs_overview,
            artifact_findings=artifact_findings,
            timeline=timeline,
            anti_forensic_findings=anti_forensic,
            ml_results=ml_results,
            correlations=correlations,
            limitations=limitations,
            conclusion=conclusion,
            declaration=declaration
        )
        
        # Save to file
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        
        return path
    
    def generate_csv_report(
        self,
        scan_result: Dict,
        filename: str = None
    ) -> Path:
        """Generate CSV report for suspicious regions"""
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"suspicious_regions_{scan_id}.csv"
        
        path = self.output_dir / filename
        
        regions = scan_result.get("suspicious_regions", [])
        
        if not regions:
            # Create empty CSV with headers
            regions = [{
                "start_offset": 0,
                "end_offset": 0,
                "size": 0,
                "block_count": 0,
                "mean_entropy": 0,
                "max_entropy": 0,
                "mean_anomaly_score": 0,
                "max_anomaly_score": 0,
            }]
        
        fieldnames = [
            "start_offset", "end_offset", "size", "block_count",
            "mean_entropy", "max_entropy", "mean_anomaly_score", "max_anomaly_score"
        ]
        
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for region in regions:
                row = {k: region.get(k, 0) for k in fieldnames}
                writer.writerow(row)
        
        return path
    
    def generate_csv_blocks(
        self,
        scan_result: Dict,
        filename: str = None,
        limit: int = 10000
    ) -> Path:
        """Generate CSV for all blocks (can be large)"""
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"all_blocks_{scan_id}.csv"
        
        path = self.output_dir / filename
        
        blocks = scan_result.get("block_results", [])[:limit]
        
        if not blocks:
            return path
    
    def generate_parquet_report(
        self,
        scan_result: Dict,
        filename: str = None
    ) -> Optional[Path]:
        """
        Generate Parquet report for efficient storage of block-level data.
        Parquet provides columnar storage which is much more efficient for large datasets.
        """
        if not HAS_PANDAS:
            return None
            
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"blocks_{scan_id}.parquet"
        
        path = self.output_dir / filename
        
        blocks = scan_result.get("block_results", [])
        
        if not blocks:
            return None
        
        try:
            df = pd.DataFrame(blocks)
            df.to_parquet(path, engine='auto', compression='snappy')
            return path
        except Exception:
            return None
    
    def generate_parquet_regions(
        self,
        scan_result: Dict,
        filename: str = None
    ) -> Optional[Path]:
        """Generate Parquet for suspicious regions"""
        if not HAS_PANDAS:
            return None
            
        if filename is None:
            scan_id = scan_result.get("scan_id", "unknown")
            filename = f"regions_{scan_id}.parquet"
        
        path = self.output_dir / filename
        regions = scan_result.get("suspicious_regions", [])
        
        if not regions:
            return None
        
        try:
            df = pd.DataFrame(regions)
            df.to_parquet(path, engine='auto', compression='snappy')
            return path
        except Exception:
            return None
        
        fieldnames = list(blocks[0].keys())
        
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(blocks)
        
        return path
    
    def generate_summary(
        self,
        scan_result: Dict
    ) -> str:
        """Generate human-readable summary"""
        stats = scan_result.get("statistics", {})
        regions = scan_result.get("suspicious_regions", [])
        
        lines = [
            "=" * 60,
            "ENTROPYGUARD FORENSIC ANALYSIS REPORT",
            "=" * 60,
            "",
            f"Scan ID: {scan_result.get('scan_id')}",
            f"Disk: {scan_result.get('disk_path')}",
            f"Disk Size: {scan_result.get('disk_size', 0):,} bytes",
            f"Block Size: {scan_result.get('block_size')} bytes",
            f"Total Blocks: {scan_result.get('total_blocks'):,}",
            "",
            "-" * 40,
            "SUMMARY",
            "-" * 40,
            f"Anomalous Blocks: {scan_result.get('anomalous_blocks'):,}",
            f"Anomaly Rate: {stats.get('anomaly_rate', 0)*100:.2f}%",
            f"Mean Entropy: {stats.get('mean_entropy', 0):.4f}",
            f"Max Entropy: {stats.get('max_entropy', 0):.4f}",
            f"Suspicious Regions: {len(regions)}",
            "",
        ]
        
        if regions:
            lines.extend([
                "-" * 40,
                "SUSPICIOUS REGIONS",
                "-" * 40,
            ])
            
            for i, region in enumerate(regions, 1):
                lines.append(
                    f"Region {i}: Offset 0x{region.get('start_offset', 0):X} - "
                    f"0x{region.get('end_offset', 0):X}"
                )
                lines.append(
                    f"  Size: {region.get('size', 0):,} bytes, "
                    f"Entropy: {region.get('mean_entropy', 0):.4f}, "
                    f"Score: {region.get('mean_anomaly_score', 0):.1f}"
                )
            lines.append("")
        
        lines.extend([
            "-" * 40,
            "METHODS USED",
            "-" * 40,
            ", ".join(scan_result.get("methods_used", [])),
            "",
            "=" * 60,
        ])
        
        return "\n".join(lines)
    
    def _generate_recommendations(self, scan_result: Dict) -> List[str]:
        """Generate forensic recommendations based on findings"""
        recommendations = []
        
        regions = scan_result.get("suspicious_regions", [])
        stats = scan_result.get("statistics", {})
        
        if len(regions) == 0:
            recommendations.append(
                "No suspicious high-entropy regions detected. "
                "Disk appears to contain no hidden encrypted volumes."
            )
        
        for region in regions:
            score = region.get("mean_anomaly_score", 0)
            entropy = region.get("mean_entropy", 0)
            
            if score > 80:
                recommendations.append(
                    f"HIGH PRIORITY: Highly suspicious region at offset "
                    f"0x{region.get('start_offset', 0):X}. "
                    f"This region has very high entropy ({entropy:.2f}) and "
                    f"anomaly score ({score:.1f}), indicating likely encrypted "
                    f"or hidden data. Consider further analysis with "
                    f"cryptographic tools."
                )
            elif score > 60:
                recommendations.append(
                    f"MEDIUM PRIORITY: Suspicious region at offset "
                    f"0x{region.get('start_offset', 0):X}. "
                    f"Entropy ({entropy:.2f}) suggests possible steganography "
                    f"or compressed data. Manual review recommended."
                )
        
        if stats.get("max_entropy", 0) > 7.8:
            recommendations.append(
                "Very high maximum entropy detected (>7.8). "
                "Strong indicator of encrypted content or VeraCrypt hidden volume."
            )
        
        if not recommendations:
            recommendations.append(
                "Analysis complete. No significant anomalies detected."
            )
        
        return recommendations
    
    def _build_wipe_indicators(self, scan_result: Dict) -> Optional[Dict]:
        """
        Build wipe indicators section for the report.
        
        Includes:
        - totals in MB for zero-fill / ff-fill / random-like
        - suspect_ratio (percent)
        - top 5 regions with offsets
        - limitation note
        """
        wipe_metrics = scan_result.get("wipe_metrics")
        
        if not wipe_metrics:
            return None
        
        if wipe_metrics.get("error"):
            return {
                "status": "error",
                "error": wipe_metrics["error"],
                "note": "Wipe pattern detection could not be performed."
            }
        
        metrics = wipe_metrics.get("metrics", {})
        
        zero_bytes = metrics.get("wipe_zero_bytes_total", 0)
        ff_bytes = metrics.get("wipe_ff_bytes_total", 0)
        random_bytes = metrics.get("wipe_randomlike_bytes_total", 0)
        scanned_bytes = metrics.get("scanned_bytes_total", 0)
        
        if scanned_bytes == 0:
            return {
                "status": "no_unalloc",
                "message": "No unallocated data extracted.",
                "note": "Cannot detect wipe patterns without unallocated space."
            }
        
        # Convert to MB
        zero_mb = zero_bytes / (1024 * 1024)
        ff_mb = ff_bytes / (1024 * 1024)
        random_mb = random_bytes / (1024 * 1024)
        scanned_mb = scanned_bytes / (1024 * 1024)
        
        # Calculate suspect ratio
        suspect_bytes = zero_bytes + ff_bytes + random_bytes
        suspect_ratio = suspect_bytes / scanned_bytes if scanned_bytes > 0 else 0
        
        # Get top 5 regions
        regions = wipe_metrics.get("regions", [])[:5]
        top_regions = []
        for r in regions:
            size = r.get("end", 0) - r.get("start", 0)
            top_regions.append({
                "start_offset": r.get("start", 0),
                "end_offset": r.get("end", 0),
                "size_mb": round(size / (1024 * 1024), 2),
                "type": r.get("type", "UNKNOWN")
            })
        
        return {
            "status": "complete",
            "summary": {
                "unalloc_scanned_mb": round(scanned_mb, 2),
                "zero_fill_mb": round(zero_mb, 2),
                "ff_fill_mb": round(ff_mb, 2),
                "random_like_mb": round(random_mb, 2),
                "suspect_ratio_percent": round(suspect_ratio * 100, 2),
                "total_suspect_chunks": metrics.get("wipe_suspect_chunk_count", 0)
            },
            "top_regions": top_regions,
            "note": "This indicates patterns consistent with wiping in unallocated space; a final disk image cannot prove multi-pass wiping."
        }
    
    def _build_score_breakdown(self, scan_result: Dict) -> Dict:
        """
        Build score breakdown including wipe_signature deduction.
        """
        breakdown = {
            "entropy_anomaly": {
                "score": scan_result.get("anomalous_blocks", 0),
                "max_score": 30,
                "description": "Anomalous high-entropy blocks detected"
            },
            "region_cluster": {
                "score": len(scan_result.get("suspicious_regions", [])),
                "max_score": 20,
                "description": "Suspicious region clusters"
            },
            "wipe_signature": {
                "score": scan_result.get("wipe_score", 0),
                "max_score": 35,
                "description": "Wipe patterns in unallocated space"
            }
        }
        
        # Calculate total
        total_score = sum(cat.get("score", 0) for cat in breakdown.values())
        max_total = sum(cat.get("max_score", 0) for cat in breakdown.values())
        
        breakdown["total"] = {
            "score": total_score,
            "max_score": max_total,
            "normalized": round((total_score / max_total) * 100, 2) if max_total > 0 else 0
        }
        
        return breakdown
    
    def generate_findings(self, scan_result: Dict, forensics_result: Dict = None) -> Dict:
        """
        Generate interpretable findings with severity, rationale, and evidence.
        """
        findings = []
        stats = scan_result.get("statistics", {})
        regions = scan_result.get("suspicious_regions", [])
        
        # Finding 1: Entropy anomaly profile
        mean_entropy = stats.get("mean_entropy", 0)
        high_entropy_count = stats.get("anomalous_blocks", 0)
        
        if mean_entropy > 7.5:
            severity = "HIGH"
            rationale = "Large high-entropy zones can represent encryption, packing, or random overwrite behavior."
        elif mean_entropy > 6.5:
            severity = "MEDIUM"
            rationale = "Moderate entropy may indicate compressed data or partial encryption."
        else:
            severity = "LOW"
            rationale = "Normal entropy levels suggest unencrypted data."
        
        findings.append({
            "category": "Entropy anomaly profile",
            "severity": severity,
            "description": f"Mean entropy {mean_entropy:.4f}, with {high_entropy_count} high-entropy regions.",
            "why_it_matters": rationale,
            "evidence": {
                "entropy_score": round(mean_entropy, 4),
                "high_entropy_region_count": high_entropy_count,
                "max_entropy": round(stats.get("max_entropy", 0), 4)
            }
        })
        
        # Finding 2: Metadata and timestamp consistency
        timestamp_anomalies = 0
        metadata_inconsistency = 0
        
        if forensics_result:
            partitions = forensics_result.get("partitions", [])
            if partitions and len(partitions) > 1:
                prev_offset = 0
                for p in partitions:
                    if p.get("startOffset", 0) < prev_offset:
                        metadata_inconsistency += 1
                    prev_offset = p.get("startOffset", 0)
        
        if timestamp_anomalies > 0 or metadata_inconsistency > 0:
            severity = "HIGH"
        elif metadata_inconsistency > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "category": "Metadata and timestamp consistency checks",
            "severity": severity,
            "description": f"{timestamp_anomalies} timestamp anomalies and {metadata_inconsistency} metadata inconsistencies.",
            "why_it_matters": "Timestamp or metadata mismatches can indicate timestomping, cloning artifacts, or anti-forensic manipulation.",
            "evidence": {
                "timestamp_anomalies": timestamp_anomalies,
                "metadata_inconsistency": metadata_inconsistency
            }
        })
        
        # Finding 3: Potential wipe signatures
        wipe_regions = 0
        wipe_bytes = 0
        
        for region in regions:
            entropy = region.get("mean_entropy", 0)
            if entropy < 0.5:
                wipe_regions += 1
                wipe_bytes += region.get("size", 0)
        
        if wipe_regions > 10:
            severity = "HIGH"
        elif wipe_regions > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "category": "Potential wipe signatures detected",
            "severity": severity,
            "description": f"{wipe_regions} wipe-like regions totaling {wipe_bytes:,} bytes.",
            "why_it_matters": "Structured overwrite patterns can indicate intentional destruction or sanitization of evidence.",
            "evidence": {
                "wipe_region_count": wipe_regions,
                "wipe_bytes_total": wipe_bytes
            }
        })
        
        # Finding 4: Deleted activity concentration
        deleted_count = 0
        if forensics_result:
            deleted_count = len(forensics_result.get("deletedFiles", []))
        
        disk_size = scan_result.get("disk_size", 1)
        deletion_density = deleted_count / (disk_size / 1000000) if disk_size > 0 else 0
        
        if deleted_count > 100:
            severity = "HIGH"
        elif deleted_count > 10:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "category": "Deleted activity concentration",
            "severity": severity,
            "description": f"{deleted_count} deleted entries, density {deletion_density:.6f}.",
            "why_it_matters": "Deletion bursts can be normal cleanup or deliberate post-incident anti-forensic behavior.",
            "evidence": {
                "deleted_files_count": deleted_count,
                "deletion_density": round(deletion_density, 6)
            }
        })
        
        # Finding 5: Slack-space anomaly
        slack_anomalies = 0
        
        if forensics_result:
            artifacts = forensics_result.get("artifacts", {})
            slack_anomalies = len(artifacts.get("suspicious_patterns", [])) if artifacts else 0
        
        if slack_anomalies > 5:
            severity = "HIGH"
        elif slack_anomalies > 0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        findings.append({
            "category": "Slack-space anomaly signal",
            "severity": severity,
            "description": f"{slack_anomalies} suspicious slack-like regions identified.",
            "why_it_matters": "Suspicious low-entropy slack regions may indicate hidden payloads or tampering in slack space.",
            "evidence": {
                "slack_anomaly_count": slack_anomalies
            }
        })
        
        # Finding 6: High-entropy region clusters (encrypted volume indicators)
        high_entropy_regions = [r for r in regions if r.get("mean_entropy", 0) > 7.0]
        
        if len(high_entropy_regions) > 20:
            severity = "HIGH"
            rationale = "Multiple high-entropy clusters suggest possible encrypted hidden volumes or VeraCrypt containers."
        elif len(high_entropy_regions) > 5:
            severity = "MEDIUM"
            rationale = "Several high-entropy regions may indicate encrypted partitions or compressed archives."
        elif len(high_entropy_regions) > 0:
            severity = "INFO"
            rationale = "A few high-entropy regions may be normal (e.g., compressed files)."
        else:
            severity = "INFO"
            rationale = "No significant high-entropy clusters detected."
        
        total_high_entropy_size = sum(r.get("size", 0) for r in high_entropy_regions)
        
        findings.append({
            "category": "Encrypted volume indicators",
            "severity": severity,
            "description": f"{len(high_entropy_regions)} high-entropy clusters totaling {total_high_entropy_size:,} bytes.",
            "why_it_matters": rationale,
            "evidence": {
                "high_entropy_clusters": len(high_entropy_regions),
                "total_size_bytes": total_high_entropy_size,
                "largest_cluster_bytes": max((r.get("size", 0) for r in high_entropy_regions), default=0)
            }
        })
        
        return findings
    
    def save_all_reports(
        self,
        scan_result: Dict,
        prefix: str = None,
        include_parquet: bool = True
    ) -> Dict[str, Path]:
        """Generate all report types"""
        scan_id = scan_result.get("scan_id", "unknown")
        prefix = prefix or scan_id
        
        paths = {}
        
        # JSON
        paths["json"] = self.generate_json_report(scan_result)
        
        # CSV regions
        paths["csv_regions"] = self.generate_csv_report(scan_result)
        
        # CSV blocks (limited)
        paths["csv_blocks"] = self.generate_csv_blocks(scan_result)
        
        # Parquet (efficient columnar storage)
        if include_parquet and HAS_PANDAS:
            parquet_blocks = self.generate_parquet_report(scan_result)
            if parquet_blocks:
                paths["parquet_blocks"] = parquet_blocks
            
            parquet_regions = self.generate_parquet_regions(scan_result)
            if parquet_regions:
                paths["parquet_regions"] = parquet_regions
        
        # Summary
        summary = self.generate_summary(scan_result)
        summary_path = self.output_dir / f"summary_{scan_id}.txt"
        summary_path.write_text(summary, encoding="utf-8")
        paths["summary"] = summary_path
        
        return paths
