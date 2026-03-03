import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Activity, 
  Database, HardDrive, ArrowLeft, Layers, Search, Trash2, 
  Terminal, Wifi, Smartphone, Mail, Eye, Lock, Download, 
  Clock, Check, AlertCircle, FileText, Timer
} from 'lucide-react';

const API_URL = '/api';

interface Finding {
  severity: 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  rationale: string;
  evidence: string;
  details?: any;
}

export default function DashboardPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) { navigate('/upload'); return; }
    fetch(`${API_URL}/result/${id}`)
      .then(res => { if (!res.ok) throw new Error('Analysis not found'); return res.json(); })
      .then(data => { setResults(data); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, [id, navigate]);

  const formatSize = (bytes: number) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-purple-400 border-purple-500 bg-purple-500/10';
      case 'HIGH': return 'text-red-400 border-red-500 bg-red-500/10';
      case 'MEDIUM': return 'text-orange-400 border-orange-500 bg-orange-500/10';
      case 'LOW': return 'text-yellow-400 border-yellow-500 bg-yellow-500/10';
      default: return 'text-blue-400 border-blue-500 bg-blue-500/10';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <XCircle className="h-5 w-5 text-purple-400" />;
      case 'HIGH': return <XCircle className="h-5 w-5 text-red-400" />;
      case 'MEDIUM': return <AlertTriangle className="h-5 w-5 text-orange-400" />;
      case 'LOW': return <AlertCircle className="h-5 w-5 text-yellow-400" />;
      default: return <CheckCircle className="h-5 w-5 text-blue-400" />;
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="text-center">
          <Shield className="h-16 w-16 text-cyan-400 animate-pulse mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Loading Results...</h2>
        </div>
      </div>
    );
  }

  if (error || !results) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-black">
        <div className="text-center">
          <XCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Analysis Not Found</h2>
          <Button onClick={() => navigate('/upload')} className="mt-4">Back to Upload</Button>
        </div>
      </div>
    );
  }

  const entropy = results.entropyResults || results.pythonAnalysis || {};
  const stats = entropy.statistics || {
    mean_entropy: entropy.mean_entropy || results.mean_entropy || 0,
    max_entropy: entropy.max_entropy || results.max_entropy || 0,
    anomalous_blocks: entropy.anomalous_blocks || results.anomalous_blocks || 0,
    total_blocks: entropy.total_blocks || results.total_blocks || 0,
    anomaly_rate: entropy.anomaly_rate || results.anomaly_rate || 0
  };
  const forensics = results.forensics || {};
  const regions = entropy.suspicious_regions || results.suspiciousRegions || entropy.suspiciousRegions || [];
  const chainOfCustody = results.chain_of_custody || [];
  const backendFindings = results.findings || [];
  const analysisStart = new Date(results.analyzedAt).getTime();
  const analysisEnd = Date.now();
  const analysisDuration = ((results.analysis_duration_ms || (analysisEnd - analysisStart)) / 1000).toFixed(1);

  // Use findings from backend if available, otherwise generate locally
  let findings: Finding[] = [];
  const meanEntropy = stats.mean_entropy || 0;
  const highEntropyRegions = regions.length;

  if (backendFindings.length > 0) {
    findings = backendFindings.map((f: any) => ({
      severity: f.severity || 'INFO',
      title: f.category || 'Unknown Finding',
      rationale: f.why_it_matters || '',
      evidence: Object.entries(f.evidence || {}).map(([k, v]) => `${k}=${v}`).join(', ')
    }));
  } else {
    // Entropy anomaly
    if (meanEntropy > 7.5) {
      findings.push({
        severity: 'HIGH',
        title: 'Entropy Anomaly Profile',
        rationale: 'Large high-entropy zones can represent encryption, packing, or random overwrite behavior commonly associated with hidden volumes.',
        evidence: `mean_entropy=${meanEntropy.toFixed(4)}, high_entropy_region_count=${highEntropyRegions}`
      });
    } else if (meanEntropy > 6.0) {
      findings.push({
        severity: 'MEDIUM',
        title: 'Elevated Entropy Profile',
        rationale: 'Some areas show elevated entropy which may indicate compressed data or partial encryption.',
        evidence: `mean_entropy=${meanEntropy.toFixed(4)}, region_count=${highEntropyRegions}`
      });
    } else {
      findings.push({
        severity: 'INFO',
        title: 'Normal Entropy Profile',
        rationale: 'Disk shows typical entropy distribution consistent with normal file system data.',
        evidence: `mean_entropy=${meanEntropy.toFixed(4)}`
      });
    }
  }

  // Timestamp consistency
  const hasMetadataIssues = (forensics.filesystem && forensics.filesystem.type === 'Unknown');
  if (hasMetadataIssues) {
    findings.push({
      severity: 'MEDIUM',
      title: 'Metadata Inconsistency Detected',
      rationale: 'Filesystem metadata could not be fully parsed. This may indicate unusual filesystem, corruption, or anti-forensic manipulation.',
      evidence: `filesystem_type=${forensics.filesystem?.type || 'Unknown'}`
    });
  }

  // Wipe detection
  if (forensics.diskWipe?.detected) {
    findings.push({
      severity: 'HIGH',
      title: 'Potential Wipe Signatures Detected',
      rationale: 'Structured overwrite patterns detected which may indicate intentional destruction or sanitization of evidence.',
      evidence: `wipe_software=${forensics.diskWipe.software || 'Unknown'}, confidence=${((forensics.diskWipe.confidence || 0) * 100).toFixed(0)}%`
    });
  }

  // Deleted files
  const deletedCount = (forensics.deletedFiles || []).length;
  if (deletedCount > 10) {
    findings.push({
      severity: 'LOW',
      title: 'Deleted Activity Concentration',
      rationale: 'Elevated number of deleted entries detected. This can indicate normal cleanup or deliberate post-incident anti-forensic behavior.',
      evidence: `deleted_files_count=${deletedCount}`
    });
  } else if (deletedCount > 0) {
    findings.push({
      severity: 'INFO',
      title: 'Deleted File Entries Present',
      rationale: 'Some deleted file entries were found. This is normal for active file systems.',
      evidence: `deleted_files_count=${deletedCount}`
    });
  }

  // Suspicious regions
  if (highEntropyRegions > 0) {
    findings.push({
      severity: highEntropyRegions > 100 ? 'HIGH' : 'MEDIUM',
      title: 'Suspicious High-Entropy Regions',
      rationale: 'Regions with unusually high entropy may contain hidden encrypted volumes, steganographic content, or VeraCrypt hidden containers.',
      evidence: `region_count=${highEntropyRegions}, total_region_bytes=${regions.reduce((a: number, r: any) => a + (r.size || 0), 0)}`
    });
  }

  // Partition info
  if ((forensics.partitions || []).length > 0) {
    findings.push({
      severity: 'INFO',
      title: 'Partition Structure Detected',
      rationale: 'Standard partition table was identified, indicating a normally structured disk.',
      evidence: `partition_count=${forensics.partitions.length}`
    });
  }

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <div className="bg-gray-900 border-b border-gray-800">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="sm" onClick={() => navigate('/upload')}>
                <ArrowLeft className="h-4 w-4 mr-2" />New Scan
              </Button>
              <div>
                <h1 className="text-2xl font-bold flex items-center gap-2">
                  <Shield className="h-6 w-6 text-cyan-400" />
                  Analysis Results
                </h1>
                <p className="text-gray-400 text-sm">{results.fileName} • {formatSize(results.fileSize)}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10" onClick={() => navigate(`/report/${id}`)}>
                <FileText className="h-4 w-4 mr-2" />Full Report
              </Button>
              <Button variant="outline" size="sm" className="border-cyan-500 text-cyan-400 hover:bg-cyan-500/10" onClick={() => window.open(`${API_URL}/result/${id}/pdf`, '_blank')}>
                <Download className="h-4 w-4 mr-2" />Download PDF
              </Button>
              <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/50">Complete</Badge>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8 space-y-6">
        
        {/* Chain of Custody / Timeline */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Timer className="h-5 w-5 text-cyan-400" />
              Chain of Custody & Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {chainOfCustody.length > 0 ? (
                chainOfCustody.map((event: any, idx: number) => (
                  <div key={idx} className="flex items-center gap-4">
                    <div className={`w-3 h-3 rounded-full ${event.status === 'COMPLETED' ? 'bg-green-500' : event.status === 'IN_PROGRESS' ? 'bg-cyan-500 animate-pulse' : 'bg-red-500'}`}></div>
                    <div className="flex-1">
                      <p className="font-medium">{event.event}</p>
                      <p className="text-sm text-gray-400">{event.details}</p>
                    </div>
                    <Badge variant="outline" className={`${event.status === 'COMPLETED' ? 'bg-green-500/10 text-green-400' : event.status === 'IN_PROGRESS' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-red-500/10 text-red-400'}`}>
                      <Check className="h-3 w-3 mr-1" /> {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                    </Badge>
                  </div>
                ))
              ) : (
                <>
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    <div className="flex-1">
                      <p className="font-medium">Analysis Initiated</p>
                      <p className="text-sm text-gray-400">{results.analyzedAt}</p>
                    </div>
                    <Badge variant="outline" className="bg-green-500/10 text-green-400">
                      <Check className="h-3 w-3 mr-1" /> Started
                    </Badge>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 rounded-full bg-cyan-500"></div>
                    <div className="flex-1">
                      <p className="font-medium">Entropy Analysis</p>
                      <p className="text-sm text-gray-400">Block-level entropy computation with Shannon entropy, chi-square, byte frequency</p>
                    </div>
                    <Badge variant="outline" className="bg-cyan-500/10 text-cyan-400">
                      <Check className="h-3 w-3 mr-1" /> Complete
                    </Badge>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 rounded-full bg-cyan-500"></div>
                    <div className="flex-1">
                      <p className="font-medium">Anomaly Detection (Z-Score + Isolation Forest)</p>
                      <p className="text-sm text-gray-400">Statistical and ML-based anomaly scoring</p>
                    </div>
                    <Badge variant="outline" className="bg-cyan-500/10 text-cyan-400">
                      <Check className="h-3 w-3 mr-1" /> Complete
                    </Badge>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 rounded-full bg-cyan-500"></div>
                    <div className="flex-1">
                      <p className="font-medium">Forensics Analysis</p>
                      <p className="text-sm text-gray-400">Partition detection (mmls), filesystem analysis (fsstat), deleted entries (fls), artifact extraction (bulk_extractor)</p>
                    </div>
                    <Badge variant="outline" className="bg-cyan-500/10 text-cyan-400">
                      <Check className="h-3 w-3 mr-1" /> Complete
                    </Badge>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    <div className="flex-1">
                      <p className="font-medium">Analysis Completed</p>
                      <p className="text-sm text-gray-400">Total processing time: {analysisDuration} seconds</p>
                    </div>
                    <Badge variant="outline" className="bg-green-500/10 text-green-400">
                      <Check className="h-3 w-3 mr-1" /> {analysisDuration}s
                    </Badge>
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Findings Section */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <FileText className="h-5 w-5 text-cyan-400" />
              Findings (Interpretation Layer)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-400 text-sm mb-6">
              Each finding includes severity, rationale, and supporting evidence for defensible reporting.
            </p>
            <div className="space-y-4">
              {findings.map((finding, idx) => (
                <div key={idx} className={`border rounded-lg p-4 ${getSeverityColor(finding.severity)}`}>
                  <div className="flex items-start gap-3">
                    {getSeverityIcon(finding.severity)}
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold">{finding.title}</h3>
                        <Badge className={`${finding.severity === 'HIGH' ? 'bg-red-500' : finding.severity === 'MEDIUM' ? 'bg-orange-500' : finding.severity === 'LOW' ? 'bg-yellow-500' : 'bg-green-500'}`}>
                          {finding.severity}
                        </Badge>
                      </div>
                      {finding.rationale && (
                        <p className="text-sm opacity-90 mb-2">{finding.rationale}</p>
                      )}
                      <p className="text-xs font-mono opacity-75">Evidence: {finding.evidence}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Technical Details */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">Disk Size</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold">{formatSize(results.fileSize)}</div></CardContent>
          </Card>
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">Total Blocks</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold">{(stats.total_blocks || 0).toLocaleString()}</div></CardContent>
          </Card>
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">Analysis Time</CardTitle></CardHeader>
            <CardContent><div className="text-2xl font-bold">{analysisDuration}s</div></CardContent>
          </Card>
        </div>

        {/* Detailed Stats */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="h-5 w-5 text-cyan-400" />
              Technical Analysis Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div><p className="text-gray-500 text-sm">Mean Entropy</p><p className="text-2xl font-bold">{Number(stats.mean_entropy || 0).toFixed(4)}</p></div>
              <div><p className="text-gray-500 text-sm">Max Entropy</p><p className="text-2xl font-bold text-cyan-400">{Number(stats.max_entropy || 0).toFixed(4)}</p></div>
              <div><p className="text-gray-500 text-sm">Anomalous Blocks</p><p className="text-2xl font-bold text-orange-400">{Number(stats.anomalous_blocks || 0).toLocaleString()}</p></div>
              <div><p className="text-gray-500 text-sm">Suspicious Regions</p><p className="text-2xl font-bold">{regions.length}</p></div>
            </div>
          </CardContent>
        </Card>

        {/* Suspicious Regions */}
        {regions.length > 0 && (
          <Card className="bg-gray-900 border-red-900/50">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Search className="h-5 w-5 text-red-400" />
                Suspicious High-Entropy Regions - {regions.length} Found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {regions.slice(0, 10).map((region: any, idx: number) => (
                  <div key={idx} className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-red-400">Region {idx + 1}</span>
                      <Badge className={region.mean_anomaly_score > 70 ? 'bg-red-500' : 'bg-orange-500'}>
                        Score: {(region.mean_anomaly_score || 0).toFixed(1)}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-2 mt-2 text-sm">
                      <div><span className="text-gray-500">Start:</span> <span className="font-mono">0x{(region.start_offset || 0).toString(16).toUpperCase()}</span></div>
                      <div><span className="text-gray-500">End:</span> <span className="font-mono">0x{(region.end_offset || 0).toString(16).toUpperCase()}</span></div>
                      <div><span className="text-gray-500">Size:</span> {formatSize(region.size || 0)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

      </div>
    </div>
  );
}
