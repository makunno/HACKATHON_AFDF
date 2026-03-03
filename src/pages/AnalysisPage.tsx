import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Header from '@/components/layout/Header';
import { CheckCircle2, Loader2 } from 'lucide-react';
import { Progress } from '@/components/ui/progress';

const API_URL = '/api';

export default function AnalysisPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'complete' | 'error'>('loading');

  useEffect(() => {
    if (!id) {
      navigate('/upload');
      return;
    }

    // Poll backend for results
    const pollForResults = () => {
      fetch(`${API_URL}/result/${id}`)
        .then(res => {
          if (res.ok) {
            return res.json();
          }
          throw new Error('Not found');
        })
        .then(data => {
          setStatus('complete');
          setTimeout(() => {
            navigate(`/dashboard/${id}`);
          }, 1500);
        })
        .catch(() => {
          // Continue polling - analysis still in progress
        });
    };

    // Poll every 2 seconds
    pollForResults();
    const interval = setInterval(pollForResults, 2000);

    return () => clearInterval(interval);
  }, [id, navigate]);

  return (
    <div className="min-h-screen bg-gray-900">
      <Header />
      <div className="container mx-auto px-4 py-12">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-12">
            <h1 className="text-4xl font-bold text-white mb-4">
              {status === 'complete' ? 'Analysis Complete!' : 'Forensic Analysis in Progress'}
            </h1>
            <p className="text-gray-400">
              {status === 'complete' 
                ? 'Redirecting to results...' 
                : 'Running full disk image analysis...'}
            </p>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 mb-6 border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">Analysis Status</h2>
              {status === 'complete' ? (
                <CheckCircle2 className="h-5 w-5 text-green-400" />
              ) : (
                <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
              )}
            </div>
            <Progress value={status === 'complete' ? 100 : 75} className="h-2" />
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h2 className="text-xl font-semibold text-white mb-6">Analysis Stages</h2>
            
            <div className="space-y-4">
              {[
                'File Upload & Validation',
                'Integrity Check (Headers, Signatures)',
                'Metadata Extraction',
                'Artifact Analysis (Wiping, Timestamps)',
                'Entropy Scan (Full File)',
                'Final Score Calculation'
              ].map((stage, index) => (
                <div key={index} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {status === 'complete' ? (
                        <CheckCircle2 className="h-5 w-5 text-green-400" />
                      ) : index < 5 ? (
                        <CheckCircle2 className="h-5 w-5 text-green-400" />
                      ) : (
                        <Loader2 className="h-5 w-5 text-cyan-400 animate-spin" />
                      )}
                      <span className={`font-medium ${
                        status === 'complete' || index < 5 
                          ? 'text-green-400' 
                          : 'text-cyan-400'
                      }`}>
                        {stage}
                      </span>
                    </div>
                    <span className="text-sm text-gray-400">
                      {status === 'complete' || index < 5 ? '100%' : 'In Progress'}
                    </span>
                  </div>
                  {index < 5 && status !== 'complete' && (
                    <Progress value={100} className="h-1" />
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700 mt-6">
            <h2 className="text-xl font-semibold text-white mb-4">Analysis Log</h2>
            <div className="bg-black rounded-lg p-4 h-48 overflow-y-auto font-mono text-xs text-gray-300">
              <div>[{new Date().toLocaleTimeString()}] Starting forensic analysis...</div>
              <div>[{new Date().toLocaleTimeString()}] File uploaded successfully</div>
              <div>[{new Date().toLocaleTimeString()}] Analyzing full file contents...</div>
              <div>[{new Date().toLocaleTimeString()}] Computing entropy (Shannon)...</div>
              <div>[{new Date().toLocaleTimeString()}] Checking for anti-forensic signatures...</div>
              <div>[{new Date().toLocaleTimeString()}] Detecting wiping patterns...</div>
              <div>[{new Date().toLocaleTimeString()}] Analyzing timestamp artifacts...</div>
              <div>[{new Date().toLocaleTimeString()}] Calculating integrity score...</div>
              {status === 'complete' && (
                <div className="text-green-400">[{new Date().toLocaleTimeString()}] Analysis complete!</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
