import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '@/components/layout/Header';
import { Button } from '@/components/ui/button';
import { Upload, FileCheck, AlertCircle, HardDrive, Loader2, File, CheckCircle, XCircle, Activity, Shield, Database } from 'lucide-react';
import { toast } from 'sonner';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

const API_URL = '/api';

export default function UploadPage() {
  const navigate = useNavigate();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('');

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  const handleFile = (file: File) => {
    const validExtensions = ['.dd', '.e01', '.img', '.raw', '.001', '.dmg', '.vhd', '.vmdk'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!validExtensions.includes(fileExtension)) {
      toast.error('Invalid file format. Please upload a disk image (.dd, .E01, .img, .raw, .001)');
      return;
    }
    
    setSelectedFile(file);
    toast.success(`File "${file.name}" ready for analysis`);
  };

  const startAnalysis = async () => {
    if (!selectedFile) {
      toast.error('Please select a disk image file first');
      return;
    }

    setUploading(true);
    setProgress(10);
    setStatusMessage('Starting analysis...');
    
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress(p => Math.min(p + 5, 90));
      }, 2000);

      const response = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        body: formData
      });

      clearInterval(progressInterval);
      setProgress(100);
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Analysis failed');
      }
      
      const result = await response.json();
      toast.success('Analysis complete!');
      navigate(`/dashboard/${result.id}`);
      
    } catch (error: any) {
      console.error('Error:', error);
      toast.error(error.message || 'Error analyzing file. Please try again.');
    } finally {
      setUploading(false);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen">
      <Header />
      
      <div className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto">
          {/* Header */}
          <div className="text-center mb-12">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass-card mb-4">
              <Shield className="h-4 w-4 text-cyber-cyan" />
              <span className="text-sm text-gray-300">AI-Powered Forensics</span>
            </div>
            <h1 className="text-4xl font-bold text-white mb-4">
              EntropyGuard
            </h1>
            <p className="text-gray-400 text-lg max-w-2xl mx-auto">
              Detect hidden encrypted volumes and high-entropy regions in disk images. 
              Advanced AI-powered analysis for digital forensics investigations.
            </p>
          </div>

          {/* Upload Area */}
          <div
            className={`glass-card p-12 text-center transition-all cursor-pointer ${
              dragActive ? 'bg-white/10 border-cyber-cyan' : 'hover:bg-white/5'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              className="hidden"
              onChange={handleChange}
              accept=".dd,.e01,.img,.raw,.001,.dmg,.vhd,.vmdk"
            />
            
            <label htmlFor="file-upload" className="cursor-pointer">
              <div className="flex flex-col items-center">
                {selectedFile ? (
                  <>
                    <FileCheck className="h-20 w-20 text-green-500 mb-4" />
                    <h3 className="text-2xl font-semibold text-white mb-2">File Ready</h3>
                    <div className="flex items-center gap-2 text-gray-400 mb-1">
                      <File className="h-4 w-4" />
                      <span>{selectedFile.name}</span>
                    </div>
                    <p className="text-sm text-gray-500">
                      {formatFileSize(selectedFile.size)}
                    </p>
                    <Button variant="outline" className="border-white/20 hover:bg-white/5 mt-4">
                      Choose Different File
                    </Button>
                  </>
                ) : (
                  <>
                    <Upload className="h-20 w-20 text-cyber-cyan mb-4" />
                    <h3 className="text-2xl font-semibold text-white mb-2">
                      Drop disk image here or click to browse
                    </h3>
                    <p className="text-gray-400 mb-4">
                      Drag and drop your forensic image file
                    </p>
                    <p className="text-sm text-gray-500">
                      Supported: .dd, .E01, .img, .raw, .001, .dmg, .vhd, .vmdk
                    </p>
                  </>
                )}
              </div>
            </label>
          </div>

          {/* Features Grid */}
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <Card className="bg-white/5 border-white/10">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-white">
                  <Activity className="h-4 w-4 text-cyber-cyan" />
                  Entropy Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-400">
                  Shannon entropy, chi-square, byte frequency, serial correlation
                </p>
              </CardContent>
            </Card>
            
            <Card className="bg-white/5 border-white/10">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-white">
                  <Shield className="h-4 w-4 text-cyber-cyan" />
                  AI Detection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-400">
                  Isolation Forest, LOF, and PyTorch Autoencoder
                </p>
              </CardContent>
            </Card>
            
            <Card className="bg-white/5 border-white/10">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-white">
                  <Database className="h-4 w-4 text-cyber-cyan" />
                  Forensics Tools
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-400">
                  mmls, fsstat, fls, bulk_extractor, EXIF extraction
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Progress */}
          {uploading && (
            <div className="mt-8 glass-card p-6">
              <div className="flex items-center gap-4 mb-4">
                <Loader2 className="h-6 w-6 text-cyber-cyan animate-spin" />
                <div className="flex-1">
                  <div className="flex justify-between text-white mb-1">
                    <span>{statusMessage || 'Processing...'}</span>
                    <span>{progress}%</span>
                  </div>
                  <Progress value={progress} className="h-2" />
                </div>
              </div>
              <p className="text-sm text-gray-400">
                Analyzing disk for hidden volumes and encrypted regions...
              </p>
            </div>
          )}

          {/* Start Button */}
          <div className="mt-8 flex justify-center">
            <Button
              size="lg"
              onClick={startAnalysis}
              disabled={!selectedFile || uploading}
              className="bg-gradient-cyber hover:opacity-90 transition-opacity px-12 py-6 text-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {uploading ? (
                <>
                  <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-5 w-5" />
                  Start Forensic Analysis
                </>
              )}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
