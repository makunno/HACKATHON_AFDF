import { Link } from 'react-router-dom';
import { Shield, Upload, LayoutDashboard, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function Header() {
  return (
    <header className="border-b border-white/10 bg-cyber-dark/50 backdrop-blur-md sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative">
              <Shield className="h-8 w-8 text-cyber-blue group-hover:text-cyber-cyan transition-colors" />
              <div className="absolute inset-0 bg-cyber-blue/20 blur-xl group-hover:bg-cyber-cyan/30 transition-all"></div>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">AFDF</h1>
              <p className="text-xs text-cyan-400">Anti-Forensic Detection Framework</p>
            </div>
          </Link>
          
          <nav className="hidden md:flex items-center gap-6">
            <Link to="/" className="text-sm text-gray-300 hover:text-cyber-cyan transition-colors">
              Home
            </Link>
            <Link to="/upload" className="text-sm text-gray-300 hover:text-cyber-cyan transition-colors flex items-center gap-2">
              <Upload className="h-4 w-4" />
              Upload
            </Link>
            <Button asChild className="bg-gradient-cyber hover:opacity-90 transition-opacity">
              <Link to="/upload">Start Analysis</Link>
            </Button>
          </nav>
        </div>
      </div>
    </header>
  );
}
