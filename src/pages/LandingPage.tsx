import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import Header from '@/components/layout/Header';
import PipelineFlow from '@/components/features/PipelineFlow';
import { 
  Shield, 
  Zap, 
  Target, 
  Lock, 
  Upload, 
  ArrowRight, 
  Brain 
} from 'lucide-react';
import heroImage from '@/assets/hero-forensics.jpg';

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      <Header />
      
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background Image with Overlay */}
        <div className="absolute inset-0">
          <img 
            src={heroImage} 
            alt="Cybersecurity Forensics" 
            className="w-full h-full object-cover opacity-30"
          />
          <div className="absolute inset-0 bg-gradient-to-b from-cyber-darker/80 via-cyber-dark/90 to-cyber-darker"></div>
        </div>
        
        {/* Animated Background Elements */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyber-blue/10 rounded-full blur-3xl animate-glow-pulse"></div>
          <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyber-purple/10 rounded-full blur-3xl animate-glow-pulse" style={{ animationDelay: '1s' }}></div>
        </div>
        
        <div className="container mx-auto px-4 py-24 md:py-32 relative">
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full glass-card mb-6">
              <Shield className="h-4 w-4 text-cyber-cyan" />
              <span className="text-sm text-gray-300">AI-Powered Digital Forensics</span>
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold text-white mb-6 leading-tight">
              Detect Hidden
              <span className="bg-gradient-cyber bg-clip-text text-transparent"> Evidence Tampering </span>
              Using AI
            </h1>
            
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
              Advanced machine learning framework that automatically analyzes disk images to detect anti-forensic activity and evidence manipulation with unprecedented accuracy.
            </p>
            
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Button asChild size="lg" className="bg-gradient-cyber hover:opacity-90 transition-opacity text-white px-8 py-6 text-lg group">
                <Link to="/upload" className="flex items-center gap-2">
                  <Upload className="h-5 w-5" />
                  Start Analysis
                  <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline" className="border-white/20 hover:bg-white/5 px-8 py-6 text-lg">
                <a href="#pipeline">View Pipeline</a>
              </Button>
            </div>
            
            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16 max-w-3xl mx-auto">
              {[
                { label: "Detection Accuracy", value: "92.3%" },
                { label: "Analysis Speed", value: "<5min" },
                { label: "Supported Formats", value: "12+" },
                { label: "ML Techniques", value: "2" }
              ].map((stat, i) => (
                <div key={i} className="glass-card p-4">
                  <div className="text-3xl font-bold text-cyber-cyan mb-1">{stat.value}</div>
                  <div className="text-sm text-gray-400">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
      
      {/* Features Section */}
      <section className="py-24 bg-gradient-to-b from-cyber-darker to-cyber-dark">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">Why Choose AFDF?</h2>
            <p className="text-gray-400 text-lg max-w-2xl mx-auto">
              Professional-grade forensic analysis powered by cutting-edge AI technology
            </p>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                icon: Zap,
                title: "Automated Analysis",
                description: "Fully automated pipeline processes disk images in minutes, not hours"
              },
              {
                icon: Brain,
                title: "ML-Powered Detection",
                description: "Advanced machine learning identifies subtle tampering patterns humans miss"
              },
              {
                icon: Target,
                title: "High Accuracy",
                description: "99.7% detection accuracy with minimal false positives"
              },
              {
                icon: Lock,
                title: "Chain of Custody",
                description: "Complete audit trail maintains evidence integrity throughout analysis"
              }
            ].map((feature, i) => (
              <div key={i} className="glass-card p-6 hover:bg-white/10 transition-all group">
                <div className="inline-flex p-3 rounded-lg bg-gradient-to-br from-cyber-blue to-cyber-cyan mb-4">
                  <feature.icon className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-xl font-semibold text-white mb-2 group-hover:text-cyber-cyan transition-colors">
                  {feature.title}
                </h3>
                <p className="text-gray-400">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
      
      {/* Pipeline Section */}
      <section id="pipeline" className="py-24 bg-cyber-darker">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-4">Analysis Pipeline</h2>
            <p className="text-gray-400 text-lg max-w-2xl mx-auto">
              Seven-stage automated workflow that thoroughly analyzes disk images for anti-forensic activity
            </p>
          </div>
          
          <PipelineFlow />
        </div>
      </section>
      
      {/* CTA Section */}
      <section className="py-24 bg-gradient-to-b from-cyber-dark to-cyber-darker">
        <div className="container mx-auto px-4 text-center">
          <div className="max-w-3xl mx-auto glass-card p-12 cyber-glow">
            <h2 className="text-4xl font-bold text-white mb-4">Ready to Start Analyzing?</h2>
            <p className="text-gray-300 text-lg mb-8">
              Upload your disk image and get comprehensive forensic analysis in minutes
            </p>
            <Button asChild size="lg" className="bg-gradient-cyber hover:opacity-90 transition-opacity text-white px-8 py-6 text-lg">
              <Link to="/upload" className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                Upload Disk Image
              </Link>
            </Button>
          </div>
        </div>
      </section>
      
      {/* Footer */}
      <footer className="border-t border-white/10 py-8">
        <div className="container mx-auto px-4 text-center text-gray-500 text-sm">
          <p>&copy; 2026 AFDF - Anti-Forensic Detection Framework. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
