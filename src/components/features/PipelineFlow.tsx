import { Shield, Cog, Wrench, ScanLine, Database, Brain, BarChart3, ArrowRight } from 'lucide-react';

interface PipelineStage {
  id: number;
  title: string;
  subtitle: string;
  icon: React.ElementType;
  color: string;
  details: string[];
}

const stages: PipelineStage[] = [
  {
    id: 1,
    title: "Evidence Integrity Check",
    subtitle: "Hash verification & format validation",
    icon: Shield,
    color: "from-green-500 to-emerald-600",
    details: ["SHA-256 hashing", "Format validation"]
  },
  {
    id: 2,
    title: "Python Pipeline Controller",
    subtitle: "Automated orchestration engine",
    icon: Cog,
    color: "from-blue-500 to-blue-600",
    details: ["Automated orchestration engine"]
  },
  {
    id: 3,
    title: "Tool Execution Layer",
    subtitle: "Forensic tools integration",
    icon: Wrench,
    color: "from-gray-500 to-gray-600",
    details: ["Sleuth Kit", "Bulk Extractor", "ExifTool", "Volatility (optional)"]
  },
  {
    id: 4,
    title: "Rust Low-Level Scanner",
    subtitle: "Deep disk analysis",
    icon: ScanLine,
    color: "from-orange-500 to-yellow-600",
    details: ["Entropy analysis", "Wipe pattern detection", "Hidden sector scan", "Slack space anomaly"]
  },
  {
    id: 5,
    title: "Data Normalization Layer",
    subtitle: "Unified schema conversion",
    icon: Database,
    color: "from-cyan-500 to-cyan-600",
    details: ["Convert all outputs", "Unified JSON schema"]
  },
  {
    id: 6,
    title: "Correlation + ML Detection Engine",
    subtitle: "AI-powered analysis",
    icon: Brain,
    color: "from-purple-500 to-purple-600",
    details: ["Cross-artifact comparison", "Anomaly detection", "Tamper confidence scoring"]
  },
  {
    id: 7,
    title: "Dashboard + Investigator Report",
    subtitle: "Results visualization",
    icon: BarChart3,
    color: "from-blue-500 to-purple-600",
    details: ["Integrity score", "Tamper alerts", "Anomaly timeline", "Final evidence verdict"]
  }
];

export default function PipelineFlow() {
  return (
    <div className="relative">
      {/* Desktop View */}
      <div className="hidden lg:block overflow-x-auto pb-8">
        <div className="flex items-center gap-4 min-w-max px-4">
          {stages.map((stage, index) => (
            <div key={stage.id} className="flex items-center">
              <div className="glass-card p-6 w-64 hover:bg-white/10 transition-all group">
                <div className={`inline-flex p-3 rounded-lg bg-gradient-to-br ${stage.color} mb-4`}>
                  <stage.icon className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-lg font-semibold text-white mb-1 group-hover:text-cyber-cyan transition-colors">
                  {stage.title}
                </h3>
                <p className="text-sm text-gray-400 mb-3">{stage.subtitle}</p>
                <ul className="space-y-1">
                  {stage.details.map((detail, i) => (
                    <li key={i} className="text-xs text-gray-500 flex items-start gap-2">
                      <span className="text-cyber-cyan mt-0.5">→</span>
                      <span>{detail}</span>
                    </li>
                  ))}
                </ul>
              </div>
              
              {index < stages.length - 1 && (
                <ArrowRight className="h-8 w-8 text-cyber-cyan mx-2 flex-shrink-0" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Mobile/Tablet View */}
      <div className="lg:hidden grid gap-4 px-4">
        {stages.map((stage, index) => (
          <div key={stage.id}>
            <div className="glass-card p-6 hover:bg-white/10 transition-all group">
              <div className="flex items-start gap-4">
                <div className={`inline-flex p-3 rounded-lg bg-gradient-to-br ${stage.color} flex-shrink-0`}>
                  <stage.icon className="h-6 w-6 text-white" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-white mb-1 group-hover:text-cyber-cyan transition-colors">
                    {stage.title}
                  </h3>
                  <p className="text-sm text-gray-400 mb-3">{stage.subtitle}</p>
                  <ul className="space-y-1">
                    {stage.details.map((detail, i) => (
                      <li key={i} className="text-xs text-gray-500 flex items-start gap-2">
                        <span className="text-cyber-cyan mt-0.5">→</span>
                        <span>{detail}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
            
            {index < stages.length - 1 && (
              <div className="flex justify-center py-2">
                <ArrowRight className="h-6 w-6 text-cyber-cyan rotate-90" />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
