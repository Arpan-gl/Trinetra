import React from 'react';
import { Layers, ShieldCheck, Database, Sliders, Cpu, Activity, Share2, FileCode } from 'lucide-react';

export const ArchitecturePipeline: React.FC = () => {
  const stages = [
    {
      level: 'L0',
      title: 'Packet & Flow Ingestion',
      icon: Database,
      badge: 'Zero-Copy Ring Buffer',
      color: 'text-sentinel-cyan',
      borderColor: 'border-sentinel-cyan/40',
      description: 'Ingests NetFlow v5/v9, IPFIX, and live PCAP stream frames into atomic ring buffers with zero kernel memory duplication.'
    },
    {
      level: 'L1',
      title: 'Protocol Normalization',
      icon: Sliders,
      badge: 'Leakage-Proof',
      color: 'text-sentinel-emerald',
      borderColor: 'border-sentinel-emerald/40',
      description: 'Decouples IP addresses and ephemeral ports to prevent geographic dataset overfitting while standardizing protocol flags.'
    },
    {
      level: 'L2',
      title: 'Robust Preprocessing',
      icon: Layers,
      badge: 'Quantile Robust Scaling',
      color: 'text-purple-400',
      borderColor: 'border-purple-400/40',
      description: 'Clips extreme burst spikes with Median Absolute Deviation (MAD) scaling and imputes dropped metadata headers.'
    },
    {
      level: 'L3',
      title: 'Spatial-Temporal Vectors',
      icon: Activity,
      badge: '32 Dimensional Space',
      color: 'text-sentinel-emerald',
      borderColor: 'border-sentinel-emerald/40',
      description: 'Extracts packet length distributions, inter-arrival time (IAT) variances, bidirectional flow asymmetries, and TCP window deltas.'
    },
    {
      level: 'L4',
      title: 'Specialized Classifier Ensemble',
      icon: Cpu,
      badge: '4 Parallel ML Engines',
      color: 'text-sentinel-cyan',
      borderColor: 'border-sentinel-cyan/40',
      description: 'Executes Random Forest, GPU-accelerated XGBoost, LightGBM, and Isolation Forest anomaly detector simultaneously in under 0.8ms.'
    },
    {
      level: 'L5',
      title: 'Meta-Learner Fusion',
      icon: ShieldCheck,
      badge: 'Stacking Meta-Model',
      color: 'text-sentinel-emerald',
      borderColor: 'border-sentinel-emerald/40',
      description: 'Blends probability vectors through a cross-validated logistic meta-learner to maximize Macro-F1 across volatile multi-class domains.'
    },
    {
      level: 'L6',
      title: 'Adaptive Thresholding Gate',
      icon: Sliders,
      badge: 'Tau-Calibrated',
      color: 'text-amber-400',
      borderColor: 'border-amber-400/40',
      description: 'Applies dynamic certainty boundaries (tau_critical = 0.82) to suppress benign noise while elevating zero-day attack anomalies.'
    },
    {
      level: 'L7',
      title: 'SIEM Dispatch & IPC Stream',
      icon: Share2,
      badge: 'Sub-Millisecond Webhook',
      color: 'text-sentinel-cyan',
      borderColor: 'border-sentinel-cyan/40',
      description: 'Dispatches validated JSON alerts via stdio pipes, local UNIX sockets, and Webhooks directly into Splunk, Elastic, or Sentinel.'
    },
  ];

  return (
    <section id="architecture" className="py-20 bg-canvas-DEFAULT relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-emerald/10 border border-sentinel-emerald/30 text-sentinel-emerald text-xs font-mono mb-3">
            <Cpu className="w-3.5 h-3.5" />
            <span>Architecture Breakdown</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            The L0–L8 Detection Pipeline
          </h2>
          <p className="text-slate-400 text-sm mt-3">
            Designed to comply strictly with SIH 2026 PS-145 constraints: zero deep packet inspection (DPI), complete airgap support, zero dataset leakage, and 50k flows/second throughput.
          </p>
        </div>

        {/* Pipeline Flow Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {stages.map((stage, idx) => {
            const Icon = stage.icon;
            return (
              <div
                key={idx}
                className="glass-panel p-5 rounded-2xl border border-white/5 hover:border-white/20 transition-all flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className={`text-xs font-mono font-extrabold px-2.5 py-1 rounded bg-white/5 border ${stage.borderColor} ${stage.color}`}>
                      {stage.level}
                    </span>
                    <Icon className={`w-4 h-4 ${stage.color} opacity-80 group-hover:scale-110 transition-transform`} />
                  </div>
                  
                  <h3 className="font-bold text-base text-white mb-1.5 group-hover:text-sentinel-emerald transition-colors">
                    {stage.title}
                  </h3>
                  
                  <div className="inline-block text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded mb-3">
                    {stage.badge}
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    {stage.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono text-slate-500">
                  <span>Stage {idx + 1} of 8</span>
                  <span className="text-sentinel-emerald">✓ Verified</span>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
