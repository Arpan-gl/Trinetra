import React from 'react';
import { BarChart3, Check, X, ShieldAlert, Award } from 'lucide-react';

export const Benchmarks: React.FC = () => {
  const benchmarkRows = [
    {
      metric: 'Throughput (Flows / Sec)',
      passivesentinel: '50,000+',
      suricata: '12,500',
      zeek: '8,200',
      snort3: '14,000',
      highlight: true
    },
    {
      metric: 'Inference Latency',
      passivesentinel: '1.3 ms',
      suricata: '8.4 ms',
      zeek: '14.2 ms',
      snort3: '6.8 ms',
      highlight: true
    },
    {
      metric: 'Packet Loss @ 50k fps',
      passivesentinel: '0.00%',
      suricata: '4.82%',
      zeek: '7.10%',
      snort3: '3.45%',
      highlight: true
    },
    {
      metric: 'Memory Footprint (RSS)',
      passivesentinel: '463 MB',
      suricata: '1,850 MB',
      zeek: '2,400 MB',
      snort3: '1,420 MB',
      highlight: false
    },
    {
      metric: 'Zero Payload / Zero DPI',
      passivesentinel: true,
      suricata: false,
      zeek: false,
      snort3: false,
      highlight: true
    },
    {
      metric: '100% Airgap Native',
      passivesentinel: true,
      suricata: false,
      zeek: false,
      snort3: false,
      highlight: false
    },
    {
      metric: 'Ensemble Meta-Learner',
      passivesentinel: true,
      suricata: false,
      zeek: false,
      snort3: false,
      highlight: false
    }
  ];

  return (
    <section id="benchmarks" className="py-20 bg-canvas-DEFAULT relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-cyan/10 border border-sentinel-cyan/30 text-sentinel-cyan text-xs font-mono mb-3">
            <BarChart3 className="w-3.5 h-3.5" />
            <span>Table 6.6 Performance Matrix</span>
          </div>
          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Benchmark & Engine Comparison
          </h2>
          <p className="text-slate-400 text-sm mt-3">
            Benchmarked against traditional signature NIDS on identical 66.9M NetFlow stream replays using dual 10GbE network interfaces.
          </p>
        </div>

        {/* Matrix Table */}
        <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden shadow-glass mb-12">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="bg-canvas-elevated border-b border-white/10 text-slate-300">
                  <th className="py-4 px-6 font-bold">System Metric</th>
                  <th className="py-4 px-6 font-extrabold text-sentinel-emerald bg-sentinel-emerald/5">
                    PASSIVESENTINEL (Ours)
                  </th>
                  <th className="py-4 px-6 text-slate-400">Suricata 7.0</th>
                  <th className="py-4 px-6 text-slate-400">Zeek 6.0</th>
                  <th className="py-4 px-6 text-slate-400">Snort 3.1</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {benchmarkRows.map((row, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                    <td className="py-4 px-6 font-medium text-slate-300">
                      {row.metric}
                    </td>

                    {/* PassiveSentinel Value */}
                    <td className="py-4 px-6 font-bold text-sentinel-emerald bg-sentinel-emerald/5">
                      {typeof row.passivesentinel === 'boolean' ? (
                        row.passivesentinel ? (
                          <span className="inline-flex items-center gap-1.5 text-sentinel-emerald">
                            <Check className="w-4 h-4" /> YES
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-slate-500">
                            <X className="w-4 h-4" /> NO
                          </span>
                        )
                      ) : (
                        row.passivesentinel
                      )}
                    </td>

                    {/* Suricata */}
                    <td className="py-4 px-6 text-slate-400">
                      {typeof row.suricata === 'boolean' ? (
                        row.suricata ? (
                          <Check className="w-4 h-4 text-slate-300" />
                        ) : (
                          <X className="w-4 h-4 text-slate-600" />
                        )
                      ) : (
                        row.suricata
                      )}
                    </td>

                    {/* Zeek */}
                    <td className="py-4 px-6 text-slate-400">
                      {typeof row.zeek === 'boolean' ? (
                        row.zeek ? (
                          <Check className="w-4 h-4 text-slate-300" />
                        ) : (
                          <X className="w-4 h-4 text-slate-600" />
                        )
                      ) : (
                        row.zeek
                      )}
                    </td>

                    {/* Snort 3 */}
                    <td className="py-4 px-6 text-slate-400">
                      {typeof row.snort3 === 'boolean' ? (
                        row.snort3 ? (
                          <Check className="w-4 h-4 text-slate-300" />
                        ) : (
                          <X className="w-4 h-4 text-slate-600" />
                        )
                      ) : (
                        row.snort3
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Rigorous Academic Science Box */}
        <div className="p-6 rounded-2xl glass-panel border border-sentinel-emerald/20 bg-gradient-to-r from-sentinel-emerald/5 to-transparent">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-xl bg-sentinel-emerald/10 border border-sentinel-emerald/30 text-sentinel-emerald shrink-0">
              <Award className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base mb-1">
                Zero Data Leakage Guarantee (5-Fold Stratified GroupKFold)
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Many ML NIDS papers report misleading 99.9% accuracy by random-splitting synthetic datasets where identical IPs or subnets bleed across train and test sets. PassiveSentinel is rigorously validated with <strong>GroupKFold cross-validation grouped on source/destination subnets</strong>, achieving an honest, leak-free <strong className="text-sentinel-emerald">0.6852 Macro-F1</strong> and <strong className="text-sentinel-emerald">0.6297 Matthews Correlation Coefficient (MCC)</strong> on unseen hostile traffic.
              </p>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
};
