import React, { useState } from 'react';
import { Play, RotateCcw, Copy, Check, AlertTriangle, ShieldCheck, Cpu, Code2, Sparkles, ChevronRight, Zap } from 'lucide-react';
import { THREAT_PRESETS, ThreatPreset } from '../data/mockThreats';
import { DetectionResult } from '../types';

export const ThreatSimulator: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<ThreatPreset>(THREAT_PRESETS[0]);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeStage, setActiveStage] = useState<number>(8); // 8 = completed
  const [result, setResult] = useState<DetectionResult>(THREAT_PRESETS[0].result);
  const [copied, setCopied] = useState<boolean>(false);
  const [activeResultTab, setActiveResultTab] = useState<'overview' | 'json' | 'pipeline'>('overview');

  const pipelineStages = [
    { id: 0, label: 'L0 Ingest', desc: 'NetFlow Packet Buffer' },
    { id: 1, label: 'L1 Norm', desc: 'IP/Port Decoupling' },
    { id: 2, label: 'L2 Prep', desc: 'Outlier Imputation' },
    { id: 3, label: 'L3 Feat', desc: '32 Temporal Vectors' },
    { id: 4, label: 'L4 Class', desc: '4-Model Ensemble' },
    { id: 5, label: 'L5 Meta', desc: 'Meta-Learner Fusion' },
    { id: 6, label: 'L6 Thresh', desc: 'Dynamic Tau Gate' },
    { id: 7, label: 'L7 Alert', desc: 'SIEM Dispatch' },
  ];

  const handleSelectPreset = (preset: ThreatPreset) => {
    setSelectedPreset(preset);
    setResult(preset.result);
    setActiveStage(8);
  };

  const runSimulation = () => {
    setIsRunning(true);
    setActiveStage(0);

    const interval = setInterval(() => {
      setActiveStage((prev) => {
        if (prev >= 7) {
          clearInterval(interval);
          setIsRunning(false);
          setResult({
            ...selectedPreset.result,
            timestamp: new Date().toISOString(),
          });
          return 8; // complete
        }
        return prev + 1;
      });
    }, 180);
  };

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="simulator" className="py-20 bg-canvas-subtle border-y border-white/[0.08] relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-cyan/10 border border-sentinel-cyan/30 text-sentinel-cyan text-xs font-mono mb-3">
              <Zap className="w-3.5 h-3.5" />
              <span>Interactive Telemetry Playground</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Live Threat Engine Simulator
            </h2>
            <p className="text-slate-400 text-sm mt-2 max-w-xl">
              Feed raw NetFlow tuples directly into the PassiveSentinel L0–L8 runtime pipeline and inspect real-time inference verdicts, latency, and MITRE ATT&CK mapping.
            </p>
          </div>

          {/* Action Trigger */}
          <div className="mt-6 md:mt-0 flex items-center gap-3">
            <button
              onClick={runSimulation}
              disabled={isRunning}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-sentinel-emerald to-sentinel-cyan text-canvas-DEFAULT font-bold text-xs sm:text-sm hover:opacity-95 transition-all shadow-glow-emerald disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-canvas-DEFAULT" />
              <span>{isRunning ? 'Analyzing L0–L8...' : 'Run L0–L8 Detection'}</span>
            </button>
          </div>
        </div>

        {/* Attack Presets Selection */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
          {THREAT_PRESETS.map((preset) => {
            const isSelected = selectedPreset.id === preset.id;
            return (
              <button
                key={preset.id}
                onClick={() => handleSelectPreset(preset)}
                className={`p-4 rounded-xl text-left transition-all border ${
                  isSelected
                    ? 'bg-canvas-elevated border-sentinel-emerald/60 shadow-glow-emerald'
                    : 'bg-canvas-DEFAULT/70 border-white/5 hover:border-white/20'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className={`text-[10px] font-mono uppercase font-semibold px-2 py-0.5 rounded ${
                    preset.result.severity === 'CRITICAL'
                      ? 'bg-sentinel-red/20 text-sentinel-red'
                      : preset.result.severity === 'HIGH'
                      ? 'bg-sentinel-amber/20 text-sentinel-amber'
                      : 'bg-sentinel-emerald/20 text-sentinel-emerald'
                  }`}>
                    {preset.result.severity}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">{preset.category}</span>
                </div>
                <h4 className="font-semibold text-sm text-slate-100 group-hover:text-sentinel-emerald mb-1">
                  {preset.name}
                </h4>
                <p className="text-xs text-slate-400 line-clamp-2">
                  {preset.description}
                </p>
              </button>
            );
          })}
        </div>

        {/* Real-time Pipeline Progress Bar */}
        <div className="glass-panel p-5 rounded-2xl mb-8 border border-white/10">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-sentinel-cyan" />
              <span>PIPELINE EXECUTION TRACE (L0 TO L7)</span>
            </span>
            <span className="text-xs font-mono text-sentinel-emerald">
              {isRunning ? `PROCESSING STAGE L${activeStage}` : 'STAGE TRACE COMPLETED (1.3ms)'}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
            {pipelineStages.map((stage) => {
              const isCurrent = isRunning && activeStage === stage.id;
              const isDone = activeStage > stage.id;

              return (
                <div
                  key={stage.id}
                  className={`p-2.5 rounded-lg border text-center transition-all ${
                    isCurrent
                      ? 'bg-sentinel-cyan/20 border-sentinel-cyan text-sentinel-cyan scale-105 shadow-glow-cyan'
                      : isDone
                      ? 'bg-sentinel-emerald/10 border-sentinel-emerald/40 text-sentinel-emerald'
                      : 'bg-canvas-DEFAULT/40 border-white/5 text-slate-500'
                  }`}
                >
                  <div className="text-[11px] font-mono font-bold">{stage.label}</div>
                  <div className="text-[10px] text-slate-400 truncate mt-0.5">{stage.desc}</div>
                  <div className="mt-1 flex justify-center">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      isCurrent ? 'bg-sentinel-cyan animate-ping' : isDone ? 'bg-sentinel-emerald' : 'bg-slate-700'
                    }`} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Playground Split: Left Flow Vector, Right Detection Output */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* Left: Raw NetFlow Input Form */}
          <div className="lg:col-span-5 glass-panel p-6 rounded-2xl border border-white/10 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
                <div className="flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-sentinel-emerald" />
                  <span className="text-xs font-mono font-bold text-white">INPUT FLOW TUPLE (NETFLOW V9)</span>
                </div>
                <span className="text-[11px] font-mono text-slate-400">Zero Payload Required</span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 bg-canvas-DEFAULT rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-500 block">SOURCE ADDRESS</span>
                    <span className="text-sentinel-cyan font-semibold">{selectedPreset.flowPayload.src_ip}</span>
                  </div>
                  <div className="p-2.5 bg-canvas-DEFAULT rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-500 block">DESTINATION ADDRESS</span>
                    <span className="text-sentinel-emerald font-semibold">{selectedPreset.flowPayload.dst_ip}</span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div className="p-2 bg-canvas-DEFAULT rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-500 block">PROTOCOL</span>
                    <span className="text-white font-semibold">{selectedPreset.flowPayload.proto}</span>
                  </div>
                  <div className="p-2 bg-canvas-DEFAULT rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-500 block">SRC PORT</span>
                    <span className="text-white">{selectedPreset.flowPayload.src_port}</span>
                  </div>
                  <div className="p-2 bg-canvas-DEFAULT rounded-lg border border-white/5">
                    <span className="text-[10px] text-slate-500 block">DST PORT</span>
                    <span className="text-white">{selectedPreset.flowPayload.dst_port}</span>
                  </div>
                </div>

                <div className="p-3 bg-canvas-DEFAULT rounded-lg border border-white/5 space-y-1.5 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Duration (ms):</span>
                    <span className="text-slate-200">{selectedPreset.flowPayload.flow_duration}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Total Fwd / Bwd Pkts:</span>
                    <span className="text-slate-200">{selectedPreset.flowPayload.tot_fwd_pkts} / {selectedPreset.flowPayload.tot_bwd_pkts}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Packet Len Mean (bytes):</span>
                    <span className="text-slate-200">{selectedPreset.flowPayload.pkt_len_mean}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Down / Up Ratio:</span>
                    <span className="text-slate-200">{selectedPreset.flowPayload.down_up_ratio}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">SYN / ACK Flags:</span>
                    <span className="text-slate-200">{selectedPreset.flowPayload.syn_flag_cnt} / {selectedPreset.flowPayload.ack_flag_cnt}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Status: Stream Synced</span>
              <span className="text-sentinel-emerald flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-sentinel-emerald animate-ping" />
                Live Ingest Active
              </span>
            </div>
          </div>

          {/* Right: Real-time Analysis Result & JSON Alert Inspector */}
          <div className="lg:col-span-7 glass-panel p-6 rounded-2xl border border-white/10">
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
              <div className="flex items-center gap-2">
                {(['overview', 'pipeline', 'json'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveResultTab(tab)}
                    className={`px-3 py-1 rounded-md text-xs font-mono font-medium capitalize transition-all ${
                      activeResultTab === tab
                        ? 'bg-sentinel-emerald/20 text-sentinel-emerald border border-sentinel-emerald/40'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {tab === 'json' ? 'JSON Contract' : tab}
                  </button>
                ))}
              </div>

              {activeResultTab === 'json' && (
                <button
                  onClick={copyJson}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-xs font-mono text-slate-300 transition-all"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-sentinel-emerald" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              )}
            </div>

            {/* View 1: Overview Card */}
            {activeResultTab === 'overview' && (
              <div className="space-y-4">
                
                {/* Verdict Header */}
                <div className="p-4 rounded-xl bg-canvas-DEFAULT border border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-xl border ${
                      result.severity === 'CRITICAL'
                        ? 'bg-sentinel-red/20 border-sentinel-red/40 text-sentinel-red shadow-glow-red'
                        : result.severity === 'HIGH'
                        ? 'bg-sentinel-amber/20 border-sentinel-amber/40 text-sentinel-amber'
                        : 'bg-sentinel-emerald/20 border-sentinel-emerald/40 text-sentinel-emerald'
                    }`}>
                      {result.severity === 'BENIGN' ? <ShieldCheck className="w-6 h-6" /> : <AlertTriangle className="w-6 h-6" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-base font-bold text-white font-mono">{result.threat_type}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold ${
                          result.severity === 'CRITICAL'
                            ? 'bg-sentinel-red text-white'
                            : result.severity === 'HIGH'
                            ? 'bg-sentinel-amber text-black'
                            : 'bg-sentinel-emerald text-black'
                        }`}>
                          {result.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{result.attack_category}</p>
                    </div>
                  </div>

                  <div className="text-right sm:border-l sm:border-white/10 sm:pl-4">
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Confidence</div>
                    <div className="text-xl font-mono font-extrabold text-sentinel-emerald">
                      {(result.ensemble_confidence * 100).toFixed(2)}%
                    </div>
                    <div className="text-[10px] font-mono text-slate-400">{result.latency_ms} ms latency</div>
                  </div>
                </div>

                {/* MITRE ATT&CK Mapping */}
                <div className="p-4 rounded-xl bg-canvas-DEFAULT border border-white/10">
                  <div className="text-xs font-mono text-slate-400 mb-2 uppercase tracking-wider flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-sentinel-cyan" />
                    <span>MITRE ATT&CK® TACTIC & TECHNIQUE</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                    <span className="px-2.5 py-1 rounded bg-white/5 border border-white/10 text-sentinel-cyan">
                      Tactic: {result.mitre_att_ck.tactic}
                    </span>
                    <span className="px-2.5 py-1 rounded bg-white/5 border border-white/10 text-sentinel-emerald">
                      {result.mitre_att_ck.technique_id}
                    </span>
                    <span className="text-slate-300">
                      {result.mitre_att_ck.technique_name}
                    </span>
                  </div>
                </div>

                {/* Recommended Remediation */}
                <div className="p-4 rounded-xl bg-canvas-DEFAULT border border-white/10">
                  <div className="text-xs font-mono text-slate-400 mb-2 uppercase tracking-wider">
                    Automated Defense Playbook
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300">
                    {result.remediation_advice.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <ChevronRight className="w-3.5 h-3.5 text-sentinel-emerald shrink-0 mt-0.5" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>

              </div>
            )}

            {/* View 2: Pipeline Internal Breakdown */}
            {activeResultTab === 'pipeline' && (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 bg-canvas-DEFAULT rounded-xl border border-white/5">
                  <span className="text-slate-400 block mb-1">L4 Specialized Model Ensemble Breakdown:</span>
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    <div className="p-2 bg-canvas-subtle rounded border border-white/5">
                      <span className="text-[10px] text-slate-500 block">Random Forest Gradient</span>
                      <span className="text-sentinel-emerald font-bold">{result.pipeline_trace.l4_detector_scores.rf_gradient.toFixed(4)}</span>
                    </div>
                    <div className="p-2 bg-canvas-subtle rounded border border-white/5">
                      <span className="text-[10px] text-slate-500 block">XGBoost Fast Classifier</span>
                      <span className="text-sentinel-cyan font-bold">{result.pipeline_trace.l4_detector_scores.xgboost_fast.toFixed(4)}</span>
                    </div>
                    <div className="p-2 bg-canvas-subtle rounded border border-white/5">
                      <span className="text-[10px] text-slate-500 block">LightGBM Deep Spatial</span>
                      <span className="text-purple-400 font-bold">{result.pipeline_trace.l4_detector_scores.lightgbm_deep.toFixed(4)}</span>
                    </div>
                    <div className="p-2 bg-canvas-subtle rounded border border-white/5">
                      <span className="text-[10px] text-slate-500 block">Isolation Forest Anomaly</span>
                      <span className="text-amber-400 font-bold">{result.pipeline_trace.l4_detector_scores.isolation_forest.toFixed(4)}</span>
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-canvas-DEFAULT rounded-xl border border-white/5 space-y-1">
                  <div className="text-slate-400">Meta-Learner Fusion Output: <span className="text-white font-bold">{result.pipeline_trace.l5_fusion_meta_learner.toFixed(4)}</span></div>
                  <div className="text-slate-400">Dynamic Threshold Decision: <span className="text-sentinel-emerald">{result.pipeline_trace.l6_threshold_eval}</span></div>
                  <div className="text-slate-400">Dispatch Target: <span className="text-slate-200">{result.pipeline_trace.l7_dispatch_status}</span></div>
                </div>
              </div>
            )}

            {/* View 3: Strict Alert Schema JSON Viewer */}
            {activeResultTab === 'json' && (
              <pre className="p-4 bg-canvas-DEFAULT rounded-xl border border-white/10 text-[11px] font-mono text-sentinel-cyan overflow-x-auto max-h-[360px] terminal-glow">
                <code>{JSON.stringify(result, null, 2)}</code>
              </pre>
            )}

          </div>

        </div>

      </div>
    </section>
  );
};
