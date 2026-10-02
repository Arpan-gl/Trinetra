import React, { useState } from 'react';
import { ArrowRight, Copy, Check, Terminal, ShieldCheck, Activity, Cpu, Database, Flame } from 'lucide-react';

export const Hero: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'npm' | 'pnpm' | 'yarn' | 'bun'>('npm');
  const [copied, setCopied] = useState(false);

  const commands = {
    npm: 'npm install @arpan-gl/passivesentinel',
    pnpm: 'pnpm add @arpan-gl/passivesentinel',
    yarn: 'yarn add @arpan-gl/passivesentinel',
    bun: 'bun add @arpan-gl/passivesentinel',
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(commands[activeTab]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="relative overflow-hidden pt-12 pb-20 md:pt-20 md:pb-32 bg-grid-pattern">
      {/* Background Neon Aura Orbs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[650px] h-[350px] bg-gradient-to-tr from-sentinel-emerald/15 to-sentinel-cyan/15 rounded-full blur-[140px] pointer-events-none -z-10" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Top Announcement Tag */}
        <div className="flex justify-center mb-6">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-sentinel-emerald/10 border border-sentinel-emerald/30 shadow-glow-emerald">
            <span className="flex h-2 w-2 rounded-full bg-sentinel-emerald animate-pulse"></span>
            <span className="text-xs font-mono font-medium text-sentinel-emerald tracking-wide uppercase">
              SIH 2026 PS-145 • Airgap L0–L8 Certified
            </span>
            <span className="text-slate-600">|</span>
            <span className="text-xs font-mono text-slate-300">Zero DPI • Zero Payload Leaks</span>
          </div>
        </div>

        {/* Main Title & Tagline */}
        <div className="text-center max-w-4xl mx-auto">
          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white mb-6 leading-[1.1]">
            Passive Threat Detection <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-sentinel-emerald via-[#5EEAD4] to-sentinel-cyan">
              Engine & Developer SDK
            </span>
          </h1>
          <p className="text-base sm:text-xl text-slate-300 mb-10 max-w-2xl mx-auto leading-relaxed font-normal">
            Enterprise-grade, sub-millisecond network traffic intrusion detection. Analyze up to <strong className="text-white font-semibold">50,000 flows/sec</strong> using an ensemble of spatial-temporal ML classifiers with strictly zero payload inspection.
          </p>

          {/* Interactive Install Bar */}
          <div className="max-w-xl mx-auto mb-10 rounded-2xl glass-panel p-2 shadow-glass border border-white/10">
            <div className="flex items-center justify-between border-b border-white/5 pb-2 px-3 mb-2">
              <div className="flex items-center gap-1">
                {(['npm', 'pnpm', 'yarn', 'bun'] as const).map((pkg) => (
                  <button
                    key={pkg}
                    onClick={() => setActiveTab(pkg)}
                    className={`px-3 py-1 rounded-md text-xs font-mono font-semibold transition-all ${
                      activeTab === pkg
                        ? 'bg-sentinel-emerald/20 text-sentinel-emerald border border-sentinel-emerald/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {pkg}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
                <span className="w-2 h-2 rounded-full bg-slate-700"></span>
                <span>Node 18+ / Py 3.10+</span>
              </div>
            </div>

            <div className="flex items-center justify-between px-3 py-2 bg-canvas-DEFAULT rounded-xl border border-white/5">
              <div className="flex items-center gap-3 overflow-x-auto text-xs font-mono text-slate-200">
                <span className="text-sentinel-cyan select-none">$</span>
                <span className="font-semibold text-slate-100">{commands[activeTab]}</span>
              </div>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sentinel-emerald/15 hover:bg-sentinel-emerald/25 text-sentinel-emerald border border-sentinel-emerald/30 text-xs font-mono font-medium transition-all shrink-0 ml-3"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Action CTAs */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <a
              href="#simulator"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl bg-sentinel-emerald text-canvas-DEFAULT font-bold text-sm hover:bg-[#20ffb0] transition-all shadow-glow-emerald"
            >
              <span>Test Live Simulator</span>
              <ArrowRight className="w-4 h-4" />
            </a>
            <a
              href="#sdk-docs"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl glass-panel text-slate-200 font-semibold text-sm hover:text-white hover:border-white/20 transition-all"
            >
              <Terminal className="w-4 h-4 text-sentinel-cyan" />
              <span>Explore SDK Reference</span>
            </a>
          </div>
        </div>

        {/* Real-world Operational Telemetry Stats */}
        <div className="mt-16 sm:mt-24 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto">
          <div className="p-5 rounded-2xl glass-panel border border-white/5 relative overflow-hidden group hover:border-sentinel-emerald/30 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400">THROUGHPUT</span>
              <Activity className="w-4 h-4 text-sentinel-emerald" />
            </div>
            <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
              50,000<span className="text-sentinel-emerald text-lg">/s</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Sustained NetFlow v9 records</p>
          </div>

          <div className="p-5 rounded-2xl glass-panel border border-white/5 relative overflow-hidden group hover:border-sentinel-cyan/30 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400">AVG LATENCY</span>
              <Cpu className="w-4 h-4 text-sentinel-cyan" />
            </div>
            <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
              1.3<span className="text-sentinel-cyan text-lg">ms</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Full L0-L8 inference dispatch</p>
          </div>

          <div className="p-5 rounded-2xl glass-panel border border-white/5 relative overflow-hidden group hover:border-sentinel-emerald/30 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400">PACKET DROP</span>
              <ShieldCheck className="w-4 h-4 text-sentinel-emerald" />
            </div>
            <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
              0.00<span className="text-sentinel-emerald text-lg">%</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Zero ring buffer packet loss</p>
          </div>

          <div className="p-5 rounded-2xl glass-panel border border-white/5 relative overflow-hidden group hover:border-sentinel-purple/30 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400">CV ACCURACY</span>
              <Flame className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono">
              68.52<span className="text-purple-400 text-lg">%</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Macro-F1 (Zero Data Leakage)</p>
          </div>
        </div>

      </div>
    </section>
  );
};
