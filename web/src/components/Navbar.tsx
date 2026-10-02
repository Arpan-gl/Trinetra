import React, { useState } from 'react';
import { Shield, Terminal, BookOpen, Cpu, BarChart3, Github, ExternalLink, Check, Copy, Zap } from 'lucide-react';

export const Navbar: React.FC = () => {
  const [copied, setCopied] = useState(false);
  const pkgCmd = 'npm i @arpan-gl/passivesentinel';

  const copyInstall = () => {
    navigator.clipboard.writeText(pkgCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/[0.08] bg-[#090A0F]/85 backdrop-blur-xl transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Logo & Brand */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-sentinel-emerald/20 via-[#00FFA3]/5 to-transparent border border-sentinel-emerald/30 shadow-glow-emerald">
            <Shield className="w-5 h-5 text-sentinel-emerald" />
            <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sentinel-emerald opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-sentinel-emerald"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-base tracking-wider text-white">PASSIVE<span className="text-sentinel-emerald">SENTINEL</span></span>
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-sentinel-emerald/10 text-sentinel-emerald border border-sentinel-emerald/20">
                v0.1.0
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-400 tracking-tight hidden sm:block">SIH 2026 PS-145 • Airgap L0-L8 Telemetry</p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-slate-300">
          <a href="#simulator" className="hover:text-sentinel-emerald flex items-center gap-1.5 transition-colors">
            <Zap className="w-3.5 h-3.5 text-sentinel-emerald" />
            <span>Simulator</span>
          </a>
          <a href="#architecture" className="hover:text-sentinel-cyan flex items-center gap-1.5 transition-colors">
            <Cpu className="w-3.5 h-3.5 text-sentinel-cyan" />
            <span>L0–L8 Engine</span>
          </a>
          <a href="#sdk-docs" className="hover:text-sentinel-emerald flex items-center gap-1.5 transition-colors">
            <BookOpen className="w-3.5 h-3.5" />
            <span>SDK Docs</span>
          </a>
          <a href="#benchmarks" className="hover:text-sentinel-cyan flex items-center gap-1.5 transition-colors">
            <BarChart3 className="w-3.5 h-3.5" />
            <span>Benchmarks</span>
          </a>
        </nav>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          {/* Quick Copy Command */}
          <button
            onClick={copyInstall}
            className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-canvas-elevated border border-white/10 hover:border-sentinel-emerald/50 text-xs font-mono text-slate-200 transition-all group"
            title="Click to copy install command"
          >
            <Terminal className="w-3.5 h-3.5 text-sentinel-emerald group-hover:rotate-12 transition-transform" />
            <span className="text-slate-400">npm i</span>
            <span className="text-sentinel-emerald font-semibold">@arpan-gl/passivesentinel</span>
            {copied ? (
              <Check className="w-3.5 h-3.5 text-sentinel-emerald animate-bounce" />
            ) : (
              <Copy className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-300" />
            )}
          </button>

          {/* NPM Package Link */}
          <a
            href="https://www.npmjs.com/package/@arpan-gl/passivesentinel"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#CB3837]/15 hover:bg-[#CB3837]/25 text-[#FF6E6C] border border-[#CB3837]/30 text-xs font-semibold transition-all"
          >
            <span>npm</span>
            <ExternalLink className="w-3 h-3" />
          </a>

          {/* GitHub Link */}
          <a
            href="https://github.com/Arpan-gl/Trinetra"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 p-2 rounded-lg bg-canvas-elevated hover:bg-canvas-surface border border-white/10 text-slate-300 hover:text-white transition-all"
            aria-label="GitHub Repository"
          >
            <Github className="w-4 h-4" />
          </a>
        </div>
      </div>
    </header>
  );
};
