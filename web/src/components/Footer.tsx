import React from 'react';
import { Shield, Github, ExternalLink, Terminal, Heart } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-white/[0.08] bg-canvas-DEFAULT py-12 text-slate-400 text-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          
          {/* Brand Info */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-sentinel-emerald/20 border border-sentinel-emerald/30">
                <Shield className="w-4 h-4 text-sentinel-emerald" />
              </div>
              <span className="font-extrabold text-sm text-white tracking-wider">
                PASSIVE<span className="text-sentinel-emerald">SENTINEL</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              Air-Gapped High-Throughput Cyber Threat Telemetry & Intrusion Detection Engine. Smart India Hackathon (SIH 2026) Problem Statement 145.
            </p>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-white/5 border border-white/10 text-[11px] font-mono text-sentinel-emerald">
              <span>● Production Release v0.1.0</span>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="font-semibold text-slate-200 mb-3 uppercase tracking-wider font-mono text-[11px]">
              Ecosystem
            </h4>
            <ul className="space-y-2 font-mono">
              <li>
                <a
                  href="https://www.npmjs.com/package/@arpan-gl/passivesentinel"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-sentinel-emerald flex items-center gap-1.5 transition-colors"
                >
                  <span>NPM Registry</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/Arpan-gl/Trinetra"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-sentinel-emerald flex items-center gap-1.5 transition-colors"
                >
                  <span>GitHub Repository</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              </li>
              <li>
                <a href="#simulator" className="hover:text-sentinel-emerald transition-colors">
                  Threat Simulator
                </a>
              </li>
              <li>
                <a href="#benchmarks" className="hover:text-sentinel-emerald transition-colors">
                  Benchmark Suite
                </a>
              </li>
            </ul>
          </div>

          {/* Standards & Specs */}
          <div>
            <h4 className="font-semibold text-slate-200 mb-3 uppercase tracking-wider font-mono text-[11px]">
              Compliance
            </h4>
            <ul className="space-y-2 font-mono">
              <li>
                <span className="text-slate-400">SIH 2026 PS-145</span>
              </li>
              <li>
                <span className="text-slate-400">Zero DPI Compliant</span>
              </li>
              <li>
                <span className="text-slate-400">MITRE ATT&CK® Matrix</span>
              </li>
              <li>
                <span className="text-slate-400">Apache 2.0 Open Source</span>
              </li>
            </ul>
          </div>

        </div>

        {/* Bottom bar */}
        <div className="pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-[11px] text-slate-500">
          <div>
            © {new Date().getFullYear()} PassiveSentinel. Built for national critical cyber infrastructure defense.
          </div>
          <div className="flex items-center gap-2">
            <span>Powered by PyTorch CUDA & Node.js IPC</span>
          </div>
        </div>

      </div>
    </footer>
  );
};
