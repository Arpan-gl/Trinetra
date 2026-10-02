import React, { useState } from 'react';
import { Terminal, Copy, Check, Code, FileText, Layers, ExternalLink, Zap } from 'lucide-react';

export const SdkDocs: React.FC = () => {
  const [activeLang, setActiveLang] = useState<'typescript' | 'python' | 'cli' | 'docker'>('typescript');
  const [copied, setCopied] = useState<boolean>(false);

  const snippets = {
    typescript: `import { EngineClient } from '@arpan-gl/passivesentinel';

// 1. Initialize the airgap-certified detection engine client
const client = new EngineClient({
  modelBundlePath: './models/v0.1',
  confidenceThreshold: 0.82,
  gpuAcceleration: true, // auto-detects CUDA / DirectML
});

await client.start();

// 2. Stream single or batched NetFlow telemetry tuples (zero DPI)
const result = await client.analyzeFlow({
  src_ip: "185.190.141.28",
  dst_ip: "10.0.4.15",
  src_port: 48921,
  dst_port: 80,
  proto: "TCP",
  flow_duration: 12480,
  tot_fwd_pkts: 8420,
  tot_bwd_pkts: 2,
  totlen_fwd_pkts: 454680,
  totlen_bwd_pkts: 80,
  pkt_len_mean: 54.0,
  pkt_len_std: 1.2,
  flow_iat_mean: 1.48,
  fwd_iat_std: 0.12,
  syn_flag_cnt: 8420,
  ack_flag_cnt: 0,
  down_up_ratio: 0.0002,
  init_fwd_win_byts: 1024
});

// 3. Evaluate real-time mitigation response
if (result.severity === 'CRITICAL') {
  console.warn(\`[CRITICAL ALERT] \${result.threat_type}\`);
  console.warn(\`Confidence: \${(result.ensemble_confidence * 100).toFixed(1)}%\`);
  console.warn(\`MITRE Technique: \${result.mitre_att_ck.technique_id}\`);
  
  // Trigger automated edge firewall block
  await firewall.blockIp(result.flow.src_ip);
}

await client.close();`,

    python: `from engine.pipeline import RuntimePipeline

# 1. Load cryptographically verified model bundle
bundle_dir = "models/v0.1"
pipeline = RuntimePipeline.load_bundle(bundle_dir)

# 2. Feed 32-dimensional normalized flow features
flow_data = {
    "flow_duration": 12480,
    "tot_fwd_pkts": 8420,
    "tot_bwd_pkts": 2,
    "totlen_fwd_pkts": 454680,
    "totlen_bwd_pkts": 80,
    "pkt_len_mean": 54.0,
    "pkt_len_std": 1.2,
    "flow_iat_mean": 1.48,
    "fwd_iat_std": 0.12,
    "syn_flag_cnt": 8420,
    "ack_flag_cnt": 0,
    "down_up_ratio": 0.0002,
    "init_fwd_win_byts": 1024
}

# 3. Perform sub-millisecond ensemble inference
alert = pipeline.predict_flow(flow_data)

print(f"Status: {alert['threat_type']}")
print(f"Probability: {alert['confidence']:.4f}")
print(f"Latency: {alert['latency_ms']} ms")`,

    cli: `# 1. Verify environment, Python engine, and GPU parity gate
npx passivesentinel doctor

# 2. Analyze flow vector from CLI inline JSON
npx passivesentinel analyze-flow --json '{"src_ip":"1.2.3.4","dst_ip":"10.0.0.1","proto":"TCP","syn_flag_cnt":5000}'

# 3. Ingest and stream PCAP / NetFlow files through L0-L8 pipeline
npx passivesentinel analyze --input traffic_dump.pcap --format netflow9 --rate 50000

# 4. Run high-throughput performance benchmark (50k flows/sec)
npx passivesentinel benchmark --batch-size 1024 --target-fps 50000

# 5. Generate formatted markdown / SIEM audit report
npx passivesentinel report --format json --output audit_trace.json`,

    docker: `# Run PassiveSentinel inside air-gapped container with GPU support
docker run -d \\
  --name passivesentinel-sidecar \\
  --gpus all \\
  --restart unless-stopped \\
  -p 9090:9090 \\
  -v ./models/v0.1:/app/models:ro \\
  ghcr.io/arpan-gl/passivesentinel:latest \\
  passivesentinel serve --host 0.0.0.0 --port 9090`
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(snippets[activeLang]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="sdk-docs" className="py-20 bg-canvas-subtle border-t border-white/[0.08] relative">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-emerald/10 border border-sentinel-emerald/30 text-sentinel-emerald text-xs font-mono mb-3">
              <Code className="w-3.5 h-3.5" />
              <span>Developer Reference & SDK</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              One SDK. Any Architecture.
            </h2>
            <p className="text-slate-400 text-sm mt-2 max-w-xl">
              Integrate PassiveSentinel into your Node.js backend, Python data pipeline, Kubernetes sidecars, or edge firewalls with ergonomic APIs and strict schema contracts.
            </p>
          </div>

          <a
            href="https://www.npmjs.com/package/@arpan-gl/passivesentinel"
            target="_blank"
            rel="noreferrer"
            className="mt-4 md:mt-0 inline-flex items-center gap-2 text-xs font-mono text-sentinel-emerald hover:underline"
          >
            <span>View package on npm registry</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>

        {/* Code Editor Container */}
        <div className="glass-panel rounded-2xl border border-white/10 overflow-hidden shadow-glass">
          
          {/* Editor Header Bar */}
          <div className="flex items-center justify-between px-4 py-3 bg-canvas-elevated border-b border-white/10">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
              <span className="ml-3 text-xs font-mono text-slate-400">
                {activeLang === 'typescript' ? 'client.ts' : activeLang === 'python' ? 'pipeline.py' : activeLang === 'cli' ? 'bash' : 'Dockerfile'}
              </span>
            </div>

            {/* Language Selector Tabs */}
            <div className="flex items-center gap-1">
              {(['typescript', 'python', 'cli', 'docker'] as const).map((lang) => (
                <button
                  key={lang}
                  onClick={() => setActiveLang(lang)}
                  className={`px-3 py-1 rounded-md text-xs font-mono uppercase font-semibold transition-all ${
                    activeLang === lang
                      ? 'bg-sentinel-emerald/20 text-sentinel-emerald border border-sentinel-emerald/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {lang === 'typescript' ? 'TypeScript SDK' : lang === 'python' ? 'Python Engine' : lang === 'cli' ? 'CLI Tool' : 'Docker'}
                </button>
              ))}

              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-3 py-1 ml-2 rounded bg-white/5 hover:bg-white/10 text-xs font-mono text-slate-300 transition-all"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-sentinel-emerald" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          {/* Syntax Code Display */}
          <div className="p-5 bg-canvas-DEFAULT overflow-x-auto">
            <pre className="text-xs font-mono text-slate-200 leading-relaxed">
              <code>{snippets[activeLang]}</code>
            </pre>
          </div>

          {/* Bottom Highlights */}
          <div className="px-5 py-3 bg-canvas-elevated/70 border-t border-white/5 flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-400 gap-2">
            <div className="flex items-center gap-3">
              <span className="text-sentinel-emerald">✓ Typescript Definitions Included</span>
              <span>•</span>
              <span className="text-sentinel-cyan">✓ Zero Network Egress (Airgap Compatible)</span>
            </div>
            <div className="text-slate-500">
              License: Apache 2.0
            </div>
          </div>

        </div>

      </div>
    </section>
  );
};
