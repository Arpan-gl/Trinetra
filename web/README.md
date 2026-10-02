# PassiveSentinel Web Platform & SDK Portal

Modern developer documentation portal & interactive threat telemetry simulator for [`@arpan-gl/passivesentinel`](https://www.npmjs.com/package/@arpan-gl/passivesentinel).

Built with React 18, Vite, TypeScript, and TailwindCSS adhering to the **Obsidian Sentinel** high-contrast neon design system.

---

## Features
- **Live Threat Simulator Playground**: Interactive simulation of volumetric DDoS SYN Floods, DNS DGA Exfiltration tunnels, Cobalt Strike C2 Jitter beacons, and clean benign traffic. Real-time L0–L8 pipeline execution tracking and strict JSON schema alert inspection.
- **One SDK Architecture**: Multi-language documentation and code recipes for TypeScript SDK (`import { EngineClient }`), Python Runtime Engine (`from engine.pipeline import RuntimePipeline`), CLI commands (`npx passivesentinel doctor`), and Docker sidecars.
- **L0–L8 Pipeline Visualizer**: Interactive architectural diagram detailing all 8 layers from zero-copy packet ingestion to SIEM JSON dispatch.
- **Table 6.6 Performance Matrix**: Benchmarked against Suricata 7, Zeek 6, and Snort 3 (50,000 flows/sec, 1.3ms latency, 0.00% packet loss).
- **Leak-Free ML Validation**: Documented 5-Fold Stratified GroupKFold cross-validation (0.6852 Macro-F1) ensuring zero IP/subnet data leakage.

---

## Local Development

```bash
# 1. Enter web directory
cd web

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

Visit `http://localhost:3000` in your browser.

---

## Production Build

```bash
npm run build
```

Generates optimized static assets in `web/dist/`.

---

## Deploying to Vercel

This folder is completely standalone and ready for 1-click deployment on Vercel:

1. Import your GitHub repository (`Arpan-gl/Trinetra`) into [Vercel](https://vercel.com).
2. Set **Root Directory** to `web`.
3. Vercel automatically detects the Vite framework and builds the project via `npm run build` with output to `dist`.
4. Zero configuration required (`vercel.json` already included).
