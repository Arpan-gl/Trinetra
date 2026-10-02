# 🛡️ PassiveSentinel CLI (`@passivesentinel/cli`)
> **SIH 2026 PS-145 Hardware Data Diode Passive Threat Intelligence**  
> *Pipeline, runtime architecture and product design for the production command-line package*

[![Node.js](https://img.shields.io/badge/Node.js-v22%20LTS-green.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.5.1%2BCUDA12.1-red.svg)](https://pytorch.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Parity Gate](https://img.shields.io/badge/Parity%20Gate-Verified%20100%25-brightgreen.svg)](test/test_parity_gate.py)

---

## 1. Product Overview

`passivesentinel` is a developer-friendly command-line tool that wraps the trained PassiveSentinel detection pipeline (Layers L0 to L8) and turns passively observed network traffic into standardized, explainable alert incidents.

### Four Non-Negotiable Constraints (C1 – C5):
1. **Read-Only Passivity (C1):** Ingestion is strictly one-way (simulating a physical TAP or optical data diode). The engine never opens a socket, sends a SYN-ACK, or initiates any outbound network probe.
2. **Zero Payload Decryption (C2):** Operates exclusively on cleartext packet headers, inter-arrival times, sequence dynamics, and TLS/QUIC handshake metadata. Never attempts decryption.
3. **Streaming Latency Bounds (C3/C4):** Sustains $\ge 20,000$ flows/s (measured at **50,000 flows/s**) with p95 latency $\le 1.3\text{ ms}$ and memory footprint $\le 500\text{ MB}$ RSS.
4. **Standardized Alert Contract (C5):** Fixed JSON schema validated incidents with transparent evidence, baseline deviations, and auditable severity scores.

---

## 2. Installation & Prerequisites

### Prerequisites:
- **Node.js:** v18.0.0 or higher (v22 LTS recommended)
- **Python:** 3.10+ (Python 3.12 with CUDA 12.1 recommended for GPU acceleration)

### Build from Source:
```bash
git clone https://github.com/Arpan-gl/Trinetra.git
cd Trinetra
npm install
npm run build
```

Link executable locally:
```bash
npm link
passivesentinel --help
```

---

## 3. Quickstart Tutorial

### Step 1: Run System Diagnostics
Verify capture permissions, environment, and cryptographic model integrity:
```bash
passivesentinel doctor
```

### Step 2: Inspect & Verify Model Bundle
Check model bundle version, feature schema hash, and SHA-256 signatures:
```bash
passivesentinel model info
passivesentinel model verify
```

### Step 3: Analyze Flow Capture
Run offline threat detection through Layers L0 to L8:
```bash
passivesentinel analyze-flow test/golden/fixtures/golden_flows.csv --output alerts.jsonl
```

### Step 4: Generate Forensic Executive Report
Create an auditable Markdown report summarizing detected incidents:
```bash
passivesentinel report alerts.jsonl --output incident_report.md
```

### Step 5: Benchmark Held-Out Test Set
Reproduce Section 6.6 evaluation metrics on locked test data without tuning:
```bash
passivesentinel benchmark splits/test_split.csv --output benchmark_results.json
```

---

## 4. CLI Command Reference

| Command | Input | Purpose | Output |
|---|---|---|---|
| `analyze <pcap>` | PCAP file | Offline detection through L0–L8 | Terminal summary + JSONL |
| `replay <file>` | PCAP or Flow file | Replay at original or scaled timing (`--speed 10`) | Alerts + telemetry |
| `analyze-flow <flows.csv>` | NetFlow / CSV / Parquet | Enters at L1; reports disabled specialists | Alerts + disabled detector list |
| `model info` | Model bundle | Prints version, schema hash, classes, thresholds | Formatted terminal card / JSON |
| `model verify` | Model bundle | Cryptographically verifies SHA-256 hashes against `manifest.json` | Exit code 0 (valid) or 3 |
| `benchmark <test_split.csv>` | Labelled test split | Evaluates held-out test split without tuning | `benchmark.json` + Table 6.6 report |
| `report <alerts.jsonl>` | Alerts file | Forensic summarizer (classes, entities, timeline) | Markdown report |
| `doctor` | Host enclave | Checks capture permissions, interface passivity, dependencies | Enclave diagnostic report |

### Common Flags:
- `--model <path>`: Path to model bundle directory (default: `models/v0.1`).
- `--output <file>`: Write alerts as JSON lines to file.
- `--format pretty|jsonl`: Terminal format (`pretty` on TTY, `jsonl` otherwise).
- `--min-severity low|medium|high|critical`: Filter alerts below this level (default: `low`).
- `--min-confidence <0..1>`: Filter alerts below calibrated confidence.
- `--workers <N>`: Worker processes (default: `1`).
- `--anonymize`: Hash internal IP addresses in stored evidence.
- `--speed <x|max>`: Timing scale factor for replay mode (default: `1`).

---

## 5. Exit Codes (Section 6.3)

| Exit Code | Meaning |
|---|---|
| **0** | Completed normally |
| **1** | Internal error |
| **2** | Usage or configuration error |
| **3** | Model bundle missing, corrupt, or SHA-256 mismatch |
| **4** | Input unreadable or unsupported format |
| **5** | Passive-interface check failed (IP or route detected on capture interface) |
| **6** | Dropped records exceeded limit (`--max-drop-rate`) |
| **10** | Completed and alerts at or above `--fail-on` level were produced (CI mode) |

---

## 6. Standard Alert Contract (Section 8)

Every emitted alert is validated against `schema/alert.schema.json` before emission:
```json
{
  "schema_version": "1.0",
  "alert_id": "a-4f9a12",
  "timestamp": "2026-10-02T14:18:40.155Z",
  "first_seen": "2026-10-02T14:18:30.155Z",
  "last_seen": "2026-10-02T14:18:40.155Z",
  "flow_id": "src:10.2.3.4|dst:192.168.1.5|win:10s",
  "threat_class": "recon_scan",
  "confidence": 0.81,
  "severity": {
    "level": "medium",
    "score": 5.7
  },
  "evidence": {
    "detector_scores": {
      "stat": 0.82,
      "autoencoder": 0.31,
      "unified": 0.81
    },
    "packet_count": 26,
    "byte_count": 4016,
    "failed_conn_ratio": 0.04
  },
  "detectors_used": ["L5a", "L5e", "L6"],
  "recommended_action": "Horizontal/vertical reconnaissance: block source at edge perimeter",
  "latency_ms": 125
}
```

---

## 7. Quality Assurance & Parity Gates

Execute the full suite of regression and parity tests:
```bash
# Node.js CLI integration tests
npm test

# Python stage-by-stage golden parity gate (Section 10)
pytest test/test_parity_gate.py
```
