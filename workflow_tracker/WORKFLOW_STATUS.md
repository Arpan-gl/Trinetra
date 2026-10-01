# 🛡️ Trinetra — Project Workflow & Execution Tracker
**Problem Statement:** SIH PS 26145 (NTRO) — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Current Phase:** Phase 2 — Threat Detection Engine & CLI Application Development  
**Last Updated:** October 2, 2026

---

## 📌 Executive Workflow State

| Milestone / Pipeline Stage | Status | Notes & Artifacts |
|---|---|---|
| **1. Threat & Protocol Definition** | ✅ Completed | 6 threat classes + Benign defined in `data/DATASET_DOCUMENTATION.md` |
| **2. Clean Baseline Dataset** | ✅ Completed | 44,798 clean records partitioned in `data/processed/` across 4 splits |
| **3. Ingestion of Real NetFlow Datasets** | ✅ Completed | **4 NetFlow v3 datasets (13.91 GB)** audited and verified in root |
| **4. Dataset Sufficiency Audit** | ✅ Completed | Confirmed 14 GB + baseline is complete; no more datasets needed |
| **5. Model Training & Evaluation Engine** | 🟡 In Progress | Training multiclass threat detector on passive features |
| **6. Trinetra Interactive CLI Application** | 🟡 In Progress | CLI interface (`stream`, `analyze`, `train`, `benchmark`) |
| **7. Passive Data Diode Stream Simulation** | ⏳ Queued | High-throughput optical tap feed simulation |

---

## 🧭 Live Architecture & Data Flow

```mermaid
graph TD
    subgraph Data_Sources [Ingested Data Sources (14+ GB)]
        A1[NF-UNSW-NB15-v3.csv<br/>577 MB - Enterprise Attacks]
        A2[NF-BoT-IoT-v3.csv<br/>3.81 GB - Botnet/DDoS]
        A3[NF-CICIDS2018-v3.csv<br/>4.22 GB - Web/Infiltration/DDoS]
        A4[NF-ToN-IoT-v3.csv<br/>5.30 GB - IoT Telemetry/Scanning]
        A5[Existing Baseline Samples<br/>DGA, CTU-13, DNS Tunnel]
    end

    subgraph Workflow_Pipeline [Workflow Pipeline]
        B1[1. Audit & Sanity Validation] --> B2[2. Chunked Preprocessing & Harmonization]
        B2 --> B3[3. Passive Feature Extraction<br/>IAT, Packet Ratios, TCP Flags]
        B3 --> B4[4. Cross-Domain Partitioning<br/>Train: CICIDS/BoT | Test: ToN-IoT/NB15]
        B4 --> B5[5. Model Benchmark & Evaluation]
    end

    Data_Sources --> B1
```

---

## 📋 Step Tracking Log Index

- **Detailed Step-by-Step History:** [`STEP_EXECUTION_LOG.md`](file:///c:/Users/arpan%20goyal/Desktop/Trinetra/workflow_tracker/STEP_EXECUTION_LOG.md)
- **NetFlow-v3 Evaluation & Impact Report:** [`DATASET_EVALUATION_REPORT.md`](file:///c:/Users/arpan%20goyal/Desktop/Trinetra/workflow_tracker/DATASET_EVALUATION_REPORT.md)
