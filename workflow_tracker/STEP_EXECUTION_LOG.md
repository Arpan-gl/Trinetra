# 📝 Step Execution & Decision Log

This document records every operational and architectural step taken in the Trinetra cybersecurity detection engine workflow.

---

### Step 001: Baseline Threat Taxonomy & Data Diode Constraints
- **Objective:** Establish physical constraints for SIH PS 26145.
- **Constraints Identified:**
  1. Passive unidirectional optical tap ingestion (no SYN-ACK injection, no active probing).
  2. Zero payload decryption (rely strictly on packet size, inter-arrival time, and protocol flags).
  3. Prevention of session leakage and target IP memorization.
- **Artifacts:**
  - `data/DATASET_DOCUMENTATION.md`
  - `data/dataset_schema.json`

---

### Step 002: Initial Prototype Sample Synthesis & Split Partitioning
- **Objective:** Generate a clean 44,798-flow benchmark dataset across 4 distinct capture scenarios (`scenario_alpha`, `beta`, `gamma`, `delta_unseen`) to validate the ML pipeline structure.
- **Status:** Verified with `pipeline/validate_data.py`. Zero feature duplicates and balanced representation of 7 classes.

---

### Step 003: Ingestion of 4 Real-World NetFlow v3 Datasets
- **Timestamp:** 2026-10-02
- **Trigger:** Addition of 4 large CSV files into workspace root:
  1. `NF-BoT-IoT-v3.csv` (3.81 GB)
  2. `NF-CICIDS2018-v3.csv` (4.22 GB)
  3. `NF-ToN-IoT-v3.csv` (5.30 GB)
  4. `NF-UNSW-NB15-v3.csv` (577 MB)
  - **Total Volume:** ~13.91 GB
- **Actions Taken:**
  1. Analyzed file headers, structure, and schema consistency across all 4 files.
  2. Confirmed that all 4 files utilize the **UQ NetFlow v3 standardized schema** (55 attributes).
  3. Evaluated importance for SIH PS 26145 (passive telemetry compliance, cross-dataset validation potential).
  4. Created the workflow tracking system in `workflow_tracker/` to maintain continuous auditability.

---

### Step 004: Dataset Sufficiency Assessment & Transition Decision
- **Timestamp:** 2026-10-02
- **Question Addressed:** Do we need more datasets or is it time to build the CLI application?
- **Decision:** **No more datasets needed.** 
- **Rationale:**
  1. We already have **13.91 GB of real-world NetFlow-v3 data** across 4 diverse environments (IoT, Enterprise, Testbed), covering all 6 threat classes specified in SIH PS 26145.
  2. We already have **44,798 clean, scenario-partitioned baseline records** in `data/processed/` ready for immediate model training.
  3. Adding more raw CSVs yields diminishing returns; hackathon juries and evaluators evaluate working software, live threat detection, alerts, and measurable performance.
- **Action Approved:** Transition directly to **building the Trinetra Threat Detection Engine & CLI Application**.

### Step 005: Architecture of the Trinetra CLI Application
- **Objective:** Build an end-to-end command-line interface (CLI) to simulate the passive data diode ingest, run multi-class threat classification, and output forensic reports.
- **Core Modules Planned:**
  1. `cli/main.py`: Entry point with commands: `stream`, `analyze`, `train`, `evaluate`, `benchmark`.
  2. `pipeline/model_engine.py`: High-performance threat classifier (LightGBM/XGBoost + Random Forest baseline).
  3. `pipeline/diode_streamer.py`: Simulates passive unidirectional optical tap feed from CSV/Parquet flows.
  4. Forensic terminal dashboard with rich alert formatting and threat breakdown.

---

### Step 006: Repository Version Control & Large Data Isolation (.gitignore)
- **Timestamp:** 2026-10-02
- **Objective:** Prevent accidental git tracking/pushing of multi-gigabyte data files and intermediate model weights.
- **Action Taken:**
  - Created `.gitignore` in repository root.
  - Explicitly excluded `data/`, `data/raw/`, `data/processed/`, as well as `*.csv`, `*.parquet`, `*.pcap`, archives, virtual environments, and `models/`.
  - Verified with `git status` that the entire `data/` folder is safely excluded from Git commits.

---

### Step 007: Whole-Dataset Full-Stream Ingestion, GPU Training & 5-Fold Cross-Validation
- **Timestamp:** 2026-10-02
- **Objective:** Address user feedback regarding low early Macro-F1 scores due to chunk truncation; utilize NVIDIA RTX 3050 Laptop GPU via Python 3.12 (CUDA 12.1); perform 5-fold cross-validation across the whole dataset without chunk limits.
- **Actions & Results:**
  1. Streamed 66.9M rows from all 4 datasets to generate `unified_full_dataset.csv` (204,164 flows).
  2. Dataset-stratified entity-disjoint split: Train (136,245), Val (28,614), Test (39,305).
  3. 5-Fold Stratified Group Cross-Validation achieved: **0.6885 ± 0.0624 Macro-F1**.
  4. Single locked test set pass on 39,305 flows achieved:
     - Accuracy: **67.31%**
     - Weighted-F1: **0.6732**
     - Macro-F1: **0.6852** (up from early 0.3x)
     - Beaconing F1: **0.9911**, Benign F1: **0.8658**, DGA F1: **0.7751**.
  5. Throughput benchmark sustained **50,000 flows/s** with 0 drops and 1.30 ms p95 latency.

---

### Step 008: PassiveSentinel CLI (v3) In-Depth Research & Implementation Plan
- **Timestamp:** 2026-10-02
- **Objective:** Thoroughly analyze `PassiveSentinel_CLI_Pipeline_Architecture_v3.pdf` across all 15 sections, confirm key design decisions (D1–D3), define the IPC protocol, model bundle manifest, capability matrix, and command suite.
- **Actions Taken:**
  1. Extracted and cross-referenced all requirements from v3 PDF.
  2. Confirmed Decision D1: Option A (TypeScript CLI + Bundled Python engine via stdio JSON-lines IPC) for zero training-serving skew and native PyTorch/LightGBM execution.
  3. Created comprehensive implementation plan artifact `cli_implementation_plan.md` covering Phases 1 through 7 with Git commit checkpoints.

---

### Step 009: End-to-End Implementation of @passivesentinel/cli Package
- **Timestamp:** 2026-10-02
- **Objective:** Implement complete production command-line interface according to Architecture v3.
- **Actions & Results:**
  1. Built versioned model bundle `models/v0.1/` with cryptographic `manifest.json`.
  2. Built high-throughput Python stdio JSON-lines IPC server (`engine/server.py`) and capability-gated pipeline (`engine/pipeline.py`).
  3. Built and executed stage-by-stage golden parity gate (`test/test_parity_gate.py`) - all 5 tests passed ($< 10^{-5}$ tolerance).
  4. Built TypeScript CLI layer: `src/index.ts`, `src/engine/client.ts`, `src/alerts/schema.ts`, `src/alerts/sink.ts`, `src/ui/renderer.ts`, and command handlers (`analyze`, `replay`, `analyze-flow`, `model`, `benchmark`, `report`, `doctor`).
  5. Built executable `bin/passivesentinel` and compiled with `tsc`.
  6. Tested all commands end-to-end; verified 5/5 integration tests passing with `npm test`.


