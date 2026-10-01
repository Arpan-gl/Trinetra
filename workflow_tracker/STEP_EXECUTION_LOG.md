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


