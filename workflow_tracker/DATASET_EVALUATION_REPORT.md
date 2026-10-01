# 📊 NetFlow v3 Dataset Evaluation & Impact Report

**Target Problem:** SIH PS 26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Analyzed Files:**
1. `NF-BoT-IoT-v3.csv` (3.81 GB)
2. `NF-CICIDS2018-v3.csv` (4.22 GB)
3. `NF-ToN-IoT-v3.csv` (5.30 GB)
4. `NF-UNSW-NB15-v3.csv` (577 MB)  
**Total Raw Footprint:** ~13.91 GB

---

## 1. Summary: Are These 4 Datasets Important?

### **Verdict: EXTREMELY CRITICAL AND VALUABLE ⭐⭐⭐⭐⭐**

These 4 files are among the most respected benchmarks in modern Network Intrusion Detection (NIDS) research: the **NetFlow v3 (UQ-NIDS-v3)** standardized datasets developed by researchers at the University of Queensland.

### Why They Are a Game-Changer for SIH PS 26145:

1. **100% Compliant with Passive Unidirectional Constraints:**
   - SIH PS 26145 specifies monitoring behind a hardware data diode / optical tap without active probing or payload decryption.
   - NetFlow v3 records are purely **flow-level telemetry** (packet arrival rates, TCP flag summaries, packet length distributions, inter-arrival times) extracted without needing deep packet payload inspection.
2. **Unified 55-Feature Architecture:**
   - In traditional research, combining UNSW-NB15, CIC-IDS2018, and BoT-IoT was impossible because each used incompatible feature extractors (Argus, CICFlowMeter, Bro/Zeek).
   - These 4 files all share the **identical 55-column NetFlow schema**, allowing seamless multi-dataset training and transfer learning.
3. **Gold Standard for Cross-Domain Generalization:**
   - Hackathon juries prioritize models that do not overfit to a single synthetic testbed.
   - With these datasets, we can train on **CICIDS2018** (enterprise traffic) + **UNSW-NB15** and test zero-shot generalization against **BoT-IoT** and **ToN-IoT** (IoT/Industrial traffic).

---

## 2. Dataset Profile & Threat Coverage

| Dataset File | File Size | Primary Threat Focus | Relevance to SIH PS 26145 Classes |
|---|---|---|---|
| **`NF-BoT-IoT-v3.csv`** | **3.81 GB** | Botnet C2, massive DoS/DDoS floods, OS/service scan | `BOTNET_C2_BEACONING`, `VOLUMETRIC_PROTOCOL_DDOS`, `RECON_PORTSCAN` |
| **`NF-CICIDS2018-v3.csv`** | **4.22 GB** | Modern enterprise attacks: Brute Force, Infiltration, Web Attacks, Botnet, DDoS | `VOLUMETRIC_PROTOCOL_DDOS`, `RECON_PORTSCAN`, `MALWARE_ENCRYPTED` |
| **`NF-ToN-IoT-v3.csv`** | **5.30 GB** | Industrial IoT, Telemetry, Scanning, Ransomware, Backdoors | `BOTNET_C2_BEACONING`, `RECON_PORTSCAN`, `DATA_EXFILTRATION` |
| **`NF-UNSW-NB15-v3.csv`** | **577 MB** | Fuzzers, Exploits, Backdoor, Reconnaissance, Shellcode, Worms | `RECON_PORTSCAN`, `MALWARE_ENCRYPTED`, `BENIGN` |

---

## 3. Schema & Feature Mapping to Trinetra

All 4 datasets share the exact same 55 attributes, which map directly to our passive threat detection engine:

| NetFlow v3 Feature Group | NetFlow v3 Columns | Trinetra Target Feature |
|---|---|---|
| **Flow Lifespan & Volume** | `FLOW_DURATION_MILLISECONDS`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS` | `duration`, `byte_count`, `packet_count`, `packet_rate`, `byte_rate` |
| **Traffic Asymmetry** | `IN_BYTES`, `OUT_BYTES`, `SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_SECOND_BYTES` | `bytes_out_ratio` (Detects Data Exfiltration) |
| **Timing & Jitter** | `SRC_TO_DST_IAT_AVG`, `SRC_TO_DST_IAT_STDDEV`, `DST_TO_SRC_IAT_*` | `mean_iat`, `iat_jitter_score` (Detects Botnet C2 Beacons) |
| **Packet Size Dynamics** | `LONGEST_FLOW_PKT`, `SHORTEST_FLOW_PKT`, `NUM_PKTS_UP_TO_128_BYTES`, `NUM_PKTS_1024_TO_1514_BYTES` | `mean_packet_size`, `std_packet_size`, `bimodal_packet_ratio` |
| **TCP Protocol State** | `TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `TCP_WIN_MAX_*` | `syn_count`, `ack_count`, `syn_ack_ratio` (Detects SYN Floods) |
| **Service & Recon** | `L4_SRC_PORT`, `L4_DST_PORT`, `PROTOCOL`, `DNS_QUERY_TYPE` | `port_entropy`, `fan_out_ratio` (Detects PortScans) |
| **Labels** | `Label` (0/1), `Attack` (String description) | `binary_label`, `threat_class` |

---

## 4. Handling 14 GB of Data Efficiently

Because the combined size is **~13.91 GB** (tens of millions of flows), attempting to load all 4 files simultaneously into standard RAM with `pd.read_csv()` will cause an Out-Of-Memory (OOM) error.

### Recommended Strategy:
1. **Stratified Sampling / Balanced Extraction:**
   - Extract a balanced, high-fidelity sample (e.g. 200,000 to 500,000 flows total) across all threat classes and benign traffic.
2. **Chunked Streaming Pipeline:**
   - Use `chunksize=50,000` with generator pipelines to process and extract features iteratively.
3. **Parquet Storage:**
   - Convert processed splits to Apache Parquet format (which provides 5x–10x compression and sub-second column reading).
4. **Cross-Domain Evaluation Suite:**
   - Train on `NF-CICIDS2018-v3` + `NF-UNSW-NB15-v3`.
   - Test generalization on `NF-BoT-IoT-v3` and `NF-ToN-IoT-v3`.
