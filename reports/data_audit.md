# 📊 PassiveSentinel Dataset Audit Report (Phase 2)
**Execution Timestamp:** 2026-10-01T20:13:46.464763Z

## 1. Dataset Inventory & Physical Characteristics

| File | Format | File Size | Approx / Total Rows | Columns | Time Range / Coverage |
|---|---|---|---|---|---|
| `data/processed/external_unseen_test.csv` | `.csv` | 3.22 MB | 11,197 | 43 | 1700000000.0 to 1701077300.0 |
| `data/processed/test.csv` | `.csv` | 3.16 MB | 11,215 | 43 | 1700000000.15 to 1700448800.0 |
| `data/processed/train.csv` | `.csv` | 3.17 MB | 11,253 | 43 | 1700000000.3 to 1700449520.0 |
| `data/processed/val.csv` | `.csv` | 3.12 MB | 11,133 | 43 | 1700000001.05 to 1701079100.0 |
| `data/raw/NF-BoT-IoT-v3.csv` | `.csv` | 3.56 GB | 16,933,808 (Sampled 50,000) | 55 | 1528096098622 to 1528105748257 |
| `data/raw/NF-CICIDS2018-v3.csv` | `.csv` | 3.93 GB | 20,115,529 (Sampled 50,000) | 55 | 1518611287705 to 1518612190299 |
| `data/raw/NF-ToN-IoT-v3.csv` | `.csv` | 4.94 GB | 27,520,260 (Sampled 50,000) | 55 | 1556028590618 to 1556028704457 |
| `data/raw/NF-UNSW-NB15-v3.csv` | `.csv` | 550.61 MB | 2,365,424 (Sampled 50,000) | 55 | 1424221091484 to 1424262180324 |
| `data/raw/dga_domains_sample.csv` | `.csv` | 0.28 MB | 9,999 | 3 | Relative / Scenario Timestamps |
| `data/raw/unsw_nb15_sample.csv` | `.csv` | 14.67 MB | 82,332 | 45 | 0 to 255 |

---

## 2. Canonical Threat Taxonomy Class Distribution

Mapped counts across audited records:

| Canonical Class ID | Canonical Class Name | Total Audited Flows | Status |
|---|---|---|---|
| 0 | **`benign`** | 194,050 | ✅ Well Represented |
| 1 | **`ddos`** | 58,655 | ✅ Well Represented |
| 2 | **`beaconing`** | 3,644 | ✅ Well Represented |
| 3 | **`dga_tunnel`** | 8,481 | ✅ Well Represented |
| 4 | **`encrypted_malware`** | 44,173 | ✅ Well Represented |
| 5 | **`recon_scan`** | 13,701 | ✅ Well Represented |
| 6 | **`exfiltration`** | 4,426 | ✅ Well Represented |

---

## 3. Data Quality, Hygiene & Anomaly Audit

| File | NaNs Observed | Infs (+/- inf) | Negative Counters | Remediation in L1 |
|---|---|---|---|---|
| `data/raw/NF-BoT-IoT-v3.csv` | 4994 | 5284 | 0 | Replace with sentinel -1.0, set `was_missing=1`, clamp negs |
| `data/raw/NF-UNSW-NB15-v3.csv` | 1996 | 5176 | 0 | Replace with sentinel -1.0, set `was_missing=1`, clamp negs |

---

## 4. Synthetic Injection & Data Augmentation Plan

As required by the paper (Section 5.1 & 8):

1. **Botnet C2 Timing Jitter Augmentation (L5b):**
   - Real botnets inject random timing jitter (up to 20%) to evade fixed-period Fourier detectors.
   - Parameterized timing jitter $dt' = dt \cdot (1 + \mathcal{U}(-0.20, 0.20))$ is applied during beaconing training.
2. **Spoofed Floods & UDP Reflection (L5a):**
   - High source-IP entropy with random TTL variance ($\mu=64, \sigma=18$) injected into benign background.
3. **Asymmetric Data Exfiltration (L5a / L6):**
   - High outbound ratio flows ($	ext{ratio\_io} > 0.95$) with long duration and sustained burst indices.