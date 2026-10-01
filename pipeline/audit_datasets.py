"""
PassiveSentinel (SIH PS-145) - Phase 2 Dataset Audit Engine
Scans data/raw/ and data/processed/, extracts schema, temporal bounds,
class distributions, missing/NaN/inf values, and generates reports/data_audit.md.
"""

import os
import glob
import json
import yaml
import numpy as np
import pandas as pd
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
CONFIGS_DIR = os.path.join(BASE_DIR, "configs")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Load label map
with open(os.path.join(CONFIGS_DIR, "label_map.yaml"), "r") as f:
    label_cfg = yaml.safe_load(f)
label_map = label_cfg["dataset_mappings"]["raw_attack_strings"]
canonical_classes = list(label_cfg["canonical_classes"].values())

def audit():
    print("Beginning Dataset Audit...")
    report_lines = []
    report_lines.append("# 📊 PassiveSentinel Dataset Audit Report (Phase 2)")
    report_lines.append(f"**Execution Timestamp:** {datetime.utcnow().isoformat()}Z\n")
    report_lines.append("## 1. Dataset Inventory & Physical Characteristics\n")
    report_lines.append("| File | Format | File Size | Approx / Total Rows | Columns | Time Range / Coverage |")
    report_lines.append("|---|---|---|---|---|---|")

    # Audit processed splits first
    processed_files = glob.glob(os.path.join(DATA_DIR, "processed", "*.csv"))
    raw_files = glob.glob(os.path.join(DATA_DIR, "raw", "*.csv"))

    class_totals = {c: 0 for c in canonical_classes}
    data_quality_issues = []

    all_files = sorted(processed_files + raw_files)

    for file_path in all_files:
        rel_path = os.path.relpath(file_path, BASE_DIR).replace("\\", "/")
        size_bytes = os.path.getsize(file_path)
        size_mb = size_bytes / (1024 * 1024)
        size_str = f"{size_mb:.2f} MB" if size_mb < 1024 else f"{size_mb / 1024:.2f} GB"
        ext = os.path.splitext(file_path)[1]

        # For very large files (> 500 MB), sample rows to avoid OOM
        is_large = size_mb > 500
        sample_rows = 50000 if is_large else None

        try:
            if is_large:
                df = pd.read_csv(file_path, nrows=sample_rows)
                # Count total lines with buffer
                with open(file_path, "rb") as bf:
                    line_count = sum(1 for _ in bf) - 1 # exclude header
                row_str = f"{line_count:,} (Sampled {sample_rows:,})"
            else:
                df = pd.read_csv(file_path)
                row_str = f"{len(df):,}"

            cols = len(df.columns)

            # Check time range
            time_col = None
            for c in ["timestamp", "FLOW_START_MILLISECONDS", "sttl", "ct_srv_src"]:
                if c in df.columns:
                    time_col = c
                    break
            
            if time_col and not df[time_col].dropna().empty:
                t_min = df[time_col].min()
                t_max = df[time_col].max()
                time_str = f"{t_min} to {t_max}"
            else:
                time_str = "Relative / Scenario Timestamps"

            report_lines.append(f"| `{rel_path}` | `{ext}` | {size_str} | {row_str} | {cols} | {time_str} |")

            # Check quality counters
            nans = df.isna().sum().sum()
            num_cols = df.select_dtypes(include=[np.number]).columns
            infs = np.isinf(df[num_cols]).values.sum() if len(num_cols) > 0 else 0
            negs = (df[num_cols] < 0).values.sum() if len(num_cols) > 0 else 0

            if nans > 0 or infs > 0 or negs > 0:
                data_quality_issues.append({
                    "file": rel_path,
                    "nans": int(nans),
                    "infs": int(infs),
                    "negatives": int(negs)
                })

            # Check labels
            label_col = None
            for lc in ["threat_class", "Attack", "attack_cat", "label", "Label"]:
                if lc in df.columns:
                    label_col = lc
                    break

            if label_col:
                for val, cnt in df[label_col].value_counts().items():
                    val_str = str(val).strip()
                    mapped = label_map.get(val_str, label_map.get(val_str.upper(), "benign"))
                    if mapped in class_totals:
                        class_totals[mapped] += int(cnt)

        except Exception as e:
            report_lines.append(f"| `{rel_path}` | `{ext}` | {size_str} | Error | Error | Error reading: {e} |")

    report_lines.append("\n---\n")
    report_lines.append("## 2. Canonical Threat Taxonomy Class Distribution\n")
    report_lines.append("Mapped counts across audited records:\n")
    report_lines.append("| Canonical Class ID | Canonical Class Name | Total Audited Flows | Status |")
    report_lines.append("|---|---|---|---|")
    for cid, cname in label_cfg["canonical_classes"].items():
        cnt = class_totals.get(cname, 0)
        status = "✅ Well Represented" if cnt > 1000 else "⚠️ Limited Count"
        report_lines.append(f"| {cid} | **`{cname}`** | {cnt:,} | {status} |")

    report_lines.append("\n---\n")
    report_lines.append("## 3. Data Quality, Hygiene & Anomaly Audit\n")
    report_lines.append("| File | NaNs Observed | Infs (+/- inf) | Negative Counters | Remediation in L1 |")
    report_lines.append("|---|---|---|---|---|")
    if data_quality_issues:
        for issue in data_quality_issues:
            report_lines.append(f"| `{issue['file']}` | {issue['nans']} | {issue['infs']} | {issue['negatives']} | Replace with sentinel -1.0, set `was_missing=1`, clamp negs |")
    else:
        report_lines.append("| *All files* | 0 | 0 | 0 | Clean |")

    report_lines.append("\n---\n")
    report_lines.append("## 4. Synthetic Injection & Data Augmentation Plan\n")
    report_lines.append("As required by the paper (Section 5.1 & 8):\n")
    report_lines.append("1. **Botnet C2 Timing Jitter Augmentation (L5b):**")
    report_lines.append("   - Real botnets inject random timing jitter (up to 20%) to evade fixed-period Fourier detectors.")
    report_lines.append("   - Parameterized timing jitter $dt' = dt \cdot (1 + \mathcal{U}(-0.20, 0.20))$ is applied during beaconing training.")
    report_lines.append("2. **Spoofed Floods & UDP Reflection (L5a):**")
    report_lines.append("   - High source-IP entropy with random TTL variance ($\mu=64, \sigma=18$) injected into benign background.")
    report_lines.append("3. **Asymmetric Data Exfiltration (L5a / L6):**")
    report_lines.append("   - High outbound ratio flows ($\text{ratio\_io} > 0.95$) with long duration and sustained burst indices.")

    out_file = os.path.join(REPORTS_DIR, "data_audit.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"Dataset audit successfully written to {out_file}")

if __name__ == "__main__":
    audit()
