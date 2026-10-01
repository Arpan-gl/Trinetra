"""
PassiveSentinel - High-Fidelity NetFlow v3 Stream Ingestion Engine
Streams across the 4 massive NetFlow v3 datasets (~14 GB) in data/raw/:
- NF-UNSW-NB15-v3.csv (2.36M rows)
- NF-BoT-IoT-v3.csv (16.9M rows)
- NF-ToN-IoT-v3.csv (27.5M rows)
- NF-CICIDS2018-v3.csv (20.1M rows)
Plus DGA domain dataset to extract a balanced, multi-domain dataset of ~135,000 flows.
"""

import os
import yaml
import numpy as np
import pandas as pd
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
CONFIGS_DIR = os.path.join(BASE_DIR, "configs")
os.makedirs(PROCESSED_DIR, exist_ok=True)

with open(os.path.join(CONFIGS_DIR, "label_map.yaml"), "r") as f:
    label_cfg = yaml.safe_load(f)
raw_attack_map = label_cfg["dataset_mappings"]["raw_attack_strings"]

# Quotas per canonical threat class to ensure balance and high F1
TARGET_QUOTAS = {
    "benign": 30000,
    "ddos": 20000,
    "beaconing": 15000,
    "dga_tunnel": 15000,
    "encrypted_malware": 20000,
    "recon_scan": 20000,
    "exfiltration": 15000
}

def extract_features_from_netflow(chunk: pd.DataFrame, source_name: str) -> pd.DataFrame:
    """Transforms raw 55 NetFlow-v3 columns to PassiveSentinel canonical schema."""
    df = pd.DataFrame()
    
    # Metadata keys (Identifier Firewall: used only for grouping)
    df["src_ip"] = chunk["IPV4_SRC_ADDR"].astype(str)
    df["dst_ip"] = chunk["IPV4_DST_ADDR"].astype(str)
    df["src_port"] = chunk["L4_SRC_PORT"].fillna(0).astype(int)
    df["dst_port"] = chunk["L4_DST_PORT"].fillna(0).astype(int)
    df["protocol"] = chunk["PROTOCOL"].fillna(6).astype(int)
    df["timestamp"] = chunk["FLOW_START_MILLISECONDS"].fillna(1700000000000).astype(float)
    df["flow_id"] = df["src_ip"] + ":" + df["src_port"].astype(str) + "->" + df["dst_ip"] + ":" + df["dst_port"].astype(str)

    # Physical flow features
    duration_s = chunk["FLOW_DURATION_MILLISECONDS"].fillna(0.0).astype(float) / 1000.0
    df["duration"] = np.maximum(0.001, duration_s)
    
    fwd_p = chunk["IN_PKTS"].fillna(1).astype(float)
    bwd_p = chunk["OUT_PKTS"].fillna(0).astype(float)
    fwd_b = chunk["IN_BYTES"].fillna(40).astype(float)
    bwd_b = chunk["OUT_BYTES"].fillna(0).astype(float)
    
    df["fwd_packets"] = fwd_p
    df["bwd_packets"] = bwd_p
    df["fwd_bytes"] = fwd_b
    df["bwd_bytes"] = bwd_b
    
    pkt_count = fwd_p + bwd_p
    byte_count = fwd_b + bwd_b
    df["packet_count"] = pkt_count
    df["byte_count"] = byte_count
    df["packet_rate"] = pkt_count / df["duration"]
    df["byte_rate"] = byte_count / df["duration"]
    
    df["mean_packet_size"] = byte_count / np.maximum(1.0, pkt_count)
    df["std_packet_size"] = np.maximum(0.0, chunk["MAX_IP_PKT_LEN"].fillna(0).astype(float) - chunk["MIN_IP_PKT_LEN"].fillna(0).astype(float)) / 2.0
    
    df["mean_iat"] = np.maximum(0.0, chunk["SRC_TO_DST_IAT_AVG"].fillna(0.0).astype(float) / 1000.0)
    df["iat_jitter_score"] = np.clip(chunk["SRC_TO_DST_IAT_STDDEV"].fillna(0.0).astype(float) / np.maximum(1.0, chunk["SRC_TO_DST_IAT_AVG"].fillna(0.0).astype(float)), 0.0, 10.0)
    df["bytes_out_ratio"] = np.clip(bwd_b / np.maximum(1.0, byte_count), 0.0, 1.0)
    
    # TCP Flags
    flags = chunk["TCP_FLAGS"].fillna(0).astype(int)
    df["syn_count"] = (flags & 2 > 0).astype(float)
    df["ack_count"] = (flags & 16 > 0).astype(float)
    df["rst_count"] = (flags & 4 > 0).astype(float)
    df["fin_count"] = (flags & 1 > 0).astype(float)
    df["psh_count"] = (flags & 8 > 0).astype(float)

    df["dns_entropy"] = 0.0
    df["is_encrypted"] = (chunk["L4_DST_PORT"].isin([443, 8443]) | (chunk["L7_PROTO"].fillna(0) == 91)).astype(float)
    df["was_missing"] = 0

    # Map Attack string to canonical threat class
    raw_attacks = chunk["Attack"].astype(str).str.strip()
    df["threat_class"] = raw_attacks.map(raw_attack_map).fillna(raw_attacks.str.lower()).fillna("benign")
    df["source_dataset"] = source_name
    return df

def stream_and_extract():
    print("=" * 70)
    print("[EXTRACTION] Extracting High-Fidelity Balanced Dataset from 14 GB NetFlow v3")
    print("=" * 70)

    collected_dfs = {k: [] for k in TARGET_QUOTAS.keys()}
    current_counts = {k: 0 for k in TARGET_QUOTAS.keys()}

    # 1. First ingest existing clean DNS DGA & Beaconing records from baseline
    base_train = pd.read_csv(os.path.join(PROCESSED_DIR, "train.csv"))
    base_val = pd.read_csv(os.path.join(PROCESSED_DIR, "val.csv"))
    base_full = pd.concat([base_train, base_val], ignore_index=True)
    
    for cls in ["dga_tunnel", "beaconing", "exfiltration"]:
        c_rows = base_full[base_full["threat_class"].str.lower() == cls].copy()
        if not c_rows.empty:
            c_rows["source_dataset"] = "Trinetra_Baseline"
            collected_dfs[cls].append(c_rows)
            current_counts[cls] += len(c_rows)
            print(f"Loaded {len(c_rows):,} baseline flows for {cls}")

    # 2. Ingest from the 4 NetFlow-v3 files in chunks
    raw_files = [
        ("NF-UNSW-NB15-v3.csv", "UNSW-NB15", 2300000),
        ("NF-ToN-IoT-v3.csv", "ToN-IoT", 1500000),
        ("NF-BoT-IoT-v3.csv", "BoT-IoT", 1500000),
        ("NF-CICIDS2018-v3.csv", "CICIDS2018", 1500000)
    ]

    for fname, src_name, max_scan_rows in raw_files:
        fpath = os.path.join(RAW_DIR, fname)
        if not os.path.exists(fpath):
            continue
        print(f"\nScanning {fname} (up to {max_scan_rows:,} rows)...")

        scanned = 0
        for chunk in pd.read_csv(fpath, chunksize=50000, nrows=max_scan_rows):
            scanned += len(chunk)
            parsed = extract_features_from_netflow(chunk, src_name)

            for cls in TARGET_QUOTAS.keys():
                needed = TARGET_QUOTAS[cls] - current_counts[cls]
                if needed > 0:
                    cls_subset = parsed[parsed["threat_class"] == cls]
                    if not cls_subset.empty:
                        take = cls_subset.iloc[:needed]
                        collected_dfs[cls].append(take)
                        current_counts[cls] += len(take)

            # Check if all quotas satisfied
            if all(current_counts[c] >= TARGET_QUOTAS[c] for c in TARGET_QUOTAS):
                print("All class quotas fully satisfied!")
                break

        print(f"Current class counts after {fname}: {current_counts}")

    # Combine all classes
    all_chunks = []
    for cls, dflist in collected_dfs.items():
        if dflist:
            all_chunks.extend(dflist)

    full_df = pd.concat(all_chunks, ignore_index=True)
    full_df = full_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_csv = os.path.join(PROCESSED_DIR, "netflow_unified_135k.csv")
    full_df.to_csv(out_csv, index=False)
    print("\n" + "=" * 70)
    print(f"[SUCCESS] Successfully wrote {len(full_df):,} flows to {out_csv}!")
    print("Class Distribution:")
    for k, v in full_df["threat_class"].value_counts().items():
        print(f"  {k:<20}: {v:,}")
    print("=" * 70)

if __name__ == "__main__":
    stream_and_extract()
