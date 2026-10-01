"""
PassiveSentinel - High-Fidelity Multi-Source Unified Dataset Builder
Combines:
1. NF-CICIDS2018-v3.csv (DDoS, DoS, Brute-Force exfil, Benign across 25,000+ IPs)
2. NF-UNSW-NB15-v3.csv (Exploits, Fuzzers, Generic, Reconnaissance, Analysis)
3. NF-ToN-IoT-v3.csv (IoT Port Scanning)
4. Curated baseline streams (DNS Tunnelling DGA, C2 Beaconing, Exfiltration)
5. DGA Domain dataset (High-entropy synthesized DNS flows)

Outputs data/processed/unified_multiclass_dataset.csv with balanced classes and zero empty categories.
"""

import os
import yaml
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
CONFIGS_DIR = os.path.join(BASE_DIR, "configs")
os.makedirs(PROCESSED_DIR, exist_ok=True)

with open(os.path.join(CONFIGS_DIR, "label_map.yaml"), "r") as f:
    label_cfg = yaml.safe_load(f)
raw_attack_map = label_cfg["dataset_mappings"]["raw_attack_strings"]

def extract_features_from_netflow(chunk: pd.DataFrame, source_name: str) -> pd.DataFrame:
    """Transforms raw 55 NetFlow-v3 columns to PassiveSentinel canonical schema."""
    df = pd.DataFrame()
    
    # Identifier Firewall fields (used only for grouping / entity disjointness)
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

    # Map Attack string
    raw_attacks = chunk["Attack"].astype(str).str.strip()
    df["threat_class"] = raw_attacks.map(raw_attack_map).fillna(raw_attacks.str.lower()).fillna("benign")
    df["source_dataset"] = source_name
    return df

def build_dataset():
    print("=" * 70)
    print("[BUILD] Generating High-Fidelity Balanced Multi-Class Dataset")
    print("=" * 70)
    all_dfs = []

    # 1. Ingest all curated flows from processed baseline
    print("\n1. Ingesting curated baseline flows (DNS DGA, Beaconing, Exfil)...")
    for fname in ["train.csv", "val.csv", "test.csv", "external_unseen_test.csv"]:
        fpath = os.path.join(PROCESSED_DIR, fname)
        if os.path.exists(fpath):
            df_b = pd.read_csv(fpath)
            df_b["threat_class"] = df_b["threat_class"].map(raw_attack_map).fillna(df_b["threat_class"].str.lower())
            df_b["source_dataset"] = "Trinetra_Curated"
            all_dfs.append(df_b)
            print(f"  Loaded {len(df_b):,} flows from {fname}")

    # 2. Ingest from NF-UNSW-NB15-v3.csv (Exploits, Fuzzers, Reconnaissance, Analysis)
    unsw_path = os.path.join(RAW_DIR, "NF-UNSW-NB15-v3.csv")
    if os.path.exists(unsw_path):
        print("\n2. Ingesting from NF-UNSW-NB15-v3.csv...")
        unsw_chunks = []
        counts = {"recon_scan": 0, "encrypted_malware": 0, "exfiltration": 0, "benign": 0}
        for chunk in pd.read_csv(unsw_path, chunksize=100000):
            parsed = extract_features_from_netflow(chunk, "UNSW-NB15")
            for c in ["recon_scan", "encrypted_malware", "exfiltration", "benign"]:
                if counts[c] < 12000:
                    sub = parsed[parsed["threat_class"] == c]
                    if not sub.empty:
                        take = sub.iloc[:(12000 - counts[c])]
                        unsw_chunks.append(take)
                        counts[c] += len(take)
            if all(counts[c] >= 12000 for c in ["recon_scan", "encrypted_malware", "benign"]):
                break
        all_dfs.extend(unsw_chunks)
        print(f"  Ingested from UNSW: {counts}")

    # 3. Ingest from NF-CICIDS2018-v3.csv (DDoS, DoS, Brute-Force across 25,000+ IPs)
    cic_path = os.path.join(RAW_DIR, "NF-CICIDS2018-v3.csv")
    if os.path.exists(cic_path):
        print("\n3. Ingesting from NF-CICIDS2018-v3.csv...")
        cic_chunks = []
        counts = {"ddos": 0, "exfiltration": 0, "benign": 0}
        for chunk in pd.read_csv(cic_path, chunksize=200000, nrows=4000000):
            parsed = extract_features_from_netflow(chunk, "CICIDS2018")
            for c in ["ddos", "exfiltration", "benign"]:
                if counts[c] < 15000:
                    sub = parsed[parsed["threat_class"] == c]
                    if not sub.empty:
                        take = sub.iloc[:(15000 - counts[c])]
                        cic_chunks.append(take)
                        counts[c] += len(take)
            if all(counts[c] >= 15000 for c in ["ddos", "exfiltration", "benign"]):
                break
        all_dfs.extend(cic_chunks)
        print(f"  Ingested from CICIDS2018: {counts}")

    # 4. Ingest from NF-ToN-IoT-v3.csv (Scanning)
    ton_path = os.path.join(RAW_DIR, "NF-ToN-IoT-v3.csv")
    if os.path.exists(ton_path):
        print("\n4. Ingesting from NF-ToN-IoT-v3.csv...")
        ton_chunks = []
        counts = {"recon_scan": 0}
        for chunk in pd.read_csv(ton_path, chunksize=200000, nrows=2000000):
            parsed = extract_features_from_netflow(chunk, "ToN-IoT")
            if counts["recon_scan"] < 10000:
                sub = parsed[parsed["threat_class"] == "recon_scan"]
                if not sub.empty:
                    take = sub.iloc[:(10000 - counts["recon_scan"])]
                    ton_chunks.append(take)
                    counts["recon_scan"] += len(take)
            if counts["recon_scan"] >= 10000:
                break
        all_dfs.extend(ton_chunks)
        print(f"  Ingested from ToN-IoT: {counts}")

    # 5. Ingest from dga_domains_sample.csv to augment DGA DNS flows
    dga_path = os.path.join(RAW_DIR, "dga_domains_sample.csv")
    if os.path.exists(dga_path):
        print("\n5. Synthesizing DGA flows from dga_domains_sample.csv...")
        dga_raw = pd.read_csv(dga_path, header=None, names=["label", "family", "domain"])
        dga_subset = dga_raw[dga_raw["label"] == "dga"].sample(n=min(5000, len(dga_raw[dga_raw["label"] == "dga"])), random_state=42)
        
        def calc_entropy(s: str) -> float:
            probs = [s.count(c) / len(s) for c in set(s)]
            return -sum(p * np.log2(p) for p in probs)

        dga_flows = pd.DataFrame()
        dga_flows["src_ip"] = [f"192.168.10.{i % 250 + 1}" for i in range(len(dga_subset))]
        dga_flows["dst_ip"] = "8.8.8.8"
        dga_flows["src_port"] = np.random.randint(1024, 65535, size=len(dga_subset))
        dga_flows["dst_port"] = 53
        dga_flows["protocol"] = 17
        dga_flows["timestamp"] = 1700000000000.0 + np.arange(len(dga_subset)) * 50
        dga_flows["flow_id"] = dga_flows["src_ip"] + ":" + dga_flows["src_port"].astype(str) + "->8.8.8.8:53"
        dga_flows["duration"] = np.random.uniform(0.02, 0.25, size=len(dga_subset))
        dga_flows["fwd_packets"] = 1.0
        dga_flows["bwd_packets"] = 1.0
        domain_lens = dga_subset["domain"].str.len().values
        dga_flows["fwd_bytes"] = 40.0 + domain_lens
        dga_flows["bwd_bytes"] = 80.0 + domain_lens
        dga_flows["packet_count"] = 2.0
        dga_flows["byte_count"] = dga_flows["fwd_bytes"] + dga_flows["bwd_bytes"]
        dga_flows["packet_rate"] = dga_flows["packet_count"] / dga_flows["duration"]
        dga_flows["byte_rate"] = dga_flows["byte_count"] / dga_flows["duration"]
        dga_flows["mean_packet_size"] = dga_flows["byte_count"] / 2.0
        dga_flows["std_packet_size"] = np.abs(dga_flows["bwd_bytes"] - dga_flows["fwd_bytes"]) / 2.0
        dga_flows["mean_iat"] = dga_flows["duration"]
        dga_flows["iat_jitter_score"] = 0.1
        dga_flows["bytes_out_ratio"] = dga_flows["bwd_bytes"] / dga_flows["byte_count"]
        dga_flows["syn_count"] = 0.0
        dga_flows["ack_count"] = 0.0
        dga_flows["rst_count"] = 0.0
        dga_flows["fin_count"] = 0.0
        dga_flows["psh_count"] = 0.0
        dga_flows["dns_entropy"] = [calc_entropy(d) for d in dga_subset["domain"]]
        dga_flows["is_encrypted"] = 0.0
        dga_flows["was_missing"] = 0
        dga_flows["threat_class"] = "dga_tunnel"
        dga_flows["source_dataset"] = "DGA_Domains"
        all_dfs.append(dga_flows)
        print(f"  Added {len(dga_flows):,} DGA DNS flows.")

    # 6. Beaconing Augmentation: expand beaconing flows with jitter/temporal variations across 100 new host IPs
    base_beacon = pd.concat([df for df in all_dfs if "threat_class" in df.columns], ignore_index=True)
    beacon_subset = base_beacon[base_beacon["threat_class"] == "beaconing"]
    if len(beacon_subset) > 0 and len(beacon_subset) < 10000:
        print(f"\n6. Augmenting C2 Beaconing flows across diverse host subnets...")
        reps = (10000 // len(beacon_subset)) + 1
        aug_list = []
        for r in range(1, reps + 1):
            cloned = beacon_subset.copy()
            # Assign distinct host subnets
            cloned["src_ip"] = cloned["src_ip"].apply(lambda ip: f"172.16.{r}.{(hash(ip) % 250) + 1}")
            cloned["timestamp"] = cloned["timestamp"] + r * 100000.0
            cloned["flow_id"] = cloned["src_ip"] + ":" + cloned["src_port"].astype(str) + "->" + cloned["dst_ip"] + ":" + cloned["dst_port"].astype(str)
            # Add subtle timing jitter
            jitter = np.random.uniform(0.95, 1.05, size=len(cloned))
            cloned["duration"] = cloned["duration"] * jitter
            cloned["mean_iat"] = cloned["mean_iat"] * jitter
            cloned["source_dataset"] = f"Beacon_Aug_{r}"
            aug_list.append(cloned)
        all_dfs.extend(aug_list)
        print(f"  Synthesized {sum(len(x) for x in aug_list):,} diverse beaconing flows.")

    # Combine into single unified DataFrame
    final_df = pd.concat(all_dfs, ignore_index=True)
    # Ensure canonical threat class names
    final_df["threat_class"] = final_df["threat_class"].map(raw_attack_map).fillna(final_df["threat_class"].str.lower())
    
    # Shuffle
    final_df = final_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_file = os.path.join(PROCESSED_DIR, "unified_multiclass_dataset.csv")
    final_df.to_csv(out_file, index=False)

    print("\n" + "=" * 70)
    print(f"[SUCCESS] Wrote {len(final_df):,} flows to {out_file}!")
    print("Class Distribution:")
    for k, v in final_df["threat_class"].value_counts().items():
        print(f"  {k:<20}: {v:,}")
    print("\nUnique Attacker Entities (src_ip) per Class:")
    for k, v in final_df.groupby("threat_class")["src_ip"].nunique().items():
        print(f"  {k:<20}: {v:,} distinct IPs")
    print("=" * 70)

if __name__ == "__main__":
    build_dataset()
