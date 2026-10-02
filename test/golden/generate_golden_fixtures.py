"""
PassiveSentinel - Golden Test Fixtures Generator (Section 10 & 13 Phase 3)
Extracts representative flows across all threat families from validation split,
evaluates them through L1 to L8, and stores stage-by-stage golden outputs.
"""

import os
import sys
import json
import torch
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.bundle import ModelBundle
from engine.pipeline import RuntimePipeline

FIXTURES_DIR = os.path.join(BASE_DIR, "test", "golden", "fixtures")
os.makedirs(FIXTURES_DIR, exist_ok=True)

def generate_goldens():
    print("Loading ModelBundle...")
    bundle = ModelBundle()
    bundle.load(strict=True)

    val_split_path = os.path.join(BASE_DIR, "splits", "val_split.csv")
    df = pd.read_csv(val_split_path, low_memory=False)

    # Pick 2-3 sample flows from each class
    sample_dfs = []
    col_name = "threat_class" if "threat_class" in df.columns else "attack_family"
    classes = df[col_name].unique()
    for c in classes:
        sub = df[df[col_name] == c].head(3)
        sample_dfs.append(sub)

    golden_df = pd.concat(sample_dfs, ignore_index=True)
    golden_csv_path = os.path.join(FIXTURES_DIR, "golden_flows.csv")
    golden_df.to_csv(golden_csv_path, index=False)
    print(f"Saved {len(golden_df)} golden sample flows to {golden_csv_path}")

    # Run through pipeline and capture stage-by-stage outputs
    pipeline = RuntimePipeline(bundle, input_type="flow")
    
    # 1. Feature extraction
    feature_names = [
        "duration", "packet_count", "byte_count", "packet_rate", "byte_rate",
        "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "mean_iat",
        "mean_packet_size", "std_packet_size", "iat_jitter_score", "bytes_out_ratio",
        "dns_entropy", "is_encrypted", "was_missing"
    ]
    X_raw = golden_df[[c for c in feature_names if c in golden_df.columns]].fillna(0).values.astype(np.float32)

    # 2. L4 Normalization
    X_norm, _ = bundle.scaler.transform(golden_df)

    # 3. L5 Specialists
    stat_probs = bundle.l5a_detector.predict_proba(X_norm)
    ae_scores, ae_flags = bundle.l5e_autoencoder.score(X_norm)

    # 4. L6 & L7 Calibrated Fusion
    expert_tokens = np.zeros((len(X_norm), X_norm.shape[1]), dtype=np.float32)
    expert_tokens[:, :7] = stat_probs
    expert_tokens[:, 7] = ae_scores
    expert_tokens[:, 8] = ae_flags

    tokens = np.zeros((len(X_norm), 4, X_norm.shape[1]), dtype=np.float32)
    for t in range(3):
        tokens[:, t, :] = X_norm
    tokens[:, -1, :] = expert_tokens

    t_X = torch.tensor(tokens, dtype=torch.float32).to(bundle.device)
    with torch.no_grad():
        logits, p_bool, s_exp, _ = bundle.l6_model(t_X)
        calibrated_probs = torch.softmax(logits / bundle.l6_model.temperature, dim=-1).cpu().numpy()
        preds = np.argmax(calibrated_probs, axis=-1)

    # 5. L8 Alerts
    alerts = pipeline.process_flow_batch(golden_df, min_severity="low", min_confidence=0.0)

    stages_data = {
        "count": len(golden_df),
        "feature_names": feature_names,
        "L3_features_sample": X_raw[:5].tolist(),
        "L4_normalized_sample": X_norm[:5].tolist(),
        "L5_stat_probs_sample": stat_probs[:5].tolist(),
        "L5_ae_scores_sample": ae_scores[:5].tolist(),
        "L6_calibrated_probs_sample": calibrated_probs[:5].tolist(),
        "L6_predicted_classes": preds.tolist(),
        "L8_alerts_count": len(alerts),
        "L8_sample_alert": alerts[0] if alerts else None
    }

    stages_json_path = os.path.join(FIXTURES_DIR, "golden_stages.json")
    with open(stages_json_path, "w") as f:
        json.dump(stages_data, f, indent=2)

    print(f"Saved golden stage-by-stage outputs to {stages_json_path}")

if __name__ == "__main__":
    generate_goldens()
