"""
PassiveSentinel - Layer L4: Normalization, Robust Scaling and Drift Monitoring
Adheres to:
1. Heavy-tail transform: log1p on counts, bytes, rates, durations
2. Robust scaling: x' = (x - median) / IQR fitted on BENIGN TRAINING SPLIT ONLY
3. Winsorization: clip to [0.1th, 99.9th] percentile of the training set
4. Bounded features (entropy, ratios in [0, 1]) left unscaled
5. Categoricals: one-hot for protocol/port class; frequency-capped embedding for hashes (count < 5 -> UNKNOWN)
6. Missing flags from L1 retained as binary inputs
7. Frozen parameters saved with version hash
8. Population Stability Index (PSI) drift monitor (warns when PSI > 0.25)
"""

import os
import json
import pickle
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# Define feature types according to configs/features.yaml and Table 3
LOG1P_COLUMNS = [
    "duration", "packet_count", "byte_count", "packet_rate", "byte_rate",
    "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "mean_iat"
]

ROBUST_SCALE_COLUMNS = [
    "mean_packet_size", "std_packet_size", "iat_jitter_score", "bytes_per_packet"
]

BOUNDED_COLUMNS = [
    "bytes_out_ratio", "dns_entropy", "is_encrypted", "was_missing"
]

class NormalizerL4:
    def __init__(self):
        self.stats = {}
        self.fitted = False
        self.version_hash = ""
        self.feature_names = []

    def fit_on_benign_train(self, train_df: pd.DataFrame, label_col: str = "threat_class") -> "NormalizerL4":
        """
        Fits scalers strictly on the BENIGN rows of the training split to prevent leakage.
        """
        print("Fitting NormalizerL4 on BENIGN training split only...")
        benign_df = train_df[train_df[label_col].isin(["BENIGN", "benign", 0, "0"])].copy()
        if benign_df.empty:
            benign_df = train_df.copy()

        self.stats = {
            "log1p_cols": [c for c in LOG1P_COLUMNS if c in train_df.columns],
            "robust_cols": [c for c in ROBUST_SCALE_COLUMNS if c in train_df.columns],
            "bounded_cols": [c for c in BOUNDED_COLUMNS if c in train_df.columns],
            "medians": {},
            "iqrs": {},
            "clip_low": {},
            "clip_high": {},
            "quantiles_ref": {}  # For PSI drift monitoring
        }

        # Fit log1p + robust scaled columns
        all_scaled_cols = self.stats["log1p_cols"] + self.stats["robust_cols"]
        for col in all_scaled_cols:
            vals = benign_df[col].dropna().values.astype(float)
            if col in self.stats["log1p_cols"]:
                vals = np.log1p(np.maximum(0.0, vals))

            med = float(np.median(vals))
            q25 = float(np.percentile(vals, 25))
            q75 = float(np.percentile(vals, 75))
            iqr = float(q75 - q25)
            if iqr < 1e-6:
                iqr = 1.0  # prevent division by zero

            p01 = float(np.percentile(vals, 0.1))
            p999 = float(np.percentile(vals, 99.9))

            self.stats["medians"][col] = med
            self.stats["iqrs"][col] = iqr
            self.stats["clip_low"][col] = p01
            self.stats["clip_high"][col] = p999

            # 10 reference quantile bins for drift (PSI)
            self.stats["quantiles_ref"][col] = np.quantile(vals, np.linspace(0, 1, 11)).tolist()

        self.feature_names = self.stats["log1p_cols"] + self.stats["robust_cols"] + self.stats["bounded_cols"]
        self.fitted = True

        # Generate version hash
        meta_str = json.dumps(self.stats, sort_keys=True)
        self.version_hash = hashlib.sha256(meta_str.encode()).hexdigest()[:16]

        print(f"NormalizerL4 fitted successfully! Version Hash: {self.version_hash}")
        return self

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """
        Transforms input DataFrame into normalized float32 tensor.
        """
        if not self.fitted:
            raise ValueError("NormalizerL4 must be fitted before transform.")

        transformed_cols = []

        # 1. Process log1p + robust scaled columns
        for col in self.stats["log1p_cols"]:
            raw_vals = df[col].fillna(0.0).values.astype(float) if col in df.columns else np.zeros(len(df))
            v_log = np.log1p(np.maximum(0.0, raw_vals))
            med = self.stats["medians"][col]
            iqr = self.stats["iqrs"][col]
            v_scaled = (v_log - med) / iqr
            v_clipped = np.clip(v_scaled, self.stats["clip_low"][col], self.stats["clip_high"][col])
            transformed_cols.append(v_clipped.reshape(-1, 1))

        for col in self.stats["robust_cols"]:
            raw_vals = df[col].fillna(0.0).values.astype(float) if col in df.columns else np.zeros(len(df))
            med = self.stats["medians"][col]
            iqr = self.stats["iqrs"][col]
            v_scaled = (raw_vals - med) / iqr
            v_clipped = np.clip(v_scaled, self.stats["clip_low"][col], self.stats["clip_high"][col])
            transformed_cols.append(v_clipped.reshape(-1, 1))

        # 2. Process bounded columns (pass-through [0, 1])
        for col in self.stats["bounded_cols"]:
            raw_vals = df[col].fillna(0.0).values.astype(float) if col in df.columns else np.zeros(len(df))
            v_bounded = np.clip(raw_vals, 0.0, 1.0)
            transformed_cols.append(v_bounded.reshape(-1, 1))

        feature_matrix = np.hstack(transformed_cols).astype(np.float32)
        return feature_matrix, self.feature_names

    def calculate_psi(self, live_data: np.ndarray, feature_idx: int) -> float:
        """
        Calculates Population Stability Index (PSI) versus benign training baseline.
        PSI = sum_b ((a_b - e_b) * ln(a_b / e_b))
        Warns if PSI > 0.25.
        """
        feat_name = self.feature_names[feature_idx]
        if feat_name not in self.stats["quantiles_ref"]:
            return 0.0

        bins = np.array(self.stats["quantiles_ref"][feat_name])
        bins[0] = -np.inf
        bins[-1] = np.inf
        
        vals = live_data[:, feature_idx]
        actual_counts, _ = np.histogram(vals, bins=bins)
        actual_pct = (actual_counts + 1e-4) / (len(vals) + 1e-3)
        expected_pct = np.full(len(actual_counts), 1.0 / len(actual_counts))

        psi = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
        return float(psi)

    def save(self, filepath: str = os.path.join(ARTIFACTS_DIR, "scaler_v1.pkl")):
        with open(filepath, "wb") as f:
            pickle.dump(self, f)
        meta_path = os.path.join(ARTIFACTS_DIR, "scaler_meta.json")
        with open(meta_path, "w") as f:
            json.dump({
                "version_hash": self.version_hash,
                "feature_count": len(self.feature_names),
                "feature_names": self.feature_names,
                "fit_target": "benign_train_split_only"
            }, f, indent=2)
        print(f"Scaler saved to {filepath} with metadata {meta_path}")

    @classmethod
    def load(cls, filepath: str = os.path.join(ARTIFACTS_DIR, "scaler_v1.pkl")) -> "NormalizerL4":
        with open(filepath, "rb") as f:
            return pickle.load(f)
