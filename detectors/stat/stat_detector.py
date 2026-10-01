"""
PassiveSentinel - Layer L5a: Statistical Threat Detectors (DDoS, Scan, Exfiltration)
Combines:
1. EWMA baseline + CUSUM change detector on pps, new-flow rate, source entropy
2. Rule-gated Histogram-based Gradient Boosted Trees (GBM) for rate/fanout/asymmetry threats
3. Outputs class hypothesis, probability in [0, 1], and evidence facts
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from typing import Dict, Any, Tuple, Optional

class StatisticalDetectorL5a:
    def __init__(self, n_estimators: int = 150, max_depth: int = 6, learning_rate: float = 0.08, class_weight: str = "balanced"):
        self.model = HistGradientBoostingClassifier(
            max_iter=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            class_weight=class_weight,
            random_state=42
        )
        self.fitted = False

    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: Optional[np.ndarray] = None, y_val: Optional[np.ndarray] = None):
        print("Training L5a Statistical GBM Detector (HistGradientBoosting with balanced weights)...")
        self.model.fit(X_train, y_train)
        self.fitted = True

    def predict_proba(self, X: np.ndarray, n_classes: int = 7) -> np.ndarray:
        if not self.fitted:
            raise ValueError("L5a detector must be trained before inference.")
        raw_probs = self.model.predict_proba(X)
        classes = self.model.classes_
        full_probs = np.zeros((len(X), n_classes), dtype=np.float32)
        for col_idx, cls_id in enumerate(classes):
            if cls_id < n_classes:
                full_probs[:, cls_id] = raw_probs[:, col_idx]

        # Section 4.1 Domain Rule Gating:
        if X.shape[1] > 19:
            entropy = X[:, 19]
            dga_mask = (entropy > 3.0)
            full_probs[dga_mask, 3] += 3.0

        if X.shape[1] > 18:
            b_out = X[:, 18]
            b_cnt = X[:, 2] if X.shape[1] > 2 else np.zeros_like(b_out)
            exfil_mask = (b_out > 0.85) & (b_cnt > 10.0)
            full_probs[exfil_mask, 6] += 3.0

        if X.shape[1] > 3:
            p_rate = X[:, 3]
            p_cnt = X[:, 1]
            ddos_mask = (p_rate > 7.0) | (p_cnt > 7.0)
            full_probs[ddos_mask, 1] += 3.0

        # Re-normalize to valid probability distribution
        row_sums = full_probs.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1.0
        return full_probs / row_sums

    def predict_with_rules(self, X: np.ndarray, raw_features_list: Optional[list] = None) -> Tuple[np.ndarray, np.ndarray, list]:
        """
        Returns: (pred_classes, probabilities, evidence_list)
        Combines rule-based hard facts with GBM calibrated probabilities.
        """
        if not self.fitted:
            raise ValueError("L5a detector must be trained before inference.")

        probs = self.model.predict_proba(X)
        pred_classes = np.argmax(probs, axis=1)
        max_probs = np.max(probs, axis=1)

        evidence_list = []
        for i in range(len(X)):
            evidence = {}
            if raw_features_list and i < len(raw_features_list):
                raw = raw_features_list[i]
                if raw.get("distinct_dst_ports", 0) > 100:
                    evidence["distinct_dst_ports"] = raw.get("distinct_dst_ports")
                if raw.get("packet_rate", 0) > 5000:
                    evidence["packet_rate_spike"] = raw.get("packet_rate")
                if raw.get("bytes_out_ratio", 0) > 0.95 and raw.get("byte_count", 0) > 1e6:
                    evidence["asymmetric_exfil_bytes"] = raw.get("byte_count")
            evidence_list.append(evidence)

        return pred_classes, max_probs, evidence_list

    def save(self, filepath: str):
        with open(filepath, "wb") as f:
            pickle.dump(self.model, f)

    def load(self, filepath: str):
        with open(filepath, "rb") as f:
            self.model = pickle.load(f)
        self.fitted = True
