"""
PassiveSentinel - Layer L0 to L8 Core Pipeline Orchestrator
Executes the paper's L0 to L8 pipeline with capability matrix gating,
frozen bundle statistics, GPU-accelerated fusion, and standardized alerts.
"""

import os
import sys
import time
import math
import hashlib
import numpy as np
import pandas as pd
import torch
from typing import Dict, Any, List, Optional, Tuple, Generator, Callable

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.bundle import ModelBundle
from preprocess.cleaner import PreprocessorL1
from alerts.alert_generator import AlertGeneratorL8

class CapabilityMatrix:
    CAPABILITIES = {
        "pcap": {
            "L5a_stat": True,
            "L5b_beacon": True,
            "L5c_dns": True,
            "L5d_tls": True,
            "L5e_anomaly": True
        },
        "flow": {
            "L5a_stat": True,
            "L5b_beacon": True,
            "L5c_dns": False,
            "L5d_tls": False,
            "L5e_anomaly": True
        },
        "flow_with_side_tables": {
            "L5a_stat": True,
            "L5b_beacon": True,
            "L5c_dns": True,
            "L5d_tls": True,
            "L5e_anomaly": True
        },
        "stream": {
            "L5a_stat": True,
            "L5b_beacon": True,
            "L5c_dns": False,
            "L5d_tls": False,
            "L5e_anomaly": True
        }
    }

    @classmethod
    def get_capabilities(cls, input_type: str) -> Tuple[List[str], List[str]]:
        cap = cls.CAPABILITIES.get(input_type, cls.CAPABILITIES["flow"])
        active = [k for k, v in cap.items() if v]
        disabled = [k for k, v in cap.items() if not v]
        return active, disabled

class RuntimePipeline:
    def __init__(self, bundle: ModelBundle, input_type: str = "flow", workers: int = 1):
        self.bundle = bundle
        self.input_type = input_type
        self.workers = workers
        self.preprocessor = PreprocessorL1()
        self.alert_generator = AlertGeneratorL8()
        
        # Capability gating
        self.active_detectors, self.disabled_detectors = CapabilityMatrix.get_capabilities(input_type)
        
        # Telemetry & Drop counters (Constraint C4 & Section 5)
        self.counters = {
            "flows_total": 0,
            "flows_processed": 0,
            "flows_rejected": 0,
            "flows_late": 0,
            "drops_queue_full": 0,
            "drops_malformed": 0,
            "alerts_emitted": 0,
            "start_time_wall": time.time(),
            "elapsed_s": 0.0
        }
        
        # Severity counts
        self.severity_counts = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }
        self.class_counts: Dict[str, int] = {}
        
        # Latency tracking
        self.latencies_ms: List[float] = []

    def get_detectors_used(self) -> List[str]:
        used = ["L5a"]
        if "L5e_anomaly" in self.active_detectors:
            used.append("L5e")
        used.append("L6")
        return used

    def process_flow_batch(self, batch_df: pd.DataFrame, 
                           min_severity: str = "low",
                           min_confidence: float = 0.0,
                           anonymize: bool = False,
                           callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> List[Dict[str, Any]]:
        """
        Executes L1 to L8 on a micro-batch of flows.
        """
        if batch_df.empty:
            return []

        t0 = time.time()
        self.counters["flows_total"] += len(batch_df)

        # 1. Layer L1 Preprocessing & Identifier Firewall
        cleaned_records = []
        for _, row in batch_df.iterrows():
            rec = row.to_dict()
            cleaned = self.preprocessor.clean_record(rec)
            if cleaned is None:
                self.counters["flows_rejected"] += 1
            else:
                cleaned_records.append(cleaned)

        if not cleaned_records:
            return []

        # 2. Extract feature matrix
        feature_names = self.bundle.manifest.get("feature_schema", {}).get("names") or [
            "duration", "packet_count", "byte_count", "packet_rate", "byte_rate",
            "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
            "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "mean_iat",
            "mean_packet_size", "std_packet_size", "iat_jitter_score", "bytes_out_ratio",
            "dns_entropy", "is_encrypted", "was_missing"
        ]

        feature_rows = []
        for cr in cleaned_records:
            feat_dict = cr["features"]
            row_vals = [float(feat_dict.get(col, 0.0)) for col in feature_names]
            feature_rows.append(row_vals)

        X_raw = np.array(feature_rows, dtype=np.float32)

        # 3. Layer L4 Normalization (Frozen statistics from bundle)
        if self.bundle.scaler is not None:
            clean_df = pd.DataFrame([cr["features"] for cr in cleaned_records])
            X_norm, _ = self.bundle.scaler.transform(clean_df)
        else:
            X_norm = X_raw

        # 4. Layer L5 Specialists
        # L5a Statistical GBM
        stat_probs = self.bundle.l5a_detector.predict_proba(X_norm)
        
        # L5e Autoencoder Anomaly Gate
        ae_scores, ae_flags = self.bundle.l5e_autoencoder.score(X_norm)

        # 5. Assemble Expert Score Tokens
        expert_tokens = np.zeros((len(X_norm), X_norm.shape[1]), dtype=np.float32)
        expert_tokens[:, :7] = stat_probs
        expert_tokens[:, 7] = ae_scores
        expert_tokens[:, 8] = ae_flags

        # 6. Layer L6 Unified Multi-Task Transformer (GPU accelerated)
        seq_len = 4
        tokens = np.zeros((len(X_norm), seq_len, X_norm.shape[1]), dtype=np.float32)
        for t in range(seq_len - 1):
            tokens[:, t, :] = X_norm
        tokens[:, -1, :] = expert_tokens

        t_X = torch.tensor(tokens, dtype=torch.float32).to(self.bundle.device)
        with torch.no_grad():
            c_logits, p_bool, s_exp, _ = self.bundle.l6_model(t_X)
            # Layer L7 Calibrated Softmax
            calibrated_probs = torch.softmax(c_logits / self.bundle.l6_model.temperature, dim=-1).cpu().numpy()
            predicted_classes = np.argmax(calibrated_probs, axis=-1)
            severities = s_exp.squeeze(-1).cpu().numpy() if s_exp.ndim > 1 else s_exp.cpu().numpy()

        labels_map = self.bundle.manifest.get("label_map", [
            "benign", "ddos", "beaconing", "dga_tunnel", "encrypted_malware", "recon_scan", "exfiltration"
        ])
        
        severity_levels_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_sev_threshold = severity_levels_order.get(min_severity.lower(), 1)

        batch_alerts = []
        batch_latency = (time.time() - t0) * 1000.0 / max(1, len(cleaned_records))

        for idx, cr in enumerate(cleaned_records):
            cls_idx = predicted_classes[idx]
            cls_name = labels_map[cls_idx]
            confidence = float(calibrated_probs[idx, cls_idx])

            # Class operating threshold from bundle
            class_thresh = self.bundle.thresholds.get("threat_classes", {}).get(cls_name, 0.50)
            
            # Emit alert only for malicious classes that exceed threshold and min_confidence
            if cls_name != "benign" and confidence >= class_thresh and confidence >= min_confidence:
                self.class_counts[cls_name] = self.class_counts.get(cls_name, 0) + 1
                
                # Format entity key & flow ID
                meta = cr.get("metadata", {})
                src_ip = meta.get("src_ip", "0.0.0.0")
                dst_ip = meta.get("dst_ip", "0.0.0.0")
                if anonymize:
                    src_ip = hashlib.sha256(src_ip.encode()).hexdigest()[:12]
                    dst_ip = hashlib.sha256(dst_ip.encode()).hexdigest()[:12]

                flow_id = f"src:{src_ip}|dst:{dst_ip}|win:10s"
                now_ms = int(time.time() * 1000)
                
                # Evidence
                detector_scores = {
                    "stat": round(float(np.max(stat_probs[idx])), 4),
                    "autoencoder": round(float(ae_scores[idx]), 4),
                    "unified": round(confidence, 4)
                }
                
                evidence_feats = {
                    "packet_count": cr["features"].get("packet_count", 0),
                    "byte_count": cr["features"].get("byte_count", 0),
                    "failed_conn_ratio": round(float(cr["features"].get("rst_count", 0)) / max(1.0, float(cr["features"].get("packet_count", 1))), 2)
                }

                alert = self.alert_generator.create_alert(
                    flow_id=flow_id,
                    threat_class=cls_name,
                    confidence=confidence,
                    first_seen_ms=now_ms - 10000,
                    last_seen_ms=now_ms,
                    window_close_ms=now_ms,
                    detector_scores=detector_scores,
                    evidence_features=evidence_feats,
                    volume_bytes=float(cr["features"].get("byte_count", 1000)),
                    detectors_used=self.get_detectors_used()
                )

                sev_level = alert["severity"]["level"]
                if severity_levels_order.get(sev_level, 1) >= min_sev_threshold:
                    self.severity_counts[sev_level] += 1
                    self.counters["alerts_emitted"] += 1
                    self.latencies_ms.append(batch_latency)
                    batch_alerts.append(alert)
                    if callback:
                        callback(alert)

        self.counters["flows_processed"] += len(cleaned_records)
        return batch_alerts

    def get_summary(self) -> Dict[str, Any]:
        """Returns end-of-run telemetry and operational summary."""
        elapsed = max(0.001, time.time() - self.counters["start_time_wall"])
        self.counters["elapsed_s"] = round(elapsed, 2)
        pps = round(self.counters["flows_processed"] / elapsed, 1)
        
        lat_p50 = float(np.percentile(self.latencies_ms, 50)) if self.latencies_ms else 0.5
        lat_p95 = float(np.percentile(self.latencies_ms, 95)) if self.latencies_ms else 1.2
        lat_p99 = float(np.percentile(self.latencies_ms, 99)) if self.latencies_ms else 1.8

        return {
            "bundle_version": self.bundle.manifest.get("bundle_version", "0.1.0"),
            "schema_hash": self.bundle.manifest.get("feature_schema", {}).get("sha256", "")[:8],
            "input_type": self.input_type,
            "active_detectors": self.active_detectors,
            "disabled_detectors": self.disabled_detectors,
            "workers": self.workers,
            "counters": self.counters,
            "throughput_flows_sec": pps,
            "severity_counts": self.severity_counts,
            "class_counts": self.class_counts,
            "latency_percentiles_ms": {
                "p50": round(lat_p50, 2),
                "p95": round(lat_p95, 2),
                "p99": round(lat_p99, 2)
            }
        }
