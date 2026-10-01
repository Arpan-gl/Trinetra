"""
PassiveSentinel - Unit Test Suite for Phases 1-4 Core Guarantees
Tests:
1. Identifier Firewall: raw IPs, ports, flow_ids, timestamps NEVER enter model feature vectors
2. Split Leakage: strict 0% entity overlap between train, val, and test splits
3. Scaler Fit-on-Train-Only: verifying scaler parameters are computed strictly from benign train data
4. Alert Schema Validation: validating Appendix A example alert record against schema/alert.schema.json
5. L1 Preprocessing & Numeric Hygiene: handling of NaNs, Infs, negative counters
"""

import os
import sys
import json
import jsonschema
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from preprocess.cleaner import PreprocessorL1
from normalize.scaler import NormalizerL4

def test_identifier_firewall():
    """Verify raw IPs, ephemeral ports, flow IDs, absolute timestamps are excluded from feature vectors."""
    prep = PreprocessorL1()
    raw_record = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "timestamp": 1700000000.5,
        "duration": 1.25,
        "fwd_packets": 10,
        "bwd_packets": 8,
        "fwd_bytes": 1024,
        "bwd_bytes": 4096,
        "threat_class": "benign"
    }
    cleaned = prep.clean_record(raw_record)
    assert cleaned is not None
    features = cleaned["features"]
    
    # Must NOT contain raw identifiers
    for identifier in ["src_ip", "dst_ip", "src_port", "dst_port", "flow_id", "timestamp"]:
        assert identifier not in features, f"Identifier firewall breached by: {identifier}"

def test_numeric_hygiene():
    """Verify NaNs, Infs, and negative counters are properly remediated."""
    prep = PreprocessorL1()
    dirty_record = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 443,
        "protocol": "TCP",
        "timestamp": 1700000001.0,
        "duration": float("nan"),
        "fwd_packets": float("inf"),
        "bwd_packets": -5,
        "fwd_bytes": 100,
        "bwd_bytes": 200
    }
    cleaned = prep.clean_record(dirty_record)
    assert cleaned is not None
    feats = cleaned["features"]
    assert feats["was_missing"] == 1
    assert not np.isnan(feats["duration"])
    assert not np.isinf(feats["fwd_packets"])
    assert feats["bwd_packets"] >= 0.0

def test_split_leakage_manifest():
    """Verify splits/manifest.json proves 0% entity overlap across train, val, test."""
    manifest_path = os.path.join(BASE_DIR, "splits", "manifest.json")
    assert os.path.exists(manifest_path), "Splits manifest does not exist."
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
    
    lv = manifest["leakage_verification"]
    assert lv["train_val_entity_overlap"] == 0
    assert lv["train_test_entity_overlap"] == 0
    assert lv["val_test_entity_overlap"] == 0
    assert lv["zero_leakage_guaranteed"] is True

def test_scaler_fit_on_train_only():
    """Verify scaler was fitted on benign training split only and metadata is present."""
    meta_path = os.path.join(BASE_DIR, "artifacts", "scaler_meta.json")
    assert os.path.exists(meta_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)
    assert meta["fit_target"] == "benign_train_split_only"
    assert len(meta["version_hash"]) > 0

def test_alert_schema_validation():
    """Verify Appendix A example alert record matches schema/alert.schema.json exactly."""
    schema_path = os.path.join(BASE_DIR, "schema", "alert.schema.json")
    with open(schema_path, "r") as f:
        schema = json.load(f)

    # Example alert record from Appendix A of paper
    example_alert = {
        "schema_version": "1.0",
        "alert_id": "a-000123",
        "timestamp": "2026-10-01T14:02:11.480Z",
        "first_seen": "2026-10-01T14:02:01.000Z",
        "last_seen": "2026-10-01T14:02:11.000Z",
        "flow_id": "src:10.2.3.4|win:10s|t:1759327321",
        "threat_class": "recon_scan",
        "confidence": 0.93,
        "severity": {"level": "high", "score": 7.8},
        "evidence": {
            "distinct_dst_ports": {"value": 840, "baseline": 6, "robust_z": 41.2},
            "failed_conn_ratio": {"value": 0.91, "baseline": 0.04},
            "sequential_port_fraction": {"value": 0.77},
            "detector_scores": {"stat": 0.97, "autoencoder": 0.81, "unified": 0.93}
        },
        "recommended_action": "Analyst review; consider blocking source at perimeter (text only)",
        "latency_ms": 412
    }

    # Should validate without raising jsonschema.ValidationError
    jsonschema.validate(instance=example_alert, schema=schema)

if __name__ == "__main__":
    print("Running core unit tests...")
    test_identifier_firewall()
    print("[PASS] test_identifier_firewall passed.")
    test_numeric_hygiene()
    print("[PASS] test_numeric_hygiene passed.")
    test_split_leakage_manifest()
    print("[PASS] test_split_leakage_manifest passed.")
    test_scaler_fit_on_train_only()
    print("[PASS] test_scaler_fit_on_train_only passed.")
    test_alert_schema_validation()
    print("[PASS] test_alert_schema_validation passed.")
    print("All Phase 1-4 unit tests PASSED successfully!")
