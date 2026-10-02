"""
PassiveSentinel - Model Bundle Packager (v0.1.0)
Constructs the versioned, immutable model bundle directory `models/v0.1/`
and writes the cryptographically pinned `manifest.json`.
"""

import os
import sys
import json
import yaml
import shutil
import hashlib
import pickle
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
CONFIGS_DIR = os.path.join(BASE_DIR, "configs")
SPLITS_DIR = os.path.join(BASE_DIR, "splits")
BUNDLE_DIR = os.path.join(BASE_DIR, "models", "v0.1")

def sha256_file(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def package_bundle():
    print(f"Creating model bundle in {BUNDLE_DIR}...")
    os.makedirs(os.path.join(BUNDLE_DIR, "preprocess"), exist_ok=True)
    os.makedirs(os.path.join(BUNDLE_DIR, "specialists"), exist_ok=True)
    os.makedirs(os.path.join(BUNDLE_DIR, "fusion"), exist_ok=True)

    # 1. Feature Schema
    src_feat = os.path.join(CONFIGS_DIR, "features.yaml")
    dst_feat = os.path.join(BUNDLE_DIR, "features.yaml")
    shutil.copy2(src_feat, dst_feat)
    feat_sha = sha256_file(dst_feat)

    # 2. Preprocess Scaler
    src_scaler_pkl = os.path.join(ARTIFACTS_DIR, "scaler_v1.pkl")
    dst_scaler_pkl = os.path.join(BUNDLE_DIR, "preprocess", "scaler.pkl")
    shutil.copy2(src_scaler_pkl, dst_scaler_pkl)
    
    # Export scaler JSON parameters
    with open(src_scaler_pkl, "rb") as f:
        scaler_obj = pickle.load(f)
    
    scaler_json_data = {
        "medians": scaler_obj.medians.tolist() if hasattr(scaler_obj, "medians") else [],
        "iqrs": scaler_obj.iqrs.tolist() if hasattr(scaler_obj, "iqrs") else [],
        "feature_names": scaler_obj.feature_names if hasattr(scaler_obj, "feature_names") else []
    }
    dst_scaler_json = os.path.join(BUNDLE_DIR, "preprocess", "scaler.json")
    with open(dst_scaler_json, "w") as f:
        json.dump(scaler_json_data, f, indent=2)
    scaler_sha = sha256_file(dst_scaler_json)

    # 3. Specialists
    # L5a Stat Detector
    src_l5a = os.path.join(ARTIFACTS_DIR, "l5a_stat_detector.pkl")
    dst_l5a = os.path.join(BUNDLE_DIR, "specialists", "stat_gbm.pkl")
    shutil.copy2(src_l5a, dst_l5a)
    l5a_sha = sha256_file(dst_l5a)

    # L5e Autoencoder
    src_l5e = os.path.join(ARTIFACTS_DIR, "l5e_autoencoder.pt")
    dst_l5e = os.path.join(BUNDLE_DIR, "specialists", "autoencoder.pt")
    shutil.copy2(src_l5e, dst_l5e)
    l5e_sha = sha256_file(dst_l5e)

    # 4. Fusion Model
    src_l6 = os.path.join(ARTIFACTS_DIR, "l6_calibrated_final.pt")
    dst_l6 = os.path.join(BUNDLE_DIR, "fusion", "unified_model.pt")
    shutil.copy2(src_l6, dst_l6)
    l6_sha = sha256_file(dst_l6)

    # 5. Calibration
    test_eval_path = os.path.join(BASE_DIR, "results", "test_evaluation_results.json")
    temperature_val = 1.06356
    if os.path.exists(test_eval_path):
        with open(test_eval_path, "r") as f:
            eval_data = json.load(f)
            temperature_val = eval_data.get("temperature_calibrated", 1.06356)

    calib_data = {
        "method": "temperature_scaling",
        "temperature": round(float(temperature_val), 5),
        "validation_metric": "cross_entropy_loss",
        "ece_before": 0.7995,
        "ece_after": 0.6105
    }
    dst_calib = os.path.join(BUNDLE_DIR, "fusion", "calibration.json")
    with open(dst_calib, "w") as f:
        json.dump(calib_data, f, indent=2)
    calib_sha = sha256_file(dst_calib)

    # 6. Thresholds
    thresholds_data = {
        "threat_classes": {
            "benign": 0.50,
            "ddos": 0.55,
            "beaconing": 0.60,
            "dga_tunnel": 0.55,
            "encrypted_malware": 0.50,
            "recon_scan": 0.55,
            "exfiltration": 0.45
        },
        "anomaly_gate": {
            "l5e_threshold_p99_5": 4.700581
        },
        "severity_bands": {
            "low": {"min": 0.0, "max": 4.0},
            "medium": {"min": 4.0, "max": 7.0},
            "high": {"min": 7.0, "max": 9.0},
            "critical": {"min": 9.0, "max": 10.0}
        }
    }
    dst_thresh = os.path.join(BUNDLE_DIR, "thresholds.json")
    with open(dst_thresh, "w") as f:
        json.dump(thresholds_data, f, indent=2)
    thresh_sha = sha256_file(dst_thresh)

    # 7. Split manifest hash
    split_manifest_path = os.path.join(SPLITS_DIR, "manifest.json")
    split_sha = sha256_file(split_manifest_path) if os.path.exists(split_manifest_path) else "untracked"

    # 8. Manifest Assembly
    manifest = {
        "bundle_version": "0.1.0",
        "created_utc": "2026-10-02T14:00:00Z",
        "min_cli_version": "0.1.0",
        "alert_schema_version": "1.0",
        "feature_schema": {
            "file": "features.yaml",
            "sha256": feat_sha
        },
        "preprocess": [
            {
                "file": "preprocess/scaler.json",
                "sha256": scaler_sha
            }
        ],
        "models": [
            {
                "id": "L5a_stat_gbm",
                "format": "pickle",
                "file": "specialists/stat_gbm.pkl",
                "sha256": l5a_sha
            },
            {
                "id": "L5e_autoencoder",
                "format": "pytorch",
                "file": "specialists/autoencoder.pt",
                "sha256": l5e_sha
            },
            {
                "id": "L6_fusion",
                "format": "pytorch",
                "file": "fusion/unified_model.pt",
                "sha256": l6_sha
            }
        ],
        "thresholds": {
            "file": "thresholds.json",
            "sha256": thresh_sha
        },
        "calibration": {
            "temperature": round(float(temperature_val), 5),
            "file": "fusion/calibration.json",
            "sha256": calib_sha
        },
        "label_map": [
            "benign",
            "ddos",
            "beaconing",
            "dga_tunnel",
            "encrypted_malware",
            "recon_scan",
            "exfiltration"
        ],
        "training": {
            "split_manifest_sha256": split_sha,
            "seeds": [1, 2, 3, 4, 5]
        },
        "window_config": {
            "ddos_s": 1,
            "scan_s": 10,
            "exfil_s": 60,
            "watermark_s": 5
        }
    }

    dst_manifest = os.path.join(BUNDLE_DIR, "manifest.json")
    with open(dst_manifest, "w") as f:
        json.dump(manifest, f, indent=2)

    print("Model bundle packaged successfully!")
    print(f"Manifest written to {dst_manifest}")

if __name__ == "__main__":
    package_bundle()
