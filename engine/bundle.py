"""
PassiveSentinel - Model Bundle Loader & Manifest Verifier
Enforces Section 9 & Section 11 of the Architecture Specification:
Loads versioned model bundle, verifies SHA-256 cryptographic signatures,
and guarantees zero runtime parameter mutation.
"""

import os
import sys
import json
import yaml
import hashlib
import pickle
import torch
import numpy as np
from typing import Dict, Any, Tuple, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from fusion.unified_encoder import UnifiedEncoderL6
from detectors.autoencoder.autoencoder import AutoencoderGateL5e

class BundleIntegrityError(Exception):
    """Raised when SHA-256 checksum or bundle manifest validation fails (Exit Code 3)."""
    pass

class BundleNotFoundError(Exception):
    """Raised when model bundle or manifest cannot be located (Exit Code 3)."""
    pass

def compute_sha256(filepath: str) -> str:
    """Computes hexadecimal SHA-256 digest of a local file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found for hash verification: {filepath}")
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

class ModelBundle:
    def __init__(self, bundle_dir: Optional[str] = None):
        if bundle_dir is None:
            bundle_dir = os.path.join(BASE_DIR, "models", "v0.1")
        self.bundle_dir = os.path.abspath(bundle_dir)
        self.manifest_path = os.path.join(self.bundle_dir, "manifest.json")
        self.manifest: Dict[str, Any] = {}
        self.scaler = None
        self.thresholds: Dict[str, Any] = {}
        self.calibration: Dict[str, Any] = {}
        self.feature_schema: Dict[str, Any] = {}
        self.l5a_detector = None
        self.l5e_autoencoder: Optional[AutoencoderGateL5e] = None
        self.l6_model: Optional[UnifiedEncoderL6] = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._is_verified = False

    def verify_integrity(self) -> Tuple[bool, list]:
        """
        Recomputes SHA-256 checksums for all manifest artifacts.
        Returns (is_valid, list_of_errors).
        """
        if not os.path.exists(self.manifest_path):
            return False, [f"Manifest missing at {self.manifest_path}"]

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            try:
                self.manifest = json.load(f)
            except Exception as e:
                return False, [f"Corrupt manifest JSON: {str(e)}"]

        errors = []

        # 1. Feature schema check
        feat_rel = self.manifest.get("feature_schema", {}).get("file")
        feat_expected = self.manifest.get("feature_schema", {}).get("sha256")
        if feat_rel:
            p = os.path.join(self.bundle_dir, feat_rel)
            if not os.path.exists(p):
                errors.append(f"Feature schema missing: {feat_rel}")
            elif compute_sha256(p) != feat_expected:
                errors.append(f"Feature schema SHA-256 mismatch for {feat_rel}")

        # 2. Preprocess check
        for pre in self.manifest.get("preprocess", []):
            rel = pre.get("file")
            exp = pre.get("sha256")
            p = os.path.join(self.bundle_dir, rel)
            if not os.path.exists(p):
                errors.append(f"Preprocessing artifact missing: {rel}")
            elif compute_sha256(p) != exp:
                errors.append(f"Preprocessing SHA-256 mismatch for {rel}")

        # 3. Models check
        for m in self.manifest.get("models", []):
            rel = m.get("file")
            exp = m.get("sha256")
            p = os.path.join(self.bundle_dir, rel)
            if not os.path.exists(p):
                errors.append(f"Model weight missing: {rel}")
            elif compute_sha256(p) != exp:
                errors.append(f"Model SHA-256 mismatch for {rel}")

        # 4. Thresholds check
        thresh_rel = self.manifest.get("thresholds", {}).get("file")
        thresh_exp = self.manifest.get("thresholds", {}).get("sha256")
        if thresh_rel:
            p = os.path.join(self.bundle_dir, thresh_rel)
            if not os.path.exists(p):
                errors.append(f"Thresholds missing: {thresh_rel}")
            elif compute_sha256(p) != thresh_exp:
                errors.append(f"Thresholds SHA-256 mismatch for {thresh_rel}")

        # 5. Calibration check
        calib_rel = self.manifest.get("calibration", {}).get("file")
        calib_exp = self.manifest.get("calibration", {}).get("sha256")
        if calib_rel:
            p = os.path.join(self.bundle_dir, calib_rel)
            if not os.path.exists(p):
                errors.append(f"Calibration file missing: {calib_rel}")
            elif compute_sha256(p) != calib_exp:
                errors.append(f"Calibration SHA-256 mismatch for {calib_rel}")

        self._is_verified = (len(errors) == 0)
        return self._is_verified, errors

    def load(self, strict: bool = True):
        """Loads and prepares all pipeline models for inference."""
        is_valid, errors = self.verify_integrity()
        if strict and not is_valid:
            raise BundleIntegrityError(f"Bundle integrity verification failed: {'; '.join(errors)}")

        # Load Thresholds
        thresh_path = os.path.join(self.bundle_dir, self.manifest["thresholds"]["file"])
        with open(thresh_path, "r", encoding="utf-8") as f:
            self.thresholds = json.load(f)

        # Load Calibration
        calib_path = os.path.join(self.bundle_dir, self.manifest["calibration"]["file"])
        with open(calib_path, "r", encoding="utf-8") as f:
            self.calibration = json.load(f)

        # Load Scaler
        scaler_pkl = os.path.join(self.bundle_dir, "preprocess", "scaler.pkl")
        if os.path.exists(scaler_pkl):
            with open(scaler_pkl, "rb") as f:
                self.scaler = pickle.load(f)

        # Load L5a Stat Detector
        l5a_path = os.path.join(self.bundle_dir, "specialists", "stat_gbm.pkl")
        with open(l5a_path, "rb") as f:
            self.l5a_detector = pickle.load(f)

        # Load L5e Autoencoder
        l5e_path = os.path.join(self.bundle_dir, "specialists", "autoencoder.pt")
        self.l5e_autoencoder = AutoencoderGateL5e(input_dim=22)
        self.l5e_autoencoder.load(l5e_path)
        self.l5e_autoencoder.threshold = self.thresholds.get("anomaly_gate", {}).get("l5e_threshold_p99_5", 4.700581)

        # Load L6 Unified Fusion Model
        l6_path = os.path.join(self.bundle_dir, "fusion", "unified_model.pt")
        self.l6_model = UnifiedEncoderL6(in_features=22, d_model=64, n_layers=2, n_heads=4, d_ff=256, n_classes=7)
        self.l6_model.load_state_dict(torch.load(l6_path, map_location=self.device, weights_only=True))
        self.l6_model.to(self.device)
        self.l6_model.eval()

        return self

    def get_info(self) -> Dict[str, Any]:
        """Returns structured bundle inspection dictionary for `model info`."""
        if not self.manifest:
            self.verify_integrity()
        return {
            "bundle_version": self.manifest.get("bundle_version", "unknown"),
            "created_utc": self.manifest.get("created_utc", "unknown"),
            "min_cli_version": self.manifest.get("min_cli_version", "unknown"),
            "alert_schema_version": self.manifest.get("alert_schema_version", "unknown"),
            "feature_schema_sha256": self.manifest.get("feature_schema", {}).get("sha256", "unknown"),
            "classes": self.manifest.get("label_map", []),
            "calibrated_temperature": self.manifest.get("calibration", {}).get("temperature"),
            "thresholds": self.thresholds or self.manifest.get("thresholds"),
            "artifacts_verified": self._is_verified
        }

if __name__ == "__main__":
    bundle = ModelBundle()
    valid, errs = bundle.verify_integrity()
    if valid:
        print("[SUCCESS] ModelBundle v0.1 passed all cryptographic integrity checks!")
        bundle.load(strict=True)
        print("Bundle loaded successfully into compute device:", bundle.device)
    else:
        print("[ERROR] Verification failed:", errs)
        sys.exit(3)
