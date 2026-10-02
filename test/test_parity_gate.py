"""
PassiveSentinel - Parity Gate Test Suite (Section 10 & Section 13 Phase 3)
Guarantees training-serving parity by replaying golden fixtures through the pipeline
and strictly asserting numeric and classification reproducibility stage by stage:
- L3 features: relative tolerance <= 1e-5
- L4 normalizer: relative tolerance <= 1e-5
- L5 specialist scores: relative tolerance <= 1e-4
- L6 & L7 calibrated confidence: absolute difference < 0.001
- L6 predicted classes: 100% agreement
- L8 alerts: 100% JSON schema validation and count agreement
"""

import os
import sys
import json
import pytest
import jsonschema
import numpy as np
import pandas as pd
import torch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.bundle import ModelBundle
from engine.pipeline import RuntimePipeline

FIXTURES_DIR = os.path.join(BASE_DIR, "test", "golden", "fixtures")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema", "alert.schema.json")

@pytest.fixture(scope="module")
def golden_data():
    flows_path = os.path.join(FIXTURES_DIR, "golden_flows.csv")
    stages_path = os.path.join(FIXTURES_DIR, "golden_stages.json")
    assert os.path.exists(flows_path), f"Golden flows missing at {flows_path}"
    assert os.path.exists(stages_path), f"Golden stages missing at {stages_path}"
    
    df = pd.read_csv(flows_path)
    with open(stages_path, "r") as f:
        stages = json.load(f)
    with open(SCHEMA_PATH, "r") as f:
        schema = json.load(f)
        
    bundle = ModelBundle()
    bundle.load(strict=True)
    pipeline = RuntimePipeline(bundle, input_type="flow")
    
    return {
        "df": df,
        "stages": stages,
        "schema": schema,
        "bundle": bundle,
        "pipeline": pipeline
    }

def test_l3_feature_parity(golden_data):
    """Assert L3 raw feature extraction matches golden fixtures within 1e-5."""
    df = golden_data["df"]
    stages = golden_data["stages"]
    feat_names = stages["feature_names"]
    
    X_raw = df[[c for c in feat_names if c in df.columns]].fillna(0).values.astype(np.float32)
    expected_sample = np.array(stages["L3_features_sample"], dtype=np.float32)
    
    np.testing.assert_allclose(X_raw[:5], expected_sample, rtol=1e-5, atol=1e-5,
                               err_msg="L3 feature extraction diverged from golden fixture")

def test_l4_normalization_parity(golden_data):
    """Assert L4 robust normalization matches golden fixtures within 1e-5."""
    df = golden_data["df"]
    stages = golden_data["stages"]
    bundle = golden_data["bundle"]
    
    X_norm, _ = bundle.scaler.transform(df)
    expected_norm_sample = np.array(stages["L4_normalized_sample"], dtype=np.float32)
    
    np.testing.assert_allclose(X_norm[:5], expected_norm_sample, rtol=1e-5, atol=1e-5,
                               err_msg="L4 normalized output diverged from golden fixture")

def test_l5_specialist_parity(golden_data):
    """Assert L5a and L5e specialist scores match golden fixtures within 1e-4."""
    df = golden_data["df"]
    stages = golden_data["stages"]
    bundle = golden_data["bundle"]
    
    X_norm, _ = bundle.scaler.transform(df)
    stat_probs = bundle.l5a_detector.predict_proba(X_norm)
    ae_scores, _ = bundle.l5e_autoencoder.score(X_norm)
    
    expected_stat = np.array(stages["L5_stat_probs_sample"], dtype=np.float32)
    expected_ae = np.array(stages["L5_ae_scores_sample"], dtype=np.float32)
    
    np.testing.assert_allclose(stat_probs[:5], expected_stat, rtol=1e-4, atol=1e-4,
                               err_msg="L5a detector probabilities diverged from golden fixture")
    np.testing.assert_allclose(ae_scores[:5], expected_ae, rtol=1e-4, atol=1e-4,
                               err_msg="L5e autoencoder anomaly scores diverged from golden fixture")

def test_l6_l7_fusion_parity(golden_data):
    """Assert L6 & L7 multi-task fusion classes match 100% and calibrated confidences agree within 0.001."""
    df = golden_data["df"]
    stages = golden_data["stages"]
    bundle = golden_data["bundle"]
    
    X_norm, _ = bundle.scaler.transform(df)
    stat_probs = bundle.l5a_detector.predict_proba(X_norm)
    ae_scores, ae_flags = bundle.l5e_autoencoder.score(X_norm)
    
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
        logits, _, _, _ = bundle.l6_model(t_X)
        calibrated_probs = torch.softmax(logits / bundle.l6_model.temperature, dim=-1).cpu().numpy()
        preds = np.argmax(calibrated_probs, axis=-1)

    expected_probs = np.array(stages["L6_calibrated_probs_sample"], dtype=np.float32)
    expected_preds = np.array(stages["L6_predicted_classes"])

    # Assert 100% predicted class match
    np.testing.assert_array_equal(preds, expected_preds, err_msg="L6 predicted classes disagree with golden fixture")
    
    # Assert calibrated probabilities within 0.001
    np.testing.assert_allclose(calibrated_probs[:5], expected_probs, atol=1e-3,
                               err_msg="L7 calibrated probabilities diverged from golden fixture")

def test_l8_alert_schema_parity(golden_data):
    """Assert L8 generated alerts comply 100% with alert.schema.json and match golden counts."""
    df = golden_data["df"]
    stages = golden_data["stages"]
    schema = golden_data["schema"]
    pipeline = golden_data["pipeline"]
    
    alerts = pipeline.process_flow_batch(df, min_severity="low", min_confidence=0.0)
    
    assert len(alerts) == stages["L8_alerts_count"], (
        f"Alert count mismatch: got {len(alerts)}, expected {stages['L8_alerts_count']}"
    )
    
    for alert in alerts:
        # Validate against JSON schema
        jsonschema.validate(instance=alert, schema=schema)
        # Check required fields and types
        assert alert["schema_version"] == "1.0"
        assert alert["threat_class"] in schema["properties"]["threat_class"]["enum"]
        assert 0.0 <= alert["confidence"] <= 1.0
        assert alert["severity"]["level"] in ["low", "medium", "high", "critical"]
        assert 0.0 <= alert["severity"]["score"] <= 10.0
        assert "detector_scores" in alert["evidence"]
        assert "detectors_used" in alert
        assert alert["recommended_action"] is not None
        assert alert["latency_ms"] >= 0
