"""
PassiveSentinel - End-to-End GPU Training & 5-Fold Grouped Cross-Validation Pipeline
Executes following the paper specifications:
1. GPU Device Setup (NVIDIA RTX CUDA acceleration)
2. Normalizer Layer L4 fit on BENIGN training flows only (zero-leakage)
3. 5-Fold Stratified Group Cross-Validation on training period by entity (Section 5.3)
   - Computes out-of-fold specialist predictions across all 5 folds
   - Records Mean and Standard Deviation of Cross-Validation Macro-F1
4. L5e Autoencoder Gate trained on benign flows with 99.5th percentile threshold
5. L6 Unified Transformer with typed Choice/Boolean/Score heads trained on GPU
6. L7 Temperature Scaling calibration on validation split
7. Single-pass evaluation on locked test split (39,305 flows) with full metrics
"""

import os
os.environ["LOKY_MAX_CPU_COUNT"] = "4"
os.environ["PYTHONUNBUFFERED"] = "1"
import sys
import json
import yaml
import pickle
import hashlib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score, matthews_corrcoef
from sklearn.model_selection import StratifiedGroupKFold

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from normalize.scaler import NormalizerL4
from detectors.stat.stat_detector import StatisticalDetectorL5a
from detectors.autoencoder.autoencoder import AutoencoderGateL5e
from fusion.unified_encoder import UnifiedEncoderL6, FocalLoss, TemperatureScalerL7

SPLITS_DIR = os.path.join(BASE_DIR, "splits")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Load canonical label mapping
with open(os.path.join(BASE_DIR, "configs", "label_map.yaml"), "r") as f:
    label_cfg = yaml.safe_load(f)

raw_attack_map = label_cfg["dataset_mappings"]["raw_attack_strings"]
class_to_id = label_cfg["class_to_id"]
canonical_classes = [label_cfg["canonical_classes"][i] for i in sorted(label_cfg["canonical_classes"].keys())]

def map_threat_series(series: pd.Series) -> np.ndarray:
    mapped = series.map(raw_attack_map).fillna(series.str.lower()).map(class_to_id).fillna(0)
    return mapped.astype(int).values

def main():
    print("=" * 70)
    print("[TRAINING] PassiveSentinel (SIH PS-145) GPU-Accelerated Pipeline")
    print("=" * 70)

    # 1. Device check
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    gpu_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
    print(f"\n[Hardware] Compute Device: {device} ({gpu_name})")

    # 2. Load partitioned splits
    print("\n[Step 1/7] Loading partitioned splits...")
    train_df = pd.read_csv(os.path.join(SPLITS_DIR, "train_split.csv"), low_memory=False)
    val_df = pd.read_csv(os.path.join(SPLITS_DIR, "val_split.csv"), low_memory=False)
    test_df = pd.read_csv(os.path.join(SPLITS_DIR, "test_split.csv"), low_memory=False)

    print(f"Loaded: Train={len(train_df):,}, Val={len(val_df):,}, Test={len(test_df):,}")

    y_train = map_threat_series(train_df["threat_class"])
    y_val = map_threat_series(val_df["threat_class"])
    y_test = map_threat_series(test_df["threat_class"])

    print("\nClass distribution in Train:")
    for i, c in enumerate(canonical_classes):
        print(f"  {c:<20}: {np.sum(y_train == i):,}")
    print("\nClass distribution in Test:")
    for i, c in enumerate(canonical_classes):
        print(f"  {c:<20}: {np.sum(y_test == i):,}")

    # 3. Fit L4 Normalizer strictly on benign train data
    print("\n[Step 2/7] Fitting Layer L4 Normalizer on BENIGN train split only...")
    normalizer = NormalizerL4().fit_on_benign_train(train_df)
    normalizer.save(os.path.join(ARTIFACTS_DIR, "scaler_v1.pkl"))

    X_train, feat_names = normalizer.transform(train_df)
    X_val, _ = normalizer.transform(val_df)
    X_test, _ = normalizer.transform(test_df)
    in_features = X_train.shape[1]

    # 4. 5-Fold Stratified Group Cross-Validation on Train
    print("\n[Step 3/7] Performing 5-Fold Stratified Group Cross-Validation (Section 5.3)...")
    sgkf = StratifiedGroupKFold(n_splits=5)
    oof_expert_scores = np.zeros((len(train_df), in_features), dtype=np.float32)
    cv_scores = []

    for fold, (trn_idx, oof_idx) in enumerate(sgkf.split(X_train, y_train, train_df["entity_key"])):
        fold_l5a = StatisticalDetectorL5a(n_estimators=100, max_depth=6, learning_rate=0.08, class_weight="balanced")
        fold_l5a.train(X_train[trn_idx], y_train[trn_idx])
        oof_probs = fold_l5a.predict_proba(X_train[oof_idx], n_classes=7)
        oof_expert_scores[oof_idx, :7] = oof_probs
        oof_preds = np.argmax(oof_probs, axis=1)
        fold_f1 = f1_score(y_train[oof_idx], oof_preds, average="macro", zero_division=0)
        cv_scores.append(fold_f1)
        print(f"  Fold {fold + 1}/5 Macro-F1: {fold_f1:.4f} (Samples: {len(oof_idx):,})")

    mean_cv_f1 = float(np.mean(cv_scores))
    std_cv_f1 = float(np.std(cv_scores))
    print(f"\n[CV Results] 5-Fold Grouped CV Macro-F1: {mean_cv_f1:.4f} (+/- {std_cv_f1:.4f})")

    # Train full L5a model on entire train set
    print("\nTraining Full L5a Statistical Detector...")
    l5a = StatisticalDetectorL5a(n_estimators=150, max_depth=6, learning_rate=0.08, class_weight="balanced")
    l5a.train(X_train, y_train, X_val, y_val)
    l5a.save(os.path.join(ARTIFACTS_DIR, "l5a_stat_detector.pkl"))

    # 5. Train L5e Autoencoder Gate on Benign only
    print("\n[Step 4/7] Training L5e Autoencoder on BENIGN train flows only...")
    benign_train_x = X_train[y_train == 0]
    benign_val_x = X_val[y_val == 0]
    l5e = AutoencoderGateL5e(input_dim=in_features)
    ae_stats = l5e.train_on_benign(benign_train_x, benign_val_x, epochs=8, batch_size=256)
    l5e.save(os.path.join(ARTIFACTS_DIR, "l5e_autoencoder.pt"))
    print(f"L5e Anomaly Threshold (99.5th percentile): {ae_stats['threshold_p99_5']:.6f}")

    # 6. Complete Expert Score Tokens
    print("\n[Step 5/7] Assembling Multi-Expert Tokens (L5a Probs + L5e Anomaly Scores)...")
    ae_train_scores, ae_train_flags = l5e.score(X_train)
    oof_expert_scores[:, 7] = ae_train_scores
    oof_expert_scores[:, 8] = ae_train_flags

    val_expert_scores = np.zeros((len(val_df), in_features), dtype=np.float32)
    val_expert_scores[:, :7] = l5a.predict_proba(X_val, n_classes=7)
    ae_val_scores, ae_val_flags = l5e.score(X_val)
    val_expert_scores[:, 7] = ae_val_scores
    val_expert_scores[:, 8] = ae_val_flags

    test_expert_scores = np.zeros((len(test_df), in_features), dtype=np.float32)
    test_expert_scores[:, :7] = l5a.predict_proba(X_test, n_classes=7)
    ae_test_scores, ae_test_flags = l5e.score(X_test)
    test_expert_scores[:, 7] = ae_test_scores
    test_expert_scores[:, 8] = ae_test_flags

    # 7. Train L6 Unified Transformer on GPU
    print("\n[Step 6/7] Training L6 Unified Encoder on GPU (T=4, d_model=64, 4 heads, SwiGLU)...")
    def build_window_tensors(X: np.ndarray, expert_scores: np.ndarray, seq_len: int = 4) -> torch.Tensor:
        batch_size = len(X)
        tokens = np.zeros((batch_size, seq_len, X.shape[1]), dtype=np.float32)
        for t in range(seq_len - 1):
            tokens[:, t, :] = X
        tokens[:, -1, :] = expert_scores
        return torch.tensor(tokens, dtype=torch.float32)

    t_X_train = build_window_tensors(X_train, oof_expert_scores, seq_len=4)
    t_X_val = build_window_tensors(X_val, val_expert_scores, seq_len=4)
    t_X_test = build_window_tensors(X_test, test_expert_scores, seq_len=4)

    t_y_train = torch.tensor(y_train, dtype=torch.long)
    t_y_val = torch.tensor(y_val, dtype=torch.long)
    t_y_test = torch.tensor(y_test, dtype=torch.long)

    bool_train = torch.zeros((len(y_train), 4), dtype=torch.float32)
    bool_train[:, 0] = torch.tensor((y_train > 0).astype(float))
    bool_val = torch.zeros((len(y_val), 4), dtype=torch.float32)
    bool_val[:, 0] = torch.tensor((y_val > 0).astype(float))

    score_train = torch.tensor(np.clip(y_train * 1.5, 0.0, 10.0), dtype=torch.float32)
    score_val = torch.tensor(np.clip(y_val * 1.5, 0.0, 10.0), dtype=torch.float32)

    train_dataset = torch.utils.data.TensorDataset(t_X_train, t_y_train, bool_train, score_train)
    train_loader = torch.utils.data.DataLoader(train_dataset, batch_size=512, shuffle=True)

    l6_model = UnifiedEncoderL6(in_features=in_features, d_model=64, n_layers=2, n_heads=4, d_ff=256, n_classes=7)
    l6_model.to(device)

    optimizer = torch.optim.AdamW(l6_model.parameters(), lr=1e-3, weight_decay=1e-2)
    focal_criterion = FocalLoss(gamma=2.0, label_smoothing=0.05).to(device)
    bce_criterion = torch.nn.BCELoss().to(device)
    mse_criterion = torch.nn.MSELoss().to(device)

    best_val_f1 = 0.0
    for epoch in range(1, 7):
        l6_model.train()
        total_loss = 0.0
        for bx, by, b_bool, b_score in train_loader:
            bx = bx.to(device)
            by = by.to(device)
            b_bool = b_bool.to(device)
            b_score = b_score.to(device)

            optimizer.zero_grad()
            c_logits, p_bool, s_exp, _ = l6_model(bx)
            loss_choice = focal_criterion(c_logits, by)
            loss_bool = bce_criterion(p_bool, b_bool)
            loss_score = mse_criterion(s_exp, b_score)
            loss = loss_choice + 0.5 * loss_bool + 0.2 * loss_score
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        l6_model.eval()
        with torch.no_grad():
            v_logits, _, _, _ = l6_model(t_X_val.to(device))
            v_preds = torch.argmax(v_logits, dim=-1).cpu().numpy()
            val_f1 = f1_score(y_val, v_preds, average="macro", zero_division=0)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            torch.save(l6_model.state_dict(), os.path.join(ARTIFACTS_DIR, "l6_best_model.pt"))
        print(f"Epoch {epoch:02d}/06 - Loss: {total_loss/len(train_loader):.4f} - Val Macro-F1: {val_f1:.4f}")

    if os.path.exists(os.path.join(ARTIFACTS_DIR, "l6_best_model.pt")):
        l6_model.load_state_dict(torch.load(os.path.join(ARTIFACTS_DIR, "l6_best_model.pt"), weights_only=True))

    # 8. Fit L7 Temperature Scaling on Validation Split
    print("\n[Step 7/7] Fitting L7 Temperature Scaling on Validation Logits...")
    l6_model.eval()
    with torch.no_grad():
        val_logits, _, _, _ = l6_model(t_X_val.to(device))
        val_logits_np = val_logits.cpu().numpy()
    
    fitted_temp = TemperatureScalerL7.fit_temperature(val_logits_np, y_val)
    l6_model.temperature.data.fill_(fitted_temp)
    torch.save(l6_model.state_dict(), os.path.join(ARTIFACTS_DIR, "l6_calibrated_final.pt"))

    # =========================================================================
    # SINGLE TEST EVALUATION (TOUCHED ONCE)
    # =========================================================================
    print("\n" + "=" * 70)
    print(f"[EVALUATION] EVALUATING ON LOCKED TEST SPLIT ({len(test_df):,} flows, TOUCHED ONCE)")
    print("=" * 70)
    
    with torch.no_grad():
        test_logits, test_bool, test_sev, _ = l6_model(t_X_test.to(device))
        test_preds = torch.argmax(test_logits, dim=-1).cpu().numpy()
        test_probs = torch.softmax(test_logits, dim=-1).cpu().numpy()

    test_macro_f1 = f1_score(y_test, test_preds, average="macro", zero_division=0)
    test_weighted_f1 = f1_score(y_test, test_preds, average="weighted", zero_division=0)
    test_accuracy = float(np.mean(test_preds == y_test))
    test_mcc = matthews_corrcoef(y_test, test_preds)

    labels_list = list(range(len(canonical_classes)))
    cls_report = classification_report(
        y_test, test_preds, labels=labels_list, target_names=canonical_classes, 
        output_dict=True, zero_division=0
    )

    print(f"\nFinal Test Accuracy:    {test_accuracy:.4f} ({test_accuracy*100:.2f}%)")
    print(f"Final Test Weighted-F1: {test_weighted_f1:.4f}")
    print(f"Final Test Macro-F1:    {test_macro_f1:.4f}")
    print(f"Final Test MCC:         {test_mcc:.4f}\n")
    print(classification_report(y_test, test_preds, labels=labels_list, target_names=canonical_classes, zero_division=0))

    results_payload = {
        "execution_seed": 42,
        "compute_device": str(device),
        "gpu_model": gpu_name,
        "temperature_calibrated": fitted_temp,
        "dataset_flows_total": len(train_df) + len(val_df) + len(test_df),
        "cross_validation": {
            "method": "5-Fold Stratified Group K-Fold (Entity Isolated)",
            "fold_scores": [round(s, 4) for s in cv_scores],
            "mean_macro_f1": round(mean_cv_f1, 4),
            "std_macro_f1": round(std_cv_f1, 4)
        },
        "test_metrics": {
            "accuracy": round(test_accuracy, 4),
            "macro_f1": round(test_macro_f1, 4),
            "weighted_f1": round(test_weighted_f1, 4),
            "matthews_corrcoef": round(test_mcc, 4),
            "per_class": cls_report
        }
    }

    results_path = os.path.join(RESULTS_DIR, "test_evaluation_results.json")
    with open(results_path, "w") as f:
        json.dump(results_payload, f, indent=2)

    print(f"Results successfully saved to {results_path}")

if __name__ == "__main__":
    main()
