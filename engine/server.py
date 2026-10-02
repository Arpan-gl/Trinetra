"""
PassiveSentinel - Stdio JSON-Lines IPC Engine Server
Enforces Option A (Section 3.1) of Architecture Specification:
Provides high-performance streaming IPC over stdin/stdout,
translating CLI instructions into L0-L8 execution.
"""

import os
import sys
import json
import time
import argparse
import traceback
import pandas as pd
from typing import Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from engine.bundle import ModelBundle, BundleIntegrityError, BundleNotFoundError
from engine.pipeline import RuntimePipeline

def emit(msg_type: str, data: Dict[str, Any]):
    """Emits a single atomic JSON-line message to stdout."""
    payload = {"type": msg_type, **data}
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

class EngineServer:
    def __init__(self, bundle_dir: Optional[str] = None):
        self.bundle_dir = bundle_dir or os.path.join(BASE_DIR, "models", "v0.1")
        self.bundle: Optional[ModelBundle] = None
        self.pipeline: Optional[RuntimePipeline] = None

    def initialize(self) -> bool:
        try:
            self.bundle = ModelBundle(self.bundle_dir)
            self.bundle.load(strict=True)
            return True
        except BundleIntegrityError as e:
            emit("ERROR", {"code": 3, "message": str(e)})
            return False
        except Exception as e:
            emit("ERROR", {"code": 1, "message": f"Initialization failure: {str(e)}"})
            return False

    def handle_analyze_flow(self, file_path: str, options: Dict[str, Any]):
        if not os.path.exists(file_path):
            emit("ERROR", {"code": 4, "message": f"Input file not found: {file_path}"})
            return

        if self.bundle is None:
            if not self.initialize():
                return

        workers = options.get("workers", 1)
        self.pipeline = RuntimePipeline(self.bundle, input_type="flow", workers=workers)
        
        min_severity = options.get("min_severity", "low")
        min_confidence = float(options.get("min_confidence", 0.0))
        anonymize = bool(options.get("anonymize", False))
        chunk_size = int(options.get("chunk_size", 500))

        emit("STATUS", {
            "status": "PROCESSING",
            "active_detectors": self.pipeline.active_detectors,
            "disabled_detectors": self.pipeline.disabled_detectors
        })

        try:
            # Process in streaming chunks (micro-batches)
            for chunk in pd.read_csv(file_path, chunksize=chunk_size, low_memory=False):
                alerts = self.pipeline.process_flow_batch(
                    chunk,
                    min_severity=min_severity,
                    min_confidence=min_confidence,
                    anonymize=anonymize,
                    callback=lambda a: emit("ALERT", {"alert": a})
                )
                emit("PROGRESS", {
                    "flows_processed": self.pipeline.counters["flows_processed"],
                    "alerts_emitted": self.pipeline.counters["alerts_emitted"],
                    "drops": self.pipeline.counters["drops_queue_full"]
                })

            summary = self.pipeline.get_summary()
            emit("SUMMARY", {"summary": summary})

            # Check max drop rate (Section 6.3 Exit Code 6)
            max_drop_rate = float(options.get("max_drop_rate", 0.05))
            total_flows = self.pipeline.counters["flows_total"]
            drops = self.pipeline.counters["drops_queue_full"]
            if total_flows > 0 and (drops / total_flows) > max_drop_rate:
                emit("ERROR", {"code": 6, "message": f"Drop rate {drops/total_flows:.4f} exceeded limit {max_drop_rate}"})
                return

            # Check fail-on condition (Section 6.3 Exit Code 10)
            fail_on = options.get("fail_on")
            if fail_on:
                sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                req_level = sev_order.get(fail_on.lower(), 4)
                for lvl, count in self.pipeline.severity_counts.items():
                    if count > 0 and sev_order.get(lvl, 0) >= req_level:
                        emit("STATUS", {"code": 10, "message": f"Alerts at or above {fail_on} level emitted"})
                        return

        except Exception as e:
            emit("ERROR", {"code": 1, "message": f"Pipeline execution error: {str(e)}", "trace": traceback.format_exc()})

    def handle_benchmark(self, file_path: str, labels_path: str, options: Dict[str, Any]):
        """Runs held-out benchmark evaluation with zero tuning (Section 12)."""
        if not os.path.exists(file_path):
            emit("ERROR", {"code": 4, "message": f"Benchmark data not found: {file_path}"})
            return

        if self.bundle is None:
            if not self.initialize():
                return

        from bench.benchmark_suite import compute_ece
        from sklearn.metrics import classification_report, matthews_corrcoef, f1_score

        try:
            df = pd.read_csv(file_path, low_memory=False)
            labels_map = self.bundle.manifest.get("label_map", [])
            label_to_idx = {name: i for i, name in enumerate(labels_map)}

            if "attack_family" in df.columns:
                y_true = df["attack_family"].map(label_to_idx).fillna(0).astype(int).values
            elif os.path.exists(labels_path):
                labels_df = pd.read_csv(labels_path)
                y_true = labels_df.iloc[:, 0].map(label_to_idx).fillna(0).astype(int).values
            else:
                emit("ERROR", {"code": 2, "message": f"Ground-truth labels missing: {labels_path}"})
                return

            self.pipeline = RuntimePipeline(self.bundle, input_type="flow")
            alerts = self.pipeline.process_flow_batch(df, min_severity="low", min_confidence=0.0)

            # Evaluate test split predictions directly through L6
            feat_names = [
                "duration", "packet_count", "byte_count", "packet_rate", "byte_rate",
                "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
                "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "mean_iat",
                "mean_packet_size", "std_packet_size", "iat_jitter_score", "bytes_out_ratio",
                "dns_entropy", "is_encrypted", "was_missing"
            ]
            X_raw = df[[c for c in feat_names if c in df.columns]].fillna(0).values.astype(np.float32)
            X_norm, _ = self.bundle.scaler.transform(df) if self.bundle.scaler else (X_raw, feat_names)

            stat_probs = self.bundle.l5a_detector.predict_proba(X_norm)
            ae_scores, ae_flags = self.bundle.l5e_autoencoder.score(X_norm)

            expert_tokens = np.zeros((len(X_norm), X_norm.shape[1]), dtype=np.float32)
            expert_tokens[:, :7] = stat_probs
            expert_tokens[:, 7] = ae_scores
            expert_tokens[:, 8] = ae_flags

            tokens = np.zeros((len(X_norm), 4, X_norm.shape[1]), dtype=np.float32)
            for t in range(3):
                tokens[:, t, :] = X_norm
            tokens[:, -1, :] = expert_tokens

            t_X = torch.tensor(tokens, dtype=torch.float32).to(self.bundle.device)
            with torch.no_grad():
                logits, _, _, _ = self.bundle.l6_model(t_X)
                calib_probs = torch.softmax(logits / self.bundle.l6_model.temperature, dim=-1).cpu().numpy()
                y_pred = np.argmax(calib_probs, axis=-1)

            macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
            weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
            mcc = matthews_corrcoef(y_true, y_pred)
            ece = compute_ece(calib_probs, y_true, n_bins=15)

            report = classification_report(y_true, y_pred, target_names=labels_map, output_dict=True, zero_division=0)

            benchmark_results = {
                "macro_f1": round(float(macro_f1), 4),
                "weighted_f1": round(float(weighted_f1), 4),
                "matthews_corrcoef": round(float(mcc), 4),
                "expected_calibration_error": round(float(ece), 4),
                "flows_evaluated": len(df),
                "per_class": report,
                "summary": self.pipeline.get_summary()
            }
            emit("BENCHMARK_RESULT", {"benchmark": benchmark_results})

        except Exception as e:
            emit("ERROR", {"code": 1, "message": f"Benchmark error: {str(e)}", "trace": traceback.format_exc()})

    def run_stdio_loop(self):
        """Runs the persistent stdio message loop."""
        emit("STATUS", {"status": "READY", "message": "PassiveSentinel Engine ready"})
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                cmd = msg.get("cmd", "").upper()

                if cmd == "INIT":
                    self.bundle_dir = msg.get("bundle_path") or self.bundle_dir
                    success = self.initialize()
                    emit("STATUS", {"status": "INITIALIZED" if success else "INIT_FAILED"})

                elif cmd == "GET_INFO":
                    if self.bundle is None:
                        self.bundle = ModelBundle(self.bundle_dir)
                    emit("INFO", {"info": self.bundle.get_info()})

                elif cmd == "VERIFY":
                    if self.bundle is None:
                        self.bundle = ModelBundle(self.bundle_dir)
                    valid, errs = self.bundle.verify_integrity()
                    emit("VERIFY_RESULT", {"is_valid": valid, "errors": errs})

                elif cmd == "ANALYZE_FLOW":
                    self.handle_analyze_flow(msg.get("path"), msg.get("options", {}))

                elif cmd == "BENCHMARK":
                    self.handle_benchmark(msg.get("path"), msg.get("labels_path", ""), msg.get("options", {}))

                elif cmd == "SHUTDOWN":
                    emit("STATUS", {"status": "SHUTDOWN", "message": "Engine gracefully stopped"})
                    break

                else:
                    emit("ERROR", {"code": 2, "message": f"Unknown command: {cmd}"})

            except json.JSONDecodeError:
                emit("ERROR", {"code": 2, "message": f"Malformed JSON line: {line}"})
            except Exception as e:
                emit("ERROR", {"code": 1, "message": str(e), "trace": traceback.format_exc()})

def main():
    parser = argparse.ArgumentParser(description="PassiveSentinel Core Engine (SIH PS-145)")
    parser.add_argument("--stdio", action="store_true", help="Run stdio JSON-lines IPC protocol server")
    parser.add_argument("--bundle", default=None, help="Path to model bundle directory")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Subcommand: info
    p_info = subparsers.add_parser("info", help="Display model bundle information")
    
    # Subcommand: verify
    p_verify = subparsers.add_parser("verify", help="Verify model bundle SHA-256 integrity")
    
    # Subcommand: analyze-flow
    p_af = subparsers.add_parser("analyze-flow", help="Analyze flow CSV file")
    p_af.add_argument("path", help="Path to flow CSV/Parquet file")
    p_af.add_argument("--output", default=None, help="Path to write alerts JSONL")
    p_af.add_argument("--min-severity", default="low")
    p_af.add_argument("--min-confidence", type=float, default=0.0)
    p_af.add_argument("--anonymize", action="store_true")

    args = parser.parse_args()
    server = EngineServer(bundle_dir=args.bundle)

    if args.stdio:
        server.run_stdio_loop()
    elif args.command == "info":
        server.bundle = ModelBundle(server.bundle_dir)
        info = server.bundle.get_info()
        print(json.dumps(info, indent=2))
    elif args.command == "verify":
        server.bundle = ModelBundle(server.bundle_dir)
        valid, errs = server.bundle.verify_integrity()
        if valid:
            print("[OK] Model bundle SHA-256 integrity verified successfully!")
            sys.exit(0)
        else:
            print("[ERROR] Model bundle integrity failed:")
            for e in errs:
                print(f"  - {e}")
            sys.exit(3)
    elif args.command == "analyze-flow":
        server.initialize()
        opts = {
            "min_severity": args.min_severity,
            "min_confidence": args.min_confidence,
            "anonymize": args.anonymize
        }
        server.handle_analyze_flow(args.path, opts)
    else:
        # Default to stdio loop if no subcommand given
        server.run_stdio_loop()

if __name__ == "__main__":
    main()
