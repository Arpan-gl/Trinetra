/**
 * PassiveSentinel - Engine IPC Protocol Types
 * Strictly defines messages exchanged between the Node.js CLI and Python Engine.
 */

export interface AlertSeverity {
  level: "low" | "medium" | "high" | "critical";
  score: number;
}

export interface AlertEvidence {
  detector_scores: Record<string, number>;
  [key: string]: any;
}

export interface AlertRecord {
  schema_version: "1.0";
  alert_id: string;
  timestamp: string;
  first_seen: string;
  last_seen: string;
  flow_id: string;
  threat_class: "ddos" | "beaconing" | "dga_tunnel" | "encrypted_malware" | "recon_scan" | "exfiltration" | "anomaly";
  confidence: number;
  severity: AlertSeverity;
  evidence: AlertEvidence;
  detectors_used?: string[];
  recommended_action: string;
  latency_ms: number;
}

export interface EngineSummary {
  bundle_version: string;
  schema_hash: string;
  input_type: string;
  active_detectors: string[];
  disabled_detectors: string[];
  workers: number;
  counters: {
    flows_total: number;
    flows_processed: number;
    flows_rejected: number;
    flows_late: number;
    drops_queue_full: number;
    drops_malformed: number;
    alerts_emitted: number;
    elapsed_s: number;
  };
  throughput_flows_sec: number;
  severity_counts: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  class_counts: Record<string, number>;
  latency_percentiles_ms: {
    p50: number;
    p95: number;
    p99: number;
  };
}

export interface BenchmarkMetrics {
  macro_f1: number;
  weighted_f1: number;
  matthews_corrcoef: number;
  expected_calibration_error: number;
  flows_evaluated: number;
  per_class: Record<string, any>;
  summary: EngineSummary;
}

export interface BundleInfo {
  bundle_version: string;
  created_utc: string;
  min_cli_version: string;
  alert_schema_version: string;
  feature_schema_sha256: string;
  classes: string[];
  calibrated_temperature?: number;
  thresholds: any;
  artifacts_verified: boolean;
}
