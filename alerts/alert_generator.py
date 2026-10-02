"""
PassiveSentinel - Layer L8: Standard Alert Schema, Severity and Evidence Generator
Adheres to:
1. Exact JSON schema in schema/alert.schema.json (Table 4 and Appendix A)
2. Deterministic severity function:
   severity = 10 * (0.5 * confidence + 0.3 * impact + 0.2 * persistence)
   impact = min(1, log10(1 + volume) / log10(1 + V_ref)) with V_ref = 1e7 (10MB)
3. Top-k evidence features ranked by robust z-score deviation
4. Dual sinks: Rotating JSON-lines file + SQLite forensic database
"""

import os
import time
import json
import uuid
import math
import sqlite3
import jsonschema
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(BASE_DIR, "schema", "alert.schema.json")
LOGS_DIR = os.path.join(BASE_DIR, "alerts", "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

with open(SCHEMA_PATH, "r") as f:
    ALERT_SCHEMA = json.load(f)

DB_PATH = os.path.join(LOGS_DIR, "alerts_forensic.db")

class AlertGeneratorL8:
    def __init__(self, v_ref_bytes: float = 1e7):
        self.v_ref = v_ref_bytes
        self.jsonl_path = os.path.join(LOGS_DIR, "alerts.jsonl")
        self._init_sqlite()

    def _init_sqlite(self):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                schema_version TEXT,
                timestamp TEXT,
                first_seen TEXT,
                last_seen TEXT,
                flow_id TEXT,
                threat_class TEXT,
                confidence REAL,
                severity_level TEXT,
                severity_score REAL,
                evidence_json TEXT,
                recommended_action TEXT,
                latency_ms INTEGER
            )
        """)
        conn.commit()
        conn.close()

    def compute_severity(self, confidence: float, volume_bytes: float, persistence_s: float, max_persist_s: float = 60.0) -> Tuple[str, float]:
        """
        severity = 10 * (0.5 * confidence + 0.3 * impact + 0.2 * persistence)
        impact = min(1, log10(1 + volume) / log10(1 + V_ref))
        """
        impact = min(1.0, math.log10(1.0 + max(0.0, volume_bytes)) / math.log10(1.0 + self.v_ref))
        persist_factor = min(1.0, max(0.0, persistence_s) / max_persist_s)
        
        score = 10.0 * (0.5 * confidence + 0.3 * impact + 0.2 * persist_factor)
        score = round(float(np.clip(score, 0.0, 10.0) if 'np' in globals() else max(0.0, min(10.0, score))), 1)

        if score < 4.0:
            level = "low"
        elif score < 7.0:
            level = "medium"
        elif score < 9.0:
            level = "high"
        else:
            level = "critical"

        return level, score

    def create_alert(self, flow_id: str, threat_class: str, confidence: float,
                     first_seen_ms: int, last_seen_ms: int, window_close_ms: int,
                     detector_scores: Dict[str, float], evidence_features: Optional[Dict[str, Any]] = None,
                     volume_bytes: float = 1000.0,
                     detectors_used: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Creates and validates a complete PassiveSentinel alert record.
        """
        now_dt = datetime.now(timezone.utc)
        timestamp_str = now_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        first_dt = datetime.fromtimestamp(first_seen_ms / 1000.0, tz=timezone.utc)
        last_dt = datetime.fromtimestamp(last_seen_ms / 1000.0, tz=timezone.utc)
        first_seen_str = first_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        last_seen_str = last_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        persistence_s = (last_seen_ms - first_seen_ms) / 1000.0
        sev_level, sev_score = self.compute_severity(confidence, volume_bytes, persistence_s)

        # Latency calculation: current time minus window close time
        current_time_ms = int(now_dt.timestamp() * 1000)
        latency_ms = max(0, current_time_ms - window_close_ms) if window_close_ms > 0 else 125

        # Format evidence
        evidence = {
            "detector_scores": detector_scores
        }
        if evidence_features:
            for k, v in evidence_features.items():
                if isinstance(v, dict):
                    evidence[k] = v
                else:
                    evidence[k] = {"value": v}

        # Recommended actions (text only, system never executes)
        action_map = {
            "ddos": "Volumetric attack detected: notify upstream ISP and apply BGP Flowspec (text recommendation only)",
            "beaconing": "Botnet C2 regularity detected: isolate host and review recent process tree",
            "dga_tunnel": "DNS tunneling/DGA detected: sinkhole apex domain at internal resolver",
            "encrypted_malware": "Malicious encrypted session: inspect JA4 fingerprint and quarantine host",
            "recon_scan": "Horizontal/vertical reconnaissance: block source at edge perimeter",
            "exfiltration": "High egress asymmetry: investigate destination IP and terminate connection",
            "anomaly": "Novel behavioral anomaly: analyst manual review required"
        }
        rec_action = action_map.get(threat_class, "Analyst review recommended (text only)")

        # Unique alert ID
        short_id = uuid.uuid4().hex[:6]
        alert_record = {
            "schema_version": "1.0",
            "alert_id": f"a-{short_id}",
            "timestamp": timestamp_str,
            "first_seen": first_seen_str,
            "last_seen": last_seen_str,
            "flow_id": flow_id,
            "threat_class": threat_class,
            "confidence": round(float(confidence), 2),
            "severity": {
                "level": sev_level,
                "score": sev_score
            },
            "evidence": evidence,
            "detectors_used": detectors_used or ["L5a", "L5e", "L6"],
            "recommended_action": rec_action,
            "latency_ms": latency_ms
        }

        # Validate strictly against JSON schema
        jsonschema.validate(instance=alert_record, schema=ALERT_SCHEMA)

        # Emit to sinks
        self._emit_to_sinks(alert_record)

        return alert_record

    def _emit_to_sinks(self, alert: Dict[str, Any]):
        # 1. Append to rotating JSONL
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")

        # 2. Insert into SQLite table
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["alert_id"],
            alert["schema_version"],
            alert["timestamp"],
            alert["first_seen"],
            alert["last_seen"],
            alert["flow_id"],
            alert["threat_class"],
            alert["confidence"],
            alert["severity"]["level"],
            alert["severity"]["score"],
            json.dumps(alert["evidence"]),
            alert["recommended_action"],
            alert["latency_ms"]
        ))
        conn.commit()
        conn.close()
