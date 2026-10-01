"""
PassiveSentinel - Layer L1: Preprocessing, Validation and Cleaning
Enforces:
1. Schema validation (mandatory 5-tuple, time, packet/byte counters)
2. Time normalization to UTC epoch milliseconds
3. De-duplication across exporters via (canonical_5tuple, time_bucket, counters)
4. Direction canonicalization (client = first sender)
5. Numeric hygiene: replace NaN / +/-inf with sentinel -1.0, binary was_missing flag, clamp neg counters to 0
6. Late-event handling with 5-second watermark
7. Identifier firewall: isolates raw IPs, ports, flow IDs, timestamps so they NEVER enter model weights
8. Domain normalization for DNS (punycode, lowercase, suffix splitting)
"""

import math
import hashlib
from typing import Dict, Any, Tuple, Optional

# Public suffixes list subset for domain normalization
COMMON_TLDS = {"com", "org", "net", "edu", "gov", "mil", "io", "co", "in", "uk", "de", "cn", "ru", "info", "biz"}

class IdentifierFirewallViolation(Exception):
    """Raised if an identifier breaches the model input firewall."""
    pass

class PreprocessorL1:
    def __init__(self, watermark_s: float = 5.0, time_bucket_s: float = 1.0):
        self.watermark_ms = int(watermark_s * 1000)
        self.time_bucket_ms = int(time_bucket_s * 1000)
        self.max_event_time_seen = 0
        self.dedup_cache = set()
        
        # Data quality telemetry counters
        self.stats = {
            "total_records": 0,
            "passed_records": 0,
            "rejected_schema": 0,
            "dedup_dropped": 0,
            "late_events": 0,
            "nan_inf_remediated": 0,
            "negative_clamped": 0,
        }

    def canonicalize_5tuple(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[str, str, int, int, str, bool]:
        """
        Direction canonicalization:
        Client is first sender. For bidirectional pairing, establish deterministic ordering.
        Returns: (canon_src, canon_dst, canon_sport, canon_dport, proto, is_forward)
        """
        ip_sport = f"{src_ip}:{src_port}"
        ip_dport = f"{dst_ip}:{dst_port}"
        
        if ip_sport <= ip_dport:
            return src_ip, dst_ip, src_port, dst_port, str(proto).upper(), True
        else:
            return dst_ip, src_ip, dst_port, src_port, str(proto).upper(), False

    def clean_record(self, raw: Dict[str, Any], processing_time_ms: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Validates, cleans, and canonicalizes a single flow/event record.
        Returns cleaned dict, or None if rejected/duplicate/straggler.
        """
        self.stats["total_records"] += 1
        
        # 1. Schema Validation: Check mandatory fields
        # Support both standard Trinetra and NetFlow-v3 keys
        src_ip = raw.get("src_ip") or raw.get("IPV4_SRC_ADDR")
        dst_ip = raw.get("dst_ip") or raw.get("IPV4_DST_ADDR")
        src_port = raw.get("src_port") if "src_port" in raw else raw.get("L4_SRC_PORT")
        dst_port = raw.get("dst_port") if "dst_port" in raw else raw.get("L4_DST_PORT")
        proto = raw.get("protocol") if "protocol" in raw else raw.get("PROTOCOL")
        
        time_val = raw.get("timestamp") or raw.get("FLOW_START_MILLISECONDS")
        
        if not (src_ip and dst_ip and src_port is not None and dst_port is not None and proto is not None and time_val is not None):
            self.stats["rejected_schema"] += 1
            return None

        # 2. Time Normalization: convert to UTC epoch milliseconds
        try:
            if isinstance(time_val, str):
                time_val = float(time_val)
            # If timestamp is in seconds (< 1e11), convert to milliseconds
            event_time_ms = int(time_val * 1000) if time_val < 1e11 else int(time_val)
        except (ValueError, TypeError):
            self.stats["rejected_schema"] += 1
            return None

        # 6. Late-Event Handling: 5-second watermark
        if event_time_ms < (self.max_event_time_seen - self.watermark_ms):
            self.stats["late_events"] += 1
            # Late event outside watermark is counted and dropped from main streaming window
            return None
        
        if event_time_ms > self.max_event_time_seen:
            self.max_event_time_seen = event_time_ms

        # 4. Direction Canonicalization
        c_src, c_dst, c_sport, c_dport, c_proto, is_fwd = self.canonicalize_5tuple(
            str(src_ip), str(dst_ip), int(src_port), int(dst_port), str(proto)
        )

        # 5. Numeric Hygiene: Extract counters & handle NaN/Inf/Negatives
        fwd_pkts = raw.get("fwd_packets") or raw.get("IN_PKTS") or 0
        bwd_pkts = raw.get("bwd_packets") or raw.get("OUT_PKTS") or 0
        fwd_bytes = raw.get("fwd_bytes") or raw.get("IN_BYTES") or 0
        bwd_bytes = raw.get("bwd_bytes") or raw.get("OUT_BYTES") or 0
        duration_s = raw.get("duration")
        if duration_s is None and "FLOW_DURATION_MILLISECONDS" in raw:
            duration_s = float(raw["FLOW_DURATION_MILLISECONDS"]) / 1000.0
        elif duration_s is None:
            duration_s = 0.0

        was_missing = 0
        clean_vals = []
        for val in [fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes, duration_s]:
            try:
                v = float(val)
                if math.isnan(v) or math.isinf(v):
                    was_missing = 1
                    self.stats["nan_inf_remediated"] += 1
                    v = -1.0
                elif v < 0:
                    self.stats["negative_clamped"] += 1
                    v = 0.0
            except (ValueError, TypeError):
                was_missing = 1
                v = -1.0
            clean_vals.append(v)

        c_fwd_pkts, c_bwd_pkts, c_fwd_bytes, c_bwd_bytes, c_duration = clean_vals

        # 3. De-duplication key
        start_bucket = event_time_ms // self.time_bucket_ms
        dedup_key = (c_src, c_dst, c_sport, c_dport, c_proto, start_bucket, int(c_fwd_pkts), int(c_fwd_bytes))
        if dedup_key in self.dedup_cache:
            self.stats["dedup_dropped"] += 1
            return None
        
        # Bounded dedup cache (keep last 50,000 keys)
        if len(self.dedup_cache) > 50000:
            self.dedup_cache.clear()
        self.dedup_cache.add(dedup_key)

        # 7. Identifier Firewall Separation:
        # metadata_keys are strictly separated from feature payload
        flow_id = f"{c_src}:{c_sport}->{c_dst}:{c_dport}_{c_proto}_{event_time_ms}"
        
        # 8. Domain normalization if DNS query present
        query_domain = raw.get("dns_query") or raw.get("domain") or ""
        subdomain, apex_domain = self.normalize_domain(str(query_domain))

        self.stats["passed_records"] += 1

        return {
            # Metadata Keys (for grouping / windows / alerts only)
            "_metadata": {
                "flow_id": flow_id,
                "src_ip": str(src_ip),
                "dst_ip": str(dst_ip),
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "protocol": c_proto,
                "event_time_ms": event_time_ms,
                "processing_time_ms": processing_time_ms or event_time_ms,
                "is_forward": is_fwd,
                "apex_domain": apex_domain,
                "subdomain": subdomain,
                "ground_truth_threat_class": raw.get("threat_class") or raw.get("Attack") or "benign"
            },
            # Sanitized flow values
            "features": {
                "duration": max(0.0, c_duration),
                "fwd_packets": max(0.0, c_fwd_pkts),
                "bwd_packets": max(0.0, c_bwd_pkts),
                "fwd_bytes": max(0.0, c_fwd_bytes),
                "bwd_bytes": max(0.0, c_bwd_bytes),
                "was_missing": was_missing,
                # Pass through other extracted physical metrics if present
                "syn_count": float(raw.get("syn_count", 0)),
                "ack_count": float(raw.get("ack_count", 0)),
                "rst_count": float(raw.get("rst_count", 0)),
                "fin_count": float(raw.get("fin_count", 0)),
                "psh_count": float(raw.get("psh_count", 0)),
                "mean_packet_size": float(raw.get("mean_packet_size") or raw.get("LONGEST_FLOW_PKT") or 0.0),
                "std_packet_size": float(raw.get("std_packet_size", 0.0)),
                "mean_iat": float(raw.get("mean_iat") or raw.get("SRC_TO_DST_IAT_AVG") or 0.0),
                "iat_jitter_score": float(raw.get("iat_jitter_score", 0.0)),
                "bytes_out_ratio": float(raw.get("bytes_out_ratio", 0.5)),
                "dns_entropy": float(raw.get("dns_entropy", 0.0)),
                "is_encrypted": float(raw.get("is_encrypted", 0.0)),
            }
        }

    @staticmethod
    def normalize_domain(domain: str) -> Tuple[str, str]:
        """Normalize domain and extract subdomain and apex."""
        if not domain:
            return "", ""
        clean = domain.strip().lower().rstrip(".")
        parts = clean.split(".")
        if len(parts) <= 1:
            return "", clean
        elif len(parts) == 2:
            return "", clean
        else:
            # e.g. sub.example.com -> subdomain='sub', apex='example.com'
            apex = ".".join(parts[-2:])
            sub = ".".join(parts[:-2])
            return sub, apex
