import { DetectionResult } from '../types';

export interface ThreatPreset {
  id: string;
  name: string;
  category: string;
  description: string;
  flowPayload: Record<string, any>;
  result: DetectionResult;
}

export const THREAT_PRESETS: ThreatPreset[] = [
  {
    id: 'ddos-syn',
    name: 'DDoS SYN Flood Volumetric',
    category: 'Denial of Service',
    description: 'High-rate TCP SYN flood overwhelming receiver queue with spoofed source IPs and asymmetric flow ratios.',
    flowPayload: {
      src_ip: "185.190.141.28",
      dst_ip: "10.0.4.15",
      src_port: 48921,
      dst_port: 80,
      proto: "TCP",
      flow_duration: 12480,
      tot_fwd_pkts: 8420,
      tot_bwd_pkts: 2,
      totlen_fwd_pkts: 454680,
      totlen_bwd_pkts: 80,
      pkt_len_mean: 54.0,
      pkt_len_std: 1.2,
      flow_iat_mean: 1.48,
      fwd_iat_std: 0.12,
      syn_flag_cnt: 8420,
      ack_flag_cnt: 0,
      down_up_ratio: 0.0002,
      init_fwd_win_byts: 1024
    },
    result: {
      alert_id: "ps-alrt-7f9a2e-ddos",
      timestamp: new Date().toISOString(),
      severity: "CRITICAL",
      threat_type: "TCP_SYN_FLOOD_VOLUMETRIC",
      attack_category: "Denial of Service (DoS/DDoS)",
      ensemble_confidence: 0.9984,
      latency_ms: 1.18,
      flow: {
        tuple: "185.190.141.28:48921 -> 10.0.4.15:80 (TCP)",
        protocol: "TCP/6",
        duration_ms: 12.48,
        byte_count: 454760,
        packet_count: 8422
      },
      pipeline_trace: {
        l0_ingest: "Zero-copy NetFlow v9 ring buffer",
        l1_normalized: true,
        l2_preprocessed: true,
        l3_feature_count: 32,
        l4_detector_scores: {
          rf_gradient: 0.994,
          xgboost_fast: 0.998,
          lightgbm_deep: 0.999,
          isolation_forest: 0.985
        },
        l5_fusion_meta_learner: 0.9984,
        l6_threshold_eval: "PASSED (0.9984 > 0.8200 tau_critical)",
        l7_dispatch_status: "EMITTED (SIEM webhook, JSON stdout)"
      },
      mitre_att_ck: {
        tactic: "Impact",
        technique_id: "T1498.001",
        technique_name: "Network Denial of Service: Direct Network Flood"
      },
      remediation_advice: [
        "Trigger BGP flowspec rate-limiting on upstream router for src prefix 185.190.141.0/24",
        "Enable hardware SYN-proxy cookie verification on ingress edge firewall",
        "Isolate target IP 10.0.4.15 VIP behind anycast scrubber"
      ]
    }
  },
  {
    id: 'dns-dga',
    name: 'DNS DGA C2 Tunneling',
    category: 'Command & Control',
    description: 'High entropy DNS query patterns exfiltrating small payload fragments via algorithmically generated subdomains.',
    flowPayload: {
      src_ip: "10.0.12.88",
      dst_ip: "198.51.100.4",
      src_port: 53102,
      dst_port: 53,
      proto: "UDP",
      flow_duration: 350020,
      tot_fwd_pkts: 184,
      tot_bwd_pkts: 184,
      totlen_fwd_pkts: 19872,
      totlen_bwd_pkts: 24288,
      pkt_len_mean: 120.0,
      pkt_len_std: 14.8,
      flow_iat_mean: 1902.2,
      fwd_iat_std: 420.5,
      syn_flag_cnt: 0,
      ack_flag_cnt: 0,
      down_up_ratio: 1.0,
      init_fwd_win_byts: 0
    },
    result: {
      alert_id: "ps-alrt-4c8d19-dga",
      timestamp: new Date().toISOString(),
      severity: "HIGH",
      threat_type: "DNS_DGA_DATA_EXFILTRATION",
      attack_category: "Command and Control / Exfiltration",
      ensemble_confidence: 0.9642,
      latency_ms: 1.42,
      flow: {
        tuple: "10.0.12.88:53102 -> 198.51.100.4:53 (UDP)",
        protocol: "UDP/17",
        duration_ms: 350.02,
        byte_count: 44160,
        packet_count: 368
      },
      pipeline_trace: {
        l0_ingest: "Zero-copy NetFlow v9 ring buffer",
        l1_normalized: true,
        l2_preprocessed: true,
        l3_feature_count: 32,
        l4_detector_scores: {
          rf_gradient: 0.952,
          xgboost_fast: 0.971,
          lightgbm_deep: 0.968,
          isolation_forest: 0.966
        },
        l5_fusion_meta_learner: 0.9642,
        l6_threshold_eval: "PASSED (0.9642 > 0.7500 tau_high)",
        l7_dispatch_status: "EMITTED (SIEM webhook, JSON stdout)"
      },
      mitre_att_ck: {
        tactic: "Command and Control",
        technique_id: "T1071.004",
        technique_name: "Application Layer Protocol: DNS Tunneling"
      },
      remediation_advice: [
        "Sinkhole authoritative nameserver 198.51.100.4 on internal recursive resolvers",
        "Inspect endpoint 10.0.12.88 for malicious scheduled tasks or unapproved daemon binaries",
        "Reset internal host credentials and rotate kerberos krbtgt ticket"
      ]
    }
  },
  {
    id: 'c2-beacon',
    name: 'Encrypted TLS Cobalt C2 Beacon',
    category: 'Persistence / C2',
    description: 'Low-frequency jittered beaconing with high TLS record entropy without SNI or certificate validation headers.',
    flowPayload: {
      src_ip: "10.0.3.42",
      dst_ip: "91.240.118.172",
      src_port: 49811,
      dst_port: 443,
      proto: "TCP",
      flow_duration: 1800000,
      tot_fwd_pkts: 45,
      tot_bwd_pkts: 42,
      totlen_fwd_pkts: 6420,
      totlen_bwd_pkts: 12890,
      pkt_len_mean: 221.9,
      pkt_len_std: 104.2,
      flow_iat_mean: 40000.0,
      fwd_iat_std: 5200.0,
      syn_flag_cnt: 1,
      ack_flag_cnt: 86,
      down_up_ratio: 0.933,
      init_fwd_win_byts: 65535
    },
    result: {
      alert_id: "ps-alrt-91bc44-beacon",
      timestamp: new Date().toISOString(),
      severity: "HIGH",
      threat_type: "COBALT_STRIKE_JITTER_BEACON",
      attack_category: "Command and Control",
      ensemble_confidence: 0.9418,
      latency_ms: 1.25,
      flow: {
        tuple: "10.0.3.42:49811 -> 91.240.118.172:443 (TCP)",
        protocol: "TCP/6",
        duration_ms: 1800.0,
        byte_count: 19310,
        packet_count: 87
      },
      pipeline_trace: {
        l0_ingest: "Zero-copy NetFlow v9 ring buffer",
        l1_normalized: true,
        l2_preprocessed: true,
        l3_feature_count: 32,
        l4_detector_scores: {
          rf_gradient: 0.925,
          xgboost_fast: 0.948,
          lightgbm_deep: 0.952,
          isolation_forest: 0.942
        },
        l5_fusion_meta_learner: 0.9418,
        l6_threshold_eval: "PASSED (0.9418 > 0.7500 tau_high)",
        l7_dispatch_status: "EMITTED (SIEM webhook, JSON stdout)"
      },
      mitre_att_ck: {
        tactic: "Command and Control",
        technique_id: "T1095",
        technique_name: "Non-Application Layer Protocol: Encrypted Channel"
      },
      remediation_advice: [
        "Block egress outbound IP 91.240.118.172 at perimeter firewall",
        "Dump volatile RAM on 10.0.3.42 for in-memory beacon shellcode extraction",
        "Quarantine host from active subnet using EDR network isolation"
      ]
    }
  },
  {
    id: 'benign-web',
    name: 'Normal HTTPS Cloud Traffic',
    category: 'Benign Flow',
    description: 'Standard TLS 1.3 web browsing traffic exhibiting standard packet distribution, typical IAT jitter, and healthy ACK windows.',
    flowPayload: {
      src_ip: "10.0.1.204",
      dst_ip: "142.250.190.46",
      src_port: 52140,
      dst_port: 443,
      proto: "TCP",
      flow_duration: 154200,
      tot_fwd_pkts: 64,
      tot_bwd_pkts: 88,
      totlen_fwd_pkts: 12450,
      totlen_bwd_pkts: 98400,
      pkt_len_mean: 729.2,
      pkt_len_std: 512.4,
      flow_iat_mean: 1014.4,
      fwd_iat_std: 890.1,
      syn_flag_cnt: 1,
      ack_flag_cnt: 151,
      down_up_ratio: 1.375,
      init_fwd_win_byts: 65535
    },
    result: {
      alert_id: "ps-pass-001a4e-benign",
      timestamp: new Date().toISOString(),
      severity: "BENIGN",
      threat_type: "BENIGN_TELEMETRY",
      attack_category: "Normal Flow (Zero Threat)",
      ensemble_confidence: 0.0124,
      latency_ms: 0.94,
      flow: {
        tuple: "10.0.1.204:52140 -> 142.250.190.46:443 (TCP)",
        protocol: "TCP/6",
        duration_ms: 154.2,
        byte_count: 110850,
        packet_count: 152
      },
      pipeline_trace: {
        l0_ingest: "Zero-copy NetFlow v9 ring buffer",
        l1_normalized: true,
        l2_preprocessed: true,
        l3_feature_count: 32,
        l4_detector_scores: {
          rf_gradient: 0.009,
          xgboost_fast: 0.014,
          lightgbm_deep: 0.014,
          isolation_forest: 0.012
        },
        l5_fusion_meta_learner: 0.0124,
        l6_threshold_eval: "FILTERED (0.0124 < 0.5000 tau_low)",
        l7_dispatch_status: "SUPPRESSED (Zero false-positive noise)"
      },
      mitre_att_ck: {
        tactic: "None",
        technique_id: "None",
        technique_name: "Clean Verified Traffic"
      },
      remediation_advice: [
        "No action required. Telemetry conforms to certified benign baselines."
      ]
    }
  }
];
