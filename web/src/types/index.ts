export interface FlowRecord {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  flow_duration: number;
  tot_fwd_pkts: number;
  tot_bwd_pkts: number;
  totlen_fwd_pkts: number;
  totlen_bwd_pkts: number;
  pkt_len_mean: number;
  pkt_len_std: number;
  flow_iat_mean: number;
  fwd_iat_std: number;
  syn_flag_cnt: number;
  ack_flag_cnt: number;
  down_up_ratio: number;
  init_fwd_win_byts: number;
}

export interface DetectionResult {
  alert_id: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';
  threat_type: string;
  attack_category: string;
  ensemble_confidence: number;
  latency_ms: number;
  flow: {
    tuple: string;
    protocol: string;
    duration_ms: number;
    byte_count: number;
    packet_count: number;
  };
  pipeline_trace: {
    l0_ingest: string;
    l1_normalized: boolean;
    l2_preprocessed: boolean;
    l3_feature_count: number;
    l4_detector_scores: {
      rf_gradient: number;
      xgboost_fast: number;
      lightgbm_deep: number;
      isolation_forest: number;
    };
    l5_fusion_meta_learner: number;
    l6_threshold_eval: string;
    l7_dispatch_status: string;
  };
  mitre_att_ck: {
    tactic: string;
    technique_id: string;
    technique_name: string;
  };
  remediation_advice: string[];
}

export interface BenchmarkData {
  metric: string;
  passivesentinel: string;
  suricata: string;
  zeek: string;
  snort3: string;
  advantage: string;
}
