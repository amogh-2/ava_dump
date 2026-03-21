use crate::config::DatasetConfig;
use crate::store::FlowFeatures;

pub fn select_features(features: &FlowFeatures, config: &DatasetConfig) -> Vec<f64> {
    let mut out = Vec::with_capacity(config.features.len());
    
    for f in &config.features {
        let val = match f.trim() {
            "Flow Duration" => features.end_time - features.start_time,
            "Total Fwd Packets" | "fwd_packets" => features.fwd_packets as f64,
            "Total Backward Packets" | "bwd_packets" => features.bwd_packets as f64,
            "Total Length of Fwd Packets" | "fwd_bytes" => features.fwd_bytes as f64,
            "Total Length of Bwd Packets" | "bwd_bytes" => features.bwd_bytes as f64,
            "Flow Bytes/s" | "bytes_per_second" => {
                let duration = features.end_time - features.start_time;
                let total_bytes = features.fwd_bytes + features.bwd_bytes;
                if duration > 0.0 {
                    total_bytes as f64 / duration
                } else {
                    0.0
                }
            },
            "Flow Packets/s" | "packets_per_second" => {
                let duration = features.end_time - features.start_time;
                let total_pkts = features.fwd_packets + features.bwd_packets;
                if duration > 0.0 {
                    total_pkts as f64 / duration
                } else {
                    0.0
                }
            },
            "FIN Flag Count" | "fin_count" => features.fin_count as f64,
            "SYN Flag Count" | "syn_count" => features.syn_count as f64,
            "ACK Flag Count" | "ack_count" => features.ack_count as f64,
            "Packet Length Mean" | "mean_packet_size" => {
                let total_pkts = features.fwd_packets + features.bwd_packets;
                if total_pkts > 0 {
                    features.total_packet_size as f64 / total_pkts as f64
                } else {
                    0.0
                }
            },
            "Fwd Packet Length Mean" => {
                if features.fwd_packets > 0 {
                    features.total_fwd_packet_size as f64 / features.fwd_packets as f64
                } else {
                    0.0
                }
            },
            "Bwd Packet Length Mean" => {
                if features.bwd_packets > 0 {
                    features.total_bwd_packet_size as f64 / features.bwd_packets as f64
                } else {
                    0.0
                }
            },
            "Fwd Packet Length Max" => features.max_fwd_packet_size as f64,
            "Bwd Packet Length Min" => {
                if features.min_bwd_packet_size == u64::MAX {
                    0.0
                } else {
                    features.min_bwd_packet_size as f64
                }
            },
            "Down/Up Ratio" => {
                if features.fwd_packets > 0 {
                    features.bwd_packets as f64 / features.fwd_packets as f64
                } else {
                    0.0
                }
            },
            "Flow IAT Mean" => {
                let total_pkts = features.fwd_packets + features.bwd_packets;
                if total_pkts > 1 {
                    features.flow_iat_total / (total_pkts as f64 - 1.0)
                } else {
                    0.0
                }
            },
            "Flow IAT Std" => {
                let total_pkts = features.fwd_packets + features.bwd_packets;
                if total_pkts > 1 {
                    let n = (total_pkts - 1) as f64;
                    let mean = features.flow_iat_total / n;
                    let variance = (features.flow_iat_sum_sq / n) - (mean * mean);
                    if variance > 0.0 {
                        variance.sqrt()
                    } else {
                        0.0
                    }
                } else {
                    0.0
                }
            },
            "Active Mean" => {
                let final_burst = features.last_flow_time - features.current_active_start;
                let active_total = features.active_time_total + final_burst;
                let mut count = features.active_count;
                if final_burst > 0.0 { count += 1; }
                
                if count > 0 {
                    active_total / count as f64
                } else {
                    0.0
                }
            },
            "Idle Mean" => {
                if features.idle_count > 0 {
                    features.idle_time_total / features.idle_count as f64
                } else {
                    0.0
                }
            },
            "Subflow Fwd Bytes" => features.fwd_bytes as f64,
            _ => 0.0,
        };
        out.push(val);
    }
    
    out
}
