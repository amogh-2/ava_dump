use crate::store::FlowFeatures;

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: f64,
    pub length: u64,
    pub is_fwd: bool,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

pub fn update_features(features: &mut FlowFeatures, packet: &PacketInfo) {
    if features.fwd_packets == 0 && features.bwd_packets == 0 {
        features.start_time = packet.timestamp;
        features.last_flow_time = packet.timestamp;
        features.current_active_start = packet.timestamp;
        features.min_packet_size = packet.length;
        features.max_packet_size = packet.length;
    }
    
    features.end_time = packet.timestamp;
    
    features.min_packet_size = features.min_packet_size.min(packet.length);
    features.max_packet_size = features.max_packet_size.max(packet.length);
    features.total_packet_size += packet.length;
    features.sum_sq_packet_size += packet.length as f64 * packet.length as f64;
    
    if packet.syn { features.syn_count += 1; }
    if packet.ack { features.ack_count += 1; }
    if packet.fin { features.fin_count += 1; }
    if packet.rst { features.rst_count += 1; }
    
    let flow_iat = packet.timestamp - features.last_flow_time;
    
    if features.fwd_packets + features.bwd_packets > 0 && flow_iat > 5.0 {
        features.idle_time_total += flow_iat;
        features.idle_count += 1;
        
        let active_time = features.last_flow_time - features.current_active_start;
        features.active_time_total += active_time;
        features.active_count += 1;
        
        features.current_active_start = packet.timestamp;
    }
    
    if features.fwd_packets + features.bwd_packets > 0 {
        features.flow_iat_total += flow_iat;
        features.flow_iat_sum_sq += flow_iat * flow_iat;
    }
    
    features.last_flow_time = packet.timestamp;
    
    if packet.is_fwd {
        features.max_fwd_packet_size = features.max_fwd_packet_size.max(packet.length);
        features.total_fwd_packet_size += packet.length;
        features.fwd_packets += 1;
        features.fwd_bytes += packet.length;
        if features.fwd_packets > 1 {
            let iat = packet.timestamp - features.last_fwd_time;
            features.fwd_iat_total += iat;
        }
        features.last_fwd_time = packet.timestamp;
    } else {
        features.min_bwd_packet_size = features.min_bwd_packet_size.min(packet.length);
        features.total_bwd_packet_size += packet.length;
        features.bwd_packets += 1;
        features.bwd_bytes += packet.length;
        if features.bwd_packets > 1 {
            let iat = packet.timestamp - features.last_bwd_time;
            features.bwd_iat_total += iat;
        }
        features.last_bwd_time = packet.timestamp;
    }
}
