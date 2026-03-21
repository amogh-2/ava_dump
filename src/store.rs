use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub start_time: f64,
    pub end_time: f64,
    
    pub fwd_packets: u64,
    pub bwd_packets: u64,
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    
    pub min_packet_size: u64,
    pub max_packet_size: u64,
    pub total_packet_size: u64,
    pub sum_sq_packet_size: f64,
    
    pub total_fwd_packet_size: u64,
    pub total_bwd_packet_size: u64,
    pub max_fwd_packet_size: u64,
    pub min_bwd_packet_size: u64,
    
    pub syn_count: u64,
    pub ack_count: u64,
    pub fin_count: u64,
    pub rst_count: u64,
    
    pub fwd_iat_total: f64,
    pub bwd_iat_total: f64,
    pub flow_iat_total: f64,
    pub flow_iat_sum_sq: f64,

    pub active_time_total: f64,
    pub active_count: u64,
    pub idle_time_total: f64,
    pub idle_count: u64,

    pub last_fwd_time: f64,
    pub last_bwd_time: f64,
    pub last_flow_time: f64,
    pub current_active_start: f64,
}

impl Default for FlowFeatures {
    fn default() -> Self {
        Self {
            start_time: 0.0,
            end_time: 0.0,
            fwd_packets: 0,
            bwd_packets: 0,
            fwd_bytes: 0,
            bwd_bytes: 0,
            min_packet_size: u64::MAX,
            max_packet_size: 0,
            total_packet_size: 0,
            sum_sq_packet_size: 0.0,
            
            total_fwd_packet_size: 0,
            total_bwd_packet_size: 0,
            max_fwd_packet_size: 0,
            min_bwd_packet_size: u64::MAX,
            
            syn_count: 0,
            ack_count: 0,
            fin_count: 0,
            rst_count: 0,
            
            fwd_iat_total: 0.0,
            bwd_iat_total: 0.0,
            flow_iat_total: 0.0,
            flow_iat_sum_sq: 0.0,
            
            active_time_total: 0.0,
            active_count: 0,
            idle_time_total: 0.0,
            idle_count: 0,
            
            last_fwd_time: 0.0,
            last_bwd_time: 0.0,
            last_flow_time: 0.0,
            current_active_start: 0.0,
        }
    }
}
