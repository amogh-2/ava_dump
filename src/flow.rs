use std::collections::HashMap;
use crate::store::{FlowKey, FlowFeatures};
use crate::features::{update_features, PacketInfo};

pub struct FlowEngine {
    flows: HashMap<FlowKey, FlowFeatures>,
}

impl FlowEngine {
    pub fn new() -> Self {
        Self { flows: HashMap::new() }
    }
    
    pub fn process_packet(&mut self, key: FlowKey, packet: PacketInfo) {
        let mut is_fwd = true;
        let mut actual_key = key.clone();
        
        let rev_key = FlowKey {
            src_ip: key.dst_ip,
            dst_ip: key.src_ip,
            src_port: key.dst_port,
            dst_port: key.src_port,
            protocol: key.protocol,
        };
        
        if self.flows.contains_key(&rev_key) && !self.flows.contains_key(&key) {
            is_fwd = false;
            actual_key = rev_key;
        }
        
        let entry = self.flows.entry(actual_key).or_default();
        let mut packet_info = packet;
        packet_info.is_fwd = is_fwd;
        
        update_features(entry, &packet_info);
    }
    
    pub fn into_flows(self) -> HashMap<FlowKey, FlowFeatures> {
        self.flows
    }
}
