use serde::Serialize;
use crate::store::FlowKey;

#[derive(Debug, Serialize)]
pub struct JsonFlowOutput {
    pub flow_id: String,
    pub features: Vec<f64>,
}

pub fn format_flow_key(key: &FlowKey) -> String {
    format!("{}-{}-{}-{}-{}", key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol)
}
