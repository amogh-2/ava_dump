mod config;
mod features;
mod flow;
mod output;
mod parser;
mod reader;
mod selector;
mod store;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: avadump <pcap_file> <config.json>");
        std::process::exit(1);
    }
    
    let pcap_path = &args[1];
    let config_path = &args[2];
    
    let config = config::DatasetConfig::load(config_path).expect("Failed to load config");
    let mut engine = flow::FlowEngine::new();
    let mut reader = reader::PcapFileReader::new(pcap_path).expect("Failed to open PCAP");
    
    while let Some(res) = reader.next_packet() {
        let (ts, data) = res.expect("Failed to read packet");
        if let Some((key, info)) = parser::parse_packet(&data, ts) {
            engine.process_packet(key, info);
        }
    }
    
    let flows = engine.into_flows();
    for (key, features) in flows {
        let selected = selector::select_features(&features, &config);
        let out = output::JsonFlowOutput {
            flow_id: output::format_flow_key(&key),
            features: selected,
        };
        let js = serde_json::to_string(&out).unwrap();
        println!("{}", js);
    }
}
