mod config;
mod features;
mod flow;
mod output;
mod parser;
mod reader;
mod selector;
mod store;

use std::collections::HashMap;
use std::env;
use std::path::Path;

use config::DatasetConfig;
use output::JsonFlowOutput;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: avadump <input_file.(pcap|csv)> <config.json> <output.json>");
        std::process::exit(1);
    }

    let input_path = &args[1];
    let config_path = &args[2];
    let output_path = &args[3];

    let config = DatasetConfig::load(config_path).expect("Failed to load config");

    if is_csv_input(input_path) {
        process_csv(input_path, &config, output_path).expect("Failed to process CSV input");
    } else {
        process_pcap(input_path, &config, output_path).expect("Failed to process PCAP input");
    }
}

fn is_csv_input(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("csv"))
        .unwrap_or(false)
}

fn process_csv(
    path: &str,
    config: &DatasetConfig,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut csv_reader = csv::Reader::from_path(path)?;
    let headers = csv_reader.headers()?.clone();
    let header_index = build_header_index(&headers);
    let mut exported = Vec::new();

    println!("CSV loaded. Extracting configured features...");

    for (row_idx, row) in csv_reader.records().enumerate() {
        let record = row?;
        let selected = select_csv_features(&record, &header_index, config);
        let flow_id = csv_flow_id(&record, &header_index, row_idx);

        exported.push(JsonFlowOutput {
            flow_id,
            features: selected,
        });
    }

    write_json_output(output_path, &exported)?;
    println!(
        "Exported {} rows with {} features each to {}",
        exported.len(),
        config.features.len(),
        output_path
    );

    Ok(())
}

fn build_header_index(headers: &csv::StringRecord) -> HashMap<String, usize> {
    headers
        .iter()
        .enumerate()
        .map(|(idx, header)| (header.trim().to_ascii_lowercase(), idx))
        .collect()
}

fn csv_flow_id(record: &csv::StringRecord, header_index: &HashMap<String, usize>, row_idx: usize) -> String {
    for key in ["flow_id", "flow id"] {
        if let Some(idx) = header_index.get(key) {
            if let Some(val) = record.get(*idx) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    format!("csv_row_{}", row_idx + 1)
}

fn select_csv_features(
    record: &csv::StringRecord,
    header_index: &HashMap<String, usize>,
    config: &DatasetConfig,
) -> Vec<f64> {
    let mut out = Vec::with_capacity(config.features.len());

    for feature in &config.features {
        let value = feature_aliases(feature)
            .iter()
            .find_map(|alias| header_index.get(alias.as_str()).and_then(|idx| record.get(*idx)))
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .unwrap_or(0.0);

        out.push(value);
    }

    out
}

fn feature_aliases(feature: &str) -> Vec<String> {
    let normalized = feature.trim().to_ascii_lowercase();
    let aliases = match normalized.as_str() {
        "total fwd packets" => vec!["fwd_packets"],
        "total backward packets" => vec!["bwd_packets"],
        "total length of fwd packets" => vec!["fwd_bytes"],
        "total length of bwd packets" => vec!["bwd_bytes"],
        "flow bytes/s" => vec!["bytes_per_second"],
        "flow packets/s" => vec!["packets_per_second"],
        "fin flag count" => vec!["fin_count"],
        "syn flag count" => vec!["syn_count"],
        "ack flag count" => vec!["ack_count"],
        _ => Vec::new(),
    };

    let mut all = Vec::with_capacity(2 + aliases.len());
    all.push(normalized);
    all.extend(aliases.into_iter().map(str::to_string));
    all
}

fn process_pcap(
    path: &str,
    config: &DatasetConfig,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = flow::FlowEngine::new();
    let mut reader = reader::PcapFileReader::new(path)?;

    println!("Parsing packets and building flows...");
    while let Some(res) = reader.next_packet() {
        let (ts, data) = res?;
        if let Some((key, info)) = parser::parse_packet(&data, ts) {
            engine.process_packet(key, info);
        }
    }

    let flows = engine.into_flows();
    println!("Flows built. Extracting configured features...");
    let mut exported = Vec::with_capacity(flows.len());

    for (key, features) in flows {
        let selected = selector::select_features(&features, config);
        exported.push(JsonFlowOutput {
            flow_id: output::format_flow_key(&key),
            features: selected,
        });
    }

    write_json_output(output_path, &exported)?;
    println!(
        "Exported {} flows with {} features each to {}",
        exported.len(),
        config.features.len(),
        output_path
    );

    Ok(())
}

fn write_json_output(
    output_path: &str,
    records: &[JsonFlowOutput],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::fs::File::create(output_path)?;
    serde_json::to_writer_pretty(output, records)?;
    Ok(())
}
