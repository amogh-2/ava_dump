mod config;
mod features;
mod flow;
mod output;
mod parser;
mod reader;
mod selector;
mod store;

use std::env;

use std::process::{Command, Stdio};
use std::io::{Write, BufReader, BufRead};
use std::path::Path;

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
    
    println!("Parsing packets and building flows...");
    while let Some(res) = reader.next_packet() {
        let (ts, data) = res.expect("Failed to read packet");
        if let Some((key, info)) = parser::parse_packet(&data, ts) {
            engine.process_packet(key, info);
        }
    }
    
    println!("Flows built. Starting ML Predictor...");
    let python_exe = if Path::new(".venv\\Scripts\\python.exe").exists() {
        ".venv\\Scripts\\python.exe"
    } else {
        "python"
    };

    let mut child = Command::new(python_exe)
        .arg("ml_model\\predict.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start predictor process");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let stderr = child.stderr.take().expect("Failed to open stderr");
    
    let flows = engine.into_flows();
    println!("Sending {} flows for classification...", flows.len());

    for (key, features) in flows {
        let selected = selector::select_features(&features, &config);
        let out = output::JsonFlowOutput {
            flow_id: output::format_flow_key(&key),
            features: selected,
        };
        let js = serde_json::to_string(&out).unwrap();
        writeln!(stdin, "{}", js).unwrap();
    }
    
    // Close stdin to signal end of data to the Python script
    drop(stdin);
    
    // Read and print classification results from Python
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        if let Ok(l) = line {
            println!("{}", l);
        }
    }

    let status = child.wait().expect("Failed to wait on predictor");
    if !status.success() {
        eprintln!("Predictor process exited with non-zero status: {}", status);
        let err_reader = BufReader::new(stderr);
        for line in err_reader.lines() {
            if let Ok(l) = line {
                eprintln!("PREDICTOR ERR: {}", l);
            }
        }
    }
}
