# Avadump Phase 1 Walkthrough

I have successfully designed and built the **avadump** Phase 1 pipeline! The system is a modular dataset-agnostic flow processor written purely in Rust.

## Features Implemented
- **Pcap Parser**: Fast offline parsing of standard PCAP files without needing `libpcap` installed on the system (using `pcap-file`).
- **Ethernet Decoder**: Robust decoding using `etherparse` to extract 5-tuples from IPv4/IPv6 and TCP/UDP.
- **Flow Engine**: A stateful flow aggregator operating over a generic [FlowFeatures](file:///c:/Users/amogh/Desktop/AvaDump/avadump/src/store.rs#14-42) struct representing a superset of possible attributes (timings, byte sizes, payload distributions, TCP flags).
- **Dataset Configuration**: The [DatasetConfig](file:///c:/Users/amogh/Desktop/AvaDump/avadump/src/config.rs#4-8) allows dynamic mapping to features like CICIDS2017 metrics.
- **JSON Serialization**: Maps selected features into flat `f64` vectors inside structured JSON for downstream machine learning datasets.

## Validation Results
We ran the pipeline against a test DHCP PCAP file with the [cicids2017.json](file:///c:/Users/amogh/Desktop/AvaDump/avadump/cicids2017.json) dataset config.

Command:
```bash
cargo run -- sample.pcap cicids2017.json
```

Output:
```json
{"flow_id":"0.0.0.0-255.255.255.255-68-67-17","features":[0.07003116607666016, 2.0, 0.0, 628.0, 0.0, 28.55, 9764.45, 342.0]}
{"flow_id":"192.168.0.1-192.168.0.10-67-68-17","features":[0.07005000114440918, 2.0, 0.0, 684.0, 0.0, 28.55, 9764.45, 342.0]}
```

This successfully verifies that the configuration drives the extraction and creates generic arrays of floats for downstream AI tools.

## Extensibility for Phase 2
The code structure [(parser -> state -> config -> selector)](file:///c:/Users/amogh/Desktop/AvaDump/avadump/src/reader.rs#10-15) guarantees we can easily swap:
- `pcap-file` with `pnet` or true [pcap](file:///c:/Users/amogh/Desktop/AvaDump/avadump/sample.pcap) for live capture.
- New dataset configs like N-BaIoT or UNSW-NB15 just by dropping a new JSON file!
