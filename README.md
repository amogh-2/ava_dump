# Avadump

Avadump is a high-performance, dataset-agnostic network flow processing engine. Written entirely in Rust, it parses raw packet captures (PCAPs), aggregates packets into stateful flows, computes a rich superset of network features natively, and dynamically extracts feature vectors based purely on JSON configuration files.

## Features
- **Dataset Agnostic**: No hardcoded dataset features! All extraction is highly configurable via JSON blueprints.
- **Fast Offline Parsing**: Pure Rust PCAP parser (`pcap-file`).
- **Stateful Flow Tracking**: Reconstructs 5-tuple flows asynchronously, accurately tracking bidirectional bursts, IATs (Inter-Arrival Times), TCP flags, Active/Idle phases, and packet size distributions.

## Extracted Metrics
Avadump supports computing dozens of flow metrics dynamically.
For my project currently it extracts exact equivalents to those found in CICIDS2017:
- **Timings**: Flow Duration, IAT Mean, IAT Std, Active Mean, Idle Mean
- **Volumes**: Total Fwd/Bwd Packets, Total Fwd/Bwd Bytes
- **Rates**: Flow Bytes/s, Flow Packets/s
- **Ratios**: Down/Up Ratio (Bwd Packets / Fwd Packets)
- **Distributions**: Min, Max, and Mean packet sizes (both directionally and aggregated)
- **State Flags**: SYN, ACK, FIN, and RST TCP flag counts

## Usage

### 1. Build the Project
```bash
cargo build --release
```

### 2. Define Dataset Schema Configuration
Define the specific mathematical metrics you want the engine to evaluate. You can add or omit features dynamically without recompiling.
```json
{
  "dataset": "CICIDS2017",
  "features": [
    " Flow Duration",
    " Total Fwd Packets",
    " Flow Bytes/s",
    " SYN Flag Count",
    " Active Mean"
  ]
}
```

### 3. Process PCAP Traces
Execute the pipeline against your network capture.
```bash
cargo run --release -- sample.pcap cicids2017.json > dataset.json
```

---

## Architecture

| Component | Description |
|-----------|-------------|
| **Parser** | Robust binary header decomposition using `etherparse` supporting IPv4/IPv6 & TCP/UDP over Ethernet. |
| **Flow Engine**| Groups packets by identical 5-tuples. Identifies flow directions natively based on initialization heuristics. |
| **Feature Store**| Tracks the complete computational superset of metrics for every flow uniformly using `HashMap` indexing. |
| **Selector** | Transforms the superset struct dynamically mapping configured string IDs to `f64` values. |
