# Forensic Detection of Encrypted Data Exfiltration Attacks

A Python-based cybersecurity research prototype for detecting covert data
exfiltration over encrypted network channels **without decrypting payloads**.

The system analyses PCAP files (or synthetic traffic) using flow metadata,
statistical features, Shannon entropy, rule-based heuristics, and machine
learning to surface suspicious behaviour that conventional signature-based
tools miss entirely.

---

## Table of Contents

1. [Background](#background)
2. [System Architecture](#system-architecture)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Module Reference](#module-reference)
7. [Detection Methodology](#detection-methodology)
8. [Attack Profiles Simulated](#attack-profiles-simulated)
9. [Output Artifacts](#output-artifacts)
10. [Extending the System](#extending-the-system)
11. [Academic Context](#academic-context)

---

## Background

Modern threat actors exfiltrate data over encrypted channels (TLS/HTTPS, DNS-
over-HTTPS, QUIC) to evade deep packet inspection.  Classical signature-based
NIDS are blind to payload content once traffic is encrypted.

This system takes a **traffic-behaviour** approach:

* Encrypted payloads have near-maximum Shannon entropy (~7.9 bits/byte).
* Exfiltration flows have anomalous volume, duration, or rate characteristics.
* DNS tunnelling produces unusually many small queries with high entropy labels.
* Slow-and-low exfil has very long durations combined with low packet rates.

---

## System Architecture

```
PCAP File
    │
    ▼
┌──────────────────┐
│  1. PCAP Parser  │  scapy streaming reader → PacketRecord objects
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  2. Flow Builder │  5-tuple aggregation → Flow objects
└────────┬─────────┘
         │
         ▼
┌────────────────────────┐
│  3. Feature Extractor  │  18 numerical features per flow
│  4. Entropy Analyzer   │  Shannon entropy of payload bytes
└────────┬───────────────┘
         │
         ▼
┌───────────────────────────┐
│  5. Dataset Construction  │  pandas DataFrame
└────────┬──────────────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐  ┌──────────────────┐
│Heurist.│  │ ML Detector      │
│Detector│  │ RandomForest     │
│Rules   │  │ IsolationForest  │
└────┬───┘  └────────┬─────────┘
     │               │
     └───────┬───────┘
             │
             ▼
┌────────────────────────┐
│  9. Forensic Artifacts │  JSON, CSV, suspicious flow log, summary
└────────────────────────┘
             │
             ▼
┌────────────────────┐
│  10. Visualisation │  entropy dist., scatter, timeline, feat. importance
└────────────────────┘
```

---

## Project Structure

```
exfiltration_detector/
├── detect_exfiltration.py   ← Main entry-point (CLI)
├── pcap_parser.py           ← Stage 1: PCAP parsing
├── flow_builder.py          ← Stage 2: Packet → flow aggregation
├── feature_extractor.py     ← Stage 3/5: Feature extraction & DataFrame
├── entropy_analyzer.py      ← Stage 4: Shannon entropy utilities
├── heuristic_detector.py    ← Stage 6: Rule-based risk scoring
├── ml_detector.py           ← Stage 7: RandomForest + IsolationForest
├── attack_simulator.py      ← Stage 8: Synthetic attack data generator
├── forensic_writer.py       ← Stage 9: JSON/CSV/log artifact writer
├── visualization.py         ← Stage 10: matplotlib chart generation
├── utils.py                 ← Shared helpers (logger, dirs, …)
├── train_model.py           ← Standalone model training script
├── test_pipeline.py         ← Integration tests (no PCAP required)
├── requirements.txt
├── README.md
├── models/
│   ├── rf_model.pkl         ← Trained RandomForestClassifier
│   ├── if_model.pkl         ← Trained IsolationForest
│   └── scaler.pkl           ← StandardScaler
├── data/
│   └── sample_dataset.csv   ← Generated training dataset
└── output/                  ← All detection run outputs
```

---

## Installation

```bash
# 1. Clone / download the project
git clone <repo-url>
cd exfiltration_detector

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Linux/macOS) scapy may require libpcap
sudo apt install libpcap-dev     # Debian/Ubuntu
brew install libpcap             # macOS
```

---

## Quick Start

### Analyse a PCAP file
```bash
python detect_exfiltration.py --pcap traffic.pcap --output results/
```

### Demo without a PCAP (synthetic data)
```bash
python detect_exfiltration.py --synthetic --output results/
```

### Train models from a dataset
```bash
# Generate dataset then train
python train_model.py --generate

# Or train from existing CSV
python train_model.py --dataset data/sample_dataset.csv --evaluate
```

### Generate a labelled training dataset
```bash
python detect_exfiltration.py --generate-dataset data/my_dataset.csv
```

### Run integration tests
```bash
python test_pipeline.py
```

---

## Module Reference

### `pcap_parser.py`
Uses scapy's streaming `PcapReader` (memory-efficient for large files).
Yields `PacketRecord` dataclasses containing timestamp, IPs, ports,
protocol number, length, and raw payload bytes.

### `flow_builder.py`
Groups packets by their normalised 5-tuple
`(src_ip, dst_ip, src_port, dst_port, protocol)`.
Bidirectional flows are merged (smaller IP/port pair becomes "src").
Tracks packet sizes and inter-arrival times for statistical features.

### `feature_extractor.py`
Extracts 18 numerical features per flow:

| Feature | Description |
|---|---|
| packet_count | Total packets in flow |
| total_bytes | Total bytes transferred |
| flow_duration | End − start time (seconds) |
| packet_rate | Packets per second |
| byte_rate | Bytes per second |
| avg_pkt_size | Mean packet length |
| std_pkt_size | Std-dev of packet lengths |
| min/max_pkt_size | Range of packet sizes |
| avg_iat | Mean inter-arrival time |
| std_iat | Std-dev of inter-arrival times |
| burstiness | CV of IAT (std/mean) |
| entropy | Shannon entropy of payload |
| is_outbound | 1 if dst_port < 1024 |
| suspicious_port | 1 if port in known-bad list |

### `entropy_analyzer.py`
Implements Shannon entropy `H = −Σ p(x)·log₂(p(x))` over raw payload bytes.
Provides sliding-window entropy for intra-flow analysis.
Classifies entropy as low / medium / high / very_high.

### `heuristic_detector.py`
Seven weighted rules produce a risk score 0–100:

| Rule | Condition | Weight |
|---|---|---|
| high_entropy | entropy ≥ 7.0 | +30 |
| very_high_entropy | entropy ≥ 7.5 | +20 |
| large_transfer | bytes ≥ 1 MB | +25 |
| huge_transfer | bytes ≥ 10 MB | +15 |
| extreme_packet_rate | rate ≥ 2000 pkt/s | +20 |
| high_packet_rate | rate ≥ 500 pkt/s | +10 |
| very_long_duration | duration ≥ 30 min | +20 |
| long_duration | duration ≥ 5 min | +10 |
| high_byte_rate | rate ≥ 500 KB/s | +10 |
| high_burstiness | CV-IAT ≥ 2.0 | +5 |
| suspicious_port | port in watchlist | +10 |

Labels: **Benign** (<30), **Suspicious** (30–59), **Possible Exfiltration** (≥60).

### `ml_detector.py`

**RandomForestClassifier** (supervised):
- 200 trees, max depth 12, balanced class weights.
- Trained on labelled flows (`benign` / `suspicious` / `exfiltration`).
- Outputs per-class probability for confidence scoring.

**IsolationForest** (unsupervised):
- 200 trees, contamination auto-set from training label ratio.
- Flags statistical outliers without any labels at inference time.
- Anomaly score (more negative = more anomalous).

**Combined label logic:**
- RF predicts `exfiltration` → "Possible Exfiltration"
- RF predicts `suspicious` OR IF flags anomaly → "Suspicious"
- Otherwise → "Benign"

### `attack_simulator.py`
Generates four synthetic attack profiles plus benign traffic:

| Profile | Ports | Key Signal |
|---|---|---|
| dns_tunneling | UDP/53 | Many small flows, very high entropy |
| https_upload | TCP/443 | Large flows, high byte-rate |
| covert_high_entropy | unusual ports | Max entropy, moderate size |
| slow_exfil | TCP/443 | Very long duration, low rate |

### `forensic_writer.py`
Writes four artifact types to the output directory:
- `flows_<ts>.csv` — all flows with all features and labels
- `report_<ts>.json` — full machine-readable JSON report
- `suspicious_flows_<ts>.txt` — human-readable log of flagged flows
- `summary_<ts>.json` — high-level statistics

### `visualization.py`
Six matplotlib charts (saved as PNG):
1. Entropy distribution histogram (colour-coded by label)
2. Flow size distribution (log scale)
3. Anomaly scatter: entropy vs byte rate
4. Suspicious flow timeline
5. RandomForest feature importances
6. Confusion matrix heatmap

---

## Detection Methodology

### Why entropy works
AES-CTR / AES-GCM ciphertext is statistically indistinguishable from random
bytes, producing Shannon entropy close to the theoretical maximum of 8 bits/byte.
Plaintext HTTP, DNS, or SMTP flows typically have entropy in the 3–6 range due
to structured headers and ASCII content.

### Why flow statistics work
Exfiltration flows have characteristic volume and timing:
- **Bulk upload** → unusually large `total_bytes` and high `byte_rate`.
- **DNS tunnelling** → many short-lived flows, abnormal `packet_count` for port 53.
- **Slow exfil** → extreme `flow_duration` with low `packet_rate`.
- **Beaconing** → periodic inter-arrival times → low `burstiness`.

---

## Attack Profiles Simulated

| Profile | MITRE ATT&CK |
|---|---|
| DNS tunnelling | T1048.001 Exfiltration Over Alternative Protocol |
| HTTPS data upload | T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| Covert high-entropy | T1573 Encrypted Channel |
| Slow-and-low | T1029 Scheduled Transfer |

---

## Output Artifacts

After a detection run, `output/` will contain:

```
output/
├── flows_20240315T120000Z.csv          ← All flows
├── report_20240315T120000Z.json        ← Full JSON report
├── suspicious_flows_20240315T120000Z.txt ← Human-readable log
├── summary_20240315T120000Z.json       ← Statistics
├── entropy_distribution_*.png
├── flow_size_distribution_*.png
├── anomaly_scatter_*.png
├── suspicious_timeline_*.png
├── feature_importance_*.png
└── detect.log
```

---

## Extending the System

- **New rules**: Add a scoring block in `heuristic_detector.py → score_flow()`.
- **New features**: Extend `feature_extractor.py → extract_features()` and add the column name to `FEATURE_COLUMNS`.
- **New attack profiles**: Add a generator function in `attack_simulator.py` following the existing pattern.
- **Real-time capture**: Replace `pcap_parser.py` with a scapy `sniff()` loop and push packets to a shared queue consumed by `flow_builder`.

---

## Academic Context

This project addresses MITRE ATT&CK Tactic **TA0010 Exfiltration** and
demonstrates techniques from the following research areas:

- Network traffic classification (Nguyen & Armitage, 2008)
- Anomaly-based IDS (Chandola et al., 2009)
- Entropy-based encrypted traffic analysis (Bro/Zeek community, 2017)
- Isolation Forest for network anomaly detection (Liu et al., 2008)

**Ethical note**: This tool is intended solely for defensive research,
blue-team operations, and educational purposes. Ensure you have written
authorisation before analysing any production network traffic.
