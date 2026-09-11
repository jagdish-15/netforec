# NETFOREC — AI-Powered Network Attack Forecasting

> **SIH Problem Statement 26153** — National Technical Research Organisation (NTRO)  
> *Theme: Blockchain & Cybersecurity*

An AI-powered CLI tool that learns network traffic behaviour and forecasts potential cyberattacks **before** compromise is completed. NETFOREC ingests flow-level network traffic data, extracts temporal features, and uses a trained LSTM-based world model to predict the likelihood and type of malicious activity in the near future.

---

## Key Features

- **World Model Architecture** — Trained LSTM that learns network state-transition dynamics `P(S_t+1 | S_t)` from temporal traffic patterns, not a static classifier.
- **7-Class Attack Prediction** — Forecasts: `No_Attack`, `Brute_Force`, `DDoS`, `DoS`, `Botnet`, `Web_Attack`, `Infiltration` with full probability distribution.
- **Temporal Feature Engineering** — Aggregates raw per-flow traffic into 5-minute network-state windows capturing flag distributions, packet timing, byte volumes, and flow dynamics.
- **Risk Assessment** — Automatic risk-level classification (LOW / MEDIUM / HIGH) based on prediction confidence.
- **CLI-First Design** — Clean, scriptable interface with human-readable tables, JSON output, and file export.

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────┐
│                     NETFOREC Pipeline                          │
│                                                               │
│  ┌─────────┐    ┌─────────────┐    ┌──────────┐    ┌───────┐  │
│  │ Raw CSV │───►│  Feature    │───►│ Standard │───►│ LSTM  │  │
│  │ Traffic │    │  Extraction │    │  Scaler  │    │ Model │  │
│  │ (Flows) │    │  (6×16 seq) │    │  (.pkl)  │    │(.pth) │  │
│  └─────────┘    └─────────────┘    └──────────┘    └───┬───┘  │
│                                                        │      │
│                              ┌─────────────────────────┘      │
│                              ▼                                │
│                     ┌────────────────┐                        │
│                     │  7-Class Prob  │                        │
│                     │  Distribution  │──► Risk Level          │
│                     │  + Prediction  │──► CLI / JSON Output   │
│                     └────────────────┘                        │
└───────────────────────────────────────────────────────────────┘
```

**Input:** 30 minutes of continuous flow-level traffic (6 consecutive 5-minute windows).  
**Output:** Probability distribution across 7 attack classes for the next 15-minute window.

---

## Setup Instructions

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/netforec.git
cd netforec

# 2. Install the package and dependencies
pip install -e .
```

This installs the `netforec` command globally in your environment — no PATH configuration needed.

---

## Usage

```bash
# Show help
netforec --help

# Analyze traffic (with bundled demo file)
netforec analyze sample_traffic.csv

# Verbose mode — shows step-by-step pipeline progress
netforec analyze sample_traffic.csv --verbose

# JSON output to stdout
netforec analyze sample_traffic.csv --json

# Save results to a file
netforec analyze sample_traffic.csv --output result.json

# Silent save (no terminal output, useful for scripting)
netforec analyze sample_traffic.csv --output result.json --quiet
```

### Sample Output

```
──────────────── NETFOREC — NETWORK ATTACK FORECAST ────────────────

History analyzed : previous 30 minutes (2024-02-15 14:00:00 -> 2024-02-15 14:25:00)
Forecast horizon : next 15 minutes
Flows processed  : 12,847

Predicted threat : DDOS
Confidence       : 73.21%

            Probability distribution
┌──────────────┬──────────────────────────┐
│ Class        │              Probability │
├──────────────┼──────────────────────────┤
│ DDoS         │ ████████████████  73.21% │
│ DoS          │ ████              12.45% │
│ No_Attack    │ ██                 6.82% │
│ Brute_Force  │ █                  3.91% │
│ Botnet       │ █                  1.87% │
│ Web_Attack   │                    0.92% │
│ Infiltration │                    0.82% │
└──────────────┴──────────────────────────┘

⚠ RISK LEVEL: HIGH
```

---

## Input Data Format

The input CSV must follow the **CIC-IDS2018** flow record format with these required columns:

| Column | Description |
|--------|-------------|
| `Timestamp` | Format: `DD/MM/YYYY HH:MM:SS` |
| `Tot Fwd Pkts` | Total forward packets |
| `Tot Bwd Pkts` | Total backward packets |
| `TotLen Fwd Pkts` | Total forward packet length |
| `TotLen Bwd Pkts` | Total backward packet length |
| `Flow Duration` | Duration of the flow |
| `Flow IAT Mean` | Mean inter-arrival time |
| `Pkt Len Mean` | Mean packet length |
| `Pkt Len Std` | Packet length standard deviation |
| `SYN Flag Cnt` | SYN flag count |
| `ACK Flag Cnt` | ACK flag count |
| `RST Flag Cnt` | RST flag count |
| `FIN Flag Cnt` | FIN flag count |
| `Down/Up Ratio` | Download/upload ratio |
| `Active Mean` | Mean active time |
| `Idle Mean` | Mean idle time |

The file must contain **at least 30 minutes** of continuous traffic (6 contiguous 5-minute windows) for the model to produce a prediction.

---

## Project Structure

```
netforec/
├── pyproject.toml              # Package config, dependencies, CLI entry point
├── README.md                   # This file
├── sample_traffic.csv          # Schema-correct demo file (30 min of synthetic flows)
└── netforec/
    ├── __init__.py
    ├── cli.py                  # UI layer — Typer commands, formatting, I/O
    ├── pipeline.py             # Orchestrates: feature extraction → scaling → model
    ├── features.py             # Raw CSV → (6, 16) windowed feature sequence
    ├── model.py                # NETFORECLSTM architecture definition
    └── model_artifacts/
        ├── netforc_lstm.pth    # Trained LSTM weights (state_dict)
        ├── netforc_scaler.pkl  # StandardScaler fit on training data
        ├── class_names.json    # 7 class names in model output order
        └── model_config.json   # Architecture hyperparameters
```

---

## Technical Details

### Feature Engineering

Raw per-flow CSV records are aggregated into **5-minute network-state windows**, producing 16 features per window:

- **Volume metrics:** Flow count, forward/backward packet and byte totals
- **Timing metrics:** Average flow duration, inter-arrival time
- **Packet characteristics:** Mean packet length, packet length standard deviation
- **TCP flag distributions:** SYN, ACK, RST, FIN flag counts
- **Flow behaviour:** Down/Up ratio, active/idle time averages

### Model Architecture

| Component | Specification |
|-----------|--------------|
| Architecture | LSTM (Long Short-Term Memory) |
| Input | (6, 16) — 6 time windows × 16 features |
| Hidden size | 64 |
| LSTM layers | 2 (with dropout = 0.2) |
| Output | 7 classes (softmax probability distribution) |
| Forecast horizon | Next 15 minutes |
| Training data | CIC-IDS2018 dataset |

### Prediction Classes

| Class | Description |
|-------|-------------|
| `No_Attack` | Normal/benign traffic |
| `Brute_Force` | Password brute-force attempts |
| `DDoS` | Distributed Denial of Service |
| `DoS` | Denial of Service |
| `Botnet` | Botnet command-and-control activity |
| `Web_Attack` | Web application attacks (SQL injection, XSS, etc.) |
| `Infiltration` | Network infiltration / lateral movement |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.9+ |
| CLI Framework | Typer + Rich |
| ML Framework | PyTorch |
| Data Processing | Pandas, NumPy |
| Model Serialization | joblib, scikit-learn |
| Dataset | CIC-IDS2018 |

---

## Team

**Team RuntimeErrors** — SIH 2026 Internal Hackathon

---

## License

This project is developed as part of the Smart India Hackathon 2026 (Problem Statement 26153).
