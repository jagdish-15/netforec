# netforec

AI-powered network attack forecasting CLI — SIH26153 (NTRO).

**Status: real inference wired in.** This is no longer a mock — it runs
the ML team's actual trained LSTM (`NETFORCLSTM`) on real flow-level CSV
input and produces real predictions.

## Setup

```bash
pip install -e .
```

Installs the `netforec` command and pulls in the real dependencies
(torch, scikit-learn, pandas, joblib) needed to run inference.

## Usage

```bash
netforec --help
netforec analyze traffic.csv
netforec analyze traffic.csv --json
netforec analyze traffic.csv --output result.json
netforec analyze traffic.csv --verbose
netforec analyze traffic.csv --output result.json --quiet   # silent save
```

Try it immediately with the bundled demo file:

```bash
netforec analyze sample_traffic.csv --verbose
```

## What the model actually predicts

Confirmed by loading the ML team's real artifacts and running inference —
**not** assumptions:

- **Input:** 30 minutes of continuous flow-level traffic (6 consecutive
  5-minute windows, no gaps). CSV must have the raw CIC-IDS2018-style
  columns (`Timestamp`, `Tot Fwd Pkts`, `Flow Duration`, `SYN Flag Cnt`,
  etc. — see `netforec/features.py` for the full required column list).
- **Output:** one prediction for the whole next-15-minute window — a
  probability distribution across 7 classes (`No_Attack`, `Brute_Force`,
  `DDoS`, `DoS`, `Botnet`, `Web_Attack`, `Infiltration`). There is **no**
  per-step/per-window forecast timeline; that was an earlier assumption
  we've since corrected.
- **PCAP is not supported.** The model only consumes flow-level CSV.
  Passing a `.pcap` gives a clear error rather than failing silently.

### Known model limitations (from the ML team's own test-set numbers)

- Overall test accuracy: ~52.8% (176-sample test set — small, so these
  numbers have real uncertainty)
- **No_Attack recall is only ~33%** — the model over-predicts attacks on
  genuinely benign traffic. Mention this caveat if you cite the "100%
  recall" numbers on rarer attack classes (some of which have test
  support as low as 2–5 samples).

## Project layout

```
netforec/
├── pyproject.toml
├── README.md
├── sample_traffic.csv         # schema-correct demo file, 30 min of synthetic flows
└── netforec/
    ├── __init__.py
    ├── cli.py                 # UI layer — Typer commands, formatting, I/O
    ├── pipeline.py            # orchestrates feature extraction -> scaling -> model
    ├── features.py            # raw CSV -> (6, 16) windowed feature sequence
    ├── model.py                # NETFORCLSTM architecture (must match .pth exactly)
    └── model_artifacts/
        ├── netforc_lstm.pth   # trained weights (state_dict)
        ├── netforc_scaler.pkl # StandardScaler fit on training data
        ├── class_names.json   # the 7 class names, in model output order
        └── model_config.json  # architecture hyperparameters
```

## Still open with the ML team

- No SHAP / attention-based explainability yet (the problem statement
  requires this)
- No mapping from `Attack_Class` (DDoS, Botnet, ...) to MITRE ATT&CK
  stages (Reconnaissance, Lateral Movement, ...) — the PS asks for the
  latter, the model currently predicts the former
- No packet-level (PCAP) feature support
- If they retrain and hand off a new model, just replace the 4 files in
  `model_artifacts/` — `pipeline.py` and `model.py` don't need to change
  unless the architecture (layer sizes) or feature list changes

## Deliverable checklist (per problem statement)

- [x] CLI interface (`netforec analyze FILE`)
- [x] Feature extraction pipeline (flow-level CSV -> windowed features)
- [x] Trained world model (LSTM) plugged into `pipeline.py`
- [ ] SHAP / attention-based explainability
- [ ] MITRE ATT&CK stage mapping
- [ ] Packet-level (PCAP) feature support
- [ ] Benchmark vs logistic regression baseline
- [ ] Demo video, architecture doc, slides
