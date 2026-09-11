"""
pipeline.py
-----------
Real inference pipeline: raw CSV -> windowed features -> scaled -> LSTM ->
7-class probability breakdown.

This replaces the earlier mock. Everything here is now backed by actual
artifacts handed off by the ML team, bundled in `netforec/model_artifacts/`:

    netforc_lstm.pth    - trained model weights (state_dict)
    netforc_scaler.pkl  - StandardScaler fit on the training data
    class_names.json    - the 7 class names, in the order the model outputs
    model_config.json   - architecture hyperparameters (input_size, hidden_size, ...)

CONFIRMED CONTRACT (verified by loading these files and running a real
forward pass — see conversation history for the test):

    Input:  a (6, 16) sequence of 5-minute windowed features (unscaled),
            produced by features.extract_sequence()
    Output: a probability distribution over 7 classes for "what happens in
            the next 15 minutes" — NOT a per-window forecast curve. There
            is no multi-step timeline; the model predicts one outcome for
            the whole 15-minute horizon.

KNOWN LIMITATIONS (from the ML team's own test-set evaluation — see their
notebook's cell output, reproduced here so this isn't lost):
    - Overall test accuracy: ~52.8% (176-sample test set)
    - No_Attack recall is only ~33% — the model over-predicts attacks on
      benign traffic. Don't oversell "100% recall on Botnet" without this
      caveat; several attack classes also have very small test support
      (Web_Attack: 2 samples, DDoS: 5 samples) so those numbers are noisy.

STILL MISSING (flagged to the ML team, not yet addressed):
    - No SHAP/attention-based explainability (PS requires this)
    - No MITRE ATT&CK stage mapping (Attack_Class != MITRE stage)
    - No packet-level (PCAP) feature support — CSV/flow-level only
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import joblib
import numpy as np
import torch

from netforec.features import FeatureExtractionError, extract_sequence
from netforec.model import NETFORECLSTM

ARTIFACTS_DIR = Path(__file__).parent / "model_artifacts"


class PipelineError(Exception):
    """Raised when the pipeline can't process the given file."""


@dataclass
class AnalysisResult:
    file_name: str
    predicted_class: str
    confidence: float  # 0.0 - 1.0, probability of predicted_class
    class_probabilities: list[tuple[str, float]]  # all 7, sorted desc
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH"
    history_minutes: int
    forecast_minutes: int
    window_start: str  # ISO timestamp of the oldest analyzed window
    window_end: str  # ISO timestamp of the most recent analyzed window
    flows_processed: int
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_name": self.file_name,
            "predicted_class": self.predicted_class,
            "confidence": round(self.confidence, 4),
            "class_probabilities": [
                {"class": c, "probability": round(p, 4)}
                for c, p in self.class_probabilities
            ],
            "risk_level": self.risk_level,
            "history_minutes": self.history_minutes,
            "forecast_minutes": self.forecast_minutes,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "flows_processed": self.flows_processed,
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------
# Artifact loading (once per process)
# --------------------------------------------------------------------------

_model = None
_scaler = None
_class_names = None
_config = None


def _load_artifacts():
    global _model, _scaler, _class_names, _config
    if _model is not None:
        return

    for fname in (
        "netforc_lstm.pth",
        "netforc_scaler.pkl",
        "class_names.json",
        "model_config.json",
    ):
        if not (ARTIFACTS_DIR / fname).exists():
            raise PipelineError(
                f"Missing model artifact: {fname}. Expected it at "
                f"{ARTIFACTS_DIR / fname}"
            )

    with open(ARTIFACTS_DIR / "model_config.json") as f:
        _config = json.load(f)
    with open(ARTIFACTS_DIR / "class_names.json") as f:
        _class_names = json.load(f)

    _scaler = joblib.load(ARTIFACTS_DIR / "netforc_scaler.pkl")

    model = NETFORECLSTM(
        input_size=_config["input_size"],
        hidden_size=_config["hidden_size"],
        num_layers=_config["num_layers"],
        num_classes=_config["num_classes"],
        dropout=_config["dropout"],
    )
    state = torch.load(
        ARTIFACTS_DIR / "netforc_lstm.pth", map_location="cpu", weights_only=False
    )
    model.load_state_dict(state)
    model.eval()
    _model = model


def _risk_level(predicted_class: str, confidence: float) -> str:
    # Mirrors the ML team's own risk logic from their demo cell, so the
    # CLI's risk labeling matches whatever they show in their slides.
    if predicted_class != "No_Attack" and confidence > 0.6:
        return "HIGH"
    if predicted_class != "No_Attack":
        return "MEDIUM"
    return "LOW"


def run_pipeline(
    file_path: str,
    forecast_steps: int = 3,  # unused — kept for CLI backward-compat, see README
    log=lambda msg: None,
) -> AnalysisResult:
    path = Path(file_path)
    if not path.exists():
        raise PipelineError(f"File not found: {file_path}")

    suffix = path.suffix.lower()
    if suffix in (".pcap", ".pcapng"):
        raise PipelineError(
            "PCAP input isn't supported yet — the current model only "
            "accepts flow-level CSV (CIC-IDS2018-style columns). Convert "
            "your capture to flow records first (e.g. with CICFlowMeter), "
            "or ask the ML team about PCAP support status."
        )
    if suffix != ".csv":
        raise PipelineError(
            f"Unsupported file type '{suffix}'. Expected .csv "
            "(flow-level, CIC-IDS2018-style columns)."
        )

    log(f"Loading {path.name}")
    _load_artifacts()
    log("Model, scaler, and class names loaded")

    log("Extracting 5-minute windowed features from raw flow records")
    try:
        extracted = extract_sequence(str(path))
    except FeatureExtractionError as exc:
        raise PipelineError(str(exc)) from exc

    log(f"Flows processed: {extracted.flows_processed:,}")
    log(f"Using windows {extracted.window_start_times[0]} -> "
        f"{extracted.window_start_times[-1]}")

    log("Scaling features")
    scaled = _scaler.transform(extracted.sequence)

    log("Running LSTM inference")
    x = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)  # (1, 6, 16)
    with torch.no_grad():
        probs = torch.softmax(_model(x), dim=1)[0].numpy()

    results = sorted(zip(_class_names, probs.tolist()), key=lambda t: -t[1])
    predicted_class, confidence = results[0]
    log(f"Predicted: {predicted_class} ({confidence * 100:.1f}%)")

    return AnalysisResult(
        file_name=path.name,
        predicted_class=predicted_class,
        confidence=confidence,
        class_probabilities=results,
        risk_level=_risk_level(predicted_class, confidence),
        history_minutes=_config["history_windows"] * 5,
        forecast_minutes=_config["future_windows"] * 5,
        window_start=str(extracted.window_start_times[0]),
        window_end=str(extracted.window_start_times[-1]),
        flows_processed=extracted.flows_processed,
        warnings=[],
    )
