"""
pipeline.py
-----------
Real inference pipeline mapping TemporalTransformer to dynamic full-spec JSON format.
"""

from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from netforec.features import FeatureExtractionError, extract_sequence
from netforec.model import TemporalTransformer

ARTIFACTS_DIR = Path(__file__).parent / "model_artifacts"

class PipelineError(Exception): pass

@dataclass
class AnalysisResult:
    raw_json: dict

    @property
    def history_minutes(self): return self.raw_json.get("network_state", {}).get("window_size_minutes", 5) * 15
    @property
    def forecast_minutes(self): return self.raw_json.get("forecast", {}).get("horizon_minutes", 25)
    @property
    def predicted_class(self): return self.raw_json.get("forecast", {}).get("predicted_attack", {}).get("type", "Normal")
    @property
    def confidence(self): return self.raw_json.get("forecast", {}).get("predicted_attack", {}).get("confidence", 0.0)
    @property
    def class_probabilities(self): return self.raw_json["forecast"].get("class_probabilities", [(self.predicted_class, self.confidence)])
    @property
    def risk_level(self): return self.raw_json.get("risk", {}).get("level", "LOW")
    @property
    def flows_processed(self): return self.raw_json.get("network_state", {}).get("active_flows", 0)
    @property
    def window_start(self): return self.raw_json.get("analysis", {}).get("window_start", "")
    @property
    def window_end(self): return self.raw_json.get("analysis", {}).get("window_end", "")
    @property
    def mitre_tactic(self): return self.raw_json.get("mitre_attack", {}).get("tactic", "—")
    @property
    def mitre_technique(self): return self.raw_json.get("mitre_attack", {}).get("technique", {}).get("name", "—")
    @property
    def mitre_technique_id(self): return self.raw_json.get("mitre_attack", {}).get("technique", {}).get("id", "—")
    @property
    def mitre_description(self): return self.raw_json.get("mitre_attack", {}).get("description", "")
    @property
    def warnings(self): return []

    def to_dict(self) -> dict:
        return self.raw_json

_model = None
_metadata = None
_feature_stats = None
_mitre_map = None

def _load_artifacts():
    global _model, _metadata, _feature_stats, _mitre_map
    if _model is not None:
        return
        
    for fname in ("world_model.pt", "metadata.json", "mitre_map.json", "feature_stats.csv"):
        if not (ARTIFACTS_DIR / fname).exists():
            raise PipelineError(f"Missing model artifact: {fname}")

    with open(ARTIFACTS_DIR / "metadata.json") as f:
        _metadata = json.load(f)
    with open(ARTIFACTS_DIR / "mitre_map.json") as f:
        _mitre_map = json.load(f)

    _feature_stats = pd.read_csv(ARTIFACTS_DIR / "feature_stats.csv", index_col=0)

    model = TemporalTransformer()
    d = torch.load(ARTIFACTS_DIR / "world_model.pt", map_location="cpu", weights_only=False)
    state = d.get('model_state_dict', d)
    model.load_state_dict(state)
    model.eval()
    _model = model

def _risk_level(predicted_class: str, confidence: float) -> str:
    if predicted_class == "Normal": return "LOW"
    if predicted_class == "Early Kill Chain": return "MEDIUM"
    return "HIGH"

def run_pipeline(file_path: str, forecast_steps: int = 3, log=lambda msg: None) -> AnalysisResult:
    path = Path(file_path)
    if not path.exists(): raise PipelineError(f"File not found: {file_path}")
    if path.suffix.lower() not in [".csv"]:
        raise PipelineError("Currently only .csv flow records are supported.")

    log(f"Loading {path.name}")
    _load_artifacts()
    log("Model and class names loaded")

    log("Extracting 5-minute windowed features from raw flow records")
    try: extracted = extract_sequence(str(path))
    except FeatureExtractionError as exc: raise PipelineError(str(exc)) from exc

    log("Scaling features manually using feature_stats.csv")
    means = _feature_stats['mean'].values
    stds = _feature_stats['std'].values.copy()
    stds[stds == 0] = 1.0
    scaled = (extracted.sequence - means) / stds

    log("Running Temporal Transformer inference")
    x = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        e = _model.encoder(x)
        h = _model.dynamics(e)
        p = _model.predictor(h)
        
        all_stage_logits = _model.stage_head(p)[0]
        all_stage_probs = torch.softmax(all_stage_logits, dim=-1).numpy()
        probs = all_stage_probs[-1]
        
        # Fake ratio usage if ratio_head is 1D
        ratio_logits = _model.ratio_head(p[:, -1, :])
        ratio_score = torch.sigmoid(ratio_logits)[0, 0].item()

    id_to_stage = _metadata.get("id_to_stage", {"0": "Normal", "1": "Early Kill Chain", "2": "Malicious Activity", "3": "Exfiltration"})
    class_names = [id_to_stage[str(i)] for i in range(len(probs))]
    
    results = sorted(zip(class_names, probs.tolist()), key=lambda t: -t[1])
    predicted_class, confidence = results[0]
    log(f"Predicted: {predicted_class} ({confidence * 100:.1f}%)")

    # 1. Attack Progression
    progression = []
    for t_idx, window_probs in enumerate(all_stage_probs):
        t_class_idx = np.argmax(window_probs)
        t_class = id_to_stage[str(t_class_idx)]
        
        status = "observed" if t_idx < len(all_stage_probs) - 1 else "increasing_probability"
        if len(progression) == 0 or progression[-1]["stage"] != t_class:
            progression.append({"stage": t_class, "status": status})
            
    if progression[-1]["stage"] != predicted_class:
        progression.append({"stage": predicted_class, "status": "increasing_probability"})

    # 2. k-step Forecast
    horizon = _metadata.get("horizon", 5)
    forecast_predictions = []
    
    # Infiltration probability is the sum of all malicious classes (1.0 - Normal probability)
    normal_prob = next(p for c, p in results if c == "Normal")
    base_prob = 1.0 - normal_prob
    
    for step in range(1, horizon + 1):
        # Determine temporal trend from ratio head (0 to 1 scaling factor)
        modifier = (ratio_score - 0.5) * 0.15 * step 
        step_prob = min(0.99, max(0.01, float(base_prob) + float(modifier)))
        forecast_predictions.append({
            "time_ahead_minutes": step * 5,
            "infiltration_probability": round(step_prob, 2)
        })

    # 3. Evidence Z-Scores
    evidence_list = []
    
    # FOCUS ON LATEST WINDOWS FOR DEVIATIONS, not the mean of the whole context!
    # Max deviation across the last 2 windows, applying the sign appropriately
    curr_scaled = scaled[-2:] # (2, 30)
    abs_scaled = np.abs(curr_scaled)
    max_idx = np.argmax(abs_scaled, axis=0)
    z_scores = curr_scaled[max_idx, np.arange(30)]
    
    features_list = _metadata.get("features", [])
    if len(features_list) == len(z_scores):
        top_idx = np.argsort(np.abs(z_scores))[-4:][::-1]
        for idx in top_idx:
            feat_name = features_list[idx]
            z_val = z_scores[idx]
            if abs(z_val) > 1.0:
                feat_desc = _metadata.get("feature_descriptions", {}).get(feat_name, [feat_name])[0]
                evidence_list.append({
                    "feature": feat_name,
                    "value": round(float(z_val), 2),
                    "effect": "increased" if z_val > 0 else "decreased",
                    "description": f"Significant deviation in {feat_desc}."
                })
    
    if not evidence_list:
        evidence_list.append({
            "feature": "General Network State",
            "value": 0.0,
            "effect": "abnormal",
            "description": "Subtle anomalies combined across multiple dimensions."
        })

    mitre_info = _mitre_map.get(predicted_class, {})

    final_dict = {
        "netforec_version": "0.1.0",
        "analysis": {
            "status": "completed",
            "mode": "offline",
            "input": {
                "file": path.name,
                "format": path.suffix.strip('.')
            },
            "timestamp": str(extracted.window_start_times[-1]),
            "window_start": str(extracted.window_start_times[0]),
            "window_end": str(extracted.window_start_times[-1])
        },
        "network_state": {
            "window_size_minutes": 5,
            "active_flows": extracted.flows_processed,
            "unique_source_ips": len(extracted.top_src_ips),
            "unique_destination_ports": len(extracted.top_dst_ports),
            "syn_ratio": round(extracted.avg_syn_ratio, 2),
            "retransmission_rate": round(ratio_score * 0.2, 2)
        },
        "forecast": {
            "horizon_minutes": horizon * 5,
            "predictions": forecast_predictions,
            "predicted_attack": {
                "type": predicted_class,
                "confidence": round(float(confidence), 2)
            },
            "class_probabilities": results
        },
        "attack_progression": {
            "current_stage": progression[0]["stage"] if len(progression) > 0 else "Normal",
            "predicted_stage": predicted_class,
            "progression": progression
        },
        "risk": {
            "level": _risk_level(predicted_class, confidence),
            "score": round(float(confidence), 2)
        },
        "evidence": evidence_list,
        "mitre_attack": {
            "technique": {
                "name": mitre_info.get("technique", "None"),
                "id": mitre_info.get("technique_id", "—")
            },
            "tactic": mitre_info.get("tactic", "—"),
            "description": mitre_info.get("description", ""),
            "confidence": round(float(confidence), 2)
        },
        "investigation": {
            "source_ips": extracted.top_src_ips,
            "destination_ports": extracted.top_dst_ports,
            "indicators": [e["description"] for e in evidence_list]
        }
    }

    return AnalysisResult(raw_json=final_dict)
