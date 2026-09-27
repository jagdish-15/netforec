"""
features.py
------------
Turns a raw flow-level CSV into the (15, 30) windowed sequence the TemporalTransformer expects.
Extracts 30 features per 5-minute window from the raw flow data.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np
import pandas as pd
from scipy.stats import entropy

FEATURES = [
    "flow_count", "total_bytes", "total_pkts", "mean_bytes_per_flow",
    "std_bytes_per_flow", "unique_src_ips", "unique_dst_ips",
    "unique_src_ports", "unique_dst_ports", "bytes_per_pkt",
    "tcp_ratio", "udp_ratio", "icmp_ratio", "syn_ratio",
    "ack_ratio", "fin_ratio", "rst_ratio", "psh_ratio",
    "mean_duration", "std_duration", "pkts_per_sec", "bytes_per_sec",
    "dst_port_entropy", "dst_ip_entropy", "src_ip_entropy",
    "mean_ttl", "std_ttl", "mean_pkts_per_flow", "std_pkts_per_flow",
    "unique_protocols"
]

HISTORY_WINDOWS = 15
WINDOW_MINUTES = 5

REQUIRED_RAW_COLUMNS = [
    "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Flow Duration", "SYN Flag Cnt", "ACK Flag Cnt", "FIN Flag Cnt", 
    "RST Flag Cnt", "PSH Flag Cnt", "TTL"
]

class FeatureExtractionError(Exception): pass

@dataclass
class ExtractedSequence:
    sequence: np.ndarray  # shape (15, 30), unscaled
    window_start_times: list
    flows_processed: int
    top_src_ips: list[str]
    top_dst_ports: list[int]
    avg_syn_ratio: float

def _parse_timestamps(df: pd.DataFrame) -> pd.Series:
    ts = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    if ts.isna().mean() > 0.5:
        ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    return ts

def _compute_entropy(series):
    counts = series.value_counts()
    if len(counts) == 0: return 0.0
    return entropy(counts)

def extract_sequence(csv_path: str) -> ExtractedSequence:
    try:
        df = pd.read_csv(csv_path)
    except Exception as exc:
        raise FeatureExtractionError(f"Could not read CSV: {exc}") from exc

    mapped_df = pd.DataFrame()
    missing = []
    for req in REQUIRED_RAW_COLUMNS:
        req_l = req.lower()
        found = False
        if req in df.columns:
            mapped_df[req] = df[req]
            found = True
        else:
            for dcol in df.columns:
                if dcol.lower().replace("_", " ") == req_l or dcol.lower().replace(" ", "") == req_l.replace(" ", ""):
                    mapped_df[req] = df[dcol]
                    found = True
                    break
        if not found:
            if req == "TTL": mapped_df["TTL"] = 64
            elif req in ("Src IP", "Dst IP"): mapped_df[req] = "0.0.0.0"
            elif req == "PSH Flag Cnt": mapped_df[req] = 0
            else: missing.append(req)

    if missing:
        raise FeatureExtractionError("CSV is missing required columns: " + ", ".join(missing))

    df = mapped_df
    df["Timestamp"] = _parse_timestamps(df)
    df = df.dropna(subset=["Timestamp"])
    
    if df.empty: raise FeatureExtractionError("No parseable Timestamps found.")

    numeric_cols = ["Src Port", "Dst Port", "Protocol", "Tot Fwd Pkts", "Tot Bwd Pkts", 
                    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Duration", "SYN Flag Cnt", 
                    "ACK Flag Cnt", "FIN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "TTL"]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["Total Packets"] = df["Tot Fwd Pkts"] + df["Tot Bwd Pkts"]
    df["Total Bytes"] = df["TotLen Fwd Pkts"] + df["TotLen Bwd Pkts"]
    
    floored_minute = df["Timestamp"].dt.floor("min")
    minute_of_hour = floored_minute.dt.minute
    df["_window"] = floored_minute - pd.to_timedelta(minute_of_hour % WINDOW_MINUTES, unit="m")

    grouped = df.groupby("_window")
    windows = pd.DataFrame(index=grouped.indices.keys())
    windows.index.name = "_window"
    
    windows["flow_count"] = grouped.size()
    windows["total_bytes"] = grouped["Total Bytes"].sum()
    windows["total_pkts"] = grouped["Total Packets"].sum()
    windows["mean_bytes_per_flow"] = grouped["Total Bytes"].mean()
    windows["std_bytes_per_flow"] = grouped["Total Bytes"].std().fillna(0)
    windows["unique_src_ips"] = grouped["Src IP"].nunique()
    windows["unique_dst_ips"] = grouped["Dst IP"].nunique()
    windows["unique_src_ports"] = grouped["Src Port"].nunique()
    windows["unique_dst_ports"] = grouped["Dst Port"].nunique()
    windows["bytes_per_pkt"] = (windows["total_bytes"] / windows["total_pkts"].replace(0, 1))
    
    def ratio(col, val): return grouped.apply(lambda x: (x[col] == val).sum() / len(x) if len(x)>0 else 0)
    def ratio_sum(col): return grouped.apply(lambda x: (x[col] > 0).sum() / len(x) if len(x)>0 else 0)
    
    windows["tcp_ratio"] = ratio("Protocol", 6)
    windows["udp_ratio"] = ratio("Protocol", 17)
    windows["icmp_ratio"] = ratio("Protocol", 1)
    windows["syn_ratio"] = ratio_sum("SYN Flag Cnt")
    windows["ack_ratio"] = ratio_sum("ACK Flag Cnt")
    windows["fin_ratio"] = ratio_sum("FIN Flag Cnt")
    windows["rst_ratio"] = ratio_sum("RST Flag Cnt")
    windows["psh_ratio"] = ratio_sum("PSH Flag Cnt")
    
    windows["mean_duration"] = grouped["Flow Duration"].mean()
    windows["std_duration"] = grouped["Flow Duration"].std().fillna(0)
    windows["pkts_per_sec"] = windows["total_pkts"] / (windows["mean_duration"].replace(0, 1))
    windows["bytes_per_sec"] = windows["total_bytes"] / (windows["mean_duration"].replace(0, 1))
    
    windows["dst_port_entropy"] = grouped["Dst Port"].apply(_compute_entropy)
    windows["dst_ip_entropy"] = grouped["Dst IP"].apply(_compute_entropy)
    windows["src_ip_entropy"] = grouped["Src IP"].apply(_compute_entropy)
    windows["mean_ttl"] = grouped["TTL"].mean()
    windows["std_ttl"] = grouped["TTL"].std().fillna(0)
    windows["mean_pkts_per_flow"] = grouped["Total Packets"].mean()
    windows["std_pkts_per_flow"] = grouped["Total Packets"].std().fillna(0)
    windows["unique_protocols"] = grouped["Protocol"].nunique()
    
    windows = windows[FEATURES].sort_index()

    if len(windows) < HISTORY_WINDOWS:
        raise FeatureExtractionError(f"Found {len(windows)} windows, need {HISTORY_WINDOWS}.")

    recent = windows.iloc[-HISTORY_WINDOWS:]
    gaps = recent.index.to_series().diff().dropna()
    if not (gaps == pd.Timedelta(minutes=WINDOW_MINUTES)).all():
        raise FeatureExtractionError("Windows are not contiguous.")

    # Filter to only rows inside our recent windows for correct IP extraction
    min_time = recent.index[0]
    max_time = recent.index[-1] + pd.Timedelta(minutes=WINDOW_MINUTES)
    recent_df = df[(df["Timestamp"] >= min_time) & (df["Timestamp"] < max_time)]

    top_src_ips = recent_df["Src IP"].value_counts().head(5).index.tolist()
    top_dst_ports = [int(p) for p in recent_df["Dst Port"].value_counts().head(5).index.tolist()]
    avg_syn_ratio = float(recent["syn_ratio"].mean())

    sequence = recent.to_numpy(dtype=np.float32)
    flows_processed = int(recent["flow_count"].sum())

    return ExtractedSequence(
        sequence=sequence, 
        window_start_times=list(recent.index), 
        flows_processed=flows_processed,
        top_src_ips=top_src_ips,
        top_dst_ports=top_dst_ports,
        avg_syn_ratio=avg_syn_ratio
    )
