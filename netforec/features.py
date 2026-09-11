"""
features.py
------------
Turns a raw flow-level CSV into the (6, 16) windowed sequence the model
expects.

This logic is PORTED from the ML team's `Final_preprocessed_dataset.ipynb`
preprocessing notebook (the DuckDB aggregation cell that builds 5-minute
network-state windows). It's reimplemented here in pandas because at
inference time we're aggregating one user-supplied file (thousands of
rows, not the multi-GB training CSV) so DuckDB's speed advantage doesn't
matter, and pandas keeps this dependency-light for the CLI.

INPUT CSV CONTRACT (confirmed from the training notebook + model_config.json)
================================================================================
Raw per-flow CSV, same column names as CIC-IDS2018 flow exports:

    Timestamp           - format "%d/%m/%Y %H:%M:%S" (day-first)
    Tot Fwd Pkts
    Tot Bwd Pkts
    TotLen Fwd Pkts
    TotLen Bwd Pkts
    Flow Duration
    Flow IAT Mean
    Pkt Len Mean
    Pkt Len Std
    SYN Flag Cnt
    ACK Flag Cnt
    RST Flag Cnt
    FIN Flag Cnt
    Down/Up Ratio
    Active Mean
    Idle Mean

A `Label` column may be present (it's ignored — the whole point is we
don't know the label yet, that's what we're predicting) but is not
required.

Only these columns are used. Note `Flow Byts/s` and `Flow Pkts/s`
appear in the ML team's intermediate windowing step but are NOT part
of the 16 features the model was actually trained on (confirmed against
their FEATURES list and model_config.json's input_size=16), so they're
not required here.

AGGREGATION (5-minute windows, matches training exactly)
================================================================================
    Flow_Count             = row count in the window
    Total_Fwd_Packets      = sum(Tot Fwd Pkts)
    Total_Bwd_Packets      = sum(Tot Bwd Pkts)
    Total_Fwd_Bytes        = sum(TotLen Fwd Pkts)
    Total_Bwd_Bytes        = sum(TotLen Bwd Pkts)
    Avg_Flow_Duration      = mean(Flow Duration)
    Avg_IAT                = mean(Flow IAT Mean)
    Avg_Packet_Length      = mean(Pkt Len Mean)
    Avg_Packet_Length_Std  = mean(Pkt Len Std)
    SYN_Count              = sum(SYN Flag Cnt)
    ACK_Count              = sum(ACK Flag Cnt)
    RST_Count              = sum(RST Flag Cnt)
    FIN_Count              = sum(FIN Flag Cnt)
    Avg_Down_Up_Ratio      = mean(Down/Up Ratio)
    Avg_Active_Mean        = mean(Active Mean)
    Avg_Idle_Mean          = mean(Idle Mean)

FEATURE ORDER MATTERS. This must match the order the StandardScaler
was fit on. Do not reorder without re-checking against the ML team's
FEATURES list.

SEQUENCE SELECTION
================================================================================
The model consumes exactly 6 consecutive 5-minute windows (30 minutes
of history) with no gap between them. We take the LAST 6 complete,
contiguous windows found in the file. If the file has more than 6
windows, older data is ignored. If it has fewer than 6, or the most
recent 6 aren't contiguous (a >5min gap), extraction fails with a
clear error rather than silently padding or guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# Order matters — must match the order the scaler/model were trained on.
FEATURES = [
    "Flow_Count",
    "Total_Fwd_Packets",
    "Total_Bwd_Packets",
    "Total_Fwd_Bytes",
    "Total_Bwd_Bytes",
    "Avg_Flow_Duration",
    "Avg_IAT",
    "Avg_Packet_Length",
    "Avg_Packet_Length_Std",
    "SYN_Count",
    "ACK_Count",
    "RST_Count",
    "FIN_Count",
    "Avg_Down_Up_Ratio",
    "Avg_Active_Mean",
    "Avg_Idle_Mean",
]

HISTORY_WINDOWS = 6  # 30 minutes
WINDOW_MINUTES = 5

REQUIRED_RAW_COLUMNS = [
    "Timestamp",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Duration",
    "Flow IAT Mean",
    "Pkt Len Mean",
    "Pkt Len Std",
    "SYN Flag Cnt",
    "ACK Flag Cnt",
    "RST Flag Cnt",
    "FIN Flag Cnt",
    "Down/Up Ratio",
    "Active Mean",
    "Idle Mean",
]


class FeatureExtractionError(Exception):
    """Raised when a CSV can't be turned into a valid model input sequence."""


@dataclass
class ExtractedSequence:
    sequence: np.ndarray  # shape (6, 16), unscaled
    window_start_times: list  # 6 pandas Timestamps, oldest -> newest
    flows_processed: int  # total raw rows used across the 6 windows


def _parse_timestamps(df: pd.DataFrame) -> pd.Series:
    # Training data uses day-first "%d/%m/%Y %H:%M:%S". Try that first for
    # an exact match with the training pipeline; fall back to pandas'
    # flexible parser (still day-first) for CSVs with slightly different
    # timestamp formatting.
    ts = pd.to_datetime(
        df["Timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    if ts.isna().mean() > 0.5:
        ts = pd.to_datetime(df["Timestamp"], dayfirst=True, errors="coerce")
    return ts


def extract_sequence(csv_path: str) -> ExtractedSequence:
    try:
        df = pd.read_csv(csv_path)
    except Exception as exc:  # noqa: BLE001
        raise FeatureExtractionError(f"Could not read CSV: {exc}") from exc

    missing = [c for c in REQUIRED_RAW_COLUMNS if c not in df.columns]
    if missing:
        raise FeatureExtractionError(
            "CSV is missing required columns: "
            + ", ".join(missing)
            + ". Expected raw CIC-IDS2018-style per-flow columns "
            "(Timestamp, Tot Fwd Pkts, Flow Duration, SYN Flag Cnt, ...)."
        )

    df["Timestamp"] = _parse_timestamps(df)
    n_bad = df["Timestamp"].isna().sum()
    df = df.dropna(subset=["Timestamp"])
    if df.empty:
        raise FeatureExtractionError(
            "No rows had a parseable Timestamp "
            f"(day-first format expected, e.g. 25/12/2026 14:05:00; "
            f"{n_bad} row(s) failed to parse)."
        )

    for col in REQUIRED_RAW_COLUMNS[1:]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Bucket into 5-minute windows, matching the training pipeline's
    # DATE_TRUNC('minute', ts) - (minute % 5) logic.
    floored_minute = df["Timestamp"].dt.floor("min")
    minute_of_hour = floored_minute.dt.minute
    window_start = floored_minute - pd.to_timedelta(
        minute_of_hour % WINDOW_MINUTES, unit="m"
    )
    df["_window"] = window_start

    grouped = df.groupby("_window")
    windows = grouped.agg(
        Flow_Count=("Timestamp", "count"),
        Total_Fwd_Packets=("Tot Fwd Pkts", "sum"),
        Total_Bwd_Packets=("Tot Bwd Pkts", "sum"),
        Total_Fwd_Bytes=("TotLen Fwd Pkts", "sum"),
        Total_Bwd_Bytes=("TotLen Bwd Pkts", "sum"),
        Avg_Flow_Duration=("Flow Duration", "mean"),
        Avg_IAT=("Flow IAT Mean", "mean"),
        Avg_Packet_Length=("Pkt Len Mean", "mean"),
        Avg_Packet_Length_Std=("Pkt Len Std", "mean"),
        SYN_Count=("SYN Flag Cnt", "sum"),
        ACK_Count=("ACK Flag Cnt", "sum"),
        RST_Count=("RST Flag Cnt", "sum"),
        FIN_Count=("FIN Flag Cnt", "sum"),
        Avg_Down_Up_Ratio=("Down/Up Ratio", "mean"),
        Avg_Active_Mean=("Active Mean", "mean"),
        Avg_Idle_Mean=("Idle Mean", "mean"),
    ).sort_index()

    if len(windows) < HISTORY_WINDOWS:
        raise FeatureExtractionError(
            f"Need at least {HISTORY_WINDOWS} x {WINDOW_MINUTES}-minute "
            f"windows ({HISTORY_WINDOWS * WINDOW_MINUTES} minutes of "
            f"continuous traffic) to make a prediction, but this file only "
            f"covers {len(windows)} window(s)."
        )

    # Take the most recent HISTORY_WINDOWS windows and require them to be
    # perfectly contiguous (each exactly 5 minutes after the last) — the
    # model was trained only on gap-free sequences.
    recent = windows.iloc[-HISTORY_WINDOWS:]
    gaps = recent.index.to_series().diff().dropna()
    expected_gap = pd.Timedelta(minutes=WINDOW_MINUTES)
    if not (gaps == expected_gap).all():
        raise FeatureExtractionError(
            f"The most recent {HISTORY_WINDOWS} windows aren't contiguous "
            f"(found a gap larger than {WINDOW_MINUTES} minutes). The model "
            "requires unbroken 5-minute windows with no missing traffic."
        )

    if recent[FEATURES].isna().any().any():
        raise FeatureExtractionError(
            "One or more windows have missing/unparseable values in a "
            "required feature column after aggregation."
        )

    sequence = recent[FEATURES].to_numpy(dtype=np.float32)
    flows_processed = int(recent["Flow_Count"].sum())

    return ExtractedSequence(
        sequence=sequence,
        window_start_times=list(recent.index),
        flows_processed=flows_processed,
    )
