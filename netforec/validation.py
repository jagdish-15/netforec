"""
validation.py
-------------
Provides structural validation logic to verify if a CSV file meets the constraints for NETFOREC.
"""
from pathlib import Path
from dataclasses import dataclass
import pandas as pd
from netforec.features import REQUIRED_RAW_COLUMNS, HISTORY_WINDOWS, WINDOW_MINUTES, _parse_timestamps

@dataclass
class ValidationResult:
    is_valid: bool
    errors: list[str]
    warnings: list[str]

def validate_input(path: Path) -> ValidationResult:
    errors = []
    warnings = []
    
    # 1. File exists and is readable
    if not path.exists():
        errors.append(f"File not found: {path.name}")
        return ValidationResult(False, errors, warnings)
    if not path.is_file():
        errors.append(f"Path is not a regular file: {path.name}")
        return ValidationResult(False, errors, warnings)
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            f.read(10)
    except Exception as e:
        errors.append(f"File is not readable: {e}")
        return ValidationResult(False, errors, warnings)
        
    # 2. Parses as valid CSV
    try:
        df = pd.read_csv(path)
    except Exception as e:
        errors.append(f"Failed to parse as valid CSV.")
        return ValidationResult(False, errors, warnings)
        
    if df.empty:
        errors.append("CSV file is completely empty.")
        return ValidationResult(False, errors, warnings)
        
    # 3. Contains all required columns
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
            # Handle features.py fallback columns
            if req not in ("TTL", "Src IP", "Dst IP", "PSH Flag Cnt"):
                missing.append(req)
            else:
                mapped_df[req] = 0

    if missing:
        errors.append(f"Missing required columns: {', '.join(missing)}")
        return ValidationResult(False, errors, warnings)
        
    # 4. No fully-empty required columns
    empty_cols = []
    for col in mapped_df.columns:
        if mapped_df[col].isna().all():
            empty_cols.append(col)
            
    if empty_cols:
        errors.append(f"Required columns contain only missing values (all NaN): {', '.join(empty_cols)}")
        return ValidationResult(False, errors, warnings)
        
    # 5. Timestamp parses
    ts = _parse_timestamps(mapped_df)
    valid_ts = ts.dropna()
    if valid_ts.empty:
        errors.append("Timestamp column does not match expected format.")
        return ValidationResult(False, errors, warnings)
        
    # 6. Contiguous duration
    min_time = valid_ts.min()
    max_time = valid_ts.max()
    dur_mins = (max_time - min_time).total_seconds() / 60.0
    req_mins = HISTORY_WINDOWS * WINDOW_MINUTES
    # Give a small 10% tolerance for synthetic data or exact boundary truncation
    if dur_mins < (req_mins * 0.95):
        errors.append(f"Insufficient contiguous duration. Found {int(dur_mins)} min, need ≥{req_mins} min.")
        return ValidationResult(False, errors, warnings)
        
    return ValidationResult(True, errors, warnings)
