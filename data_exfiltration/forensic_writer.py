"""
forensic_writer.py — Stage 9: Generate structured forensic evidence artifacts.

Outputs:
  • JSON report      — full machine-readable report
  • CSV report       — tabular flow data
  • Suspicious log   — human-readable text log of flagged flows
  • Summary JSON     — high-level statistics
"""

from __future__ import annotations
import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd

from utils import setup_logger, ensure_dir, timestamp_str

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_val(v: Any) -> Any:
    """Convert numpy / pandas scalar types to plain Python for JSON."""
    import numpy as np
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    if isinstance(v, (np.ndarray,)):
        return v.tolist()
    if pd.isna(v):
        return None
    return v


def _row_to_dict(row: pd.Series) -> Dict[str, Any]:
    return {k: _safe_val(v) for k, v in row.items()}


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_csv_report(df: pd.DataFrame, output_dir: str, prefix: str = "flows") -> str:
    """
    Write all flows to a CSV file.

    Returns:
        Path to the created file.
    """
    ensure_dir(output_dir)
    path = os.path.join(output_dir, f"{prefix}_{timestamp_str()}.csv")
    df.to_csv(path, index=False)
    logger.info("CSV report written: %s", path)
    return path


def write_json_report(df: pd.DataFrame, output_dir: str, prefix: str = "report") -> str:
    """
    Write full JSON report containing every flow's features and detection results.

    Returns:
        Path to the created file.
    """
    ensure_dir(output_dir)
    path = os.path.join(output_dir, f"{prefix}_{timestamp_str()}.json")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_flows": int(len(df)),
        "flagged_flows": int((df.get("heuristic_label", pd.Series(dtype=str)) != "Benign").sum()),
        "flows": [_row_to_dict(row) for _, row in df.iterrows()],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("JSON report written: %s  (%d flows)", path, len(df))
    return path


def write_suspicious_log(df: pd.DataFrame, output_dir: str) -> str:
    """
    Write a human-readable text log of suspicious / exfiltration flows.

    Returns:
        Path to the created file.
    """
    ensure_dir(output_dir)
    path = os.path.join(output_dir, f"suspicious_flows_{timestamp_str()}.txt")

    # Determine which label column to use
    label_col = None
    for candidate in ("ml_label", "heuristic_label"):
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None:
        logger.warning("No label column found — skipping suspicious log.")
        return ""

    flagged = df[df[label_col] != "Benign"]

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  FORENSIC EXFILTRATION DETECTION -- SUSPICIOUS FLOW LOG\n")
        f.write(f"  Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"  Total flows analysed : {len(df)}\n")
        f.write(f"  Flagged flows        : {len(flagged)}\n")
        f.write("=" * 70 + "\n\n")

        for i, (_, row) in enumerate(flagged.iterrows(), start=1):
            f.write(f"[{i:04d}] " + "-" * 42 + "\n")
            f.write(f"  Src        : {row.get('src_ip','?')}:{int(row.get('src_port',0))}\n")
            f.write(f"  Dst        : {row.get('dst_ip','?')}:{int(row.get('dst_port',0))}\n")
            f.write(f"  Protocol   : {row.get('protocol_name', row.get('protocol','?'))}\n")
            f.write(f"  Start time : {row.get('start_time','?')}\n")
            f.write(f"  Duration   : {row.get('flow_duration', 0):.2f} s\n")
            f.write(f"  Packets    : {int(row.get('packet_count',0))}\n")
            f.write(f"  Bytes      : {int(row.get('total_bytes',0)):,}\n")
            f.write(f"  Byte rate  : {row.get('byte_rate',0):.1f} B/s\n")
            f.write(f"  Entropy    : {row.get('entropy',0):.4f} bits/byte\n")
            f.write(f"  Burstiness : {row.get('burstiness',0):.4f}\n")

            if "heuristic_score" in row:
                f.write(f"  Heuristic score  : {int(row['heuristic_score'])}\n")
                f.write(f"  Heuristic label  : {row.get('heuristic_label','?')}\n")
                f.write(f"  Triggered rules  : {row.get('triggered_rules','none')}\n")

            if "ml_label" in row:
                f.write(f"  ML label         : {row['ml_label']}\n")
                f.write(f"  RF confidence    : {row.get('rf_confidence',0):.4f}\n")
                f.write(f"  IF anomaly score : {row.get('if_anomaly_score',0):.6f}\n")

            f.write("\n")

    logger.info("Suspicious flow log written: %s  (%d entries)", path, len(flagged))
    return path


def write_summary(df: pd.DataFrame, output_dir: str) -> str:
    """
    Write a high-level JSON summary of the detection run.

    Returns:
        Path to the created file.
    """
    ensure_dir(output_dir)
    path = os.path.join(output_dir, f"summary_{timestamp_str()}.json")

    label_col = "ml_label" if "ml_label" in df.columns else "heuristic_label"
    label_counts: Dict[str, int] = {}
    if label_col in df.columns:
        label_counts = df[label_col].value_counts().to_dict()
        label_counts = {k: int(v) for k, v in label_counts.items()}

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_flows": int(len(df)),
        "label_distribution": label_counts,
        "entropy_stats": {
            "mean": float(df["entropy"].mean()) if "entropy" in df.columns else None,
            "max":  float(df["entropy"].max())  if "entropy" in df.columns else None,
            "min":  float(df["entropy"].min())  if "entropy" in df.columns else None,
        },
        "total_bytes_analysed": int(df["total_bytes"].sum()) if "total_bytes" in df.columns else 0,
        "unique_src_ips": int(df["src_ip"].nunique()) if "src_ip" in df.columns else 0,
        "unique_dst_ips": int(df["dst_ip"].nunique()) if "dst_ip" in df.columns else 0,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Summary written: %s", path)
    return path


def write_all_artifacts(df: pd.DataFrame, output_dir: str) -> Dict[str, str]:
    """
    Convenience wrapper — write every artifact type and return paths.

    Returns:
        Dict mapping artifact type → file path.
    """
    return {
        "csv": write_csv_report(df, output_dir),
        "json": write_json_report(df, output_dir),
        "suspicious_log": write_suspicious_log(df, output_dir),
        "summary": write_summary(df, output_dir),
    }
