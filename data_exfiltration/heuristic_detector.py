"""
heuristic_detector.py — Stage 6: Rule-based risk scoring.

Each rule contributes a weighted score.  The final risk_score is normalised
to [0, 100].  Flows above configurable thresholds are flagged.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple

import pandas as pd

from utils import setup_logger

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Thresholds (tunable)
# ---------------------------------------------------------------------------

THRESHOLDS = {
    # Entropy thresholds (bits / byte)
    "entropy_high": 7.0,        # weight +30
    "entropy_very_high": 7.5,   # weight +20 (additive on top of high)

    # Data volume
    "large_transfer_bytes": 1_000_000,   # 1 MB  → +25
    "huge_transfer_bytes": 10_000_000,   # 10 MB → +15 (additive)

    # Packet rate (packets / second)
    "high_packet_rate": 500,     # +10
    "extreme_packet_rate": 2000, # +10 (additive)

    # Flow duration (seconds)
    "long_duration": 300,        # 5 min → +10
    "very_long_duration": 1800,  # 30 min → +10 (additive)

    # Byte rate (bytes / second)
    "high_byte_rate": 500_000,   # +10

    # Burstiness coefficient of variation
    "high_burstiness": 2.0,      # +5

    # Suspicious ports flag
    "suspicious_port": 1,        # +10

    # Risk score thresholds for labelling
    "suspicious_threshold": 30,
    "exfiltration_threshold": 60,
}


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_name: str
    triggered: bool
    contribution: int
    detail: str


def score_flow(row: pd.Series) -> Tuple[int, List[RuleResult]]:
    """
    Apply all heuristic rules to a single flow (DataFrame row).

    Returns:
        (risk_score_0_100, list_of_RuleResult)
    """
    rules: List[RuleResult] = []
    raw_score = 0

    # ── Entropy rules ─────────────────────────────────────────────────────
    entropy = row.get("entropy", 0.0)

    if entropy >= THRESHOLDS["entropy_high"]:
        contrib = 30
        raw_score += contrib
        rules.append(RuleResult("high_entropy", True, contrib,
                                f"entropy={entropy:.2f} ≥ {THRESHOLDS['entropy_high']}"))
        if entropy >= THRESHOLDS["entropy_very_high"]:
            raw_score += 20
            rules.append(RuleResult("very_high_entropy", True, 20,
                                    f"entropy={entropy:.2f} ≥ {THRESHOLDS['entropy_very_high']}"))
    else:
        rules.append(RuleResult("high_entropy", False, 0, f"entropy={entropy:.2f}"))

    # ── Volume rules ──────────────────────────────────────────────────────
    total_bytes = row.get("total_bytes", 0)

    if total_bytes >= THRESHOLDS["large_transfer_bytes"]:
        raw_score += 25
        rules.append(RuleResult("large_transfer", True, 25,
                                f"total_bytes={total_bytes:,}"))
        if total_bytes >= THRESHOLDS["huge_transfer_bytes"]:
            raw_score += 15
            rules.append(RuleResult("huge_transfer", True, 15,
                                    f"total_bytes={total_bytes:,}"))
    else:
        rules.append(RuleResult("large_transfer", False, 0, f"total_bytes={total_bytes:,}"))

    # ── Packet rate rules ─────────────────────────────────────────────────
    pkt_rate = row.get("packet_rate", 0.0)

    if pkt_rate >= THRESHOLDS["extreme_packet_rate"]:
        raw_score += 20
        rules.append(RuleResult("extreme_packet_rate", True, 20,
                                f"packet_rate={pkt_rate:.1f}"))
    elif pkt_rate >= THRESHOLDS["high_packet_rate"]:
        raw_score += 10
        rules.append(RuleResult("high_packet_rate", True, 10,
                                f"packet_rate={pkt_rate:.1f}"))
    else:
        rules.append(RuleResult("high_packet_rate", False, 0, f"packet_rate={pkt_rate:.1f}"))

    # ── Duration rules ────────────────────────────────────────────────────
    duration = row.get("flow_duration", 0.0)

    if duration >= THRESHOLDS["very_long_duration"]:
        raw_score += 20
        rules.append(RuleResult("very_long_duration", True, 20,
                                f"duration={duration:.1f}s"))
    elif duration >= THRESHOLDS["long_duration"]:
        raw_score += 10
        rules.append(RuleResult("long_duration", True, 10,
                                f"duration={duration:.1f}s"))
    else:
        rules.append(RuleResult("long_duration", False, 0, f"duration={duration:.1f}s"))

    # ── Byte rate ─────────────────────────────────────────────────────────
    byte_rate = row.get("byte_rate", 0.0)
    if byte_rate >= THRESHOLDS["high_byte_rate"]:
        raw_score += 10
        rules.append(RuleResult("high_byte_rate", True, 10,
                                f"byte_rate={byte_rate:.1f} B/s"))
    else:
        rules.append(RuleResult("high_byte_rate", False, 0, f"byte_rate={byte_rate:.1f} B/s"))

    # ── Burstiness ────────────────────────────────────────────────────────
    burstiness = row.get("burstiness", 0.0)
    if burstiness >= THRESHOLDS["high_burstiness"]:
        raw_score += 5
        rules.append(RuleResult("high_burstiness", True, 5,
                                f"burstiness={burstiness:.2f}"))
    else:
        rules.append(RuleResult("high_burstiness", False, 0, f"burstiness={burstiness:.2f}"))

    # ── Suspicious port ───────────────────────────────────────────────────
    if row.get("suspicious_port", 0) >= 1:
        raw_score += 10
        rules.append(RuleResult("suspicious_port", True, 10,
                                f"dst_port={int(row.get('dst_port', 0))}"))
    else:
        rules.append(RuleResult("suspicious_port", False, 0, ""))

    # Clamp to 100
    risk_score = min(raw_score, 100)
    return risk_score, rules


def label_from_score(score: int) -> str:
    if score >= THRESHOLDS["exfiltration_threshold"]:
        return "Possible Exfiltration"
    elif score >= THRESHOLDS["suspicious_threshold"]:
        return "Suspicious"
    return "Benign"


# ---------------------------------------------------------------------------
# Batch detection
# ---------------------------------------------------------------------------

def apply_heuristics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply heuristic scoring to every row in *df*.

    Adds columns:
        heuristic_score  — integer 0–100
        heuristic_label  — 'Benign' | 'Suspicious' | 'Possible Exfiltration'
        triggered_rules  — comma-separated names of triggered rules

    Args:
        df: Feature DataFrame (output of feature_extractor).

    Returns:
        DataFrame with new columns appended.
    """
    scores, labels, rule_lists = [], [], []

    for _, row in df.iterrows():
        score, rules = score_flow(row)
        scores.append(score)
        labels.append(label_from_score(score))
        triggered = [r.rule_name for r in rules if r.triggered]
        rule_lists.append(", ".join(triggered) if triggered else "none")

    df = df.copy()
    df["heuristic_score"] = scores
    df["heuristic_label"] = labels
    df["triggered_rules"] = rule_lists

    suspicious_count = (df["heuristic_label"] != "Benign").sum()
    logger.info("Heuristic detection complete — %d / %d flows flagged",
                suspicious_count, len(df))
    return df
