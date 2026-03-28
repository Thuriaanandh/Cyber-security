"""
feature_extractor.py — Stage 3 & 5: Extract numerical features from flows and
build a pandas DataFrame ready for ML training/inference.
"""

from __future__ import annotations
from typing import Dict, List

import numpy as np
import pandas as pd

from flow_builder import Flow, FlowKey
from entropy_analyzer import shannon_entropy
from utils import setup_logger, safe_divide, protocol_name

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Single-flow feature extraction
# ---------------------------------------------------------------------------

def extract_features(flow: Flow) -> Dict[str, float]:
    """
    Compute all numerical features for a single Flow object.

    Args:
        flow: Aggregated network flow.

    Returns:
        Dictionary of feature_name → float value.
    """
    sizes = flow.packet_sizes if flow.packet_sizes else [0]
    iats = flow.inter_arrival_times if flow.inter_arrival_times else [0.0]

    duration = flow.duration
    packet_count = flow.packet_count
    total_bytes = flow.total_bytes

    # Basic rates
    packet_rate = safe_divide(packet_count, duration)
    byte_rate = safe_divide(total_bytes, duration)
    avg_pkt_size = safe_divide(total_bytes, packet_count)

    # Packet-size statistics
    std_pkt_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0
    min_pkt_size = float(min(sizes))
    max_pkt_size = float(max(sizes))

    # Inter-arrival time statistics
    avg_iat = float(np.mean(iats))
    std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0

    # Burstiness: coefficient of variation of inter-arrival times
    # High burstiness can indicate tunnelled or covert traffic
    burstiness = safe_divide(std_iat, avg_iat) if avg_iat > 0 else 0.0

    # Payload entropy
    entropy = shannon_entropy(flow.payload_bytes)

    # Direction hint: if dst_port < 1024 it is typically "outbound to server"
    is_outbound = 1 if flow.dst_port < 1024 else 0

    # Suspicious port flag (common exfiltration / tunnelling ports)
    suspicious_ports = {53, 443, 80, 8080, 8443, 4444, 1337, 6667, 6666}
    suspicious_port_flag = int(
        flow.dst_port in suspicious_ports or flow.src_port in suspicious_ports
    )

    return {
        "src_port": float(flow.src_port),
        "dst_port": float(flow.dst_port),
        "protocol": float(flow.protocol),
        "packet_count": float(packet_count),
        "total_bytes": float(total_bytes),
        "flow_duration": float(duration),
        "packet_rate": float(packet_rate),
        "byte_rate": float(byte_rate),
        "avg_pkt_size": float(avg_pkt_size),
        "std_pkt_size": float(std_pkt_size),
        "min_pkt_size": float(min_pkt_size),
        "max_pkt_size": float(max_pkt_size),
        "avg_iat": float(avg_iat),
        "std_iat": float(std_iat),
        "burstiness": float(burstiness),
        "entropy": float(entropy),
        "is_outbound": float(is_outbound),
        "suspicious_port": float(suspicious_port_flag),
    }


def extract_metadata(flow: Flow) -> Dict[str, str]:
    """Non-numeric flow identifiers kept for reporting purposes."""
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "protocol_name": protocol_name(flow.protocol),
        "start_time": str(flow.start_time),
        "end_time": str(flow.end_time),
    }


# ---------------------------------------------------------------------------
# Batch extraction → DataFrame
# ---------------------------------------------------------------------------

def flows_to_dataframe(flows: List[Flow], label: str = "unknown") -> pd.DataFrame:
    """
    Convert a list of Flow objects into a pandas DataFrame.

    Args:
        flows: List of Flow objects.
        label: Class label to attach to every row ('benign', 'exfiltration', …).

    Returns:
        DataFrame with one row per flow.
    """
    records = []
    for flow in flows:
        row = {}
        row.update(extract_metadata(flow))
        row.update(extract_features(flow))
        row["label"] = label
        records.append(row)

    if not records:
        logger.warning("No flows provided to flows_to_dataframe — empty DataFrame returned.")
        return pd.DataFrame()

    df = pd.DataFrame(records)
    logger.info("Feature extraction complete — %d flows → DataFrame shape %s",
                len(flows), df.shape)
    return df


# ---------------------------------------------------------------------------
# Feature column list (used by ML modules to select numeric columns)
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "src_port", "dst_port", "protocol",
    "packet_count", "total_bytes", "flow_duration",
    "packet_rate", "byte_rate",
    "avg_pkt_size", "std_pkt_size", "min_pkt_size", "max_pkt_size",
    "avg_iat", "std_iat", "burstiness",
    "entropy", "is_outbound", "suspicious_port",
]
