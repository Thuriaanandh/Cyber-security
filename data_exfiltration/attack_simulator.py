"""
attack_simulator.py — Stage 8: Generate synthetic network flow records that
mimic known data-exfiltration patterns.

Produces labelled DataFrames (or CSV files) that can be used to:
  • Augment real traffic for ML training.
  • Unit-test the detection pipeline without a real PCAP.

Attack profiles implemented
───────────────────────────
1. dns_tunneling      — Many small UDP/53 flows with very high entropy payloads.
2. https_upload       — Large TCP/443 flows with high byte-rate.
3. covert_high_entropy— Random high-entropy bursts on unusual ports.
4. slow_exfil         — Low-and-slow: small packets over very long durations.
"""

from __future__ import annotations
import random
import string
from typing import List, Dict, Any

import numpy as np
import pandas as pd

from feature_extractor import FEATURE_COLUMNS
from utils import setup_logger

logger = setup_logger(__name__)

RNG = np.random.default_rng(seed=42)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_ip() -> str:
    return ".".join(str(RNG.integers(1, 254)) for _ in range(4))


def _rand_private_ip() -> str:
    return f"192.168.{RNG.integers(0,255)}.{RNG.integers(1,254)}"


def _high_entropy_bytes(n: int) -> bytes:
    """Return n pseudo-random bytes (simulates encrypted payload)."""
    return bytes(RNG.integers(0, 256, size=n, dtype=np.uint8))


def _entropy_of_bytes(data: bytes) -> float:
    """Quick Shannon entropy — avoids importing entropy_analyzer here."""
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ---------------------------------------------------------------------------
# Attack profile generators
# ---------------------------------------------------------------------------

def _generate_dns_tunneling(n: int) -> List[Dict[str, Any]]:
    """DNS tunnelling: frequent small bursts to port 53 with high entropy."""
    rows = []
    for _ in range(n):
        total_bytes = int(RNG.integers(500, 8_000))
        pkt_count = int(RNG.integers(10, 60))
        duration = float(RNG.uniform(0.5, 30.0))
        payload = _high_entropy_bytes(total_bytes)

        rows.append({
            "src_ip": _rand_private_ip(),
            "dst_ip": _rand_ip(),
            "src_port": int(RNG.integers(49152, 65535)),
            "dst_port": 53,
            "protocol": 17,          # UDP
            "protocol_name": "UDP",
            "packet_count": pkt_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packet_rate": pkt_count / duration,
            "byte_rate": total_bytes / duration,
            "avg_pkt_size": total_bytes / pkt_count,
            "std_pkt_size": float(RNG.uniform(5, 30)),
            "min_pkt_size": 60.0,
            "max_pkt_size": 512.0,
            "avg_iat": duration / pkt_count,
            "std_iat": float(RNG.uniform(0.01, 0.5)),
            "burstiness": float(RNG.uniform(1.5, 4.0)),
            "entropy": _entropy_of_bytes(payload),
            "is_outbound": 1,
            "suspicious_port": 1,
            "start_time": str(RNG.uniform(1_700_000_000, 1_710_000_000)),
            "end_time": str(RNG.uniform(1_700_000_000 + duration, 1_710_000_000)),
            "label": "exfiltration",
            "attack_type": "dns_tunneling",
        })
    return rows


def _generate_https_upload(n: int) -> List[Dict[str, Any]]:
    """HTTPS exfiltration: large flows to port 443 with very high entropy."""
    rows = []
    for _ in range(n):
        total_bytes = int(RNG.integers(500_000, 50_000_000))
        pkt_count = int(RNG.integers(500, 50_000))
        duration = float(RNG.uniform(10, 3600))
        payload = _high_entropy_bytes(min(total_bytes, 10_000))

        rows.append({
            "src_ip": _rand_private_ip(),
            "dst_ip": _rand_ip(),
            "src_port": int(RNG.integers(49152, 65535)),
            "dst_port": 443,
            "protocol": 6,            # TCP
            "protocol_name": "TCP",
            "packet_count": pkt_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packet_rate": pkt_count / duration,
            "byte_rate": total_bytes / duration,
            "avg_pkt_size": total_bytes / pkt_count,
            "std_pkt_size": float(RNG.uniform(50, 500)),
            "min_pkt_size": 40.0,
            "max_pkt_size": 1500.0,
            "avg_iat": duration / pkt_count,
            "std_iat": float(RNG.uniform(0.0001, 0.01)),
            "burstiness": float(RNG.uniform(0.3, 1.2)),
            "entropy": _entropy_of_bytes(payload),
            "is_outbound": 1,
            "suspicious_port": 1,
            "start_time": str(RNG.uniform(1_700_000_000, 1_710_000_000)),
            "end_time": str(RNG.uniform(1_700_000_000 + duration, 1_710_000_000)),
            "label": "exfiltration",
            "attack_type": "https_upload",
        })
    return rows


def _generate_covert_high_entropy(n: int) -> List[Dict[str, Any]]:
    """High-entropy flows on unusual/suspicious ports."""
    unusual_ports = [4444, 1337, 6667, 8443, 9001, 31337]
    rows = []
    for _ in range(n):
        total_bytes = int(RNG.integers(10_000, 5_000_000))
        pkt_count = int(RNG.integers(50, 5000))
        duration = float(RNG.uniform(5, 900))
        payload = _high_entropy_bytes(min(total_bytes, 5_000))
        dst_port = int(RNG.choice(unusual_ports))

        rows.append({
            "src_ip": _rand_private_ip(),
            "dst_ip": _rand_ip(),
            "src_port": int(RNG.integers(49152, 65535)),
            "dst_port": dst_port,
            "protocol": 6,
            "protocol_name": "TCP",
            "packet_count": pkt_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packet_rate": pkt_count / duration,
            "byte_rate": total_bytes / duration,
            "avg_pkt_size": total_bytes / pkt_count,
            "std_pkt_size": float(RNG.uniform(20, 400)),
            "min_pkt_size": 40.0,
            "max_pkt_size": 1500.0,
            "avg_iat": duration / pkt_count,
            "std_iat": float(RNG.uniform(0.001, 0.1)),
            "burstiness": float(RNG.uniform(0.8, 3.0)),
            "entropy": _entropy_of_bytes(payload),
            "is_outbound": 1,
            "suspicious_port": 1,
            "start_time": str(RNG.uniform(1_700_000_000, 1_710_000_000)),
            "end_time": str(RNG.uniform(1_700_000_000 + duration, 1_710_000_000)),
            "label": "exfiltration",
            "attack_type": "covert_high_entropy",
        })
    return rows


def _generate_slow_exfil(n: int) -> List[Dict[str, Any]]:
    """Low-and-slow: tiny packets over very long durations to avoid rate thresholds."""
    rows = []
    for _ in range(n):
        total_bytes = int(RNG.integers(50_000, 2_000_000))
        pkt_count = int(RNG.integers(100, 2000))
        duration = float(RNG.uniform(3600, 86400))     # 1h – 24h
        payload = _high_entropy_bytes(min(total_bytes, 2_000))

        rows.append({
            "src_ip": _rand_private_ip(),
            "dst_ip": _rand_ip(),
            "src_port": int(RNG.integers(49152, 65535)),
            "dst_port": 443,
            "protocol": 6,
            "protocol_name": "TCP",
            "packet_count": pkt_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packet_rate": pkt_count / duration,
            "byte_rate": total_bytes / duration,
            "avg_pkt_size": total_bytes / pkt_count,
            "std_pkt_size": float(RNG.uniform(5, 50)),
            "min_pkt_size": 40.0,
            "max_pkt_size": 200.0,
            "avg_iat": duration / pkt_count,
            "std_iat": float(RNG.uniform(1, 60)),
            "burstiness": float(RNG.uniform(1.0, 5.0)),
            "entropy": _entropy_of_bytes(payload),
            "is_outbound": 1,
            "suspicious_port": 1,
            "start_time": str(RNG.uniform(1_700_000_000, 1_710_000_000)),
            "end_time": str(RNG.uniform(1_700_000_000 + duration, 1_710_000_000)),
            "label": "suspicious",
            "attack_type": "slow_exfil",
        })
    return rows


def _generate_benign(n: int) -> List[Dict[str, Any]]:
    """Normal web / background traffic."""
    normal_ports = [80, 443, 8080, 22, 25, 587, 993, 3306, 5432]
    rows = []
    for _ in range(n):
        total_bytes = int(RNG.integers(200, 200_000))
        pkt_count = int(RNG.integers(2, 500))
        duration = float(RNG.uniform(0.01, 120))
        dst_port = int(RNG.choice(normal_ports))
        # Benign payloads have lower entropy (structured protocols / text)
        entropy = float(RNG.uniform(3.0, 6.5))

        rows.append({
            "src_ip": _rand_private_ip(),
            "dst_ip": _rand_ip(),
            "src_port": int(RNG.integers(49152, 65535)),
            "dst_port": dst_port,
            "protocol": 6,
            "protocol_name": "TCP",
            "packet_count": pkt_count,
            "total_bytes": total_bytes,
            "flow_duration": duration,
            "packet_rate": pkt_count / duration,
            "byte_rate": total_bytes / duration,
            "avg_pkt_size": total_bytes / pkt_count,
            "std_pkt_size": float(RNG.uniform(10, 300)),
            "min_pkt_size": 40.0,
            "max_pkt_size": 1500.0,
            "avg_iat": duration / pkt_count,
            "std_iat": float(RNG.uniform(0.001, 2)),
            "burstiness": float(RNG.uniform(0.1, 1.5)),
            "entropy": entropy,
            "is_outbound": int(RNG.integers(0, 2)),
            "suspicious_port": 0,
            "start_time": str(RNG.uniform(1_700_000_000, 1_710_000_000)),
            "end_time": str(RNG.uniform(1_700_000_000 + duration, 1_710_000_000)),
            "label": "benign",
            "attack_type": "benign",
        })
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_dataset(
    n_benign: int = 1000,
    n_dns: int = 200,
    n_https: int = 200,
    n_covert: int = 200,
    n_slow: int = 150,
    save_path: str = None,
) -> pd.DataFrame:
    """
    Create a labelled synthetic dataset combining benign and attack flows.

    Args:
        n_benign:   Number of benign flow samples.
        n_dns:      DNS tunnelling samples.
        n_https:    HTTPS upload samples.
        n_covert:   Covert high-entropy samples.
        n_slow:     Slow-exfil samples.
        save_path:  If provided, write CSV to this path.

    Returns:
        Labelled pandas DataFrame.
    """
    rows: List[Dict] = []
    rows.extend(_generate_benign(n_benign))
    rows.extend(_generate_dns_tunneling(n_dns))
    rows.extend(_generate_https_upload(n_https))
    rows.extend(_generate_covert_high_entropy(n_covert))
    rows.extend(_generate_slow_exfil(n_slow))

    df = pd.DataFrame(rows)

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    logger.info("Synthetic dataset generated: %d rows  (benign=%d, attack=%d)",
                len(df), n_benign, len(df) - n_benign)

    if save_path:
        df.to_csv(save_path, index=False)
        logger.info("Dataset saved to %s", save_path)

    return df
