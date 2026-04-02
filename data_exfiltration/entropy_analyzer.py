"""
entropy_analyzer.py — Stage 4: Shannon entropy calculation for byte sequences.

High entropy (close to 8.0 bits/byte) strongly suggests encrypted, compressed,
or otherwise randomised payloads — a key indicator of covert exfiltration.
"""

from __future__ import annotations
import math
from collections import Counter
from typing import Union

import numpy as np

from utils import setup_logger

logger = setup_logger(__name__)


# ---------------------------------------------------------------------------
# Core entropy functions
# ---------------------------------------------------------------------------

def shannon_entropy(data: Union[bytes, bytearray]) -> float:
    """
    Compute the Shannon entropy of *data* in bits per byte.

    H = - Σ  p(x) · log₂(p(x))

    Args:
        data: Raw bytes to analyse.

    Returns:
        Entropy value in range [0.0, 8.0].
        Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return round(entropy, 6)


def normalised_entropy(data: Union[bytes, bytearray]) -> float:
    """
    Return entropy normalised to [0.0, 1.0].

    1.0 = perfectly uniform (maximally random / encrypted).
    """
    raw = shannon_entropy(data)
    return round(raw / 8.0, 6)


def classify_entropy(entropy_value: float) -> str:
    """
    Heuristic classification of an entropy value.

    Args:
        entropy_value: Shannon entropy in bits/byte (0–8).

    Returns:
        One of: 'low', 'medium', 'high', 'very_high'
    """
    if entropy_value < 3.5:
        return "low"
    elif entropy_value < 5.5:
        return "medium"
    elif entropy_value < 7.0:
        return "high"
    else:
        return "very_high"


def sliding_window_entropy(data: bytes, window: int = 256) -> list[float]:
    """
    Compute entropy over a sliding window across *data*.

    Useful for identifying bursts of high-entropy content within a flow.

    Args:
        data:   Payload bytes.
        window: Window size in bytes.

    Returns:
        List of entropy values (one per window position).
    """
    if len(data) < window:
        return [shannon_entropy(data)]

    results = []
    for i in range(0, len(data) - window + 1, window // 2):
        chunk = data[i: i + window]
        results.append(shannon_entropy(chunk))
    return results


def mean_sliding_entropy(data: bytes, window: int = 256) -> float:
    """Return the mean of sliding-window entropy values."""
    values = sliding_window_entropy(data, window)
    if not values:
        return 0.0
    return float(np.mean(values))
