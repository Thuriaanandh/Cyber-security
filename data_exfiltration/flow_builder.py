"""
flow_builder.py — Stage 2: Aggregate individual packets into bidirectional flows.

A *flow* is identified by the 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)

All packets belonging to that 5-tuple are grouped regardless of direction
(i.e. the reverse direction is normalised so the smaller IP is always "src").
"""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from pcap_parser import PacketRecord
from utils import setup_logger

logger = setup_logger(__name__)

# Flow key type alias
FlowKey = Tuple[str, str, int, int, int]


@dataclass
class Flow:
    """Aggregated network flow built from individual PacketRecords."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    packet_count: int = 0
    total_bytes: int = 0
    start_time: float = float("inf")
    end_time: float = 0.0

    # Per-packet lists — used for statistical feature extraction
    packet_sizes: List[int] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)  # seconds
    payload_bytes: bytes = field(default_factory=bytes)

    _last_timestamp: float = field(default=0.0, repr=False)

    # ------------------------------------------------------------------ #
    def update(self, pkt: PacketRecord) -> None:
        """Incorporate a single PacketRecord into this flow."""
        self.packet_count += 1
        self.total_bytes += pkt.length
        self.packet_sizes.append(pkt.length)
        self.payload_bytes += pkt.payload

        # Time tracking
        if pkt.timestamp < self.start_time:
            self.start_time = pkt.timestamp
        if pkt.timestamp > self.end_time:
            self.end_time = pkt.timestamp

        # Inter-arrival time
        if self._last_timestamp > 0:
            iat = pkt.timestamp - self._last_timestamp
            self.inter_arrival_times.append(max(iat, 0.0))
        self._last_timestamp = pkt.timestamp

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(self.end_time - self.start_time, 0.0)

    @property
    def key(self) -> FlowKey:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

def _normalise_key(pkt: PacketRecord) -> FlowKey:
    """
    Return a canonical 5-tuple so that forward and reverse packets map
    to the same flow.  We sort by (ip, port) pair lexicographically.
    """
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    if a <= b:
        return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
    else:
        return (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)


def build_flows(packets: List[PacketRecord]) -> Dict[FlowKey, Flow]:
    """
    Aggregate a list of PacketRecords into flows.

    Args:
        packets: Flat list of PacketRecord objects (output of pcap_parser).

    Returns:
        Dictionary mapping FlowKey → Flow.
    """
    flows: Dict[FlowKey, Flow] = {}

    for pkt in packets:
        key = _normalise_key(pkt)

        if key not in flows:
            flows[key] = Flow(
                src_ip=key[0],
                dst_ip=key[1],
                src_port=key[2],
                dst_port=key[3],
                protocol=key[4],
            )

        flows[key].update(pkt)

    logger.info("Flow building complete — %d unique flows from %d packets",
                len(flows), len(packets))
    return flows


def flows_to_list(flows: Dict[FlowKey, Flow]) -> List[Flow]:
    """Return flows as a plain list (convenient for iteration)."""
    return list(flows.values())
