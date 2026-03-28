"""
pcap_parser.py — Stage 1: Parse PCAP files and yield individual packet records.

Supports both scapy (preferred) and a fallback pure-Python stub so the rest
of the pipeline can still run when scapy is not installed (e.g. during unit
tests with synthetic data).
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Iterator, List
from utils import setup_logger

logger = setup_logger(__name__)


@dataclass
class PacketRecord:
    """Lightweight representation of a single parsed packet."""
    timestamp: float          # Unix epoch float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int             # IP proto number  (6=TCP, 17=UDP, …)
    length: int               # total packet length (bytes)
    payload: bytes = field(default_factory=bytes)  # raw payload


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_pcap(pcap_path: str) -> Iterator[PacketRecord]:
    """
    Yield PacketRecord objects for every IP packet in *pcap_path*.

    Tries scapy first; falls back to an informative error if scapy is absent.

    Args:
        pcap_path: Path to the .pcap / .pcapng file.

    Yields:
        PacketRecord for each parseable IP packet.
    """
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    try:
        from scapy.all import PcapReader, IP, TCP, UDP, Raw  # type: ignore
        logger.info("Parsing PCAP with scapy: %s", pcap_path)
        yield from _parse_with_scapy(pcap_path)
    except ImportError:
        logger.warning("scapy not installed — cannot parse real PCAP files. "
                       "Use the attack_simulator to generate synthetic data.")
        return


def _parse_with_scapy(pcap_path: str) -> Iterator[PacketRecord]:
    """Internal: parse using scapy's streaming PcapReader (memory-efficient)."""
    from scapy.all import PcapReader, IP, TCP, UDP, Raw  # type: ignore

    parsed = 0
    skipped = 0

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            try:
                if not pkt.haslayer(IP):
                    skipped += 1
                    continue

                ip = pkt[IP]
                proto = ip.proto

                # Extract transport-layer ports
                src_port, dst_port = 0, 0
                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    from scapy.all import UDP as ScapyUDP
                    src_port = pkt[ScapyUDP].sport
                    dst_port = pkt[ScapyUDP].dport

                # Raw payload bytes (application layer)
                payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

                record = PacketRecord(
                    timestamp=float(pkt.time),
                    src_ip=str(ip.src),
                    dst_ip=str(ip.dst),
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    length=len(pkt),
                    payload=payload,
                )
                parsed += 1
                yield record

            except Exception as exc:
                logger.debug("Skipping malformed packet: %s", exc)
                skipped += 1

    logger.info("PCAP parsing complete — %d packets parsed, %d skipped", parsed, skipped)


# ---------------------------------------------------------------------------
# Convenience loader (returns list, fine for smaller files)
# ---------------------------------------------------------------------------

def load_packets(pcap_path: str) -> List[PacketRecord]:
    """Load all packet records from a PCAP file into a list."""
    return list(parse_pcap(pcap_path))
