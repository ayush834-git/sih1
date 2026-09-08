"""Packet parser for TShark field-delimited stream with strict isolation validation (SIH 26153)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Set


@dataclass(frozen=True)
class ParsedPacket:
    timestamp: float          # Epoch seconds with microsecond resolution
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int             # 6 for TCP
    frame_len: int            # Wire bytes
    payload_len: int          # TCP payload bytes
    syn: bool
    ack: bool
    rst: bool
    fin: bool
    psh: bool
    raw_flags: str            # e.g. "0x0002"
    ttl: int | None
    window_size: int | None
    packet_hash: str          # Deterministic SHA-256 of packet contents
    is_in_scope: bool = True  # True if packet strictly belongs to localhost experiment
    isolation_violation_reason: str | None = None
    urg: bool = False
    is_fragment: bool = False
    frag_offset: int = 0
    is_retransmission: bool = False


# Wireshark -T fields specification
TSHARK_FIELD_ARGS = [
    "-T", "fields",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "ip.proto",
    "-e", "frame.len",
    "-e", "tcp.len",
    "-e", "tcp.flags.syn",
    "-e", "tcp.flags.ack",
    "-e", "tcp.flags.reset",
    "-e", "tcp.flags.fin",
    "-e", "tcp.flags.push",
    "-e", "tcp.flags",
    "-e", "ip.ttl",
    "-e", "tcp.window_size",
    "-e", "tcp.flags.urg",
    "-e", "ip.flags.mf",
    "-e", "ip.frag_offset",
    "-e", "tcp.analysis.retransmission",
    "-E", "separator=\t",
]


def _parse_bool(val: str) -> bool:
    val = val.strip().lower()
    return val in ("1", "true", "t", "yes")


def _parse_int(val: str, default: int = 0) -> int:
    val = val.strip()
    if not val:
        return default
    # Handle comma-separated multiple values (take first)
    if "," in val:
        val = val.split(",")[0].strip()
    try:
        if val.startswith("0x") or val.startswith("0X"):
            return int(val, 16)
        return int(val)
    except ValueError:
        return default


def _parse_float(val: str, default: float = 0.0) -> float:
    val = val.strip()
    if not val:
        return default
    if "," in val:
        val = val.split(",")[0].strip()
    try:
        return float(val)
    except ValueError:
        return default


def parse_tshark_line(
    line: str,
    allowed_ips: Set[str] | None = None,
    allowed_ports: Set[int] | None = None,
) -> ParsedPacket | None:
    """Parse a single tab-separated line from TShark stdout into a ParsedPacket.
    
    Returns None if line is empty or a non-data header/footer line.
    Empirically validates whether the packet belongs strictly to the intended
    experiment scope.
    """
    line = line.strip("\r\n")
    if not line:
        return None

    parts = line.split("\t")
    if len(parts) < 14:
        # Malformed or header/status message line (e.g. "Capturing on...")
        return None

    time_str = parts[0].strip()
    try:
        timestamp = float(time_str)
    except ValueError:
        # Not a data packet line
        return None

    src_ip = parts[1].strip().split(",")[0]
    dst_ip = parts[2].strip().split(",")[0]
    src_port = _parse_int(parts[3])
    dst_port = _parse_int(parts[4])
    protocol = _parse_int(parts[5], default=6)
    frame_len = _parse_int(parts[6])
    payload_len = _parse_int(parts[7])
    syn = _parse_bool(parts[8])
    ack = _parse_bool(parts[9])
    rst = _parse_bool(parts[10])
    fin = _parse_bool(parts[11])
    psh = _parse_bool(parts[12]) if len(parts) > 12 else False
    raw_flags = parts[13].strip() if len(parts) > 13 else "0x0000"
    ttl = _parse_int(parts[14]) if len(parts) > 14 and parts[14].strip() else None
    window_size = _parse_int(parts[15]) if len(parts) > 15 and parts[15].strip() else None

    # Extended PS-required packet fields: URG, IP fragments, retransmissions
    urg = _parse_bool(parts[16]) if len(parts) > 16 and parts[16].strip() else False
    if not urg and raw_flags:
        try:
            f_int = int(raw_flags, 16) if raw_flags.startswith("0x") else int(raw_flags)
            if f_int & 0x0020:
                urg = True
        except ValueError:
            pass

    is_mf = _parse_bool(parts[17]) if len(parts) > 17 and parts[17].strip() else False
    frag_offset = _parse_int(parts[18]) if len(parts) > 18 and parts[18].strip() else 0
    is_fragment = is_mf or (frag_offset > 0)
    is_retransmission = _parse_bool(parts[19]) if len(parts) > 19 and parts[19].strip() else False

    # Derive canonical SHA-256 digest of packet attributes
    digest_src = f"{timestamp:.6f}|{src_ip}:{src_port}|{dst_ip}:{dst_port}|{protocol}|{frame_len}|{raw_flags}"
    packet_hash = hashlib.sha256(digest_src.encode()).hexdigest()

    # Empirical isolation verification:
    is_in_scope = True
    violation_reason = None

    if allowed_ips is not None:
        if src_ip not in allowed_ips or dst_ip not in allowed_ips:
            is_in_scope = False
            violation_reason = f"IP out of scope: src={src_ip}, dst={dst_ip} (expected {allowed_ips})"

    if is_in_scope and allowed_ports is not None:
        if src_port not in allowed_ports and dst_port not in allowed_ports:
            is_in_scope = False
            violation_reason = f"Port out of scope: sport={src_port}, dport={dst_port} (expected {allowed_ports})"

    return ParsedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        frame_len=frame_len,
        payload_len=payload_len,
        syn=syn,
        ack=ack,
        rst=rst,
        fin=fin,
        psh=psh,
        raw_flags=raw_flags,
        ttl=ttl,
        window_size=window_size,
        packet_hash=packet_hash,
        is_in_scope=is_in_scope,
        isolation_violation_reason=violation_reason,
        urg=urg,
        is_fragment=is_fragment,
        frag_offset=frag_offset,
        is_retransmission=is_retransmission,
    )
