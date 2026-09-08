"""Subprocess manager for live TShark packet capture on Windows loopback with empirical isolation validation (SIH 26153)."""
from __future__ import annotations

import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Sequence, Set

from runtime.live.backend import find_tshark_executable, get_verified_loopback_interface
from runtime.live.packet_parser import (
    ParsedPacket,
    TSHARK_FIELD_ARGS,
    parse_tshark_line,
)

logger = logging.getLogger("live_packet_capture")


@dataclass
class CaptureSessionStats:
    interface_name: str
    bpf_filter: str
    start_time: float = 0.0
    end_time: float = 0.0
    packets_captured: int = 0
    in_scope_packets: int = 0
    out_of_scope_packets: int = 0
    isolation_violations: List[str] = field(default_factory=list)
    is_active: bool = False
    process_pid: int | None = None


class LivePacketCapture:
    """Controls a TShark capture subprocess on \\Device\\NPF_Loopback.
    
    Streams parsed packets into memory and validates that all packets
    belong strictly to the intended localhost experiment scope.
    """

    def __init__(
        self,
        allowed_ports: Sequence[int] = (8765, 8766, 8767, 8768, 8769, 8770),
        allowed_ips: Sequence[str] = ("127.0.0.1", "::1"),
        custom_bpf_filter: str | None = None,
    ) -> None:
        self.allowed_ports: Set[int] = set(allowed_ports)
        self.allowed_ips: Set[str] = set(allowed_ips)
        self.tshark_path = find_tshark_executable()
        self.loopback_iface = get_verified_loopback_interface()

        if custom_bpf_filter:
            self.bpf_filter = custom_bpf_filter
        else:
            # Build restrictive BPF filter matching the designated ports on loopback
            port_clauses = " or ".join(f"port {p}" for p in self.allowed_ports)
            self.bpf_filter = f"tcp and ({port_clauses})"

        self.stats = CaptureSessionStats(
            interface_name=self.loopback_iface.device_name,
            bpf_filter=self.bpf_filter,
        )

        self._process: subprocess.Popen[str] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._packets: List[ParsedPacket] = []
        self._lock = threading.Lock()

    @property
    def is_active(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> None:
        """Spawn the TShark capture process and start stdout stream reading."""
        if self.is_active:
            return

        cmd = [
            str(self.tshark_path),
            "-i", self.loopback_iface.device_name,
            "-f", self.bpf_filter,
            "-l",  # Flush stdout on every packet
            *TSHARK_FIELD_ARGS,
        ]

        logger.info("Starting TShark with command: %s", " ".join(cmd))

        self._stop_event.clear()
        with self._lock:
            self._packets.clear()

        self.stats = CaptureSessionStats(
            interface_name=self.loopback_iface.device_name,
            bpf_filter=self.bpf_filter,
            start_time=time.time(),
            is_active=True,
        )

        # Launch TShark with unbuffered/line-buffered text pipe
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.stats.process_pid = self._process.pid

        # Start stdout reader thread
        self._reader_thread = threading.Thread(
            target=self._read_stdout,
            daemon=True,
        )
        self._reader_thread.start()

    def _read_stdout(self) -> None:
        if not self._process or not self._process.stdout:
            return

        for line in iter(self._process.stdout.readline, ""):
            if self._stop_event.is_set():
                break
            if not line:
                continue

            packet = parse_tshark_line(
                line,
                allowed_ips=self.allowed_ips,
                allowed_ports=self.allowed_ports,
            )
            if packet is not None:
                with self._lock:
                    self._packets.append(packet)
                    self.stats.packets_captured += 1
                    if packet.is_in_scope:
                        self.stats.in_scope_packets += 1
                    else:
                        self.stats.out_of_scope_packets += 1
                        violation_msg = (
                            f"Packet at {packet.timestamp}: {packet.isolation_violation_reason}"
                        )
                        self.stats.isolation_violations.append(violation_msg)
                        logger.warning("ISOLATION VIOLATION: %s", violation_msg)

    def get_packets(self) -> List[ParsedPacket]:
        """Return a copy of all packets captured so far."""
        with self._lock:
            return list(self._packets)

    def get_packets_in_range(self, start_ts: float, end_ts: float) -> List[ParsedPacket]:
        """Return packets strictly within [start_ts, end_ts) for causal windowing."""
        with self._lock:
            return [
                p for p in self._packets
                if start_ts <= p.timestamp < end_ts
            ]

    def stop(self) -> CaptureSessionStats:
        """Stop TShark capture and ensure complete process termination without orphans."""
        self._stop_event.set()

        if self._process:
            pid = self._process.pid
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    self._process.kill()
                    self._process.wait(timeout=2.0)
                except OSError:
                    pass
            self._process = None

        if self._reader_thread:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None

        self.stats.end_time = time.time()
        self.stats.is_active = False
        return self.stats
