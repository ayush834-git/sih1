"""Controlled localhost-only TCP traffic generator and safe echo sink server (SIH 26153)."""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from typing import List, Sequence, Set


@dataclass
class GeneratorStats:
    scenario: str
    target_ports: List[int]
    start_time: float = 0.0
    end_time: float = 0.0
    connections_attempted: int = 0
    connections_succeeded: int = 0
    bytes_sent: int = 0
    packets_estimate: int = 0
    is_running: bool = False


class LocalEchoServer:
    """Multi-port lightweight TCP sink/echo server bound strictly to 127.0.0.1."""

    def __init__(self, ports: Sequence[int] = (8765, 8766, 8767, 8768, 8769, 8770)) -> None:
        self.ports = list(ports)
        self.sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        for port in self.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                s.listen(128)
                s.settimeout(0.5)
                self.sockets.append(s)
                t = threading.Thread(target=self._listen_loop, args=(s,), daemon=True)
                t.start()
                self._threads.append(t)
            except OSError as e:
                # If a port is temporarily in use, close any already opened
                self.stop()
                raise RuntimeError(f"Failed to bind local echo server to 127.0.0.1:{port}: {e}") from e

    def _listen_loop(self, s: socket.socket) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            # Handle client in background worker
            threading.Thread(target=self._client_handler, args=(conn,), daemon=True).start()

    def _client_handler(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(1.0)
            while not self._stop_event.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                # Echo small response or ack
                conn.sendall(b"ACK:" + data[:16])
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop_event.set()
        for s in self.sockets:
            try:
                s.close()
            except OSError:
                pass
        self.sockets.clear()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()


class ControlledTrafficGenerator:
    """Generates strictly localhost TCP traffic according to controlled profiles."""

    def __init__(
        self,
        ports: Sequence[int] = (8765, 8766, 8767, 8768, 8769),
    ) -> None:
        self.ports = list(ports)
        self.server = LocalEchoServer(ports=self.ports)
        self.stats = GeneratorStats(scenario="none", target_ports=self.ports)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, scenario: str = "baseline", speed: float = 1.0) -> None:
        """Start both the local echo server and traffic generation thread."""
        if self.stats.is_running:
            return

        self.server.start()
        self.stats = GeneratorStats(
            scenario=scenario,
            target_ports=self.ports,
            start_time=time.time(),
            is_running=True,
        )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_scenario,
            args=(scenario, speed),
            daemon=True,
        )
        self._thread.start()

    def _run_scenario(self, scenario: str, speed: float) -> None:
        delay_scale = max(0.1, 1.0 / max(speed, 0.1))

        if scenario == "recon_scan":
            self._scenario_recon_scan(delay_scale)
        elif scenario == "sustained":
            self._scenario_sustained(delay_scale)
        elif scenario == "burst":
            self._scenario_burst(delay_scale)
        elif scenario == "churn":
            self._scenario_churn(delay_scale)
        else:
            self._scenario_baseline(delay_scale)

    def _send_probe(self, port: int, payload_bytes: int = 256) -> bool:
        self.stats.connections_attempted += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", port))
            payload = b"X" * payload_bytes
            s.sendall(payload)
            self.stats.bytes_sent += len(payload)
            # Read echo response
            _ = s.recv(1024)
            s.close()
            self.stats.connections_succeeded += 1
            return True
        except (socket.timeout, OSError):
            return False

    def _scenario_baseline(self, delay_scale: float) -> None:
        """Steady low-volume periodic pings on port 8765."""
        while not self._stop_event.is_set():
            self._send_probe(self.ports[0], payload_bytes=128)
            time.sleep(1.0 * delay_scale)

    def _scenario_sustained(self, delay_scale: float) -> None:
        """Continuous steady TCP traffic on port 8765."""
        while not self._stop_event.is_set():
            self._send_probe(self.ports[0], payload_bytes=2048)
            time.sleep(0.2 * delay_scale)

    def _scenario_recon_scan(self, delay_scale: float) -> None:
        """Probes multiple ports in round-robin fashion, producing high port diversity."""
        idx = 0
        while not self._stop_event.is_set():
            port = self.ports[idx % len(self.ports)]
            self._send_probe(port, payload_bytes=64)
            idx += 1
            time.sleep(0.3 * delay_scale)

    def _scenario_burst(self, delay_scale: float) -> None:
        """Short bursts of concurrent probes followed by quiet periods."""
        while not self._stop_event.is_set():
            threads = []
            for _ in range(5):
                t = threading.Thread(target=self._send_probe, args=(self.ports[0], 512))
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=1.0)
            time.sleep(2.0 * delay_scale)

    def _scenario_churn(self, delay_scale: float) -> None:
        """Rapid connect and close cycles."""
        while not self._stop_event.is_set():
            self._send_probe(self.ports[0], payload_bytes=16)
            time.sleep(0.05 * delay_scale)

    def stop(self) -> GeneratorStats:
        """Stop traffic generation and the local echo server cleanly."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

        self.server.stop()
        self.stats.end_time = time.time()
        self.stats.is_running = False
        return self.stats
