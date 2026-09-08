"""Standalone CLI script to execute the authoritative live packet capture experiment (SIH 26153)."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from runtime.demo_adapter import DemoAdapter
from runtime.live.backend import inspect_capture_backend
from runtime.live.live_controller import LiveCaptureController
from runtime.live.provenance import EXPERIMENT_DIR


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_live_experiment")


async def main() -> None:
    logger.info("=== Starting Task 15 Live Packet Capture Experiment ===")
    backend = inspect_capture_backend()
    logger.info("TShark binary: %s (v%s)", backend.tshark_path, backend.version_str)
    logger.info("Npcap status: detected=%s, version=%s", backend.has_npcap, backend.npcap_version)
    logger.info("Loopback interface: %s (%s)", backend.loopback_interface.device_name, backend.loopback_interface.description)

    adapter = DemoAdapter()
    controller = LiveCaptureController(adapter=adapter, window_duration_s=10.0)

    # Execute 3 10-second windows with controlled recon_scan traffic
    scenario = "recon_scan"
    windows = 3
    speed = 5.0  # accelerated wall-clock progression (2s per 10s window)

    logger.info("Initiating live capture: scenario=%s, windows=%d, speed=%.1fx", scenario, windows, speed)
    start_status = await controller.start(scenario=scenario, duration_windows=windows, speed=speed)
    logger.info("Live capture started with run_id=%s, pid=%s", controller.run_id, controller.capture.stats.process_pid)

    # Wait for completion of the windows
    if controller._task:
        await controller._task

    # Inspect results
    final_status = controller.get_status()
    logger.info("Live capture completed.")
    logger.info("Packets captured: %d", final_status["packets_captured"])
    logger.info("In scope: %d, Out of scope: %d", final_status["in_scope_packets"], final_status["out_of_scope_packets"])
    logger.info("Isolation passed: %s", final_status["isolation_passed"])
    logger.info("States built: %d", final_status["states_built"])
    logger.info("Forecast events emitted: %d", final_status["events_emitted"])

    # Verify artifacts on disk
    manifest_path = EXPERIMENT_DIR / "run_manifest.json"
    assert manifest_path.is_file(), f"Expected manifest file at {manifest_path}"
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    logger.info("Manifest verification: is_valid_experiment=%s, run_id=%s", manifest["is_valid_experiment"], manifest["run_id"])
    logger.info("Cryptographic digests: packets=%s, states=%s, events=%s",
                manifest["cryptographic_integrity"]["packets_sha256"][:12] + "...",
                manifest["cryptographic_integrity"]["states_sha256"][:12] + "...",
                manifest["cryptographic_integrity"]["events_sha256"][:12] + "...")

    logger.info("All artifacts persisted to: %s", EXPERIMENT_DIR.resolve())


if __name__ == "__main__":
    asyncio.run(main())
