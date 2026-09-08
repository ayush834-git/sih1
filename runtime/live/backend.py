"""Discovery and verification of Windows Npcap and TShark capture backend (SIH 26153)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


STANDARD_TSHARK_PATHS = [
    Path(r"C:\Program Files\Wireshark\tshark.exe"),
    Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
]


@dataclass(frozen=True)
class CaptureInterface:
    index: int
    device_name: str
    description: str
    is_loopback: bool


@dataclass(frozen=True)
class BackendInfo:
    tshark_path: str
    version_str: str
    has_npcap: bool
    npcap_version: str
    interfaces: Sequence[CaptureInterface]
    loopback_interface: CaptureInterface | None


def find_tshark_executable() -> Path:
    """Locate the tshark executable on Windows using standard paths and PATH."""
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    which_path = shutil.which("tshark")
    if which_path and Path(which_path).is_file():
        return Path(which_path)

    for standard_path in STANDARD_TSHARK_PATHS:
        if standard_path.is_file():
            return standard_path

    raise FileNotFoundError(
        "tshark executable not found. Verified locations checked: PATH, "
        f"{[str(p) for p in STANDARD_TSHARK_PATHS]}"
    )


def inspect_capture_backend() -> BackendInfo:
    """Query TShark to discover installed version, Npcap capability, and interfaces."""
    tshark_path = find_tshark_executable()

    # 1. Inspect version and Npcap info via tshark -v
    proc_v = subprocess.run(
        [str(tshark_path), "-v"],
        capture_output=True,
        text=True,
        check=True,
    )
    v_output = proc_v.stdout
    version_match = re.search(r"TShark \(Wireshark\) ([\d\.]+)", v_output)
    version_str = version_match.group(1) if version_match else "unknown"

    npcap_match = re.search(r"Npcap\s+([\d\.]+)", v_output, re.IGNORECASE)
    has_npcap = bool(npcap_match) or ("libpcap" in v_output.lower() and "win" in v_output.lower())
    npcap_version = npcap_match.group(1) if npcap_match else ("detected" if has_npcap else "none")

    # 2. Enumerate interfaces via tshark -D
    proc_d = subprocess.run(
        [str(tshark_path), "-D"],
        capture_output=True,
        text=True,
        check=True,
    )
    interfaces: list[CaptureInterface] = []
    loopback_iface: CaptureInterface | None = None

    # Line format: "1. \\Device\\NPF_{...} (Friendly Name)" or "8. \\Device\\NPF_Loopback (Adapter...)"
    pattern = re.compile(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$")
    for line in proc_d.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if match:
            idx = int(match.group(1))
            dev_name = match.group(2)
            desc = match.group(3) or ""
            is_loopback = (
                "loopback" in dev_name.lower()
                or "loopback" in desc.lower()
                or dev_name == r"\Device\NPF_Loopback"
            )
            iface = CaptureInterface(
                index=idx,
                device_name=dev_name,
                description=desc,
                is_loopback=is_loopback,
            )
            interfaces.append(iface)
            if is_loopback and loopback_iface is None:
                loopback_iface = iface

    return BackendInfo(
        tshark_path=str(tshark_path),
        version_str=version_str,
        has_npcap=has_npcap,
        npcap_version=npcap_version,
        interfaces=tuple(interfaces),
        loopback_interface=loopback_iface,
    )


def get_verified_loopback_interface() -> CaptureInterface:
    """Discover and return the verified \\Device\\NPF_Loopback capture interface."""
    info = inspect_capture_backend()
    if not info.has_npcap:
        raise RuntimeError("Npcap is required for Windows packet capture but was not detected in TShark runtime info.")
    if not info.loopback_interface:
        raise RuntimeError(
            "No loopback interface (\\Device\\NPF_Loopback) found among enumerated interfaces: "
            f"{[i.device_name for i in info.interfaces]}"
        )
    return info.loopback_interface
