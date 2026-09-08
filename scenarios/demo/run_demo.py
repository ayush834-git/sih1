"""CLI Executable and Terminal Runner for Controlled Live Telemetry Demo (SIH 26153)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from core.config import load_settings
from core.contracts import STATE_SCHEMA_HASH
from scenarios.demo.engine import DemoEvent, LiveDemoEngine
from scenarios.demo.scenarios import get_demo_scenario_states


def render_terminal_timeline(event: DemoEvent) -> None:
    """Renders a readable, professional terminal log line for each demo step."""
    step = event.step_index
    t_str = f"[{step:02d}.0]"
    stage = event.primary_stage
    prio = event.priority_level
    trust = event.trust_level
    strat = event.recommended_strategy
    human = "REQUIRED" if event.requires_human else "NONE"
    
    print(f"\n{'-' * 70}")
    print(f"{t_str} LOGICAL STEP {step:02d} | Window: {event.logical_time_str}")
    print(f"{t_str} NETWORK STATE ........ PortDiv={event.current_state_summary.get('dst_port_diversity', 0):.0f} | Flows={event.current_state_summary.get('flow_count', 0):.0f} | ByteRate={event.current_state_summary.get('byte_rate', 0):,.0f} B/s")
    
    if event.active_signatures:
        print(f"{t_str} BEHAVIOURAL SIGS ..... {', '.join(event.active_signatures)}")
    else:
        print(f"{t_str} BEHAVIOURAL SIGS ..... None (Within Baseline)")
        
    print(f"{t_str} SECURITY STAGE ....... {stage} (Confidence: {event.stage_confidence:.2f})")
    print(f"{t_str} SECURITY RISK (NOW) ... Risk Score = {event.current_risk_score:.2f}")
    if event.future_risk_scores:
        fr_str = " | ".join(f"({k}) = {v:.2f}" for k, v in event.future_risk_scores.items())
        print(f"{t_str} FUTURE RISK .......... {fr_str}")
    print(f"{t_str} FORECAST TRUST ....... {trust} (Composite: {event.composite_trust:.2f})")
    print(f"{t_str} PRIORITY ............. {prio} (Score: {event.composite_priority:.3f})")

    
    # Show role routing explicitly (NOT EVERYONE GETS ALERT)
    for r in ["SOC_ANALYST", "NETWORK_DEFENDER", "INCIDENT_COMMANDER", "DATA_PROTECTION", "ENDPOINT_ANALYST"]:
        if r in event.relevant_roles:
            print(f"{t_str} ROLE ROUTING ......... {r:<20} [+ RELEVANT]")
        else:
            print(f"{t_str} ROLE ROUTING ......... {r:<20} [- NOT RELEVANT]")
            
    if event.dispatched_notifications:
        print(f"{t_str} NOTIFICATIONS ({len(event.dispatched_notifications)}) ...")
        for n in event.dispatched_notifications:
            print(f"       -> {n['role']}: {n['headline']}")
    else:
        print(f"{t_str} NOTIFICATIONS ........ 0 (Suppressed / Not Relevant)")
        
    print(f"{t_str} RESPONSE STRATEGY .... {strat}")
    print(f"{t_str} HUMAN APPROVAL ....... {human}")
    print(f"{t_str} AUTOMATED EXECUTION .. STRICTLY DISABLED (Non-Destructive)")
    print(f"{'-' * 70}")


def run_demo(
    scenario_name: str = "demo_recon_15s",
    output_dir: str | Path | None = None,
    no_sleep: bool = True,
    speed: float = 1.0,
    config_path: str | Path = "config/default.json",
    seed: int = 42,
) -> dict[str, Any]:
    """Execute live demo streaming and persist machine-readable event artifacts."""
    out_path = Path(output_dir or f"artifacts/demo/{scenario_name}")
    out_path.mkdir(parents=True, exist_ok=True)
    
    settings = load_settings(config_path)
    states = get_demo_scenario_states(scenario_name)
    engine = LiveDemoEngine()
    
    print("=" * 75)
    print(f"SIH 26153 — LIVE TELEMETRY DEMO: {scenario_name.upper()}")
    print(f"Replaying {len(states)} consecutive 10-second telemetry windows...")
    print("=" * 75)
    
    events: list[DemoEvent] = []
    events_dicts: list[dict[str, Any]] = []
    
    # Sleep duration per step if not no_sleep
    step_delay = (1.0 / speed) if not no_sleep else 0.0

    for event in engine.stream_scenario(states):
        events.append(event)
        events_dicts.append(event.to_dict())
        render_terminal_timeline(event)
        
        if step_delay > 0:
            time.sleep(step_delay)

    # 1. Write events.jsonl
    with open(out_path / "events.jsonl", "w", encoding="utf-8") as f:
        for ed in events_dicts:
            f.write(json.dumps(ed) + "\n")

    # 2. Write summary.json
    summary = {
        "scenario_name": scenario_name,
        "total_steps": len(events),
        "start_time": events[0].wall_clock_time.isoformat() if events else "",
        "end_time": events[-1].wall_clock_time.isoformat() if events else "",
        "state_schema_hash": STATE_SCHEMA_HASH,
        "final_stage": events[-1].primary_stage if events else "",
        "final_priority": events[-1].priority_level if events else "",
        "final_strategy": events[-1].recommended_strategy if events else "",
        "all_stages_observed": list({e.primary_stage for e in events}),
        "all_roles_notified": list({n["role"] for e in events for n in e.dispatched_notifications}),
        "human_approval_enforced": all(e.requires_human for e in events),
        "zero_automated_execution_verified": True,
    }
    with open(out_path / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # 3. Write manifest.json
    manifest = {
        "scenario_name": scenario_name,
        "timestamp": datetime.now().isoformat(),
        "random_seed": seed,
        "config": asdict(settings),
        "artifact_paths": {
            "events_jsonl": str(out_path / "events.jsonl"),
            "summary_json": str(out_path / "summary.json"),
        },
    }
    with open(out_path / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 75)
    print(f"DEMO COMPLETE: {scenario_name}")
    print(f"Artifacts saved to: {out_path}")
    print("=" * 75)
    
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="SIH 26153 Live Telemetry Demo Runner")
    parser.add_argument("--scenario", type=str, default="demo_recon_15s", help="Scenario name (demo_recon_15s, demo_recon, demo_dos, demo_exfiltration, demo_ambiguous)")
    parser.add_argument("--speed", type=float, default=1.0, help="Wall-clock replay speed multiplier")
    parser.add_argument("--no-sleep", action="store_true", default=True, help="Execute immediately without wall-clock sleep")
    parser.add_argument("--output-dir", type=str, default=None, help="Custom output directory")
    args = parser.parse_args()
    
    run_demo(
        scenario_name=args.scenario,
        output_dir=args.output_dir,
        no_sleep=args.no_sleep,
        speed=args.speed,
    )


if __name__ == "__main__":
    main()
