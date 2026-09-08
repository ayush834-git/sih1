"""Detailed audit of raw attack timestamps and official documentation schedule."""
import csv
from collections import defaultdict
from pathlib import Path
from datetime import datetime

files = [
    Path(r"C:\Users\ayush\Downloads\Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"),
    Path(r"C:\Users\ayush\Downloads\Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"),
]

for p in files:
    print("=" * 70)
    print(f"EXACT ATTACK CLUSTERS IN RAW CSV: {p.name}")
    print("=" * 70)

    attack_times = []
    all_times = []
    
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        header = next(reader)
        ts_idx = -1
        lbl_idx = -1
        for i, col in enumerate(header):
            c_clean = col.strip().lower()
            if c_clean == "timestamp":
                ts_idx = i
            elif c_clean == "label":
                lbl_idx = i

        for row in reader:
            if len(row) <= max(ts_idx, lbl_idx):
                continue
            lbl = row[lbl_idx].strip()
            ts_str = row[ts_idx].strip()
            if not ts_str or ts_str.lower() == "timestamp":
                continue
            
            try:
                # Parse DD/MM/YYYY HH:MM:SS
                dt = datetime.strptime(ts_str.split(".")[0], "%d/%m/%Y %H:%M:%S")
                all_times.append(dt)
                if lbl.lower() != "benign" and lbl.lower() != "label":
                    attack_times.append(dt)
            except Exception as e:
                pass

    all_times.sort()
    attack_times.sort()

    print(f"Overall Time Range: {all_times[0]} -> {all_times[-1]}")
    
    # Cluster attack timestamps separated by gaps > 10 minutes (600s)
    clusters = []
    current_cluster = []
    for t in attack_times:
        if not current_cluster:
            current_cluster.append(t)
        else:
            if (t - current_cluster[-1]).total_seconds() > 600:
                clusters.append(current_cluster)
                current_cluster = [t]
            else:
                current_cluster.append(t)
    if current_cluster:
        clusters.append(current_cluster)

    print(f"Found {len(clusters)} distinct attack clusters:")
    for idx, c in enumerate(clusters, 1):
        print(f"  Cluster {idx}: {c[0].strftime('%Y-%m-%d %H:%M:%S')} to {c[-1].strftime('%Y-%m-%d %H:%M:%S')} (Duration: {(c[-1]-c[0]).total_seconds()/60:.1f} mins, Rows: {len(c):,})")

    # Check overall session gaps in all_times
    gaps = []
    for i in range(1, len(all_times)):
        diff = (all_times[i] - all_times[i-1]).total_seconds()
        if diff > 600:
            gaps.append((all_times[i-1], all_times[i], diff))
    print(f"\nMajor Telemetry Gaps (> 10 mins): {len(gaps)}")
    for g_start, g_end, d in gaps:
        print(f"  Gap: {g_start.strftime('%H:%M:%S')} to {g_end.strftime('%H:%M:%S')} (Duration: {d/60:.1f} mins / {d/3600:.2f} hours)")
