"""Audit raw CSV timestamps and labels for Wednesday and Thursday."""
import csv
from collections import Counter
from pathlib import Path
from datetime import datetime

scratch_dir = Path("artifacts/scratch")
scratch_dir.mkdir(parents=True, exist_ok=True)

files = [
    Path(r"C:\Users\ayush\Downloads\Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"),
    Path(r"C:\Users\ayush\Downloads\Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"),
]

for p in files:
    if not p.exists():
        print(f"File not found: {p}")
        continue

    print("=" * 70)
    print(f"ANALYZING {p.name} ({p.stat().st_size:,} bytes)")
    print("=" * 70)

    labels = Counter()
    attack_timestamps = []
    all_timestamps = []
    ts_samples = []
    hours_counter = Counter()

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

        print(f"Timestamp index: {ts_idx}, Label index: {lbl_idx}")

        row_count = 0
        for row in reader:
            row_count += 1
            if len(row) <= max(ts_idx, lbl_idx):
                continue
            lbl = row[lbl_idx].strip()
            ts = row[ts_idx].strip()
            labels[lbl] += 1

            if row_count <= 5 or (row_count % 150000 == 0):
                ts_samples.append((row_count, ts, lbl))

            if lbl.lower() != "benign" and lbl.lower() != "label":
                attack_timestamps.append(ts)

            # Check hour distribution
            if len(ts) >= 13:
                # e.g. 28/02/2018 01:42:00 -> grab time part
                time_part = ts.split(" ")[-1] if " " in ts else ts
                hh = time_part.split(":")[0] if ":" in time_part else "??"
                hours_counter[hh] += 1

    print(f"Total rows read: {row_count:,}")
    print(f"Label distribution: {dict(labels)}")
    print("Sample raw timestamp strings:")
    for r_i, ts, lbl in ts_samples:
        print(f"  Row {r_i:,}: '{ts}' (Label: {lbl})")

    print("\nHour distribution of ALL rows:")
    for h, c in sorted(hours_counter.items()):
        print(f"  Hour {h}: {c:,} rows")

    if attack_timestamps:
        print(f"\nTotal Attack rows: {len(attack_timestamps):,}")
        attack_hours = Counter([t.split(" ")[-1].split(":")[0] for t in attack_timestamps if ":" in t])
        print(f"Attack hours distribution: {dict(attack_hours)}")
        print("First 10 attack timestamps:")
        for t in attack_timestamps[:10]:
            print(f"  '{t}'")
        print("Last 10 attack timestamps:")
        for t in attack_timestamps[-10:]:
            print(f"  '{t}'")
