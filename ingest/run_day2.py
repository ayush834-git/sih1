import argparse
from ingest.cic_flow import build_states, write_artifacts

parser = argparse.ArgumentParser(description="Offline CIC CSV to NetworkState artifact")
parser.add_argument("csv_path"); parser.add_argument("--output", default="artifacts/state_sequences")
args = parser.parse_args(); states, stats = build_states(args.csv_path); artifact, manifest = write_artifacts(states, stats, args.csv_path, args.output)
print(f"states={len(states)} artifact={artifact} manifest={manifest}")
