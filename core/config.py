from dataclasses import dataclass
from pathlib import Path
import json

@dataclass(frozen=True)
class Settings:
    window_size_seconds: int; history_depth: int; trajectory_count: int; forecast_horizon: int; scaler: str; model_hierarchy: list[str]
    long_gap_seconds: int = 300; max_timestamp_failure_fraction: float = 0.01
def load_settings(path: str | Path = "config/default.json") -> Settings:
    with open(path, encoding="utf-8") as handle: return Settings(**json.load(handle))
