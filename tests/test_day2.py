import csv, json, tempfile, unittest
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from core.config import load_settings
from core.contracts import FeatureAvailability
from ingest.cic_flow import REQUIRED, TOPOLOGY, CleaningStats, build_states, read_flows, write_artifacts

FIELDS = sorted(REQUIRED)
def row(timestamp: str, **changes: str) -> dict[str, str]:
    result = {field: "1" for field in FIELDS}; result.update({"Timestamp": timestamp, "Flow Duration": "1000000", "Tot Fwd Pkts": "4", "Tot Bwd Pkts": "2", "TotLen Fwd Pkts": "400", "TotLen Bwd Pkts": "200", "Flow IAT Mean": "200000", "Flow IAT Std": "10000", "Pkt Len Mean": "100", "Pkt Len Std": "10", "Dst Port": "443"}); result.update(changes); return result

class DayTwoTests(unittest.TestCase):
    def write_csv(self, rows):
        temp = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", newline="", delete=False, encoding="utf-8")
        with temp:
            writer = csv.DictWriter(temp, fieldnames=FIELDS); writer.writeheader(); writer.writerows(rows)
        self.addCleanup(lambda: Path(temp.name).unlink(missing_ok=True)); return temp.name
    def test_dayfirst_headers_numeric_duplicates_and_sorting(self):
        path = self.write_csv([row("28/02/2018 08:00:12"), dict(zip(FIELDS, FIELDS)), row("28/02/2018 08:00:02"), row("28/02/2018 08:00:12")])
        states, stats = build_states(path); self.assertEqual(stats.repeated_headers_removed, 1); self.assertEqual(stats.duplicates_removed, 1); self.assertEqual(len(states), 2); self.assertEqual(states[0].timestamp_start, datetime(2018, 2, 28, 8, 0)); self.assertEqual(states[0].flow_count, 1)
    def test_nan_inf_and_invalid_timestamp_failure_behavior(self):
        path = self.write_csv([row("28/02/2018 08:00:00"), row("28/02/2018 08:00:01", **{"Flow Duration": "inf"}), row("not-a-timestamp")])
        with self.assertRaises(ValueError): build_states(path)
    def test_window_aggregation_gap_and_session(self):
        path = self.write_csv([row("28/02/2018 08:00:00"), row("28/02/2018 08:00:01", **{"TotLen Fwd Pkts": "600"}), row("28/02/2018 08:06:00")])
        states, _ = build_states(path); first = states[0]; self.assertEqual(first.flow_count, 2); self.assertEqual(first.byte_rate, 140.0); self.assertEqual(first.packet_rate, 1.2); self.assertTrue(states[1].is_empty); self.assertTrue(states[-1].gap_before); self.assertNotEqual(first.session_id, states[-1].session_id)
    def test_unavailable_topology_is_not_zero_or_predictive(self):
        path = self.write_csv([row("28/02/2018 08:00:00")]); state = build_states(path)[0][0]
        for name in TOPOLOGY: self.assertIsNone(getattr(state, name)); self.assertEqual(state.feature_availability[name], FeatureAvailability.UNAVAILABLE); self.assertNotIn(name, state.feature_values())
        self.assertEqual(state.data_quality, 1.0); self.assertEqual(state.dst_port_diversity, 1)
    def test_future_richer_source_can_mark_feature_available(self):
        path = self.write_csv([row("28/02/2018 08:00:00")]); state = build_states(path)[0][0]
        availability = dict(state.feature_availability); availability["src_ip_diversity"] = FeatureAvailability.AVAILABLE
        rich = replace(state, src_ip_diversity=2, feature_availability=availability); self.assertEqual(rich.feature_values()["src_ip_diversity"], 2.0)
    def test_no_label_or_infiltration_leakage(self):
        path = self.write_csv([row("28/02/2018 08:00:00")]); state = build_states(path)[0][0]
        self.assertNotIn("Label", state.__dataclass_fields__); self.assertNotIn("infiltration_fraction", state.__dataclass_fields__); self.assertNotIn("infiltration_fraction", state.feature_values())
    def test_deterministic_artifacts_and_provenance(self):
        path = self.write_csv([row("28/02/2018 08:00:11"), row("28/02/2018 08:00:01")]); one, stats_one = build_states(path); two, stats_two = build_states(path)
        self.assertEqual([s.provenance_hash for s in one], [s.provenance_hash for s in two]); self.assertEqual([s.feature_values() for s in one], [s.feature_values() for s in two])
        with tempfile.TemporaryDirectory() as directory:
            artifact, manifest = write_artifacts(one, stats_one, path, directory); self.assertTrue(artifact.exists()); self.assertEqual(json.loads(manifest.read_text())["state_count"], len(one))
    def test_nan_and_inf_row_preservation_and_feature_survival(self):
        path = self.write_csv([row("28/02/2018 08:00:01", **{"Flow Duration": "inf", "Flow IAT Mean": "nan", "SYN Flag Cnt": "2"})])
        states, stats = build_states(path)
        self.assertEqual(stats.rows_read, 1)
        self.assertEqual(stats.rows_retained, 1)
        self.assertEqual(stats.rows_removed, 0)
        self.assertEqual(stats.inf_values_seen, 1)
        self.assertEqual(stats.nan_values_seen, 1)
        self.assertEqual(stats.rows_with_invalid_numeric_values, 1)
        self.assertEqual(len(states), 1)
        state = states[0]
        self.assertEqual(state.flow_count, 1)
        self.assertEqual(state.dst_port_diversity, 1)
        self.assertEqual(state.syn_count, 2)
        self.assertEqual(state.feature_availability["mean_flow_duration"], FeatureAvailability.UNAVAILABLE)
        self.assertEqual(state.feature_availability["iat_mean"], FeatureAvailability.UNAVAILABLE)
        self.assertNotIn("mean_flow_duration", state.feature_values())
        self.assertNotIn("iat_mean", state.feature_values())
        self.assertIn("syn_count", state.feature_values())
        self.assertIn("dst_port_diversity", state.feature_values())
    def test_genuine_zero_distinguishable_from_missing(self):
        path_zero = self.write_csv([row("28/02/2018 08:00:00", **{"SYN Flag Cnt": "0"})])
        state_zero = build_states(path_zero)[0][0]
        self.assertEqual(state_zero.feature_availability["syn_count"], FeatureAvailability.AVAILABLE)
        self.assertEqual(state_zero.feature_values()["syn_count"], 0.0)

        path_missing = self.write_csv([row("28/02/2018 08:00:00", **{"SYN Flag Cnt": "nan"})])
        state_missing = build_states(path_missing)[0][0]
        self.assertEqual(state_missing.feature_availability["syn_count"], FeatureAvailability.UNAVAILABLE)
        self.assertNotIn("syn_count", state_missing.feature_values())
    def test_aggregation_ignores_invalid_observations_appropriately(self):
        path = self.write_csv([
            row("28/02/2018 08:00:01", **{"Flow Duration": "1000000"}),
            row("28/02/2018 08:00:02", **{"Flow Duration": "nan"}),
            row("28/02/2018 08:00:03", **{"Flow Duration": "3000000"}),
        ])
        state = build_states(path)[0][0]
        self.assertEqual(state.flow_count, 3)
        self.assertEqual(state.feature_availability["mean_flow_duration"], FeatureAvailability.AVAILABLE)
        self.assertAlmostEqual(state.mean_flow_duration, 2.0)
        self.assertAlmostEqual(state.feature_values()["mean_flow_duration"], 2.0)
    def test_all_invalid_aggregate_becomes_unavailable_not_zero(self):
        path = self.write_csv([
            row("28/02/2018 08:00:01", **{"Flow IAT Mean": "nan", "Flow IAT Std": "inf"}),
            row("28/02/2018 08:00:02", **{"Flow IAT Mean": "inf", "Flow IAT Std": "nan"}),
        ])
        state = build_states(path)[0][0]
        self.assertEqual(state.flow_count, 2)
        self.assertEqual(state.feature_availability["iat_mean"], FeatureAvailability.UNAVAILABLE)
        self.assertEqual(state.feature_availability["iat_std"], FeatureAvailability.UNAVAILABLE)
        self.assertNotIn("iat_mean", state.feature_values())
        self.assertNotIn("iat_std", state.feature_values())
        self.assertLess(state.data_quality, 1.0)
        self.assertGreater(state.data_quality, 0.0)
    def test_invalid_timestamp_causes_row_rejection(self):
        stats = CleaningStats()
        path = self.write_csv([row("28/02/2018 08:00:01"), row("invalid-timestamp")])
        flows = list(read_flows(path, stats))
        self.assertEqual(len(flows), 1)
        self.assertEqual(stats.rows_removed_for_invalid_timestamp, 1)
        self.assertEqual(stats.rows_read, 2)
        self.assertEqual(stats.rows_retained, 1)

if __name__ == "__main__": unittest.main()
