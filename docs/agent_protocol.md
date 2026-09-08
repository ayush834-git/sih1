# Day-1 Agent Protocol

Frozen interfaces may not be changed without human approval and an accompanying decision-log entry. Every future experiment must persist run id, code hash, dataset hashes, configuration, seed, feature schema, split, thresholds, artifacts, metrics, and failures under `artifacts/experiments/` and be registered append-only in `experiment_registry.md`.

Missing data must be reported, never invented. Work is sequential against frozen boundaries. Day-1 work must not add live infrastructure, cloud dependencies, real ML, real PCAP processing, fabricated labels, probabilities, or intelligence.
