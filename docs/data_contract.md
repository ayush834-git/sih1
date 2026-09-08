# Data Contract

The Day-1 telemetry boundary produces only `NetworkState` objects defined in `core/contracts.py`.

- Required state features are versioned by `STATE_SCHEMA_HASH`.
- Network states must have a deterministic SHA-256 provenance hash.
- Timestamps must cover the declared window duration.
- `is_empty` exactly matches zero flows; zero data quality is only valid for an empty state.
- Raw labels, attack types, and `infiltration_fraction` are forbidden.
- Gaps and sessions are explicit. No state API exposes cross-gap transition training.
- Packet fields are nullable pending the later PCAP path; Day 1 does not extract packets.

The synthetic smoke fixture is not telemetry evidence and must not be used for model training, metrics, demonstrations of capability, or research claims.

## Day-2 CSV observability policy

The available CIC-IDS2018 80-column CSV exports do not expose `Src IP`, `Dst IP`, or `Src Port`. Thus `src_ip_diversity`, `dst_ip_diversity`, `src_port_diversity`, `fan_out`, `internal_ratio`, and `east_west_count` are null and marked `UNAVAILABLE` for this source. This means not observable, not zero and not low-quality data. They are excluded from predictive feature construction and future delta-state inputs. PCAP or merged telemetry may populate the same fields later.

The Day-2 reader accepts observed headers such as `Tot Fwd Pkts`, `TotLen Fwd Pkts`, and `Flow Byts/s`. It parses `Timestamp` strictly as day-first, removes repeated headers and exact duplicate clean records, rejects malformed/non-finite required numeric rows, and records each removal reason. CIC source timestamps are timezone-naive; the pipeline preserves that fact and does not invent an offset. No caps are calculated from data on Day 2; training-derived caps are a later transformation.
