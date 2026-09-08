# SIH 26153 — Frozen Day-1 Architecture

This document transfers the approved architecture-review contracts into the repository. It is the authoritative implementation contract for Day 1; `MASTER_CONTEXT.md` remains historical context.

The system is: telemetry → NetworkState → Forecast → Trajectory → TrustAssessment → SecurityAssessment → PriorityAssessment → ResponseRecommendation → RoleNotification. It is an offline, receding-horizon predictive-defence architecture, not a conventional per-flow IDS.

## Frozen boundaries

`NetworkState` carries time-bounded flow, diversity/topology, TCP, timing, distribution, optional packet-derived data, and provenance/session/gap metadata. It excludes all labels and `infiltration_fraction`. Empty windows, partial quality, and gaps are explicit; states adjacent to a gap cannot be used for transitions. Topology-dependent fields are nullable and have typed availability (`AVAILABLE`, `UNAVAILABLE`, `INVALID`), distinct from data quality. Unavailable values never enter predictive features.

`Forecast` contains a source state id, target time, horizon, delta and predicted feature mappings, model/schema identity, creation time, and an explicit failure reason. A successful forecast validates `predicted = source + delta`; failures have empty prediction mappings.

`Trajectory` holds ordered forecast steps, a bounded weight, observation errors, lifecycle state, and pruning explanation. Active weights are managed as a group by future trajectory management; a pruned trajectory requires a reason.

`TrustAssessment` carries confidence, disagreement, shift, novelty, historical error, data quality, composite trust, configured trust level, and non-empty contributing factors. `INSUFFICIENT` represents unavailable evidence.

`SecurityAssessment` has a behavioural signature, ordered candidate stages, primary stage, evidence, and novelty. `Unknown` is always a candidate. ATT&CK IDs, if later supplied, require official-taxonomy validation and review.

`PriorityAssessment` separates likelihood from consequence, asset criticality, path leverage, proximity and actionability. Asset-graph absence uses uncertain 0.5 defaults, never fabricated certainty.

`ResponseRecommendation` can only contain reversible actions. Low/insufficient trust and escalation require human involvement. This project recommends response actions; it does not autonomously execute destructive actions.

`RoleNotification` is role-specific for Network Security, Incident Response, Threat Intelligence, and Cloud/System Administration. Notification intent and urgency must agree; unknown relevance errs toward notification.

## Day-1 scope

Only typed contracts, configuration, documentation, synthetic placeholder traversal, and offline tests exist. Real CSV/PCAP ingestion, learned dynamics, probabilistic generation, ATT&CK interpretation, asset graphs, thresholds, and real response policies remain replaceable future work.
