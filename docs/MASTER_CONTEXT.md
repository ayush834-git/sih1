# SIH 26153 — MASTER PROJECT CONTEXT
## Predictive Cyber Defense / AI-Based Network Attack Forecasting

**PS:** SIH26153  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software  
**Purpose:** Single continuity document covering the project from the original PS, ideation branches, feasibility research, 18 experiments, failures and deductions, final architecture, attacks, demo, validation, AI operating protocol, and 12-day build plan.

---

# 1. THE PROBLEM

The PS is explicitly about moving beyond static intrusion classification. It asks for:

- evolving network-state representation;
- learned temporal/state-transition dynamics;
- future-state and attacker-progression forecasting;
- infiltration probability over future windows;
- attack-stage mapping such as MITRE ATT&CK;
- explainability;
- both flow- and packet-level features;
- generalization beyond memorized signatures;
- precision/recall/F1/FPR benchmarking, including logistic regression;
- reproducible open-source code/model/configuration;
- offline PCAP/CSV demonstration;
- enterprise/CII applicability.

The conceptual chain is:

    network traffic
        -> evolving network state
        -> learned transition dynamics
        -> future-state forecast
        -> attacker progression
        -> proactive defence

Required deliverables: source code, README, <=2-page architecture document, <=2-minute demo video, <=5-slide presentation.

---

# 2. HOW WE BRANCHED FROM THE ORIGINAL IDEA

The starting thought was essentially:

> Can we simulate network attacks and identify different attack types?

That immediately raised a deeper question: a normal IDS answers **“what is happening now?”**, while this PS asks **“what is likely to happen next?”**

The project therefore branched from:

    traffic -> classifier -> attack/not attack

toward:

    traffic -> evolving state -> future state -> attack progression

The central thesis became:

# Predictive Cyber Defense
### See the attack. Predict the next move. Buy the defender time.

The intended loop:

    OBSERVE
       -> CURRENT STATE
       -> FORECAST
       -> MULTIPLE PLAUSIBLE FUTURES
       -> SECURITY INTERPRETATION
       -> PRIORITY
       -> RESPONSE / HUMAN ESCALATION
       -> OBSERVE AGAIN
       -> RECONSIDER

26153 became the front-runner because its technical ceiling, differentiation, research depth and alignment with the PS were much stronger than the easier generic-detection alternatives.

Other PS directions considered included 26145 (unidirectional IP threat detection), 26150 (DVR/NVR forensics), 26151 (dark-web attribution), 26105 (cyber-risk quantification), 26155 (compliance), and 26104 (voice fraud). The strategic conclusion was that 26153 has the highest ceiling, while 26145 is the safer fallback.

---

# 3. THE FIRST MAJOR DECISION: FEASIBILITY BEFORE BUILD

We explicitly decided that the first stage was NOT “build the final ML model.”

It was:

> **Test whether predictive network dynamics are real enough to justify building the final system.**

Small models were experimental instruments.

The current scientific question became:

> Can short-horizon forecasting of evolving network behaviour provide reliable, actionable lead time before consequential attack transitions?

This prevented premature investment in a large Transformer/GNN/RL system.

---

# 4. DATA RESEARCH AND DATA ACTUALLY USED

The principal public benchmark researched was CSE-CIC-IDS2018.

It provides relevant flow/PCAP/log/timing information and multiple attack scenarios, including:

- brute force
- Heartbleed
- botnet
- DoS
- DDoS
- web attacks
- infiltration

Two uploaded flow files were used in feasibility work:

    Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
    Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv

Important data findings:

- Wednesday had about 613,104 raw rows.
- 33 repeated header rows were detected and removed.
- Clean Wednesday count: about 613,071.
- Timestamps required dayfirst=True because dates are DD/MM/YYYY.
- Four infiltration-active blocks were observed:

    Wed block 1: 01:42 -> 02:39
    Wed block 2: 10:50 -> 12:04
    Thu block 3: 02:00 -> 03:36
    Thu block 4: 09:57 -> 10:54

These remain **observed infiltration blocks**, not “officially documented sessions,” until correspondence with official documentation is independently verified.

The dataset is a benchmark, not a perfect representation of real enterprise networks. The intended stronger methodology is:

    public benchmark: CIC-IDS2018
              +
    controlled validation: Caldera / Atomic Red Team / equivalent

---

# 5. NETWORK STATE CONSTRUCTION

A single flow is NOT treated as a state.

Instead:

    S_t = f(traffic observed during time window t)

Candidate features:

### Flow/volume
- flow count
- byte rate
- packet rate
- flow duration

### Diversity/topology
- source diversity
- destination diversity
- source/destination port diversity
- fan-out
- internal/external ratios
- east-west connections

### TCP
- SYN
- ACK
- RST
- related statistics/ratios

### Timing
- IAT mean
- IAT variance/std
- timing shifts

### Distribution
- packet statistics
- byte statistics
- variability

`infiltration_fraction` is diagnostic only and must NEVER be used as a predictive feature.

---

# 6. WINDOW EXPERIMENT

We tested 5s, 10s and 30s windows.

Approximate Wednesday results:

    5s:
        ~6766 non-empty windows
        ~78.3% coverage
        ~90.6 flows/window

    10s:
        ~3406 non-empty windows
        ~78.8% coverage
        ~180 flows/window

    30s:
        ~1138 non-empty windows
        ~79.0% coverage
        ~538.7 flows/window

Conclusion:

- windowed state construction is feasible;
- traffic is not too sparse;
- ~21% empty buckets exist;
- transitions must NEVER be fabricated across gaps.

10 seconds became the first operating point. 5s/30s remain evaluation options.

---

# 7. THE 18 FEASIBILITY EXPERIMENTS

## Experiment 1 — State construction
Question: Is traffic dense enough for temporal states?

Finding: Yes at 5s/10s/30s.

Decision: Never fabricate transitions across gaps.

## Experiment 2 — Absolute-state prediction
Question: Does S_t -> S_t+1 beat naive baselines?

Finding: Persistence and rolling mean were surprisingly strong.

Decision: Absolute-level prediction alone is too easy / weak as the central research target.

## Experiment 3 — Delta-state prediction
Question: Is ΔS more learnable/useful?

    ΔS_t = S_(t+1) - S_t
    S_hat_(t+1) = S_t + ΔS_hat_t

Finding: Learned ΔS beat zero-change in the audited feasibility work.

Caveat: zero-change is a low bar. Stronger baselines such as persistence, EWMA and AR-style delta forecasting must be included before claiming distinctive ML superiority.

Decision: Delta-state becomes the primary working formulation.

## Experiment 4 — Short history
Question: Does (S_t-2, S_t-1, S_t) -> ΔS_t help?

Finding: Small but directionally consistent improvement in some tests.

Decision: Short history has value; a Transformer is not automatically necessary.

## Experiment 5 — Held-out infiltration blocks
Question: Does the signal generalize rather than memorize?

Finding: Delta-state advantage persisted across the observed held-out infiltration blocks.

Caveat: only four observed blocks. Suggestive, not statistically definitive broad generalization.

Decision: Continue.

## Experiment 6 — Predicted state -> infiltration label
Question: Can future state directly become an infiltration label?

Finding: Weak/inconsistent.

Correct interpretation: the first security mapping was too coarse. This does NOT prove security prediction is fundamentally impossible.

Decision: Insert a behavioral-signature bridge.

## Experiment 7 — Behavioral-signature prediction
Question: Can we predict how behaviour changes?

Dimensions included volume, ports, SYN/RST/ACK, IAT and packet/byte behaviour.

Finding: Several dimensions showed useful directional signal.

Decision:

    ΔS
     -> future behavioural signature
     -> security meaning

## Experiment 8 — Large transition forecasting
Question: Can major behavioural transitions be anticipated?

Finding: Some meaningful discrimination, sometimes tens of seconds early.

Caveat: recall/coverage was not reliable enough for a general early-warning claim.

Decision: promising, but security target and lead-time methodology must improve.

## Experiment 9 — Long open-loop forecasting
Question: Does recursive forecast quality remain trustworthy?

Finding: Trust degrades over longer rollouts.

Decision:

    short forecast
       -> observe reality
       -> correct
       -> forecast again

This created the receding-horizon architecture.

## Experiment 10 — Receding-horizon loop
Question: Does observe -> forecast -> reforecast improve security discrimination?

Finding: Better in some blocks, not universally.

Decision: Mechanism is right; binary alert mapping is too crude.

## Experiment 11 — Behavioural transition forecasting
Question: Does predicted behaviour align with actual behaviour near infiltration onset?

Finding: Some meaningful directional alignment, but not cleanly monotonic.

Decision: Do not claim exact stage timing.

## Experiment 12 — Decision-aware warning
Question: Should current-state detection and forecasting compete?

Finding:

    current-state detector = broader coverage
    forecast = more selective / potentially higher precision

Decision: Run both in parallel. Forecasting augments detection.

## Experiment 13 — Response-gain framing
Question: Does forecasting buy real defender response time?

Finding: Some apparent lead-time cases existed, but some were evaluation-window artifacts.

Decision: The claim “useful response time gained” is NOT validated yet. No response-time number ships without a controlled non-predictive baseline and realistic defensive action.

## Experiment 14 — Regime clustering
Question: Do states form natural behavioural regimes?

Finding: Coarse structure exists, but pathological tiny clusters occurred at multiple K values.

Decision: Clustering is diagnostic only, never ground truth or attack-stage labels.

## Experiment 15 — DDoS cross-family transfer
Question: Does an infiltration-trained dynamics model transfer to DDoS?

Finding: Badly. Worse than persistence.

Decision: Reject one universal unconditioned dynamics model.

## Experiment 16 — DDoS adaptation
Question: Does small calibration fix cross-family transfer?

Finding: Mixed and not robust.

Decision: “A few samples will fix it” is rejected.

## Experiment 17 — Distribution shift
Question: Can the system know when its learned dynamics no longer apply?

Finding: Shift detection strongly separated DDoS from the infiltration distribution.

Critical insight:

> OOD / distribution shift is not the same as maliciousness.

Shift is a model-trust signal.

## Experiment 18 — Shared adaptation
Question: Does joint infiltration + early DDoS training generalize to unseen DDoS?

Finding: Still failed to beat zero-change.

Decision:

    adaptive / conditional dynamics
    +
    explicit uncertainty
    +
    graceful degradation

are required.

---

# 8. WHAT THE 18 EXPERIMENTS COLLECTIVELY CHANGED

The research progression:

    static classification
        -> wrong abstraction level

    network state
        -> absolute prediction
        -> simple baselines strong

    delta-state
        -> predictive structure appears

    short history
        -> small improvement

    behavioural signature
        -> security relevance emerges

    large-transition forecasting
        -> promising but imperfect

    long open-loop
        -> unstable

    receding horizon
        -> preferred architecture

    cross-family universal model
        -> fails

    distribution shift
        -> model-trust signal

    adaptive/conditional dynamics
        -> final direction

This is why the final architecture is not arbitrary complexity. It is the result of repeatedly attacking simpler assumptions.

---

# 9. WHAT IS PROVEN VS NOT PROVEN

## Supported enough to build

- windowed network-state representation;
- short-horizon network-state evolution has predictive structure;
- delta-state is a strong working formulation;
- short history has some value;
- delta-state advantage appears across observed infiltration blocks;
- some behavioural dimensions have predictable directional change;
- forecasting and current-state detection are complementary;
- distribution shift is detectable;
- universal infiltration -> DDoS transfer fails;
- small calibration is not a robust universal solution.

## Still to prove

- reliable attack-stage prediction;
- broad attack-family generalization;
- actual useful defender response-time gain;
- improved defensive outcome from that gain;
- exhaustive packet-level value;
- full MITRE mapping accuracy;
- final probabilistic model superiority;
- robust calibration across environments;
- independent live validation at meaningful scale.

Current status:

> We have enough evidence to justify building the full prototype, but the security-semantic bridge and operational response benefit remain the decisive research questions.

---

# 10. FINAL RESEARCH QUESTION

> **Can short-horizon forecasting of evolving network behaviour provide reliable, actionable lead time before consequential attack transitions?**

The true KPI is NOT minimum RMSE.

The objective is:

    maximize meaningful defender response time
    for as many relevant attacks as possible
    while maintaining sufficient accuracy
    and acceptable false-alarm cost.

Think Pareto frontier:

    accuracy <-> useful lead time <-> false alarms <-> actionability

---

# 11. FINAL ARCHITECTURE

    FLOW + PACKET TELEMETRY
              |
              v
        NETWORK STATE S_t
              |
        recent history
              |
              v
      SHORT-HORIZON DYNAMICS
              |
       P(ΔS | history, context)
              |
              v
     FUTURE STATE DISTRIBUTION
              |
              v
        TOP-K FUTURES
       /       |             F1       F2       F3
     48%      27%      15%
              |
              v
     BEHAVIOURAL SIGNATURE
              |
              v
     SECURITY INTERPRETATION
              |
       candidate stages
       + alternatives
              |
              v
          ATT&CK
              |
              v
        EXPLAINABILITY
              |
              v
       ATTACK PATH / INTEREST
              |
              v
           PRIORITY
              |
              v
      RESPONSE / ESCALATION
              |
              v
       NEW TELEMETRY
              |
              +----> RECONSIDERATION

Trust surrounds the forecasting layer:

    forecast confidence
    model disagreement
    distribution shift
    novelty
    data quality
    historical error
    environment context

Trust determines whether the system predicts confidently, recommends cautiously, or escalates to a human.

---

# 12. MULTI-FUTURE IS NON-NEGOTIABLE

Never collapse the final system into:

    current state -> single next stage

The intended behaviour is:

    current evidence
          -> multiple plausible futures
          -> new evidence
          -> re-rank
          -> new futures

Example:

    Initial:
        Enumeration       51%
        Credential path   27%
        Alternate         14%
        Unknown             8%

    New telemetry:

        Enumeration       24%
        Credential path   49%
        Alternate         10%
        Unknown            17%

    RECONSIDERATION TRIGGERED

The model updates its belief instead of pretending its original prediction was certain.

---

# 13. ATTACKER INTEREST / ATTACK PATH

Do not infer final attacker objective from the first target.

Instead:

    first target
       -> subsequent actions
       -> reachable assets
       -> repeated focus
       -> privilege/relationship changes
       -> critical-asset proximity
       -> estimated attacker interest

A low-value host can be high priority if it unlocks a high-value downstream asset.

Priority:

    likelihood
    × consequence
    × asset criticality
    × attack-path leverage
    × proximity
    × actionability

---

# 14. SECURITY INTERPRETATION / ATT&CK

CIC-IDS2018 does not provide perfect MITRE ATT&CK stage labels.

Therefore never do:

    dataset label -> fake ATT&CK label

Instead:

    traffic evidence
       -> network state
       -> forecast
       -> future behavioural signature
       -> evidence layer
       -> candidate ATT&CK interpretation

A stage prediction is evidence-supported interpretation, not proof of attacker intent.

---

# 15. ATTACK PORTFOLIO

## Attack 1 — Infiltration
Flagship scenario.

Conceptual path:

    Normal
      -> Recon
      -> port/service probing
      -> suspicious internal connections
      -> predicted lateral movement

Purpose:

- multi-stage evolution;
- multi-future forecasting;
- stage reasoning;
- response-window experiment.

Potential response:

- isolate suspicious endpoint;
- restrict east-west communication;
- rate-limit suspicious connections.

## Attack 2 — DDoS
Stress test, not primary proof.

Path:

    Normal
      -> traffic increase
      -> rapid source/flow growth
      -> service-impact risk

If adaptive DDoS dynamics fail the Day-6 tripwire:

    DDoS
      -> distribution shift HIGH
      -> model trust LOW
      -> forecast downgraded/suppressed
      -> human-first escalation

No improved DDoS prediction claim.

## Attack 3 — Brute Force
Tests low-volume repeated behaviour rather than huge traffic spikes.

## Attack 4 — Web attacks
Tests partial observability and mixed traffic.

## Attack 5 — Botnet
Stretch only if the core system is stable.

Each family exists to stress a different assumption.

---

# 16. CURRENT DETECTOR + FORECASTER

These are complementary:

    CURRENT-STATE PATH
        broad coverage
        immediate anomalies
        low latency

    FORECAST PATH
        selective
        future-oriented
        progression-aware

The system can therefore say:

    Current detector:
        suspicious activity = YES

    Forecast:
        likely next transition = lateral movement

    Trust:
        HIGH

    Priority:
        critical application path

    Recommendation:
        prepare containment

---

# 17. TRUST / KNOWLEDGE PHILOSOPHY

Novelty should increase attention, not create blind spots.

Separate:

    source trust
    from
    pattern novelty

Evidence-aware knowledge considers:

- source credibility;
- repeated observations;
- independent corroboration;
- validation;
- freshness;
- environment relevance;
- novelty;
- impact.

Pattern lifecycle:

    observation
       -> candidate
       -> emerging
       -> corroborated
       -> validated / established

One observation cannot automatically rewrite core knowledge.

Prediction cannot self-validate its own knowledge.

---

# 18. LLM ROLE

The LLM is downstream and advisory.

FAST PATH:

    telemetry
       -> state
       -> forecast
       -> priority
       -> alert/action

DEEP PATH:

    structured context
       -> knowledge
       -> LLM
       -> candidate reasoning
       -> human review

LLM may receive:

- current state;
- recent trajectory;
- candidate futures;
- uncertainty;
- assets;
- relationships;
- trusted knowledge.

LLM may produce:

- hypotheses;
- investigation ideas;
- possible mitigations;
- human-readable context.

LLM must NOT:

- define ground truth;
- become the forecaster;
- directly control the network;
- delay immediate alerts;
- replace the fast path.

---

# 19. RESPONSE / DEFENSIVE POLICY

The message is:

> **Buy the defender time.**

Not “AI fights hackers.”

### High trust

    structured forecast
    + safe/reversible recommendation/action

### Medium trust

    prepare
    + monitor
    + analyst review

### Low trust

    human alert
    + evidence packet

### Novel + high impact

    human-first
    + safe protective measures
    + preserve evidence

Possible controlled reversible actions:

- rate limiting;
- quarantine/isolation;
- restricting suspicious communication;
- controlled blocking;
- increased monitoring;
- additional inspection.

No destructive autonomous response.

---

# 20. ROLE-SPECIFIC NOTIFICATIONS — FINAL RESPONSE DEMO IDEA

Roles:

- Network Security
- Incident Response
- Threat Intelligence
- Cloud/System Admin

Notification logic:

    notification(role)
      = f(predicted trajectory,
          asset relevance,
          role responsibility,
          impact,
          confidence)

Example:

Network Security:
    ACTIVE
    Enumeration likely next
    Port diversity ↑↑
    Affected segment: X
    Confidence: 84%

Incident Response:
    HIGH PRIORITY
    Predicted path approaches critical application
    Recommended: investigate / prepare containment

Threat Intelligence:
    CONTEXT
    Behaviour partially matches known technique
    Evidence + provenance + confidence

Cloud/System Admin:
    No notification
    because their assets are not implicated.

Later, if the path reaches their scope:

    CLOUD ADMIN
    ACTION REQUIRED
    Potential impact to production service
    Inspect workload / restrict access

This demonstrates that the system does not broadcast every alert to everyone.

---

# 21. FINAL DEMO STRUCTURE

Total demo <=2 minutes.

## ACT 0 — WITHOUT US

Short compressed baseline.

    same controlled attack
       -> real traditional detector
       -> alert after consequential point

The baseline MUST be fair and real, never a strawman.

## ACT 1 — WITH US: 15–18 SECOND ATTACK

    0s     baseline
    2s     suspicious behaviour
    4s     discovery/recon
    6s     scanning/enumeration
    8s     progression signal strengthens
    10s    predicted next path
    12s    attacker changes/deviates
    14–17s reconsideration + alternative trajectory
    18s    consequential point

Audience sees:

    PAST -> NOW -> FUTURE

and:

    forecast -> new evidence -> reconsideration

The attack controller may know the script. The forecasting engine must only receive telemetry and remain blind to the script.

## ACT 2 — RESPONSE

    attack assessment
       -> who needs to know?
       -> role-specific notification
       -> priority
       -> recommended response

Closing frame:

    INCIDENT STATUS

    Predicted path:
        Recon -> Enumeration -> ...

    Highest-risk asset:
        Financial DB

    Model trust:
        86%

    Distribution shift:
        LOW

    Response coordination:
        3 roles notified

    Forecast lead:
        XX sec*

    *Only shown if a final controlled experiment validates it.

---

# 22. TWO DEMO MODES

## Research mode

    CIC-IDS2018 replay
       -> forecast
       -> actual future
       -> error / lead-time analysis

## Judge mode

    controlled attack/emulation
       -> telemetry
       -> forecasting engine

The predictor does not receive the attack script.

---

# 23. THE DECISIVE A/B EXPERIMENT

Run the same attack twice.

## Run A — predictive defense OFF

    attack
      -> progression
      -> detection
      -> response
      -> impact

## Run B — predictive defense ON

    attack
      -> forecast
      -> notification
      -> containment / human intervention
      -> impact delayed or reduced

Keep constant:

- topology;
- initial state;
- attack scenario;
- attack conditions.

Only predictive-defense capability changes.

Ideally repeat multiple times.

Primary metric:

    Response Time Gained

Conceptually:

    ΔT =
      T_critical-impact, protected
      -
      T_critical-impact, baseline

Secondary metrics:

- affected hosts;
- successful attack transitions;
- service degradation;
- propagation;
- suspicious flows;
- exposure duration.

Economic numbers, if used, must be explicitly labelled illustrative scenario economics, not real enterprise loss.

---

# 24. BASELINES

Serious comparisons should include:

- persistence;
- zero-change;
- rolling/EWMA;
- AR-style baseline where feasible;
- logistic regression (explicit PS requirement);
- Ridge;
- GBDT.

If a neural model does not beat classical baselines, do not force it into the final system.

A simple validated model is better than an impressive unvalidated model.

---

# 25. EXPLAINABILITY

Every displayed security assessment should include:

- predicted stage;
- alternative stages;
- confidence;
- model trust;
- shift status;
- top features;
- feature direction.

Example:

    WHY?

    Destination-port diversity   ↑↑
    New destinations              ↑
    SYN activity                  ↑
    Packet rate                   ↑

Use SHAP or an equivalent method where appropriate.

Validate:

- explanation consistency;
- feature perturbation;
- no leakage;
- manual review.

---

# 26. SCIENTIFIC NON-NEGOTIABLES

1. Every experiment writes metrics/config/provenance before its result is used.
2. Save model, scaler, state schema and exact split/timestamps.
3. No test information in preprocessing, feature selection, thresholds or window choice.
4. Keep infiltration blocks distinct until session mapping is verified.
5. Never convert a proxy metric into the main claim.
6. Report failures.
7. Simple baselines remain in serious comparisons.
8. The model is expendable; the hypothesis is not.
9. Never fabricate transitions across gaps.
10. Never use infiltration_fraction as a predictor.
11. Never pretend CIC labels are exact ATT&CK labels.
12. Never claim universal attack prediction.
13. Never claim response-time gain without controlled measurement.
14. Never hide a weak predictor behind a strong priority/UI layer.
15. Never let the LLM become the authoritative predictor.
16. Do not add GNN/Transformer/RL merely for appearance.
17. Do not build a giant knowledge graph or 20 attack types for SIH.
18. Measure end-to-end latency, not only model inference latency.
19. Tag system actions because defense changes telemetry.
20. Simultaneous campaigns require multiple live hypotheses.

---

# 27. 12-DAY EXECUTION ROADMAP

## Day 1 — Architecture + repository

Freeze:

- NetworkState
- Forecast
- Trajectory
- TrustAssessment
- SecurityAssessment
- PriorityAssessment
- ResponseRecommendation

Create:

    /core/state
    /core/dynamics
    /core/trajectory
    /core/uncertainty
    /core/security
    /core/priority
    /core/response
    /ingest
    /eval
    /scenarios
    /ui
    /artifacts
    /docs

Dummy telemetry must traverse every interface.

## Day 2 — Data/audit pipeline

Implement:

- CSV ingestion;
- dayfirst parsing;
- repeated-header removal;
- NaN/Inf handling;
- sorting;
- duplicates;
- gaps;
- session boundaries;
- provenance hashes.

Same command twice must produce identical state artifact hash.

## Day 3 — Packet bridge

Implement feasible:

- TTL;
- TTL variance;
- TCP window;
- fragmentation;
- payload-size statistics;
- retransmissions where reliable;
- scan-related patterns where valid.

CSV and PCAP paths must converge to compatible NetworkState objects.

## Day 4 — World-model core

Implement:

- persistence;
- rolling/EWMA;
- AR-style baseline;
- logistic regression;
- Ridge;
- GBDT.

Chronological splits only.

## Day 5 — Uncertainty + multi-future

Implement:

- ensemble disagreement;
- residual distribution;
- distribution-shift score;
- historical forecast error.

Generate genuine top-K futures. No cosmetic random futures.

## Day 6 — Receding horizon + reconsideration

Implement:

    receive state
      -> forecast
      -> observe
      -> compare
      -> update trust
      -> rerank
      -> reconsider

Validate with a controlled path change.

### DDoS tripwire

By end of Day 6, if adaptive/conditional DDoS dynamics do not clearly beat the predefined baseline:

    DDoS demo =
        distribution shift
        -> low trust
        -> forecast downgrade/suppression
        -> human-first escalation

No improved DDoS prediction claim.

## Day 7 — Security behavioural layer

Build:

    future state
      -> behavioural signature
      -> evidence
      -> candidate stages

Test infiltration, benign counterexamples, ablations and explanations.

## Day 8 — ATT&CK + explainability

Build:

- stage interpretation;
- ATT&CK mapping;
- SHAP/equivalent;
- explanation object.

### Mandatory clean-clone dry run

Before continuing:

- fresh clone;
- clean environment;
- one command;
- offline;
- dependencies;
- model loading;
- state pipeline;
- one replay;
- dashboard;
- artifact creation.

If it fails, stop adding features until integration is fixed.

## Day 9 — Attack path / priority

Build a lightweight asset graph.

Priority:

    likelihood
    × consequence
    × criticality
    × leverage
    × proximity
    × actionability

Validate by changing asset criticality while holding forecast constant.

## Day 10 — Graceful degradation + response

Integrate:

- current detector;
- forecast detector;
- shift detector;
- priority;
- safe response;
- human escalation;
- role-specific notifications.

No destructive autonomous response.

## Day 11 — Frozen validation

No new features.

Attack families:

- infiltration;
- DDoS;
- brute force;
- web;
- botnet if time permits.

Required metrics:

- precision;
- recall;
- F1;
- FPR;
- logistic regression benchmark.

World-model metrics:

- delta error;
- directional accuracy;
- K-step degradation;
- prediction interval coverage;
- calibration;
- held-out performance.

Security metrics:

- stage accuracy where defensible;
- confusion matrix;
- explanation consistency.

Operational metrics:

- alert latency;
- forecast-update latency;
- useful response-time opportunity;
- false-alert burden;
- coverage.

## Day 12 — Final integration

No new architecture.

Fresh environment.

Verify:

- one-command setup;
- offline execution;
- CSV replay;
- PCAP path;
- model loading;
- dashboard;
- reports;
- explainability;
- failure handling.

Produce:

- GitHub repository;
- README;
- <=2-page architecture;
- <=5-slide presentation;
- <=2-minute demo;
- scenario configs;
- final experiment report;
- model/config bundles.

---

# 28. AI / AGENT OPERATING SYSTEM

AI must accelerate implementation, not invent scientific meaning.

## One source of truth

    /docs/architecture.md
    /docs/data_contract.md
    /docs/experiment_registry.md
    /docs/decision_log.md

## Every task begins with

    ticket ID
    objective
    inputs
    output contract
    acceptance tests
    files allowed to modify
    dependencies

## Rules

- AI agents do not silently change interfaces.
- Breaking changes require human approval.
- Agents must run tests before reporting success.
- Status must be DONE / PARTIAL / BLOCKED / FAILED.
- No agent invents missing data.
- Implementation agents do not decide security semantics.
- Research decisions stay centralized.
- One agent owns a directory at a time.

## Every experiment saves

    run ID
    git hash if available
    dataset hashes
    config
    seed
    feature schema
    split definition
    thresholds
    model/scaler
    metrics
    failure status

---

# 29. WORKSTREAM / AI ALLOCATION

Human ownership:

### Project lead
- architecture;
- research;
- evaluation;
- security semantics;
- integration;
- judge narrative.

### ML teammate/agent
- state;
- dynamics;
- uncertainty;
- evaluation.

### Cyber/telemetry teammate/agent
- PCAP;
- attack replay;
- ATT&CK semantics;
- controlled scenarios.

### Backend teammate/agent
- APIs;
- state cache;
- logging;
- orchestration.

### UI teammate/agent
- dashboard;
- timeline;
- trajectory visualization;
- explanations;
- role notifications.

### Documentation/testing agent
- tests;
- README;
- architecture document;
- presentation;
- experiment reports.

Suggested AI allocation:

    Codex 1 -> core ML + evaluation
    Codex 2 -> backend + integration

    Antigravity 1 -> UI
    Antigravity 2 -> attack/replay harness
    Antigravity 3 -> packet/feature pipeline
    Antigravity 4 -> tests/docs/presentation

    ChatGPT -> architecture, experiment design, scientific review,
               red-team review, integration review, claim auditing

---

# 30. LINEAR HANDOFF

Every component publishes:

1. interface;
2. implementation;
3. tests;
4. example input/output;
5. saved artifact;
6. known limitations.

Example:

    StateBuilder v1
       -> state_schema.json
       -> sample_state.json
       -> tests
       -> Dynamics agent consumes frozen contract

The next agent consumes the interface, not an informal conversation.

---

# 31. FALLBACK HIERARCHY

If packet extraction fails:

    robust packet subset
    + preserve interface

If probabilistic futures are weak:

    calibrated ensemble/sample futures
    + never fake a distribution

If stage mapping is weak:

    candidate stages
    + evidence
    + alternatives
    + unknown

If asset graph is too slow:

    static lightweight graph

If autonomous response is risky:

    recommendation-only
    + reversible simulation

If response-time metric is weak:

    no response-time number
    + show measured warning opportunity and limitations

If neural model loses to classical models:

    keep the classical model

If DDoS adaptation fails:

    shift detection
    + low trust
    + human-first escalation
    + no improved DDoS forecasting claim

---

# 32. WHAT MUST NEVER BE SACRIFICED

1. Multi-future forecasting.
2. Trust/uncertainty.
3. Reconsideration.
4. Fair baselines.
5. Temporal leakage control.
6. Real telemetry in the demo.
7. Honest ATT&CK interpretation.
8. LLM out of the forecasting critical path.
9. No fabricated response-time number.
10. No fake DDoS success.
11. No strawman baseline.
12. No hiding weak ML behind UI.

---

# 33. FINAL COMPETITIVE STORY

Do NOT say:

> “We built an AI-powered IDS.”

Say:

> **We learn how network behaviour evolves, forecast multiple plausible attack futures, continuously revise those forecasts as evidence changes, recognize when our learned dynamics are unreliable, and turn consequential predictions into explainable, role-aware defensive decisions.**

The operational questions:

    WHAT IS HAPPENING?
           ↓
    WHAT WILL HAPPEN NEXT?
           ↓
    WHY?
           ↓
    WHAT MATTERS MOST?
           ↓
    WHO NEEDS TO KNOW?
           ↓
    WHAT CAN WE DO NOW?
           ↓
    DID WE BUY USEFUL TIME?

---

# 34. FINAL PROJECT POSITION

The project is ambitious for a second-year team, but the architecture is deliberately layered so that each part can be validated independently.

The research contribution is not:

> “We used GBDT.”

It is the defensible chain:

    meaningful state representation
      -> temporal/delta forecasting
      -> multi-future simulation
      -> leakage-resistant evaluation
      -> held-out validation
      -> security interpretation
      -> explainability
      -> priority
      -> forecast-driven defence
      -> measured response-window outcome

The project is allowed to become simpler where evidence demands it.

The model is expendable.

The hypothesis is not.

---

# 35. ONE-SENTENCE MASTER THESIS

> **Predict the evolution of the network before the attack's consequences become inevitable, continuously reconsider the prediction as the attacker changes course, and turn the most consequential plausible future into actionable defender time.**

---

# 36. CURRENT STATUS

    PS alignment                         HIGH
    Research foundation                 STRONG / FEASIBILITY PASSED
    Delta-state formulation             SUPPORTED
    Held-out infiltration signal        PROMISING, SMALL-N
    Behavioural forecasting             PROMISING
    Universal cross-family dynamics     REJECTED
    Distribution-shift layer            SUPPORTED
    Attack-stage prediction              NOT YET PROVEN
    Useful response-time gain            NOT YET PROVEN
    Full ATT&CK mapping                 NOT YET PROVEN
    Full packet integration             NOT YET PROVEN
    Live integrated demo                TO BUILD

FINAL STATUS:

> **We have earned the right to build. We have not earned the right to overclaim.**

The next phase is implementation, controlled validation, and integration.

Build principle:

> **Freeze the interfaces. Preserve the vision. Test every claim. Let evidence decide the model.**
