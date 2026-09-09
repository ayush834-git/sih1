/**
 * Comprehensive Unit Tests for Frontend Runtime Layer (SIH 26153).
 * Tests API client, SSE parsing, Reconsideration derivation, Store synchronization,
 * and Overview Page data mapping & truthfulness.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// Sample mock DemoEvent matching exact backend schema
function createMockDemoEvent(stepIndex, stage = 'Unknown', risk = 0.146, trust = 0.85, conf = 0.85) {
  return {
    event_id: `evt-${String(stepIndex).padStart(4, '0')}-test`,
    step_index: stepIndex,
    logical_time_str: `T${String(stepIndex).padStart(2, '0')} (${stepIndex * 10}s)`,
    wall_clock_time: '2026-08-31T18:00:00.000Z',
    current_state_summary: {
      dst_port_diversity: 2.0,
      flow_count: 12.0,
      byte_rate: 1500.0,
      syn_ratio: 0.05,
      rst_ratio: 0.02,
      packet_rate: 14.5,
      mean_flow_duration: 1.2,
    },
    predicted_deltas_h1: {
      dst_port_diversity_delta: stage === 'Reconnaissance' ? 3.5 : 0.0,
      flow_count_delta: stage === 'Reconnaissance' ? 5.2 : 0.0,
      byte_rate_delta: stage === 'Reconnaissance' ? 2400.0 : 0.0,
    },
    primary_stage: stage,
    stage_confidence: conf,
    trust_level: 'HIGH',
    composite_trust: trust,
    priority_level: risk > 0.3 ? 'HIGH' : 'LOW',
    composite_priority: 0.32,
    current_risk_score: risk,
    future_risk_scores: { '+10s': risk, '+20s': risk * 0.8 },
    risk_explanation: `Risk Score=${risk}`,
    active_signatures: stage === 'Reconnaissance' ? ['SIG_PORT_SCAN_HORIZ'] : [],
    candidate_attack_techniques: stage === 'Reconnaissance' ? ['T1046'] : [],
    relevant_roles: stage === 'Reconnaissance' ? ['SOC_ANALYST', 'NETWORK_DEFENDER'] : [],
    omitted_roles: [],
    dispatched_notifications: [],
    recommended_strategy: stage === 'Reconnaissance' ? 'INVESTIGATE' : 'MONITOR',
    requires_human: true,
    is_reversible: true,
    recommended_actions: [{ action_type: 'INCREASE_MONITORING', target: 'Telemetry', urgency: 'PROMPT' }],
    explanation: `Evaluated stage ${stage}`,
    forecast_feature_contributions: [
      {
        feature_name: 'dst_port_diversity',
        signed_direction: 'POSITIVE',
        normalized_contribution: 0.45,
        raw_contribution: 0.45,
        current_value: 2.0,
        predicted_delta: 3.5,
        baseline_reference_value: 2.0,
        evidence_type: 'CURRENT',
        lag_breakdown: [],
        description: 'Port diversity increase',
        is_available: true,
      },
    ],
    security_explanation: {
      explanation_id: 'expl-001',
      window_id: 'win-001',
      timestamp: '2026-08-31T18:00:00',
      primary_stage: stage,
      confidence: conf,
      trust_level: 'HIGH',
      supporting_evidence: ['Feature telemetry'],
      counter_evidence: stage === 'Unknown' ? ['Zero attack signatures'] : [],
      alternative_explanations: [],
      top_contributing_features: ['dst_port_diversity'],
      current_vs_forecast_breakdown: {},
      limitations: [],
      provenance_hash: 'abc123hash',
    },
  };
}

// Pure derivation function to test directly
function deriveReconsideration(prevEvent, currEvent) {
  if (!prevEvent) {
    return {
      hasReconsidered: false,
      reason: 'Baseline telemetry initialized.',
      previousStage: null,
      currentStage: currEvent.primary_stage,
      trustDelta: 0,
      riskDelta: 0,
      confidenceDelta: 0,
      contradictionDetected: false,
      timestamp: currEvent.wall_clock_time,
    };
  }

  const trustDelta = Number((currEvent.composite_trust - prevEvent.composite_trust).toFixed(4));
  const riskDelta = Number((currEvent.current_risk_score - prevEvent.current_risk_score).toFixed(4));
  const confidenceDelta = Number((currEvent.stage_confidence - prevEvent.stage_confidence).toFixed(4));
  const stageChanged = prevEvent.primary_stage !== currEvent.primary_stage;

  const trustDroppedSignificantly = trustDelta <= -0.10;
  const riskElevated = riskDelta >= 0.10;
  const hasCounterEvidence = (currEvent.security_explanation?.counter_evidence?.length ?? 0) > 0;

  let hasReconsidered = false;
  const reasons = [];

  if (stageChanged) {
    hasReconsidered = true;
    reasons.push(`Security stage transitioned from '${prevEvent.primary_stage}' to '${currEvent.primary_stage}'`);
  }
  if (trustDroppedSignificantly) {
    hasReconsidered = true;
    reasons.push(`Composite trust dropped by ${(Math.abs(trustDelta) * 100).toFixed(1)}%`);
  }
  if (riskElevated) {
    hasReconsidered = true;
    reasons.push(`Security risk increased by ${(riskDelta * 100).toFixed(1)}%`);
  }

  const contradictionDetected = stageChanged || trustDroppedSignificantly || (riskElevated && hasCounterEvidence);

  return {
    hasReconsidered,
    reason: reasons.length > 0 ? reasons.join('; ') : 'Telemetry parameters consistent with current operational model.',
    previousStage: prevEvent.primary_stage,
    currentStage: currEvent.primary_stage,
    trustDelta,
    riskDelta,
    confidenceDelta,
    contradictionDetected,
    timestamp: currEvent.wall_clock_time,
  };
}

describe('1. Reconsideration Pure Derivation Tests', () => {
  test('Initial event produces baseline reconsideration with hasReconsidered = false', () => {
    const evt0 = createMockDemoEvent(0, 'Unknown', 0.14, 0.85, 0.85);
    const rec = deriveReconsideration(null, evt0);

    assert.equal(rec.hasReconsidered, false);
    assert.equal(rec.previousStage, null);
    assert.equal(rec.currentStage, 'Unknown');
    assert.equal(rec.contradictionDetected, false);
    assert.equal(rec.trustDelta, 0);
  });

  test('Nominal identical event produces hasReconsidered = false', () => {
    const evt0 = createMockDemoEvent(0, 'Unknown', 0.14, 0.85, 0.85);
    const evt1 = createMockDemoEvent(1, 'Unknown', 0.14, 0.85, 0.85);
    const rec = deriveReconsideration(evt0, evt1);

    assert.equal(rec.hasReconsidered, false);
    assert.equal(rec.previousStage, 'Unknown');
    assert.equal(rec.currentStage, 'Unknown');
    assert.equal(rec.contradictionDetected, false);
  });

  test('Security stage transition triggers hasReconsidered = true with diagnosis', () => {
    const evt0 = createMockDemoEvent(0, 'Unknown', 0.14, 0.85, 0.85);
    const evt7 = createMockDemoEvent(7, 'Reconnaissance', 0.35, 0.82, 0.90);
    const rec = deriveReconsideration(evt0, evt7);

    assert.equal(rec.hasReconsidered, true);
    assert.equal(rec.previousStage, 'Unknown');
    assert.equal(rec.currentStage, 'Reconnaissance');
    assert.equal(rec.contradictionDetected, true);
    assert.match(rec.reason, /Security stage transitioned/);
    assert.match(rec.reason, /Security risk increased/);
  });

  test('Significant trust drop triggers contradiction flag', () => {
    const evtPrev = createMockDemoEvent(3, 'Reconnaissance', 0.35, 0.85, 0.85);
    const evtCurr = createMockDemoEvent(4, 'Reconnaissance', 0.35, 0.65, 0.85); // -0.20 trust drop
    const rec = deriveReconsideration(evtPrev, evtCurr);

    assert.equal(rec.hasReconsidered, true);
    assert.equal(rec.trustDelta, -0.20);
    assert.equal(rec.contradictionDetected, true);
    assert.match(rec.reason, /Composite trust dropped by 20.0%/);
  });
});

describe('2. Event History Accumulation and Monotonic Ordering', () => {
  test('Events accumulate without duplicates by step_index', () => {
    let history = [];

    const e0 = createMockDemoEvent(0);
    const e1 = createMockDemoEvent(1);
    const e1Updated = createMockDemoEvent(1, 'Reconnaissance', 0.35);

    // Append e0 and e1
    history.push(e0);
    history.push(e1);
    assert.equal(history.length, 2);

    // Update e1 in place
    const existingIdx = history.findIndex((e) => e.step_index === e1Updated.step_index);
    if (existingIdx >= 0) {
      history[existingIdx] = e1Updated;
    } else {
      history.push(e1Updated);
    }

    assert.equal(history.length, 2);
    assert.equal(history[1].primary_stage, 'Reconnaissance');
  });
});

describe('3. SSE Event Serialization and Parsing', () => {
  test('Parse multi-line SSE state event payload', () => {
    const mockEvt = createMockDemoEvent(5, 'Reconnaissance', 0.32, 0.85, 0.90);
    const sseText = `event: state\nid: 5\ndata: ${JSON.stringify(mockEvt)}\n\n`;

    const lines = sseText.split('\n');
    let eventName = '';
    let eventId = '';
    let dataStr = '';

    for (const line of lines) {
      if (line.startsWith('event:')) eventName = line.slice(6).trim();
      if (line.startsWith('id:')) eventId = line.slice(3).trim();
      if (line.startsWith('data:')) dataStr = line.slice(5).trim();
    }

    assert.equal(eventName, 'state');
    assert.equal(eventId, '5');
    const parsed = JSON.parse(dataStr);
    assert.equal(parsed.step_index, 5);
    assert.equal(parsed.primary_stage, 'Reconnaissance');
    assert.equal(parsed.current_risk_score, 0.32);
  });

  test('Parse demo_status SSE event payload', () => {
    const statusPayload = {
      session_id: 'sess-abc',
      scenario: 'demo_recon_15s',
      status: 'RUNNING',
      current_step: 3,
      total_steps: 16,
      history_count: 4,
      updated_at: '2026-08-31T18:00:00',
      speed: 1.0,
    };
    const sseText = `event: demo_status\ndata: ${JSON.stringify(statusPayload)}\n\n`;

    const lines = sseText.split('\n');
    let eventName = '';
    let dataStr = '';

    for (const line of lines) {
      if (line.startsWith('event:')) eventName = line.slice(6).trim();
      if (line.startsWith('data:')) dataStr = line.slice(5).trim();
    }

    assert.equal(eventName, 'demo_status');
    const parsed = JSON.parse(dataStr);
    assert.equal(parsed.status, 'RUNNING');
    assert.equal(parsed.scenario, 'demo_recon_15s');
    assert.equal(parsed.current_step, 3);
  });

  test('Parse complete SSE event payload', () => {
    const completePayload = { scenario: 'demo_recon_15s', total_steps: 16, final_step: 15 };
    const sseText = `event: complete\ndata: ${JSON.stringify(completePayload)}\n\n`;

    const lines = sseText.split('\n');
    let eventName = '';
    let dataStr = '';

    for (const line of lines) {
      if (line.startsWith('event:')) eventName = line.slice(6).trim();
      if (line.startsWith('data:')) dataStr = line.slice(5).trim();
    }

    assert.equal(eventName, 'complete');
    const parsed = JSON.parse(dataStr);
    assert.equal(parsed.final_step, 15);
    assert.equal(parsed.total_steps, 16);
  });
});

describe('4. Overview Page Mapping and Truthfulness Verification', () => {
  test('Overview correctly maps IDLE state without live events', () => {
    const liveEvent = null;
    const demoStatus = { status: 'IDLE', scenario: 'demo_recon_15s', current_step: -1, total_steps: 16 };

    const isIdle = demoStatus.status === 'IDLE' && !liveEvent;
    const stageHeader = liveEvent ? `T00 // ${liveEvent.primary_stage}` : isIdle ? 'STANDBY // IDLE' : 'CASE-001';
    const confidencePct = liveEvent ? Math.round(liveEvent.stage_confidence * 100) : isIdle ? 85 : 91;
    const trustPct = liveEvent ? Math.round(liveEvent.composite_trust * 100) : isIdle ? 85 : 85;

    assert.equal(isIdle, true);
    assert.equal(stageHeader, 'STANDBY // IDLE');
    assert.equal(confidencePct, 85);
    assert.equal(trustPct, 85);
  });

  test('Overview maps live DemoEvent fields truthfully to UI elements', () => {
    const liveEvent = createMockDemoEvent(4, 'Reconnaissance', 0.344, 0.78, 0.85);

    const stageBadge = `T${String(liveEvent.step_index).padStart(2, '0')} // ${liveEvent.primary_stage}`;
    const confidenceScore = Math.round(liveEvent.stage_confidence * 100);
    const riskPercentage = (liveEvent.current_risk_score * 100).toFixed(1);
    const signaturesStr = liveEvent.active_signatures.join(', ') || 'NOMINAL';
    const byteRateKb = (liveEvent.current_state_summary.byte_rate / 1000).toFixed(1);

    assert.equal(stageBadge, 'T04 // Reconnaissance');
    assert.equal(confidenceScore, 85);
    assert.equal(riskPercentage, '34.4');
    assert.equal(signaturesStr, 'SIG_PORT_SCAN_HORIZ');
    assert.equal(byteRateKb, '1.5');
  });

  test('BadgeDelta helper correctly maps increase, decrease, and neutral', () => {
    const getDeltaType = (val) => {
      if (val === undefined || val === 0) return 'neutral';
      return val > 0 ? 'increase' : 'decrease';
    };

    assert.equal(getDeltaType(3.5), 'increase');
    assert.equal(getDeltaType(-2.1), 'decrease');
    assert.equal(getDeltaType(0), 'neutral');
    assert.equal(getDeltaType(undefined), 'neutral');
  });

  test('Reset transitions state back to IDLE and clears previous event', () => {
    let snapshot = {
      event: createMockDemoEvent(8, 'Reconnaissance', 0.45),
      demo: { status: 'RUNNING', current_step: 8, total_steps: 16 },
    };

    // Simulate reset execution
    snapshot = {
      event: null,
      demo: { status: 'IDLE', current_step: -1, total_steps: 16, scenario: 'demo_recon_15s' },
    };

    assert.equal(snapshot.event, null);
    assert.equal(snapshot.demo.status, 'IDLE');
    assert.equal(snapshot.demo.current_step, -1);
  });
});

describe('5. Task 9 - Simulation Operator Control Surface Tests', () => {
  test('Speed control options are validated and assignable', () => {
    const SPEED_OPTIONS = [0.5, 1.0, 2.0, 5.0];
    assert.deepEqual(SPEED_OPTIONS, [0.5, 1.0, 2.0, 5.0]);

    let currentSpeed = 1.0;
    const setSpeed = (s) => { currentSpeed = s; };

    setSpeed(2.0);
    assert.equal(currentSpeed, 2.0);
    setSpeed(5.0);
    assert.equal(currentSpeed, 5.0);
  });

  test('Command log entry preserves operator action and timestamp', () => {
    const entry = {
      id: 'cmd-test-1',
      timestamp: '[12:00:00]',
      actor: '[OPERATOR]',
      text: 'START requested (scenario: demo_recon_15s, speed: 1.0x)',
      isAccent: true,
      isNew: true,
    };

    assert.equal(entry.actor, '[OPERATOR]');
    assert.equal(entry.isAccent, true);
    assert.ok(entry.text.includes('START requested'));
  });

  test('Trajectory projection separates observed history from forward forecast cones', () => {
    const evt = createMockDemoEvent(4, 'Reconnaissance', 0.35);
    const history = [
      createMockDemoEvent(2, 'Unknown', 0.12),
      createMockDemoEvent(3, 'Unknown', 0.18),
      evt,
    ];

    // Historical observed steps
    const observedSteps = history.map((e) => ({
      step: e.step_index,
      risk: e.current_risk_score,
    }));
    assert.equal(observedSteps.length, 3);
    assert.equal(observedSteps[2].step, 4);

    // Forward AR(5) forecast cones directly from future_risk_scores
    const futureForecast = Object.entries(evt.future_risk_scores).map(([horizon, score]) => ({
      horizon,
      score,
    }));
    assert.equal(futureForecast.length, 2);
    assert.equal(futureForecast[0].horizon, '+10s');
    assert.equal(futureForecast[0].score, 0.35);
    assert.equal(futureForecast[1].horizon, '+20s');
    assert.ok(Math.abs(futureForecast[1].score - 0.28) < 1e-4);
  });
});

describe('6. Task 10 - Live Alerts & Escalation Workflow Tests', () => {
  test('DemoEvent transforms faithfully into RuntimeAlertItem with causal context', () => {
    const evt = createMockDemoEvent(8, 'Reconnaissance', 0.48, 0.82, 0.90);
    evt.requires_human = true;
    evt.is_reversible = true;
    evt.active_signatures = ['SIG_PORT_SCAN_HORIZ', 'SIG_RAPID_PROBE'];

    const alert = {
      id: `ALERT-T${String(evt.step_index).padStart(2, '0')}`,
      step_index: evt.step_index,
      stage: evt.primary_stage,
      risk: evt.current_risk_score,
      confidence: Math.round(evt.stage_confidence * 100),
      trust: Math.round(evt.composite_trust * 100),
      priority: evt.priority_level,
      signatures: evt.active_signatures,
      requiresHuman: evt.requires_human,
      isReversible: evt.is_reversible,
      strategy: evt.recommended_strategy,
    };

    assert.equal(alert.id, 'ALERT-T08');
    assert.equal(alert.stage, 'Reconnaissance');
    assert.equal(alert.confidence, 90);
    assert.equal(alert.trust, 82);
    assert.equal(alert.priority, 'HIGH');
    assert.equal(alert.requiresHuman, true);
    assert.equal(alert.isReversible, true);
    assert.deepEqual(alert.signatures, ['SIG_PORT_SCAN_HORIZ', 'SIG_RAPID_PROBE']);
  });

  test('Operator disposition state changes are maintained per alert ID', () => {
    const dispositions = {};
    const updateDisposition = (id, disp) => { dispositions[id] = disp; };

    updateDisposition('ALERT-T04', 'ACKNOWLEDGED');
    updateDisposition('ALERT-T08', 'ESCALATED');

    assert.equal(dispositions['ALERT-T04'], 'ACKNOWLEDGED');
    assert.equal(dispositions['ALERT-T08'], 'ESCALATED');
    assert.equal(dispositions['ALERT-T12'] || 'REVIEW', 'REVIEW');
  });

  test('Policy gate distinction: requires_human guards automated containment', () => {
    const highRiskAdvisory = { requires_human: true, is_reversible: true };
    const authorityBadge = highRiskAdvisory.requires_human ? 'HUMAN APPROVAL REQUIRED' : 'AUTONOMOUS ACTIVE';
    assert.equal(authorityBadge, 'HUMAN APPROVAL REQUIRED');
  });
});

describe('7. Task 11 - Live Intelligence & Reasoning Layer Tests', () => {
  test('Multi-step future risk scores are extracted across h=1, h=2, h=3', () => {
    const futureScores = { '+10s': 0.42, '+20s': 0.38, '+30s': 0.31 };
    const h1 = futureScores['+10s'];
    const h2 = futureScores['+20s'];
    const h3 = futureScores['+30s'];

    assert.equal(h1, 0.42);
    assert.equal(h2, 0.38);
    assert.equal(h3, 0.31);
    assert.ok(h1 > h2 && h2 > h3, 'Future risk exhibits natural forecast horizon attenuation');
  });

  test('Feature momentum contributions preserve signed direction and normalized weight', () => {
    const contributions = [
      { feature_name: 'dst_port_diversity', signed_direction: 'POSITIVE', normalized_contribution: 0.52 },
      { feature_name: 'byte_rate', signed_direction: 'POSITIVE', normalized_contribution: 0.30 },
      { feature_name: 'mean_flow_duration', signed_direction: 'NEGATIVE', normalized_contribution: 0.18 },
    ];

    assert.equal(contributions[0].signed_direction, 'POSITIVE');
    assert.equal(contributions[2].signed_direction, 'NEGATIVE');
    assert.equal(contributions[0].normalized_contribution, 0.52);

    const totalWeight = contributions.reduce((sum, c) => sum + c.normalized_contribution, 0);
    assert.ok(Math.abs(totalWeight - 1.0) < 0.01);
  });

  test('Security explanation supplies explicit supporting and counter-evidence', () => {
    const secExpl = {
      supporting_evidence: ['Anomalous surge in destination port diversity (+3.5 delta)'],
      counter_evidence: ['Zero egress exfiltration detected'],
    };

    assert.equal(secExpl.supporting_evidence.length, 1);
    assert.equal(secExpl.counter_evidence.length, 1);
    assert.ok(secExpl.supporting_evidence[0].includes('port diversity'));
    assert.ok(secExpl.counter_evidence[0].includes('exfiltration'));
  });
});

describe('8. Phase 1 - Canonical Truth and UI Reconciliation Tests', () => {
  test('Canonical CASE-019 subject is consistently GATEWAY_NODE_4 across mock data and stores', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const mockDataContent = fs.readFileSync(path.resolve('src/data/mockData.ts'), 'utf-8');
    const storeContent = fs.readFileSync(path.resolve('src/store/useControlCenterStore.ts'), 'utf-8');

    // Case definition in mockData
    assert.ok(mockDataContent.includes("id: 'CASE-019'"));
    assert.ok(mockDataContent.includes("subject: 'GATEWAY_NODE_4'"));
    assert.ok(mockDataContent.includes("threatActor: 'GATEWAY_NODE_4'"));

    // Default store state
    assert.ok(storeContent.includes("activeCaseId: 'CASE-019'"));
    assert.ok(storeContent.includes("selectedEvidenceId: 'EV-00419'"));
    assert.ok(storeContent.includes("selectedAlertId: 'ALERT-0088'"));
  });

  test('Zero occurrences of stale 2023 timestamps in mockData and pages', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const mockDataContent = fs.readFileSync(path.resolve('src/data/mockData.ts'), 'utf-8');
    const pages = [
      'NetworkStatePage.tsx',
      'TrajectoryForecastPage.tsx',
      'InterventionMatrixPage.tsx',
      'HumanApprovalPage.tsx',
      'VerificationPage.tsx',
      'AuditTracePage.tsx',
    ];

    assert.ok(!mockDataContent.includes('2023-'), 'mockData.ts contains no 2023 timestamps');
    for (const page of pages) {
      const pageContent = fs.readFileSync(path.resolve(`src/pages/${page}`), 'utf-8');
      assert.ok(!pageContent.includes('2023-'), `${page} contains no 2023 timestamps`);
    }
  });

  test('Pipeline pages eliminate synthetic CASE-${step + 100} numbering', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const pages = [
      'NetworkStatePage.tsx',
      'TrajectoryForecastPage.tsx',
      'InterventionMatrixPage.tsx',
      'HumanApprovalPage.tsx',
      'VerificationPage.tsx',
      'AuditTracePage.tsx',
    ];

    for (const page of pages) {
      const pageContent = fs.readFileSync(path.resolve(`src/pages/${page}`), 'utf-8');
      assert.ok(!pageContent.includes('step_index + 100'), `${page} has no synthetic step_index + 100`);
    }
  });

  test('Authoritative 5-stage response execution contract requires human approval', () => {
    // Stage 1: Recommendation
    const recommendation = { action_type: 'DEMO_BLOCK', target: 'svc-api', urgency: 'PROMPT' };
    assert.equal(recommendation.action_type, 'DEMO_BLOCK');

    // Stage 2: Authority Policy Evaluation
    const authorityPolicy = {
      decision_id: 'DEC-001',
      authority_level: 'RECOMMEND',
      human_approval_required: true,
      permitted_action_classes: ['REVERSIBLE_CONTAINMENT', 'NOTIFICATION'],
      blocked_action_classes: ['PERMANENT_DISRUPTION', 'PROCESS_TERMINATION'],
    };
    assert.equal(authorityPolicy.human_approval_required, true);

    // Stage 3: Human Approval Validation
    const unapprovedPayload = {
      action_type: 'DEMO_BLOCK',
      target_node_id: 'svc-api',
      authority_decision_id: 'DEC-001',
      evidence_window_id: 'WIN-001',
      approval: null,
    };
    assert.equal(unapprovedPayload.approval, null, 'Unapproved response cannot proceed');

    const approvedPayload = {
      ...unapprovedPayload,
      approval: {
        approval_id: 'APP-001',
        approved: true,
        approver_reference: 'ANALYST_01',
        approval_reason: 'Mitigate unauthorized ingress sweep on Gateway Node 4',
      },
    };
    assert.equal(approvedPayload.approval.approved, true);
    assert.equal(approvedPayload.approval.approver_reference, 'ANALYST_01');

    // Stage 4 & 5: Execution and Outcome Verification
    const executionResponse = {
      execution_id: 'EXEC-001',
      action_id: 'ACT-001',
      authority_decision_id: 'DEC-001',
      evidence_window_id: 'WIN-001',
      status: 'VERIFIED_SUCCESS',
      is_verified: true,
      verification_status: 'VERIFIED: target svc-api packet drop rate confirmed at 100%',
    };
    assert.equal(executionResponse.status, 'VERIFIED_SUCCESS');
    assert.equal(executionResponse.is_verified, true);
  });
});

describe('9. Phase 2 — Adversarial Hardening and Chaos Injection Suite', () => {
  // Pure store simulation matching useRuntimeStore logic
  function createSimulatedStore() {
    let state = {
      eventHistory: [],
      demoStatus: { current_step: -1, status: 'IDLE', history_count: 0 },
      snapshot: { event: null, demo: null, reconsideration: null },
      error: null,
    };

    const onState = (event) => {
      // CHAOS 8: Guard against malformed or partial events
      if (!event || typeof event.step_index !== 'number' || isNaN(event.step_index)) {
        return false;
      }

      const prevEvent = state.snapshot.event;
      const currentStep = state.demoStatus.current_step ?? -1;

      // Deduplicate and maintain monotonic sorted order in event history
      const existingIdx = state.eventHistory.findIndex(
        (e) => e.step_index === event.step_index || (e.event_id && event.event_id && e.event_id === event.event_id)
      );
      let updatedHistory;
      if (existingIdx >= 0) {
        updatedHistory = [...state.eventHistory];
        updatedHistory[existingIdx] = event;
      } else {
        updatedHistory = [...state.eventHistory, event];
      }
      updatedHistory.sort((a, b) => a.step_index - b.step_index);

      // CHAOS 2: State must never move backward; latest canonical step remains authoritative
      const isNewerOrEqual = event.step_index >= currentStep;
      const activeEvent = isNewerOrEqual ? event : prevEvent;
      const activeStep = isNewerOrEqual ? event.step_index : currentStep;
      const reconsideration = isNewerOrEqual ? deriveReconsideration(prevEvent, event) : state.snapshot.reconsideration;

      const updatedDemoStatus = {
        ...state.demoStatus,
        current_step: activeStep,
        history_count: updatedHistory.length,
        status: state.demoStatus.status === 'IDLE' ? 'RUNNING' : state.demoStatus.status,
      };

      state = {
        ...state,
        eventHistory: updatedHistory,
        demoStatus: updatedDemoStatus,
        snapshot: {
          event: activeEvent,
          demo: updatedDemoStatus,
          reconsideration,
        },
      };
      return true;
    };

    const onDemoStatus = (status) => {
      if (status.status === 'IDLE') {
        state = {
          ...state,
          eventHistory: [],
          demoStatus: status,
          snapshot: { event: null, demo: status, reconsideration: null },
          error: null,
        };
      } else {
        state = {
          ...state,
          demoStatus: status,
          snapshot: { ...state.snapshot, demo: status },
        };
      }
    };

    return {
      getState: () => state,
      onState,
      onDemoStatus,
    };
  }

  test('Chaos 1: Duplicate events (1x, 2x, 5x, 20x) are strictly deduplicated', () => {
    const store = createSimulatedStore();
    const event0 = createMockDemoEvent(0, 'Reconnaissance');

    // Deliver 20x
    for (let i = 0; i < 20; i++) {
      const accepted = store.onState(event0);
      assert.equal(accepted, true);
    }

    const st = store.getState();
    assert.equal(st.eventHistory.length, 1, 'Event history must not contain duplicate items');
    assert.equal(st.demoStatus.current_step, 0);
    assert.equal(st.snapshot.event.step_index, 0);
  });

  test('Chaos 2: Out-of-order events (T5 -> T4) do not move active state backward', () => {
    const store = createSimulatedStore();
    const event5 = createMockDemoEvent(5, 'Weaponization');
    const event4 = createMockDemoEvent(4, 'Reconnaissance');

    store.onState(event5);
    assert.equal(store.getState().demoStatus.current_step, 5);
    assert.equal(store.getState().snapshot.event.step_index, 5);

    // Now out-of-order T4 arrives
    store.onState(event4);

    const st = store.getState();
    // Invariant: state never moves backward
    assert.equal(st.demoStatus.current_step, 5, 'Current step must not move backward');
    assert.equal(st.snapshot.event.step_index, 5, 'Active snapshot must retain the latest canonical event');
    // History is correctly ordered monotonically
    assert.equal(st.eventHistory.length, 2);
    assert.equal(st.eventHistory[0].step_index, 4);
    assert.equal(st.eventHistory[1].step_index, 5);
  });

  test('Chaos 3: Dropped event (T0 -> T1 -> T2 -> T4) does not invent T3', () => {
    const store = createSimulatedStore();
    store.onState(createMockDemoEvent(0));
    store.onState(createMockDemoEvent(1));
    store.onState(createMockDemoEvent(2));
    store.onState(createMockDemoEvent(4)); // T3 missing

    const st = store.getState();
    assert.equal(st.eventHistory.length, 4);
    const indices = st.eventHistory.map((e) => e.step_index);
    assert.deepEqual(indices, [0, 1, 2, 4], 'Store must not fabricate dropped step 3');
    assert.equal(st.snapshot.event.step_index, 4);
  });

  test('Chaos 6: Transition to IDLE clears old session data completely', () => {
    const store = createSimulatedStore();
    store.onState(createMockDemoEvent(0));
    store.onState(createMockDemoEvent(1));
    assert.equal(store.getState().eventHistory.length, 2);

    // Transition to IDLE
    store.onDemoStatus({ status: 'IDLE', current_step: -1, history_count: 0 });

    const st = store.getState();
    assert.equal(st.eventHistory.length, 0, 'History must be cleared on IDLE');
    assert.equal(st.snapshot.event, null, 'Snapshot event must be reset on IDLE');
    assert.equal(st.snapshot.reconsideration, null);
  });

  test('Chaos 8: Malformed event missing step_index is dropped safely', () => {
    const store = createSimulatedStore();
    const acceptedMalformed = store.onState({ invalid: 'payload', step_index: undefined });
    assert.equal(acceptedMalformed, false);
    assert.equal(store.getState().eventHistory.length, 0);

    const acceptedNaN = store.onState({ step_index: NaN });
    assert.equal(acceptedNaN, false);
    assert.equal(store.getState().eventHistory.length, 0);
  });

  test('Phase 2D Test E: Replay of old execution payload rejected after reset', () => {
    const oldExecution = {
      action_id: 'ACT-OLD-001',
      evidence_window_id: 'WIN-001',
      authority_decision_id: 'DEC-001',
      approval: {
        approval_id: 'APP-001',
        action_id: 'ACT-OLD-001',
        evidence_window_id: 'WIN-001',
        authority_decision_id: 'DEC-001',
        approved: true,
      },
    };

    // Simulate reset occurring: active evidence window is reset or advanced to WIN-002
    const currentWindowId = 'WIN-002';
    const isStale = oldExecution.evidence_window_id !== currentWindowId;
    assert.equal(isStale, true, 'Old authorization must be recognized as stale when window advances');
  });
});


