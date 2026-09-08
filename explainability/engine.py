"""Explainability and Feature-Contribution Engine for SIH 26153."""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Mapping, Sequence

import numpy as np

from core.contracts import Direction, NetworkState, SecurityAssessment, TrustLevel, new_id
from eval.dataset import CSV_AVAILABLE_FEATURES
from eval.metrics_v2 import RobustScaleStatistics
from eval.models_v2 import ARStyleBaselineV2
from explainability.contracts import (
    ContributionDirection,
    EvidenceType,
    FeatureContribution,
    ForecastExplanation,
    LagContribution,
    SecurityHypothesisExplanation,
)
from security.contracts import BehaviouralSignature, EvidenceScope, StageHypothesis


class ExplainabilityEngine:
    """Deterministic mathematical explanation generator for dynamics models and security bridge."""

    def __init__(
        self,
        feature_names: Sequence[str] | None = None,
        scales: RobustScaleStatistics | None = None,
    ) -> None:
        self.feature_names = tuple(feature_names or CSV_AVAILABLE_FEATURES)
        self.scales = scales
        self._feat_to_idx = {f: i for i, f in enumerate(self.feature_names)}

    def explain_ar_forecast(
        self,
        ar_model: ARStyleBaselineV2,
        current_state: NetworkState,
        history_deltas: np.ndarray,  # Shape: (p, D) or (p * D,)
        target_feature: str,
        horizon_step: int = 1,
        baseline_state: NetworkState | None = None,
        trust_level: TrustLevel = TrustLevel.HIGH,
        confidence: float = 0.85,
    ) -> ForecastExplanation:
        """
        Explain a single feature AR(p) prediction using exact mathematical lag decomposition.
        Delta_hat_x_j(t+1) = c_j + sum_{l=1}^p beta_{j, l} * Delta_x_j(t - l + 1)
        """
        if target_feature not in self._feat_to_idx:
            raise ValueError(f"Unknown target feature: {target_feature}")

        feat_idx = self._feat_to_idx[target_feature]
        p = ar_model.selected_p
        D = len(self.feature_names)

        # Reshape history_deltas if flattened (p * D) -> (p, D)
        if history_deltas.ndim == 1:
            h_deltas = history_deltas.reshape((p, D))
        else:
            h_deltas = history_deltas

        # Extract per-feature linear regression model
        reg = ar_model.models[feat_idx]
        coeffs = reg.coef_  # Shape: (p,)
        intercept = reg.intercept_

        # Extract historical deltas for this feature in lag order:
        # lag 1 is the most recent historical delta (index -1), lag p is oldest (index 0)
        # Note: in ARStyleBaselineV2, X_deltas columns are [Delta_{t-p+1}, ..., Delta_t]
        lag_contributions: list[LagContribution] = []
        raw_lag_sum = 0.0
        abs_lag_sum = 0.0

        for lag_i in range(p):
            lag_order = p - lag_i
            val = float(h_deltas[lag_i, feat_idx])
            beta = float(coeffs[lag_i])
            signed_contrib = beta * val
            raw_lag_sum += signed_contrib
            abs_lag_sum += abs(signed_contrib)

        for lag_i in range(p):
            lag_order = p - lag_i
            val = float(h_deltas[lag_i, feat_idx])
            beta = float(coeffs[lag_i])
            signed_contrib = beta * val
            rel_wt = abs(signed_contrib) / (abs_lag_sum + 1e-9)
            lag_contributions.append(
                LagContribution(
                    lag_order=lag_order,
                    coefficient=beta,
                    lag_value=val,
                    signed_contribution=signed_contrib,
                    relative_weight=rel_wt,
                )
            )

        predicted_delta = float(intercept + raw_lag_sum)
        curr_val = float(current_state.feature_values().get(target_feature, 0.0))
        forecast_val = curr_val + predicted_delta
        base_val = float(baseline_state.feature_values().get(target_feature, 0.0)) if baseline_state else curr_val

        # Determine evidence type
        delta_curr_vs_base = curr_val - base_val
        is_curr_elevated = abs(delta_curr_vs_base) > 1e-4
        is_pred_significant = abs(predicted_delta) > 1e-4

        if is_curr_elevated and is_pred_significant:
            evidence_type = EvidenceType.BOTH
        elif is_pred_significant:
            evidence_type = EvidenceType.FORECAST
        else:
            evidence_type = EvidenceType.CURRENT

        # Feature contribution object for the target feature
        dir_enum = (
            ContributionDirection.POSITIVE
            if predicted_delta > 1e-6
            else ContributionDirection.NEGATIVE
            if predicted_delta < -1e-6
            else ContributionDirection.NEUTRAL
        )

        target_contrib = FeatureContribution(
            feature_name=target_feature,
            signed_direction=dir_enum,
            normalized_contribution=1.0,
            raw_contribution=abs(predicted_delta),
            current_value=curr_val,
            predicted_delta=predicted_delta,
            baseline_reference_value=base_val,
            evidence_type=evidence_type,
            lag_breakdown=tuple(lag_contributions),
            description=f"Autoregressive AR({p}) prediction driven by recent {target_feature} momentum.",
            is_available=True,
        )

        limitations = (
            "Model contributions reflect statistical linear autoregressive correlations, not global causal mechanisms.",
            "Unavailable network topology attributes (e.g. host endpoint IPs) are excluded from the model.",
        )

        prov_hash = hashlib.sha256(
            f"{current_state.window_id}:{target_feature}:{predicted_delta}:{p}".encode("utf-8")
        ).hexdigest()

        return ForecastExplanation(
            explanation_id=new_id("expl-fc"),
            window_id=current_state.window_id,
            timestamp=current_state.timestamp_end,
            model_name=f"AR({p})",
            horizon=horizon_step,
            target_feature=target_feature,
            predicted_delta=predicted_delta,
            current_value=curr_val,
            forecast_value=forecast_val,
            baseline_reference_value=base_val,
            top_features=(target_contrib,),
            evidence_type=evidence_type,
            confidence=confidence,
            trust_level=trust_level,
            limitations=limitations,
            provenance_hash=prov_hash,
        )

    def explain_multi_feature_rollout(
        self,
        ar_model: ARStyleBaselineV2,
        current_state: NetworkState,
        history_deltas: np.ndarray,
        top_k: int = 5,
        baseline_state: NetworkState | None = None,
        trust_level: TrustLevel = TrustLevel.HIGH,
    ) -> list[FeatureContribution]:
        """Rank top contributing features across all predicted features."""
        contributions: list[FeatureContribution] = []
        p = ar_model.selected_p
        D = len(self.feature_names)

        if history_deltas.ndim == 1:
            h_deltas = history_deltas.reshape((p, D))
        else:
            h_deltas = history_deltas

        raw_scores: list[tuple[str, float, float, float, float, list[LagContribution]]] = []

        for f_idx, feat in enumerate(self.feature_names):
            reg = ar_model.models[f_idx]
            coeffs = reg.coef_
            intercept = reg.intercept_

            lag_contribs: list[LagContribution] = []
            raw_lag_sum = 0.0
            abs_lag_sum = 0.0

            for lag_i in range(p):
                val = float(h_deltas[lag_i, f_idx])
                beta = float(coeffs[lag_i])
                signed_c = beta * val
                raw_lag_sum += signed_c
                abs_lag_sum += abs(signed_c)

            for lag_i in range(p):
                lag_order = p - lag_i
                val = float(h_deltas[lag_i, f_idx])
                beta = float(coeffs[lag_i])
                signed_c = beta * val
                rel_w = abs(signed_c) / (abs_lag_sum + 1e-9)
                lag_contribs.append(
                    LagContribution(
                        lag_order=lag_order,
                        coefficient=beta,
                        lag_value=val,
                        signed_contribution=signed_c,
                        relative_weight=rel_w,
                    )
                )

            pred_delta = float(intercept + raw_lag_sum)
            curr_v = float(current_state.feature_values().get(feat, 0.0))
            base_v = float(baseline_state.feature_values().get(feat, 0.0)) if baseline_state else curr_v

            # Scale-normalize contribution if scales are available
            if self.scales and feat in self.scales.feature_names:
                scale_idx = self.scales.feature_names.index(feat)
                eff_scale = max(float(self.scales.effective_scales[scale_idx]), 1e-6)
                norm_score = abs(pred_delta) / eff_scale
            else:
                norm_score = abs(pred_delta)

            raw_scores.append((feat, pred_delta, curr_v, base_v, norm_score, lag_contribs))

        # Sort descending by normalized score
        raw_scores.sort(key=lambda item: item[4], reverse=True)
        max_score = max((item[4] for item in raw_scores), default=1.0)
        max_score = max(max_score, 1e-6)

        for feat, p_delta, c_val, b_val, score, lag_list in raw_scores[:top_k]:
            dir_e = (
                ContributionDirection.POSITIVE
                if p_delta > 1e-6
                else ContributionDirection.NEGATIVE
                if p_delta < -1e-6
                else ContributionDirection.NEUTRAL
            )
            d_curr = c_val - b_val
            is_c_elev = abs(d_curr) > 1e-4
            is_p_sig = abs(p_delta) > 1e-4

            if is_c_elev and is_p_sig:
                ev_type = EvidenceType.BOTH
            elif is_p_sig:
                ev_type = EvidenceType.FORECAST
            else:
                ev_type = EvidenceType.CURRENT

            contributions.append(
                FeatureContribution(
                    feature_name=feat,
                    signed_direction=dir_e,
                    normalized_contribution=score / max_score,
                    raw_contribution=p_delta,
                    current_value=c_val,
                    predicted_delta=p_delta,
                    baseline_reference_value=b_val,
                    evidence_type=ev_type,
                    lag_breakdown=tuple(lag_list),
                    description=f"Autoregressive AR({p}) momentum for {feat} with normalized impact {score/max_score:.2f}.",
                    is_available=True,
                )
            )

        return contributions

    def explain_security_hypothesis(
        self,
        hypothesis_or_assessment: StageHypothesis | Sequence[StageHypothesis] | SecurityAssessment | None,
        current_state: NetworkState,
        top_k: int = 5,
        baseline_state: NetworkState | None = None,
    ) -> SecurityHypothesisExplanation:
        """
        Generate a typed explainability object for a stage hypothesis synthesized by the Security Bridge.
        """
        if isinstance(hypothesis_or_assessment, (list, tuple)) and len(hypothesis_or_assessment) > 0:
            primary = hypothesis_or_assessment[0]
        elif isinstance(hypothesis_or_assessment, StageHypothesis):
            primary = hypothesis_or_assessment
        elif hasattr(hypothesis_or_assessment, "primary_hypothesis"):
            primary = hypothesis_or_assessment.primary_hypothesis
        else:
            primary = None

        if not primary or primary.candidate_stage == "Unknown":
            conf = primary.confidence if primary else 0.90
            tl = primary.trust_level if primary else TrustLevel.HIGH
            return SecurityHypothesisExplanation(
                explanation_id=new_id("expl-sec"),
                window_id=current_state.window_id,
                timestamp=current_state.timestamp_end,
                primary_stage="Unknown / Benign",
                confidence=conf,
                trust_level=tl,
                supporting_evidence=("Telemetry parameters conform to baseline operating distribution.",),
                counter_evidence=("Zero active behavioural attack signatures detected.",),
                alternative_explanations=("Normal enterprise background traffic.",),
                top_contributing_features=(),
                current_vs_forecast_breakdown={"status": "Nominal baseline - no anomalous transition detected."},
                limitations=("Statistical assessment only; benign baseline does not guarantee absence of low-and-slow zero-days.",),
                provenance_hash=hashlib.sha256(f"{current_state.window_id}:benign".encode("utf-8")).hexdigest(),
            )

        # Collect supporting signatures and aggregate per feature
        supporting_evidence_lines: list[str] = []
        counter_evidence_lines: list[str] = list(primary.counter_evidence)
        alt_explanations: list[str] = list(primary.alternative_explanations)
        curr_vs_fc: dict[str, str] = {}

        # Feature accumulator: feat -> {has_curr: bool, fc_deltas: list[float], c_val: float, b_val: float}
        feat_data: dict[str, dict[str, Any]] = {}

        for sig in primary.supporting_signatures:
            supporting_evidence_lines.append(f"{sig.signature_type.value}: {sig.explanation}")
            for feat in sig.supporting_features:
                if feat not in self._feat_to_idx:
                    continue
                if feat not in feat_data:
                    c_val = float(current_state.feature_values().get(feat, 0.0))
                    b_val = float(baseline_state.feature_values().get(feat, 0.0)) if baseline_state else c_val
                    feat_data[feat] = {
                        "has_curr": False,
                        "fc_deltas": [],
                        "c_val": c_val,
                        "b_val": b_val,
                    }

                if sig.scope == EvidenceScope.CURRENT:
                    feat_data[feat]["has_curr"] = True
                elif sig.scope == EvidenceScope.FORECAST:
                    # Check both exact name and _delta suffix
                    p_delta = float(sig.predicted_deltas.get(feat, sig.predicted_deltas.get(f"{feat}_delta", 0.0)))
                    if abs(p_delta) > 1e-4:
                        feat_data[feat]["fc_deltas"].append(p_delta)

        feature_contrib_dict: dict[str, FeatureContribution] = {}
        for feat, data in feat_data.items():
            c_val = data["c_val"]
            b_val = data["b_val"]
            fc_deltas = data["fc_deltas"]
            avg_p_delta = float(np.mean(fc_deltas)) if fc_deltas else 0.0

            has_curr_elev = data["has_curr"] or abs(c_val - b_val) > 1e-4
            has_fc_prog = len(fc_deltas) > 0 and abs(avg_p_delta) > 1e-4

            if has_curr_elev and has_fc_prog:
                ev_type = EvidenceType.BOTH
                desc = f"Observed {feat} elevation ({c_val:.1f}) is reinforced by forecasted growth ({avg_p_delta:+.1f})."
            elif has_fc_prog:
                ev_type = EvidenceType.FORECAST
                desc = f"Model predicts {feat} will expand ({avg_p_delta:+.1f}) across upcoming observation window."
            else:
                ev_type = EvidenceType.CURRENT
                desc = f"Observed {feat} is currently elevated ({c_val:.1f}) relative to baseline ({b_val:.1f})."

            curr_vs_fc[feat] = desc
            dir_e = ContributionDirection.POSITIVE if (avg_p_delta > 0 or c_val > b_val) else ContributionDirection.NEGATIVE

            feature_contrib_dict[feat] = FeatureContribution(
                feature_name=feat,
                signed_direction=dir_e,
                normalized_contribution=1.0,
                raw_contribution=abs(avg_p_delta) if has_fc_prog else abs(c_val - b_val),
                current_value=c_val,
                predicted_delta=avg_p_delta,
                baseline_reference_value=b_val,
                evidence_type=ev_type,
                description=desc,
                is_available=True,
            )

        # Normalize relative contributions
        top_contribs = list(feature_contrib_dict.values())
        max_raw = max((fc.raw_contribution for fc in top_contribs), default=1.0)
        max_raw = max(max_raw, 1e-6)

        normalized_contribs: list[FeatureContribution] = []
        for fc in top_contribs[:top_k]:
            normalized_contribs.append(
                FeatureContribution(
                    feature_name=fc.feature_name,
                    signed_direction=fc.signed_direction,
                    normalized_contribution=fc.raw_contribution / max_raw,
                    raw_contribution=fc.raw_contribution,
                    current_value=fc.current_value,
                    predicted_delta=fc.predicted_delta,
                    baseline_reference_value=fc.baseline_reference_value,
                    evidence_type=fc.evidence_type,
                    description=fc.description,
                    is_available=fc.is_available,
                )
            )

        limitations = (
            "Feature contributions indicate statistical alignment with known behavioural patterns, not verified adversary intent.",
            "Host-level lateral fan-out is unobservable in anonymized flow telemetry.",
        )

        prov_hash = hashlib.sha256(
            f"{current_state.window_id}:{primary.candidate_stage}:{primary.confidence}".encode("utf-8")
        ).hexdigest()

        return SecurityHypothesisExplanation(
            explanation_id=new_id("expl-sec"),
            window_id=current_state.window_id,
            timestamp=current_state.timestamp_end,
            primary_stage=primary.candidate_stage,
            confidence=primary.confidence,
            trust_level=primary.trust_level,
            supporting_evidence=tuple(supporting_evidence_lines),
            counter_evidence=tuple(counter_evidence_lines),
            alternative_explanations=tuple(alt_explanations),
            top_contributing_features=tuple(normalized_contribs),
            current_vs_forecast_breakdown=curr_vs_fc,
            limitations=limitations,
            provenance_hash=prov_hash,
        )

    def explain_via_perturbation(
        self,
        predict_fn: Any,
        x_input: np.ndarray,  # 1D array of input features
        feature_names: Sequence[str],
        perturbation_factor: float = 0.20,
    ) -> list[dict[str, Any]]:
        """
        Model-agnostic local feature importance via controlled input perturbation.
        x_j -> x_j * (1 + delta) -> measure Delta output
        """
        base_out = np.array(predict_fn(x_input.reshape(1, -1))[0])
        results: list[dict[str, Any]] = []

        for j, feat in enumerate(feature_names):
            x_pert = x_input.copy()
            val = x_pert[j]
            delta = abs(val) * perturbation_factor if abs(val) > 1e-4 else perturbation_factor
            x_pert[j] += delta

            pert_out = np.array(predict_fn(x_pert.reshape(1, -1))[0])
            diff = pert_out - base_out
            norm_diff = float(np.linalg.norm(diff))

            results.append({
                "feature_name": feat,
                "base_value": float(val),
                "perturbed_value": float(x_pert[j]),
                "output_shift_l2": norm_diff,
                "signed_direction": "INCREASING" if np.sum(diff) > 0 else "DECREASING",
            })

        results.sort(key=lambda r: r["output_shift_l2"], reverse=True)
        return results
