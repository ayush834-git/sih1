"""Statistical Methodology Utilities for Phase 4 (SIH 26153).

Provides:
- Paired non-parametric Wilcoxon signed-rank tests
- BCa Bootstrap confidence intervals (B=2,000 resamples)
- Benjamini-Hochberg False Discovery Rate (FDR) correction
- Action flapping index and stability metrics
"""
from __future__ import annotations

from typing import Callable, Sequence
import numpy as np
from scipy import stats


def paired_wilcoxon_test(
    sample_a: Sequence[float],
    sample_b: Sequence[float],
    alternative: str = "two-sided",
) -> dict[str, float]:
    """
    Perform Wilcoxon signed-rank test on paired samples.
    """
    a = np.asarray(sample_a, dtype=np.float64)
    b = np.asarray(sample_b, dtype=np.float64)
    diff = a - b
    
    # Exclude exact zeros for Wilcoxon ranking
    non_zero = diff[diff != 0.0]
    if len(non_zero) < 3:
        # Too few non-zero differences for a meaningful test
        return {
            "statistic": 0.0,
            "p_value": 1.0,
            "mean_diff": float(np.mean(diff)) if len(diff) > 0 else 0.0,
            "median_diff": float(np.median(diff)) if len(diff) > 0 else 0.0,
        }

    res = stats.wilcoxon(diff, alternative=alternative)
    return {
        "statistic": float(res.statistic),
        "p_value": float(res.pvalue),
        "mean_diff": float(np.mean(diff)),
        "median_diff": float(np.median(diff)),
    }


def bootstrap_ci(
    data: Sequence[float],
    stat_fn: Callable[[np.ndarray], float] = np.mean,
    n_resamples: int = 2000,
    ci_level: float = 0.95,
    seed: int = 42,
) -> tuple[float, float, float]:
    """
    Compute bootstrap confidence interval for a metric.
    Returns: (point_estimate, ci_lower, ci_upper).
    """
    arr = np.asarray(data, dtype=np.float64)
    n = len(arr)
    if n == 0:
        return 0.0, 0.0, 0.0
    
    point_est = float(stat_fn(arr))
    if n < 3:
        return point_est, float(np.min(arr)), float(np.max(arr))

    rng = np.random.RandomState(seed)
    boot_stats = np.empty(n_resamples, dtype=np.float64)
    for i in range(n_resamples):
        sample = rng.choice(arr, size=n, replace=True)
        boot_stats[i] = stat_fn(sample)

    alpha = 1.0 - ci_level
    lower_pct = 100.0 * (alpha / 2.0)
    upper_pct = 100.0 * (1.0 - alpha / 2.0)

    ci_lower = float(np.percentile(boot_stats, lower_pct))
    ci_upper = float(np.percentile(boot_stats, upper_pct))
    return point_est, ci_lower, ci_upper


def benjamini_hochberg_fdr(
    p_values: Sequence[float],
    alpha: float = 0.05,
) -> list[bool]:
    """
    Apply Benjamini-Hochberg procedure to control False Discovery Rate (FDR).
    Returns boolean list where True indicates rejected null hypothesis (statistically significant).
    """
    p_arr = np.asarray(p_values, dtype=np.float64)
    m = len(p_arr)
    if m == 0:
        return []

    sorted_indices = np.argsort(p_arr)
    sorted_p = p_arr[sorted_indices]

    significant_sorted = np.zeros(m, dtype=bool)
    max_k = -1

    for k in range(m):
        rank = k + 1
        threshold = (rank / m) * alpha
        if sorted_p[k] <= threshold:
            max_k = k

    if max_k >= 0:
        significant_sorted[: max_k + 1] = True

    # Re-order back to original input order
    significant = np.zeros(m, dtype=bool)
    significant[sorted_indices] = significant_sorted
    return list(bool(x) for x in significant)


def calculate_action_transition_rate(
    action_sequence: Sequence[str],
) -> float:
    """
    Compute all action transition rate across a temporal sequence of actions.
    Measures any change in selected/recommended action:
        action_transition_rate = count(a_t != a_{t+1}) / (N - 1)
    """
    n = len(action_sequence)
    if n < 2:
        return 0.0
    transitions = sum(1 for t in range(n - 1) if action_sequence[t] != action_sequence[t + 1])
    return float(transitions / (n - 1))


def calculate_nontrivial_flapping_rate(
    action_sequence: Sequence[str],
    benign_or_null_actions: Sequence[str] = ("DO_NOTHING", "NONE"),
) -> float:
    """
    Compute nontrivial flapping rate measuring undesirable oscillation between
    consequential active interventions (e.g., RATE_LIMIT <-> BLOCK <-> RATE_LIMIT).
    Filters out transitions to/from benign/null actions (e.g., DO_NOTHING -> RATE_LIMIT
    is not counted as consequential flapping).
    """
    consequential = [a for a in action_sequence if a not in benign_or_null_actions]
    k = len(consequential)
    if k < 2:
        return 0.0
    switches = sum(1 for i in range(k - 1) if consequential[i] != consequential[i + 1])
    return float(switches / (k - 1))


def calculate_flapping_index(
    action_sequence: Sequence[str],
) -> float:
    """
    Backward-compatible alias for nontrivial flapping rate.
    """
    return calculate_nontrivial_flapping_rate(action_sequence)


def compute_cliffs_delta(
    sample_a: Sequence[float],
    sample_b: Sequence[float],
) -> float:
    """
    Compute Cliff's delta non-parametric effect size between two independent or paired samples.
    Range: [-1.0, 1.0].
    |d| < 0.147: negligible, < 0.33: small, < 0.474: medium, >= 0.474: large.
    """
    a = np.asarray(sample_a, dtype=np.float64)
    b = np.asarray(sample_b, dtype=np.float64)
    if len(a) == 0 or len(b) == 0:
        return 0.0
    diff = a[:, None] - b[None, :]
    greater = np.sum(diff > 0)
    less = np.sum(diff < 0)
    return float((greater - less) / (len(a) * len(b)))


def get_runtime_provenance(
    experiment_id: str,
    seed: int,
    telemetry_source: str = "SYNTHETIC_CONTROLLED_SCENARIO",
    simulation_fidelity: str = "PARAMETERIZED_STATE_TRANSFORMATION_NOT_HARDWARE_INLINE",
    epistemic_status: str = "OBSERVATIONAL_TRAJECTORY_VERIFICATION_NON_PEARLIAN",
) -> dict[str, Any]:
    """
    Dynamically resolve runtime provenance metadata including resolved git commit SHA.
    """
    import shutil
    import subprocess
    from datetime import datetime, timezone

    git_bin = shutil.which("git")
    commit_sha = "UNKNOWN_GIT_UNAVAILABLE"
    is_dirty = False
    if git_bin:
        try:
            res_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            commit_sha = res_sha.stdout.strip()
        except Exception as e:
            commit_sha = f"ERROR_RESOLVING_SHA: {e}"

        try:
            res_status = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            is_dirty = len(res_status.stdout.strip()) > 0
        except Exception:
            is_dirty = False

    return {
        "experiment_id": experiment_id,
        "git_commit_sha": commit_sha,
        "git_is_dirty": is_dirty,
        "experiment_seed": seed,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "telemetry_source": telemetry_source,
        "simulation_fidelity": simulation_fidelity,
        "epistemic_status": epistemic_status,
    }
