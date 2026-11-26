"""Significance testing and bootstrap confidence intervals.

Warning: the Wilcoxon signed-rank test on n paired seeds has a minimum attainable two-sided
exact p-value of 2 / 2**n. With 5 seeds that is 0.0625, so no comparison over 5 seeds can reach
p < 0.05 under the exact test. Use min_wilcoxon_p(n) to check this before interpreting results.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

import numpy as np
from scipy import stats as sps

# Nemenyi critical values q_alpha for alpha = 0.05 (Demsar, 2006), k = 2..20 methods.
Q_ALPHA_005 = {
    2: 1.960, 3: 2.343, 4: 2.569, 5: 2.728, 6: 2.850, 7: 2.949, 8: 3.031, 9: 3.102,
    10: 3.164, 11: 3.219, 12: 3.268, 13: 3.313, 14: 3.354, 15: 3.391, 16: 3.426,
    17: 3.458, 18: 3.489, 19: 3.517, 20: 3.544,
}


def min_wilcoxon_p(n: int) -> float:
    """Smallest attainable exact two-sided Wilcoxon signed-rank p-value for n pairs."""
    if n < 1:
        raise ValueError("n must be >= 1")
    return 2.0 / (2 ** n)


def wilcoxon_paired(a: Sequence[float], b: Sequence[float]) -> tuple[float, float]:
    """Two-sided paired Wilcoxon test. Returns (statistic, p); (nan, nan) if undefined."""
    try:
        res = sps.wilcoxon(np.asarray(a, float), np.asarray(b, float))
    except ValueError:
        return float("nan"), float("nan")
    return float(res.statistic), float(res.pvalue)


def friedman_nemenyi(score_matrix: Any, method_names: Sequence[str], alpha: float = 0.05) -> dict:
    """Friedman test and Nemenyi post-hoc critical difference.

    score_matrix has one row per block (seed or dataset) and one column per method; higher
    scores are better. Friedman needs at least 3 methods (reported as nan for 2). Nemenyi uses
    q_alpha for alpha = 0.05 and supports up to 20 methods.
    """
    M = np.asarray(score_matrix, dtype=float)
    n, k = M.shape
    if k != len(method_names):
        raise ValueError("method_names must match the number of columns")
    if k < 2 or k > 20:
        raise ValueError("friedman_nemenyi supports 2 to 20 methods")
    if alpha != 0.05:
        raise ValueError("only alpha=0.05 critical values are tabulated")
    if k >= 3:
        stat, p = sps.friedmanchisquare(*M.T)
        stat, p = float(stat), float(p)
    else:
        stat, p = float("nan"), float("nan")
    ranks = sps.rankdata(-M, axis=1)
    avg = ranks.mean(axis=0)
    q = Q_ALPHA_005[k]
    cd = q * np.sqrt(k * (k + 1) / (6.0 * n))
    pairs = [(method_names[i], method_names[j]) for i in range(k) for j in range(i + 1, k)
             if abs(avg[i] - avg[j]) > cd]
    return {
        "friedman_statistic": stat,
        "friedman_p": p,
        "average_ranks": {name: float(r) for name, r in zip(method_names, avg)},
        "critical_difference": float(cd),
        "q_alpha": q,
        "n_blocks": int(n),
        "significantly_different_pairs": pairs,
    }


def bootstrap_ci(y_true: Any, y_pred: Any, metric_fn: Callable[[Any, Any], float], n: int = 1000,
                 seed: int = 0, alpha: float = 0.05) -> tuple[float, float, float]:
    """Percentile bootstrap over test rows. Returns (point_estimate, lower, upper)."""
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    rng = np.random.default_rng(seed)
    N = len(y_true)
    vals = np.empty(n)
    for i in range(n):
        idx = rng.integers(0, N, N)
        vals[i] = metric_fn(y_true[idx], y_pred[idx])
    lo, hi = np.nanpercentile(vals, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(metric_fn(y_true, y_pred)), float(lo), float(hi)
