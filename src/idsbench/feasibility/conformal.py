"""Split-conformal p-values, Benjamini-Hochberg, and weighted conformal (Tibshirani et al. 2019).

Convention: higher score = more anomalous; calibration scores come from benign rows only.
"""

from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler


def conformal_pvalues(cal_scores, test_scores) -> np.ndarray:
    """p_j = (1 + #{cal >= s_j}) / (n_cal + 1), vectorised with searchsorted."""
    cal = np.sort(np.asarray(cal_scores, dtype=float))
    s = np.asarray(test_scores, dtype=float)
    n = len(cal)
    count_ge = n - np.searchsorted(cal, s, side="left")
    return (1.0 + count_ge) / (n + 1.0)


def benjamini_hochberg(pvals, alpha: float) -> np.ndarray:
    """Boolean rejection mask controlling the FDR at level alpha."""
    p = np.asarray(pvals, dtype=float)
    m = len(p)
    if m == 0:
        return np.zeros(0, dtype=bool)
    order = np.argsort(p)
    thresh = alpha * np.arange(1, m + 1) / m
    below = p[order] <= thresh
    reject = np.zeros(m, dtype=bool)
    if below.any():
        k = np.max(np.flatnonzero(below))
        reject[order[: k + 1]] = True
    return reject


def weighted_conformal_pvalues(cal_scores, cal_w, test_scores, test_w) -> np.ndarray:
    """p_j = (sum_i w_i 1[s_i >= s_j] + w_j) / (sum_i w_i + w_j).

    With all weights equal to 1 this reduces to conformal_pvalues. Test weights w_j are the
    density-ratio weights of the test points (label-free on the target side).
    """
    cal = np.asarray(cal_scores, dtype=float)
    w = np.asarray(cal_w, dtype=float)
    order = np.argsort(cal)
    cal_sorted = cal[order]
    w_sorted = w[order]
    suffix = np.concatenate([np.cumsum(w_sorted[::-1])[::-1], [0.0]])  # suffix[k] = sum_{i>=k}
    s = np.asarray(test_scores, dtype=float)
    wt = np.asarray(test_w, dtype=float)
    idx = np.searchsorted(cal_sorted, s, side="left")
    total = w.sum()
    return (suffix[idx] + wt) / (total + wt)


def fused_score(ref_scores, query_scores) -> np.ndarray:
    """Bonferroni-style fusion: -min over models of the conformal p-value.

    ``ref_scores[m]`` is model m's reference (benign calibration) score array; ``query_scores[m]``
    holds model m's scores for the query rows. Higher fused score = more anomalous. The reference
    sets must not contain the query rows: see ``split_calibration``.
    """
    pv = np.vstack([conformal_pvalues(r, q) for r, q in zip(ref_scores, query_scores)])
    return -pv.min(axis=0)


def split_calibration(cal_idx, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Random disjoint halves of a calibration index set: (reference, threshold) sets.

    A set that serves as the reference for conformal p-values must not also set the threshold on
    the scores those p-values produce: the threshold rows would then be compared with themselves
    and the realised FPR is no longer controlled. The halves use their own RNG stream.
    """
    cal_idx = np.asarray(cal_idx)
    perm = np.random.default_rng([seed, 17]).permutation(cal_idx)
    half = len(perm) // 2
    return np.sort(perm[:half]), np.sort(perm[half:])


def effective_sample_size(w) -> float:
    """Kish effective sample size (sum w)^2 / sum w^2."""
    w = np.asarray(w, dtype=float)
    return float(w.sum() ** 2 / (w ** 2).sum())


def fit_domain_model(X_src, X_tgt, seed: int = 0, clip: tuple[float, float] = (0.05, 20.0)):
    """Fit a domain classifier (source = 0, target = 1) on features only and return a weight function.

    The returned function maps feature rows Z to density-ratio weights p/(1-p) (times the sample-size
    ratio n_src/n_tgt, so identical distributions give weights near 1), clipped to ``clip``.
    """
    X_src = np.asarray(X_src, dtype=float)
    X_tgt = np.asarray(X_tgt, dtype=float)
    X = np.vstack([X_src, X_tgt])
    d = np.r_[np.zeros(len(X_src)), np.ones(len(X_tgt))]
    scaler = StandardScaler().fit(X)
    clf = LogisticRegression(max_iter=500, random_state=seed)
    clf.fit(scaler.transform(X), d)
    ratio = len(X_src) / len(X_tgt)

    def weights(Z):
        p = clf.predict_proba(scaler.transform(np.asarray(Z, dtype=float)))[:, 1]
        p = np.clip(p, 1e-9, 1 - 1e-9)
        return np.clip(ratio * p / (1 - p), *clip)

    return weights


def domain_weights(X_src, X_tgt, seed: int = 0, clip: tuple[float, float] = (0.05, 20.0)
                   ) -> tuple[np.ndarray, np.ndarray]:
    """Density-ratio weights for both samples from one domain classifier (features only)."""
    w = fit_domain_model(X_src, X_tgt, seed, clip)
    return w(X_src), w(X_tgt)
