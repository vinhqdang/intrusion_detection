import numpy as np
from scipy.stats import kstest

from idsbench.feasibility.common import threshold_at_fpr
from idsbench.feasibility.conformal import (
    benjamini_hochberg, conformal_pvalues, domain_weights, weighted_conformal_pvalues,
)


def test_benign_pvalues_are_uniform():
    rng = np.random.default_rng(0)
    cal = rng.normal(0, 1, 1000)
    test = rng.normal(0, 1, 2000)
    p = conformal_pvalues(cal, test)
    assert kstest(p, "uniform").pvalue > 0.01
    assert p.min() > 0 and p.max() <= 1


def test_bh_fdr_controlled_on_synthetic():
    fdr = []
    for rep in range(50):
        rng = np.random.default_rng(100 + rep)
        cal = rng.normal(0, 1, 1000)
        benign = rng.normal(0, 1, 1000)
        anom = rng.normal(3, 1, 100)
        scores = np.r_[benign, anom]
        is_null = np.r_[np.ones(1000, bool), np.zeros(100, bool)]
        rej = benjamini_hochberg(conformal_pvalues(cal, scores), alpha=0.1)
        fdp = (rej & is_null).sum() / max(rej.sum(), 1)
        fdr.append(fdp)
    assert np.mean(fdr) <= 0.15


def test_threshold_realised_fpr_on_fresh_benign():
    rng = np.random.default_rng(1)
    cal = rng.normal(size=2000)
    thr, ok = threshold_at_fpr(cal, 0.05)
    assert ok
    fresh = rng.normal(size=20000)
    assert np.mean(fresh > thr) <= 0.05 + 0.01


def test_threshold_not_attainable_for_small_calibration():
    thr, ok = threshold_at_fpr(np.arange(100.0), 1e-3)
    assert not ok and np.isinf(thr)


def test_weighted_with_unit_weights_matches_unweighted():
    rng = np.random.default_rng(2)
    cal = rng.normal(size=300)
    test = rng.normal(size=50)
    p1 = conformal_pvalues(cal, test)
    p2 = weighted_conformal_pvalues(cal, np.ones(300), test, np.ones(50))
    assert np.allclose(p1, p2)


def test_domain_weights_detect_shift():
    rng = np.random.default_rng(3)
    src = rng.normal(0, 1, (2000, 3))
    tgt = rng.normal(1.5, 1, (2000, 3))
    w_src, w_tgt = domain_weights(src, tgt, seed=0)
    assert w_tgt.mean() > w_src.mean()
    assert w_src.min() >= 0.05 and w_tgt.max() <= 20


def test_domain_weights_near_one_without_shift():
    rng = np.random.default_rng(4)
    src = rng.normal(0, 1, (3000, 3))
    tgt = rng.normal(0, 1, (1000, 3))
    w_src, w_tgt = domain_weights(src, tgt, seed=0)
    assert abs(w_src.mean() - 1) < 0.1 and abs(w_tgt.mean() - 1) < 0.2


def test_fused_threshold_realised_fpr_on_fresh_benign():
    """Fusion with split calibration: the threshold set is scored against a disjoint reference set,
    so the realised FPR on fresh benign stays within 20% of the target on average."""
    from idsbench.feasibility.conformal import fused_score, split_calibration

    targets = (1e-2, 1e-3)
    realised = {t: [] for t in targets}
    for rep in range(20):
        rng = np.random.default_rng(500 + rep)
        # two correlated benign scores, one per model (higher = more anomalous)
        s1 = rng.normal(size=(8000, 2))
        s1[:, 1] = 0.5 * s1[:, 0] + np.sqrt(1 - 0.25) * s1[:, 1]
        ref, thr_set = s1[:4000], s1[4000:]
        fresh = rng.normal(size=(200_000, 2))
        fresh[:, 1] = 0.5 * fresh[:, 0] + np.sqrt(1 - 0.25) * fresh[:, 1]
        cal_fused = fused_score([ref[:, 0], ref[:, 1]], [thr_set[:, 0], thr_set[:, 1]])
        fresh_fused = fused_score([ref[:, 0], ref[:, 1]], [fresh[:, 0], fresh[:, 1]])
        for t in targets:
            thr, ok = threshold_at_fpr(cal_fused, t)
            assert ok
            realised[t].append(np.mean(fresh_fused > thr))
    for t in targets:
        assert np.mean(realised[t]) <= 1.2 * t, (t, np.mean(realised[t]))

    cal = np.arange(1000)
    ref_idx, thr_idx = split_calibration(cal, seed=3)
    assert len(np.intersect1d(ref_idx, thr_idx)) == 0
    assert len(ref_idx) + len(thr_idx) == len(cal)
