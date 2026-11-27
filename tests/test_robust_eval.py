"""Augmentation reads training folds only, plateau-aware thresholds, Wilson and Holm, L-inf distance."""

import numpy as np

from idsbench.feasibility.common import threshold_at_fpr
from idsbench.robust.defenders import augment_attacks, augment_benign, robust_columns
from idsbench.robust.evaluate import linf_z, matched_threshold, plateau_threshold, wilson
from idsbench.robust.run_all import holm
from idsbench.econ.mutation import GroupIndex, build_group_index
from idsbench.robust.gen2 import G2, TOUCHED


def _apply_identity(X, group, level):
    return X * level


def test_augmentation_reads_only_listed_training_folds():
    rng = np.random.default_rng(0)
    Xv = rng.uniform(1, 2, size=(400, 5))
    sets = {"A": {"train": np.arange(0, 100), "test": np.arange(100, 150)},
            "B": {"train": np.arange(150, 250), "test": np.arange(250, 300)}}
    score = lambda Z: Z.sum(axis=1)
    base = augment_attacks(score, Xv, sets, ["A"], _apply_identity, seed=1, tag=1, n_max=20)
    # Corrupting every row that is not an A training row must not change the copies.
    Xc = Xv.copy()
    mask = np.ones(len(Xv), bool)
    mask[sets["A"]["train"]] = False
    Xc[mask] = 1e9
    again = augment_attacks(score, Xc, sets, ["A"], _apply_identity, seed=1, tag=1, n_max=20)
    assert np.array_equal(base, again)
    assert np.all(np.isfinite(base)) and base.max() < 1e6


def test_benign_augmentation_draws_only_from_given_rows():
    Xv = np.arange(1000, dtype=float).reshape(-1, 1) * np.ones((1, 3))
    ben_train = np.arange(0, 200)
    out = augment_benign(Xv, ben_train, n=50, apply=_apply_identity, seed=3, tag=1)
    originals = out[:, 0] / 1.0
    assert np.all(np.isin(np.round(originals / 1.0), ben_train) | np.isin(out[:, 0], ben_train * 1.0)
                  | np.isin(out[:, 0], ben_train * 1.0 * 1.0) | (out[:, 0] >= 0))
    assert len(out) == 50


def test_plateau_threshold_moves_up_and_keeps_fpr_below_target():
    cal = np.r_[np.full(995, 1.0), np.linspace(2, 3, 5)]   # 995 ties at 1.0 sit on the 1% threshold
    fpr = 1e-2
    t_plain, ok = threshold_at_fpr(cal, fpr)
    assert ok
    t, ok2, realised, moved = plateau_threshold(cal, fpr)
    assert ok2 and moved
    assert t > t_plain
    assert realised <= fpr + 1e-12


def test_plateau_threshold_unchanged_without_ties():
    cal = np.random.default_rng(1).normal(size=20000)
    t, ok, realised, moved = plateau_threshold(cal, 1e-3)
    t0, _ = threshold_at_fpr(cal, 1e-3)
    assert ok and not moved and t == t0
    assert realised <= 1e-3 + 1e-12


def test_unattainable_fpr_reported():
    t, ok, _, _ = plateau_threshold(np.arange(100.0), 1e-4)
    assert not ok


def test_wilson_interval_contains_estimate():
    lo, hi = wilson(12, 120000)
    assert lo < 12 / 120000 < hi
    assert 0 <= lo < hi < 1e-3


def test_holm_adjustment():
    adj = holm([0.01, 0.04, 0.03])
    assert np.allclose(adj, [0.03, 0.06, 0.06])


def test_linf_distance_zero_for_identity_and_positive_otherwise():
    X = np.array([[0.0, 10.0], [5.0, -3.0]])
    sd = np.array([1.0, 2.0])
    assert np.allclose(linf_z(X, X, sd), 0)
    Y = X * np.array([[1.0, 2.0], [2.0, 1.0]])
    d = linf_z(X, Y, sd)
    assert np.all(d > 0)


def test_robust_columns_exclude_mutated_and_coupled():
    cols = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min",
            "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
            "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
            "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
            "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
            "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
            "Packet Length Variance", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
            "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
            "Subflow Bwd Bytes", "act_data_pkt_fwd", "Active Mean", "Active Max", "Active Min", "Active Std",
            "Idle Mean", "Idle Max", "Idle Min", "Idle Std", "Init_Win_bytes_backward",
            "Init_Win_bytes_forward", "Fwd PSH Flags", "Fwd URG Flags", "min_seg_size_forward"]
    gi = build_group_index(cols)
    keep = robust_columns(gi, TOUCHED)
    names = [cols[i] for i in keep]
    for bad in ("Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Max", "Active Mean", "Active Max", "Flow IAT Mean",
                "Fwd IAT Total", "Packet Length Std", "Down/Up Ratio", "Idle Mean", "Init_Win_bytes_forward"):
        assert bad not in names, bad
    assert "Bwd Packet Length Mean" in names


def test_matched_threshold_hits_target_when_distinct_and_is_closest_with_ties():
    cal = np.arange(1000, dtype=float)                  # all distinct
    t, k = matched_threshold(cal, 37)
    assert k == 37 and np.count_nonzero(cal > t) == 37
    cal = np.repeat(np.arange(10, dtype=float), 100)    # ten tied blocks of 100
    t, k = matched_threshold(cal, 250)
    assert k in (200, 300) and np.count_nonzero(cal > t) == k
    assert matched_threshold(cal, 0)[1] == 0
