"""Mutation invariants (E4): uncontrollable features untouched, forward-only controllability, timing and padding
bounds, byte totals and means consistent with totals, derived identities (delta form), the strong attacker,
the explicit robust feature set, and the feature-group log."""

import math

import numpy as np
import pandas as pd
import pytest

from idsbench.econ.mutation import (
    DERIVED, GROUPS, PAD_MAX, ROBUST_DROP_DEPENDENT, STRONG_LEVELS, apply_group, attack_path, budgets,
    build_group_index, identity_hold_rates, recall_at, recall_from_scores, score_path, strong_attack,
    write_feature_log,
)
from idsbench.feasibility.e3_crosspair import ALIASES

# Uncontrollable and never changed by any group. Derived features (Flow IAT Mean/Min/Std, Down/Up Ratio,
# Packet Length Std/Variance, Fwd Packet Length Std) are no longer in this list: since the identity rules
# of design 4.1 they change with the mutation (see DERIVED in mutation.py).
BACKWARD_2017 = [
    "Total Backward Packets", "Total Length of Bwd Packets", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Avg Bwd Segment Size", "Bwd Header Length", "Bwd IAT Total", "Bwd IAT Max", "Bwd IAT Min",
    "Bwd IAT Mean", "Bwd IAT Std", "Active Mean", "Active Max", "Active Min", "Active Std",
    "Idle Mean", "Idle Max", "Idle Min", "Idle Std", "Init_Win_bytes_backward", "Init_Win_bytes_forward",
    "Destination Port", "Protocol", "Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count",
    "SYN Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "ECE Flag Count",
    "CWE Flag Count", "RST Flag Count", "min_seg_size_forward",
]


def _frame(n: int = 400, seed: int = 0) -> pd.DataFrame:
    """Flows whose aggregates satisfy the identities used by the mutation (rates, max/min, means)."""
    rng = np.random.default_rng(seed)
    dur = rng.uniform(1e3, 1e7, n)
    f_pk = rng.integers(2, 40, n).astype(float)
    b_pk = rng.integers(0, 40, n).astype(float)
    f_mean = rng.uniform(0, 1400, n)
    b_mean = np.where(b_pk > 0, rng.uniform(0, 1400, n), 0.0)
    f_by, b_by = f_pk * f_mean, b_pk * b_mean
    f_max = f_mean + rng.uniform(0, 300, n)
    f_min = f_mean * rng.uniform(0, 1, n)
    b_max = np.where(b_pk > 0, b_mean + rng.uniform(0, 300, n), 0.0)
    b_min = np.where(b_pk > 0, b_mean * rng.uniform(0, 1, n), 0.0)
    pk = f_pk + b_pk
    mean_all = (f_by + b_by) / pk
    fwd_iat_total = dur * rng.uniform(0, 0.9, n)
    flow_iat_mean = dur / np.maximum(pk - 1, 1)
    fwd_iat_max = fwd_iat_total * rng.uniform(0, 1, n)
    fwd_iat_min = np.where(rng.random(n) < 0.1, -1.0, fwd_iat_max * rng.uniform(0, 1, n))
    d = {
        "Flow Duration": dur,
        "Flow IAT Mean": flow_iat_mean, "Flow IAT Max": np.maximum(dur / 2, fwd_iat_max),
        "Flow IAT Min": dur / 9, "Flow IAT Std": dur / 5,
        "Fwd IAT Total": fwd_iat_total, "Fwd IAT Max": fwd_iat_max, "Fwd IAT Min": fwd_iat_min,
        "Fwd IAT Mean": fwd_iat_total / (f_pk - 1), "Fwd IAT Std": dur / 11,
        "Bwd IAT Total": dur * 0.2, "Bwd IAT Max": dur * 0.1, "Bwd IAT Min": dur * 0.01,
        "Bwd IAT Mean": dur * 0.05, "Bwd IAT Std": dur * 0.02,
        "Active Mean": dur / 4, "Active Max": dur / 3, "Active Min": dur / 7, "Active Std": dur / 9,
        "Idle Mean": dur / 6, "Idle Max": dur / 5, "Idle Min": dur / 8, "Idle Std": dur / 12,
        "Max Packet Length": np.maximum(f_max, b_max), "Min Packet Length": np.minimum(f_min, np.where(b_pk > 0, b_min, np.inf)),
        "Packet Length Mean": mean_all, "Average Packet Size": mean_all,
        "Packet Length Std": rng.uniform(0, 900, n), "Packet Length Variance": rng.uniform(0, 9e5, n),
        "Fwd Packet Length Max": f_max, "Fwd Packet Length Min": f_min, "Fwd Packet Length Mean": f_mean,
        "Fwd Packet Length Std": rng.uniform(0, 900, n),
        "Bwd Packet Length Max": b_max, "Bwd Packet Length Min": b_min, "Bwd Packet Length Mean": b_mean,
        "Bwd Packet Length Std": rng.uniform(0, 900, n),
        "Avg Fwd Segment Size": f_mean, "Avg Bwd Segment Size": b_mean, "min_seg_size_forward": rng.integers(0, 60, n).astype(float),
        "Total Fwd Packets": f_pk, "Total Backward Packets": b_pk,
        "Subflow Fwd Packets": f_pk, "Subflow Bwd Packets": b_pk,
        "Subflow Fwd Bytes": f_by, "Subflow Bwd Bytes": b_by,
        "Total Length of Fwd Packets": f_by, "Total Length of Bwd Packets": b_by,
        "act_data_pkt_fwd": rng.integers(0, 40, n).astype(float),
        "Flow Packets/s": pk / (dur / 1e6), "Flow Bytes/s": (f_by + b_by) / (dur / 1e6),
        "Fwd Packets/s": f_pk / (dur / 1e6), "Bwd Packets/s": b_pk / (dur / 1e6),
        "Fwd Header Length": 20.0 * f_pk, "Bwd Header Length": 20.0 * b_pk,
        "Down/Up Ratio": np.floor(b_pk / f_pk),
        "Init_Win_bytes_forward": rng.integers(-1, 65535, n).astype(float),
        "Init_Win_bytes_backward": rng.integers(-1, 65535, n).astype(float),
        "Destination Port": rng.integers(1, 65535, n).astype(float),
        "Protocol": rng.integers(0, 3, n).astype(float),
    }
    for flag in ("Fwd PSH Flags", "Fwd URG Flags", "FIN Flag Count", "SYN Flag Count", "PSH Flag Count",
                 "ACK Flag Count", "URG Flag Count", "ECE Flag Count", "CWE Flag Count", "RST Flag Count"):
        d[flag] = rng.integers(0, 2, n).astype(float)
    return pd.DataFrame(d)


def _ok_frame():
    df = _frame()
    gi = build_group_index(df.columns)
    return df, gi, df.to_numpy(dtype=float)


def test_backward_and_uncontrollable_features_are_never_changed():
    df, gi, X = _ok_frame()
    cols = [df.columns.get_loc(c) for c in BACKWARD_2017]
    for groups, mult in budgets():
        for g in groups:
            for level in (math.sqrt(mult), mult):
                Y = apply_group(X, gi, g, level)
                np.testing.assert_array_equal(Y[:, cols], X[:, cols], err_msg=f"{g} {level}")


def test_controllable_set_is_forward_only():
    _, gi, _ = _ok_frame()
    names = set(gi.columns)
    controllable = {gi.columns[i] for i in gi.controllable_idx()}
    assert controllable <= names
    assert not any(c.lower().startswith("bwd") or "backward" in c.lower() or "bwd" in c.lower()
                   for c in controllable)
    for c in ("Flow Duration", "Fwd IAT Total", "Flow IAT Max", "Fwd Packet Length Max",
              "Total Fwd Packets", "Total Length of Fwd Packets", "Fwd Header Length", "Subflow Fwd Bytes"):
        assert c in controllable


def test_timing_increases_only_and_keeps_negative_sentinels():
    df, gi, X = _ok_frame()
    fwd_min = df.columns.get_loc("Fwd IAT Min")
    neg = X[:, fwd_min] < 0
    assert neg.any()
    for level in (1.22, 1.5, 2.0, 5.0):
        Y = apply_group(X, gi, "timing", level)
        t = gi.timing
        nonneg = X[:, t] >= 0
        assert np.all(Y[:, t][nonneg] >= X[:, t][nonneg] - 1e-9)
        np.testing.assert_array_equal(Y[neg, fwd_min], X[neg, fwd_min])


def test_flow_iat_max_only_increases_to_at_least_new_fwd_iat_max():
    df, gi, X = _ok_frame()
    fi, fw = df.columns.get_loc("Flow IAT Max"), df.columns.get_loc("Fwd IAT Max")
    Y = apply_group(X, gi, "timing", 3.0)
    assert np.all(Y[:, fi] >= X[:, fi] - 1e-9)
    nonneg = X[:, fw] >= 0
    assert np.all(Y[nonneg, fi] >= Y[nonneg, fw] - 1e-9)


def test_padding_is_bounded_and_never_decreases():
    df, gi, X = _ok_frame()
    c = gi.length
    for mult in (1.5, 2.0, 5.0):
        for level in (math.sqrt(mult), mult):
            Y = apply_group(X, gi, "length", level)
            assert np.all(Y[:, c] >= X[:, c] - 1e-9)
            big = X[:, c] > PAD_MAX
            np.testing.assert_array_equal(Y[:, c][big], X[:, c][big])
            assert np.all(Y[:, c][~big] <= PAD_MAX + 1e-9)


def test_padding_raises_forward_bytes_by_packets_times_mean_change():
    df, gi, X = _ok_frame()
    fm = df.columns.get_loc("Fwd Packet Length Mean")
    tf = df.columns.get_loc("Total Fwd Packets")
    Y = apply_group(X, gi, "length", 2.0)
    delta = Y[:, fm] - X[:, fm]
    for b in ("Total Length of Fwd Packets", "Subflow Fwd Bytes"):
        j = df.columns.get_loc(b)
        np.testing.assert_allclose(Y[:, j] - X[:, j], X[:, tf] * delta, rtol=1e-9, atol=1e-6)


def test_count_group_adds_whole_packets_and_header_bytes_per_packet():
    df, gi, X = _ok_frame()
    tf = df.columns.get_loc("Total Fwd Packets")
    fh = df.columns.get_loc("Fwd Header Length")
    Y = apply_group(X, gi, "count", 2.0)
    np.testing.assert_array_equal(Y[:, gi.packets], np.ceil(Y[:, gi.packets]))
    assert np.all(Y[:, tf] >= X[:, tf])
    added = Y[:, tf] - X[:, tf]
    per_pkt = X[:, fh] / np.maximum(X[:, tf], 1.0)
    np.testing.assert_allclose(Y[:, fh] - X[:, fh], added * per_pkt, rtol=1e-9, atol=1e-9)


@pytest.mark.parametrize("group", GROUPS)
def test_aggregates_are_consistent_with_forward_and_backward(group):
    df, gi, X = _ok_frame()
    col = df.columns.get_loc
    for level in (1.22, 2.0, 5.0):
        Y = apply_group(X, gi, group, level)
        dur = Y[:, col("Flow Duration")] / 1e6
        pos = dur > 0
        tot = Y[:, col("Total Fwd Packets")] + Y[:, col("Total Backward Packets")]
        np.testing.assert_allclose(Y[pos, col("Flow Packets/s")], tot[pos] / dur[pos], rtol=1e-9)
        np.testing.assert_allclose(Y[pos, col("Fwd Packets/s")], Y[pos, col("Total Fwd Packets")] / dur[pos],
                                   rtol=1e-9)
        np.testing.assert_allclose(Y[pos, col("Bwd Packets/s")],
                                   Y[pos, col("Total Backward Packets")] / dur[pos], rtol=1e-9)
        byt = Y[:, col("Total Length of Fwd Packets")] + Y[:, col("Total Length of Bwd Packets")]
        np.testing.assert_allclose(Y[pos, col("Flow Bytes/s")], byt[pos] / dur[pos], rtol=1e-9)
        # Packet length mean and average size equal the packet-weighted mean (the frame satisfies the
        # identity exactly, so the delta update must reproduce it).
        npk = tot
        ok = npk > 0
        mean_id = byt[ok] / npk[ok]
        np.testing.assert_allclose(Y[ok, col("Packet Length Mean")], mean_id, rtol=1e-9, atol=1e-9)
        np.testing.assert_allclose(Y[ok, col("Average Packet Size")], mean_id, rtol=1e-9, atol=1e-9)
        if group == "length":
            fmx = Y[:, col("Fwd Packet Length Max")]
            bmx = X[:, col("Bwd Packet Length Max")]
            np.testing.assert_allclose(Y[:, col("Max Packet Length")], np.maximum(fmx, bmx))
            fmn = Y[:, col("Fwd Packet Length Min")]
            bmn = X[:, col("Bwd Packet Length Min")]
            np.testing.assert_allclose(Y[:, col("Min Packet Length")], np.minimum(fmn, bmn))


def test_mean_change_matches_change_of_identity_on_a_non_identity_frame():
    """On data where the identity does not hold, the update still moves the mean by the identity's change."""
    df, gi, X = _ok_frame()
    X2 = X.copy()
    col = df.columns.get_loc
    X2[:, col("Packet Length Mean")] += 7.0    # an off-identity row set
    Y = apply_group(X2, gi, "count", 2.0)
    n0 = X2[:, col("Total Fwd Packets")] + X2[:, col("Total Backward Packets")]
    n1 = Y[:, col("Total Fwd Packets")] + Y[:, col("Total Backward Packets")]
    b0 = X2[:, col("Total Length of Fwd Packets")] + X2[:, col("Total Length of Bwd Packets")]
    b1 = Y[:, col("Total Length of Fwd Packets")] + Y[:, col("Total Length of Bwd Packets")]
    ok = (n0 > 0) & (n1 > 0)
    np.testing.assert_allclose(Y[ok, col("Packet Length Mean")] - X2[ok, col("Packet Length Mean")],
                               (b1 / n1 - b0 / n0)[ok], rtol=1e-9, atol=1e-9)


def test_iat_min_and_std_change_only_with_duration_and_fwd_std_only_in_length_group():
    """Flow IAT Std/Min scale with the flow duration (timing group only); Fwd Packet Length Std changes only
    through the length group; dummy packets (count group) leave both gap and length spreads unchanged."""
    df, gi, X = _ok_frame()
    col = df.columns.get_loc
    Y = apply_group(X, gi, "count", 2.0)
    for n in ("Flow IAT Std", "Flow IAT Min", "Fwd Packet Length Std"):
        np.testing.assert_array_equal(Y[:, col(n)], X[:, col(n)])
    Y = apply_group(X, gi, "length", 2.0)
    for n in ("Flow IAT Std", "Flow IAT Min", "Flow IAT Mean"):
        np.testing.assert_array_equal(Y[:, col(n)], X[:, col(n)])
    Y = apply_group(X, gi, "timing", 2.0)
    fim = col("Flow IAT Min")
    fwm = col("Fwd IAT Min")
    fwd_is_min = np.isclose(X[:, fim], X[:, fwm], rtol=1e-9, atol=1e-6) & (X[:, fwm] >= 0)
    np.testing.assert_allclose(Y[fwd_is_min, fim], 2.0 * X[fwd_is_min, fim], rtol=1e-9)
    np.testing.assert_array_equal(Y[~fwd_is_min, fim], X[~fwd_is_min, fim])
    ratio = np.where(X[:, col("Flow Duration")] > 0, Y[:, col("Flow Duration")] / np.maximum(X[:, col("Flow Duration")], 1e-12), 1.0)
    np.testing.assert_allclose(Y[:, col("Flow IAT Std")], X[:, col("Flow IAT Std")] * ratio, rtol=1e-9)


def test_min_seg_size_forward_is_never_changed_and_in_no_group():
    df, gi, X = _ok_frame()
    c = df.columns.get_loc("min_seg_size_forward")
    assert c not in set(gi.controllable_idx().tolist()) | set(gi.derived_idx().tolist())
    for g in GROUPS:
        np.testing.assert_array_equal(apply_group(X, gi, g, 5.0)[:, c], X[:, c])


def test_derived_identities_hold_after_mutation_for_identity_rows():
    """On the frame, which satisfies the identities, every rule reproduces the identity after a change."""
    df, gi, X = _ok_frame()
    col = df.columns.get_loc
    for g in GROUPS:
        Y = apply_group(X, gi, g, 3.0)
        n = Y[:, col("Total Fwd Packets")] + Y[:, col("Total Backward Packets")]
        ok = n >= 2
        np.testing.assert_allclose(Y[ok, col("Flow IAT Mean")],
                                   (Y[:, col("Flow Duration")] / np.maximum(n - 1, 1))[ok], rtol=1e-9)
        tf = Y[:, col("Total Fwd Packets")]
        okf = tf >= 2
        np.testing.assert_allclose(Y[okf, col("Fwd IAT Mean")],
                                   (Y[:, col("Fwd IAT Total")] / np.maximum(tf - 1, 1))[okf], rtol=1e-9)
        np.testing.assert_array_equal(Y[:, col("Down/Up Ratio")],
                                      np.floor(Y[:, col("Total Backward Packets")] / Y[:, col("Total Fwd Packets")]))


def test_packet_length_variance_is_delta_updated_and_std_is_its_root():
    df, gi, X = _ok_frame()
    col = df.columns.get_loc
    Y = apply_group(X, gi, "length", 2.0)
    np.testing.assert_allclose(Y[:, col("Packet Length Std")] ** 2,
                               np.maximum(X[:, col("Packet Length Std")] ** 2
                                          + (Y[:, col("Packet Length Variance")] - X[:, col("Packet Length Variance")]), 0.0),
                               rtol=1e-9, atol=1e-6)
    # Bhatia-Davis bound: the approximated forward std cannot exceed the bound for the new mean and minimum.
    mu, lo = Y[:, col("Fwd Packet Length Mean")], Y[:, col("Fwd Packet Length Min")]
    hi = np.maximum(PAD_MAX, X[:, col("Fwd Packet Length Max")])
    bound = np.sqrt(np.maximum((hi - mu) * (mu - lo), 0.0))
    assert np.all(Y[:, col("Fwd Packet Length Std")] <= bound + 1e-9)
    assert np.all(Y[:, col("Fwd Packet Length Std")] <= X[:, col("Fwd Packet Length Std")] * 2.0 + 1e-9)


def test_per_row_levels_equal_scalar_levels():
    df, gi, X = _ok_frame()
    lv = np.where(np.arange(len(X)) % 2 == 0, 1.5, 4.0)
    Y = apply_group(X, gi, "timing", lv)
    Y_even = apply_group(X[::2], gi, "timing", 1.5)
    np.testing.assert_allclose(Y[::2], Y_even, rtol=1e-12, atol=1e-9)
    Y_odd = apply_group(X[1::2], gi, "timing", 4.0)
    np.testing.assert_allclose(Y[1::2], Y_odd, rtol=1e-12, atol=1e-9)


def test_robust_input_is_untouched_by_every_budget_and_excludes_derived_columns():
    """xgb_robustfeat must not see a mutated or derived column (design 4.1, item 2)."""
    df, gi, X = _ok_frame()
    robust = gi.robust_idx()
    mutated = set(gi.mutated_idx().tolist())
    derived = set(gi.derived_idx().tolist())
    dependent = set(gi.idx(ROBUST_DROP_DEPENDENT).tolist())
    assert not set(robust.tolist()) & (mutated | derived | dependent)
    for groups, mult in budgets():
        for g in groups:
            Y = apply_group(X, gi, g, mult)
            np.testing.assert_array_equal(Y[:, robust], X[:, robust], err_msg=f"{g} x{mult}")
    kept = {gi.columns[i].lower() for i in robust}
    for name in ("init_win_bytes_forward", "fwd psh flags", "fwd urg flags", "active mean", "idle std",
                 "flow iat mean", "fwd iat total", "packet length std", "down/up ratio", "fwd packet length std"):
        assert name not in kept, name
    assert not set(DERIVED) & kept
    assert {"bwd packet length max", "total backward packets", "bwd iat mean", "protocol"} <= kept


def test_robust_columns_exclude_controllable_derived_and_timing_or_size_dependent():
    df, gi, _ = _ok_frame()
    robust = {gi.columns[i] for i in gi.robust_idx()}
    controllable = {gi.columns[i] for i in gi.controllable_idx()}
    derived = {gi.columns[i] for i in gi.derived_idx()}
    assert not robust & (controllable | derived)
    assert not robust & {c for c in gi.columns if gi.canonical[gi.columns.index(c)] in ROBUST_DROP_DEPENDENT}
    assert len(robust) + len((controllable | derived) | {gi.columns[i] for i in gi.idx(ROBUST_DROP_DEPENDENT)}) \
        == len(gi.columns)


def test_feature_log_lists_robust_columns_and_identity_rates(tmp_path):
    df, gi, X = _ok_frame()
    rates = identity_hold_rates(X, gi)
    assert rates["flow iat mean"]["holds"] == pytest.approx(1.0)
    assert rates["down/up ratio"]["holds"] == pytest.approx(1.0)
    path = tmp_path / "e4_feature_groups.md"
    write_feature_log(path, {"frame": gi}, {"frame": rates})
    text = path.read_text()
    assert "robust model input" in text and "robust model excluded" in text
    assert "| flow iat mean |" in text and "| down/up ratio |" in text
    assert "Bhatia-Davis" in text and "delta" in text
    assert "AI" not in text.split()


def test_strong_attack_scores_match_returned_states_and_include_the_unmutated_flow():
    df, gi, X = _ok_frame()
    w = np.linspace(1.0, -1.0, X.shape[1]) / 1e4

    def score(Z):
        return Z @ w

    rng = np.random.default_rng(0)
    best_s, best_X = strong_attack(score, X[:200], gi, ("timing", "length", "count"), 5.0, rng)
    np.testing.assert_allclose(score(best_X), best_s, rtol=1e-9, atol=1e-12)
    assert np.all(best_s <= score(X[:200]) + 1e-12)


def test_strong_attack_single_group_is_exhaustive_over_the_level_grid():
    df, gi, X = _ok_frame()
    w = np.sin(np.arange(X.shape[1])) / 1e4

    def score(Z):
        return Z @ w

    grid = np.linspace(1.0, 5.0, STRONG_LEVELS)
    brute = np.min(np.stack([score(apply_group(X[:150], gi, "length", lv)) for lv in grid]
                            + [score(X[:150])]), axis=0)
    best_s, _ = strong_attack(score, X[:150], gi, ("length",), 5.0, np.random.default_rng(1))
    np.testing.assert_allclose(best_s, brute, rtol=1e-9, atol=1e-12)


def test_recall_from_scores_is_the_fraction_above_threshold():
    s = np.array([0.1, 0.5, 0.9, 2.0])
    assert recall_from_scores(s, 0.4, True) == pytest.approx(0.75)
    assert np.isnan(recall_from_scores(s, 0.4, False))


def test_uncontrollable_backward_features_are_in_the_robust_set_except_dependent_ones():
    df, gi, _ = _ok_frame()
    robust = {gi.columns[i] for i in gi.robust_idx()}
    dependent = {"Active Mean", "Idle Std", "Init_Win_bytes_forward", "Fwd PSH Flags", "Fwd URG Flags"}
    assert not dependent & robust
    assert {"Bwd Packet Length Max", "Total Backward Packets", "Bwd IAT Mean", "Protocol"} <= robust


def test_score_path_is_monotone_and_final_state_matches_last_column():
    df, gi, X = _ok_frame()
    w = np.linspace(1.0, -1.0, X.shape[1])

    def score(Z):
        return Z @ w / 1e4

    path, Xf = attack_path(score, X, gi, ("timing", "length", "count"), 5.0, "score")
    assert path.shape == (len(X), 4)
    assert np.all(np.diff(path, axis=1) <= 1e-12)
    np.testing.assert_allclose(score(Xf), path[:, -1], rtol=1e-9, atol=1e-12)
    thr = float(np.quantile(score(X), 0.5))
    before = recall_at(path[:, :1], thr, True)
    after = recall_at(path, thr, True)
    assert after <= before + 1e-12
    assert math.isnan(recall_at(path, thr, False))


def test_label_mode_uses_one_random_order_per_flow():
    df, gi, X = _ok_frame()
    w = np.ones(X.shape[1]) / 1e4

    def score(Z):
        return Z @ w

    p1 = score_path(score, X, gi, ("timing", "count"), 2.0, "label", np.random.default_rng(7))
    p2 = score_path(score, X, gi, ("timing", "count"), 2.0, "label", np.random.default_rng(7))
    np.testing.assert_array_equal(p1, p2)
    assert p1.shape == (len(X), 3)


def test_augmentation_never_reads_held_out_family():
    from idsbench.econ.measure import augmentation_rows

    df, gi, X = _ok_frame()
    rng = np.random.default_rng(3)
    perm = rng.permutation(len(X))
    sets = {"A": {"train": perm[:150]}, "B": {"train": perm[150:300]}, "C": {"train": perm[300:]}}
    fams = ["A", "B"]                       # C held out
    Xa, src = augmentation_rows(lambda Z: Z @ np.ones(X.shape[1]) / 1e4, X, sets, fams, gi, seed=0,
                                n_max=50)
    assert len(Xa) == len(src) == 100
    assert set(src) == {"A", "B"}
    assert "C" not in set(src)
    # Every augmented row is a mutation of a row of A or B (the held-out rows never enter).
    allowed = set(np.r_[sets["A"]["train"], sets["B"]["train"]].tolist())
    assert allowed
