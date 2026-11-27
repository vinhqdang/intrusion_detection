"""G2 invariants (design section 3.2): no reduction, server-only fields unchanged, recomputed identities."""

import numpy as np
import pytest

from idsbench.feasibility.e3_crosspair import ALIASES
from idsbench.robust.gen2 import GROUPS, MAY_DECREASE, G2, MTU, apply_budget, flow_uniform

COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "act_data_pkt_fwd", "Active Mean",
    "Active Max", "Idle Mean", "Init_Win_bytes_backward", "Init_Win_bytes_forward",
]
SERVER_ONLY = ["Total Length of Bwd Packets", "Bwd Packet Length Max", "Bwd Packet Length Min",
               "Bwd Packet Length Mean", "Bwd Packet Length Std", "Bwd Header Length", "Idle Mean",
               "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_backward", "Init_Win_bytes_forward"]


def _flows(n=300, seed=0):
    rng = np.random.default_rng(seed)
    dur = rng.uniform(1e3, 1e7, n)
    nf = rng.integers(2, 30, n).astype(float)
    nb = rng.integers(0, 30, n).astype(float)
    mu_f = rng.uniform(1, 1400, n)
    s_f = rng.uniform(0, 400, n)
    mu_b = np.where(nb > 0, rng.uniform(1, 1400, n), 0.0)
    s_b = np.where(nb > 0, rng.uniform(0, 400, n), 0.0)
    bf, bb = nf * mu_f, nb * mu_b
    gap = dur / np.maximum(nf + nb - 1, 1)
    fim = np.where(nf > 1, rng.uniform(1, 1e5, n), 0.0)
    fit = fim * (nf - 1)
    fwd_max = fim * rng.uniform(1, 3, n)
    fwd_min = fim * rng.uniform(0, 1, n)
    bwd_mean = np.where(nb > 1, rng.uniform(1, 1e5, n), 0.0)
    bwd_total = bwd_mean * np.maximum(nb - 1, 0)
    byt = bf + bb
    pk = nf + nb
    pl_mean = byt / pk
    pl_var = np.maximum(((nf * (s_f ** 2 + (mu_f - pl_mean) ** 2)) + nb * (s_b ** 2 + (mu_b - pl_mean) ** 2)) / pk, 0)
    d = {
        "Flow Duration": dur, "Total Fwd Packets": nf, "Total Backward Packets": nb,
        "Total Length of Fwd Packets": bf, "Total Length of Bwd Packets": bb,
        "Fwd Packet Length Max": mu_f + s_f, "Fwd Packet Length Min": np.zeros(n),
        "Fwd Packet Length Mean": mu_f, "Fwd Packet Length Std": s_f,
        "Bwd Packet Length Max": np.where(nb > 0, mu_b + s_b, 0), "Bwd Packet Length Min": np.zeros(n),
        "Bwd Packet Length Mean": mu_b, "Bwd Packet Length Std": s_b,
        "Flow Bytes/s": byt / (dur / 1e6), "Flow Packets/s": pk / (dur / 1e6),
        "Flow IAT Mean": gap, "Flow IAT Std": gap / 2, "Flow IAT Max": np.maximum(fwd_max, gap),
        "Flow IAT Min": fwd_min, "Fwd IAT Total": fit, "Fwd IAT Mean": fim, "Fwd IAT Std": fim / 3,
        "Fwd IAT Max": fwd_max, "Fwd IAT Min": fwd_min, "Bwd IAT Total": bwd_total, "Bwd IAT Mean": bwd_mean,
        "Bwd IAT Std": bwd_mean / 2, "Bwd IAT Max": bwd_mean * 2, "Bwd IAT Min": bwd_mean / 2,
        "Fwd Header Length": 20.0 * nf, "Bwd Header Length": 20.0 * nb, "Fwd Packets/s": nf / (dur / 1e6),
        "Bwd Packets/s": nb / (dur / 1e6), "Min Packet Length": np.zeros(n),
        "Max Packet Length": np.maximum(mu_f + s_f, np.where(nb > 0, mu_b + s_b, 0)),
        "Packet Length Mean": pl_mean, "Packet Length Std": np.sqrt(pl_var), "Packet Length Variance": pl_var,
        "Down/Up Ratio": np.where(nf > 0, np.floor(nb / np.maximum(nf, 1)), 0), "Average Packet Size": pl_mean,
        "Avg Fwd Segment Size": mu_f, "Avg Bwd Segment Size": mu_b, "Subflow Fwd Packets": nf,
        "Subflow Fwd Bytes": bf, "Subflow Bwd Packets": nb, "Subflow Bwd Bytes": bb,
        "act_data_pkt_fwd": rng.integers(0, 20, n).astype(float), "Active Mean": rng.uniform(1, 1e5, n),
        "Active Max": rng.uniform(1, 1e5, n), "Idle Mean": rng.uniform(1, 1e5, n),
        "Init_Win_bytes_backward": rng.integers(-1, 6000, n).astype(float),
        "Init_Win_bytes_forward": rng.integers(-1, 6000, n).astype(float),
    }
    return np.column_stack([d[c] for c in COLS])


@pytest.fixture(scope="module")
def setup():
    X = _flows()
    return X, G2(COLS), {c: i for i, c in enumerate(COLS)}


def test_no_reduction_and_level_one_identity(setup):
    X, g, _ = setup
    ok = X[:, COLS.index("Total Fwd Packets")] >= 2
    for grp in ("timing", "length", "count"):
        Y = g.apply(X, grp, 2.0)
        same = g.apply(X, grp, 1.0)
        assert np.array_equal(same, X)
        assert np.all(Y[:, COLS.index("Flow Duration")] >= X[:, COLS.index("Flow Duration")] - 1e-9)
        assert np.all(Y[:, COLS.index("Total Length of Fwd Packets")] >= X[:, COLS.index("Total Length of Fwd Packets")] - 1e-6)
        assert np.all(Y[:, COLS.index("Total Fwd Packets")] >= X[:, COLS.index("Total Fwd Packets")])
        assert np.all(Y[:, COLS.index("Fwd Header Length")] >= X[:, COLS.index("Fwd Header Length")] - 1e-9)
        assert np.all(Y[:, COLS.index("Fwd IAT Total")][ok] >= X[:, COLS.index("Fwd IAT Total")][ok] - 1e-6)


def test_server_only_fields_unchanged_except_coupled_timing(setup):
    X, g, _ = setup
    for grp in ("length", "count"):
        Y = g.apply(X, grp, 5.0)
        for name in SERVER_ONLY:
            assert np.array_equal(Y[:, COLS.index(name)], X[:, COLS.index(name)]), (grp, name)
    Y = g.apply(X, "timing", 5.0)
    for name in ("Bwd Packet Length Max", "Bwd Packet Length Mean", "Bwd Header Length", "Init_Win_bytes_forward",
                 "Idle Mean", "Subflow Bwd Packets"):
        assert np.array_equal(Y[:, COLS.index(name)], X[:, COLS.index(name)]), name


def test_timing_budget_is_additive_and_coupled(setup):
    X, g, _ = setup
    m = 2.0
    Y = g.apply(X, "timing", m)
    nf = X[:, COLS.index("Total Fwd Packets")]
    mean = X[:, COLS.index("Fwd IAT Mean")]
    ok = nf >= 2
    delta = np.where(mean > 0, mean, 1000.0)[ok] * (m - 1)
    dmean = Y[:, COLS.index("Fwd IAT Mean")][ok] - mean[ok]
    assert np.allclose(dmean, delta, rtol=1e-9)
    ddur = Y[:, COLS.index("Flow Duration")][ok] - X[:, COLS.index("Flow Duration")][ok]
    assert np.allclose(ddur, (nf[ok] - 1) * delta, rtol=1e-9)
    nb = X[:, COLS.index("Total Backward Packets")]
    coup = ok & (nb > 1)
    dbt = Y[:, COLS.index("Bwd IAT Total")] - X[:, COLS.index("Bwd IAT Total")]
    assert np.all(dbt[coup] >= -1e-9)


def test_length_target_within_bounds_and_mean_identity(setup):
    X, g, _ = setup
    m = 5.0
    Y = g.apply(X, "length", m)
    mu0 = X[:, COLS.index("Fwd Packet Length Mean")]
    mu1 = Y[:, COLS.index("Fwd Packet Length Mean")]
    data = mu0 > 0
    assert np.all(mu1[data] >= mu0[data] - 1e-9)
    assert np.all(mu1[data] <= np.maximum(mu0[data], np.minimum(MTU, m * mu0[data])) + 1e-9)
    assert np.all(Y[:, COLS.index("Fwd Packet Length Min")] == X[:, COLS.index("Fwd Packet Length Min")])
    mx0 = X[:, COLS.index("Fwd Packet Length Max")]
    assert np.all(Y[:, COLS.index("Fwd Packet Length Max")] <= np.maximum(MTU, mx0) + 1e-6)


def test_count_zero_packets_and_min_becomes_zero(setup):
    X, g, _ = setup
    m = 2.0
    Y = g.apply(X, "count", m)
    nf = X[:, COLS.index("Total Fwd Packets")]
    k = np.ceil((m - 1) * nf)
    assert np.allclose(Y[:, COLS.index("Total Fwd Packets")], nf + k)
    assert np.all(Y[:, COLS.index("Fwd Packet Length Min")] == 0)
    assert np.array_equal(Y[:, COLS.index("Total Length of Fwd Packets")], X[:, COLS.index("Total Length of Fwd Packets")])
    mean_new = Y[:, COLS.index("Fwd Packet Length Mean")]
    mean_old = X[:, COLS.index("Fwd Packet Length Mean")]
    assert np.allclose(mean_new * (nf + k), mean_old * nf, rtol=1e-9, atol=1e-9)


def test_recomputed_identities_after_every_group(setup):
    X, g, _ = setup
    for grp in ("timing", "length", "count"):
        Y = g.apply(X, grp, 2.0)
        nf = Y[:, COLS.index("Total Fwd Packets")]
        nb = Y[:, COLS.index("Total Backward Packets")]
        n = nf + nb
        dur = Y[:, COLS.index("Flow Duration")]
        ok = n >= 2
        assert np.allclose(Y[:, COLS.index("Flow IAT Mean")][ok], dur[ok] / (n[ok] - 1), rtol=1e-9)
        okf = nf > 0
        assert np.all(Y[:, COLS.index("Down/Up Ratio")][okf] == np.floor(nb[okf] / nf[okf]))
        byt = Y[:, COLS.index("Total Length of Fwd Packets")] + Y[:, COLS.index("Total Length of Bwd Packets")]
        assert np.allclose(Y[:, COLS.index("Average Packet Size")], byt / n, rtol=1e-9)
        assert np.allclose(Y[:, COLS.index("Packet Length Mean")], byt / n, rtol=1e-9)
        assert np.all(Y[:, COLS.index("Packet Length Variance")] >= -1e-9)


def test_flow_draws_deterministic_and_per_flow(setup):
    X, g, _ = setup
    assert np.array_equal(g.apply(X, "length", 3.0), g.apply(X, "length", 3.0))
    u = flow_uniform(X)
    assert np.all((u >= 0) & (u < 1))
    assert np.array_equal(flow_uniform(X[::-1])[::-1], u)
    # Same flow in a different batch gets the same draw.
    assert np.array_equal(g.apply(X[:50], "length", 3.0), g.apply(X, "length", 3.0)[:50])


def test_budget_composition_in_group_order(setup):
    X, g, _ = setup
    a = apply_budget(g, X[:20], ("timing", "count"), 2.0)
    b = g.apply(g.apply(X[:20], "timing", 2.0), "count", 2.0)
    assert np.array_equal(a, b)


# ---------------------------------------------------------------- real-data-like flows and two column layouts
# Real CICFlowMeter rows do not satisfy the packet-length identities (the mean is bytes / packets on about a fifth of
# original rows). These flows keep the consistent forward statistics but perturb the derived aggregates, so that the
# identities fail as they do on real data.
LENGTH_NAMES = (
    "fwd packet length max", "fwd packet length min", "fwd packet length mean", "fwd packet length std",
    "avg fwd segment size", "total length of fwd packets", "subflow fwd bytes", "bwd packet length max",
    "bwd packet length min", "bwd packet length mean", "bwd packet length std", "packet length mean",
    "packet length std", "packet length variance", "average packet size", "max packet length", "min packet length",
)


def _real_like(n=400, seed=7):
    X = _flows(n, seed)
    rng = np.random.default_rng(seed + 1000)
    c = {name: i for i, name in enumerate(COLS)}
    var = X[:, c["Packet Length Variance"]] * rng.uniform(0.5, 2.0, n)
    X[:, c["Packet Length Variance"]] = var
    X[:, c["Packet Length Std"]] = np.sqrt(var)
    X[:, c["Packet Length Mean"]] *= rng.uniform(0.6, 1.4, n)
    X[:, c["Average Packet Size"]] *= rng.uniform(0.5, 1.5, n)
    X[:, c["Max Packet Length"]] *= rng.uniform(0.8, 1.2, n)
    X[:, c["Min Packet Length"]] = rng.uniform(0, 20, n) * (rng.random(n) < 0.5)
    X[:, c["Fwd Packet Length Min"]] = np.minimum(X[:, c["Fwd Packet Length Min"]] + rng.uniform(0, 30, n),
                                                  X[:, c["Fwd Packet Length Mean"]])
    X[:, c["Flow IAT Mean"]] *= rng.uniform(0.7, 1.3, n)
    X[:, c["Flow Bytes/s"]] *= rng.uniform(0.5, 1.5, n)
    X[:, c["Down/Up Ratio"]] = rng.integers(0, 4, n).astype(float)
    return X


def _cse2018_names():
    """The CSE-CIC-IDS2018 spelling of every column that has an alias (the other names are unchanged)."""
    inv = {v: k for k, v in ALIASES["cicids2018"].items()}
    return [inv[c.lower()].title() if c.lower() in inv else c for c in COLS]


LAYOUTS = {"cic2017": (COLS, None), "cse2018": (_cse2018_names(), ALIASES["cicids2018"])}


@pytest.fixture(scope="module", params=sorted(LAYOUTS))
def layout_setup(request):
    names, aliases = LAYOUTS[request.param]
    X = _real_like()
    return X, G2(names, aliases)


def test_fixture_breaks_length_identities(layout_setup):
    X, g = layout_setup
    c = {k: g.lay.c(k) for k in ("total fwd packets", "total backward packets", "total length of fwd packets",
                                 "total length of bwd packets", "packet length mean", "average packet size")}
    pk = X[:, c["total fwd packets"]] + X[:, c["total backward packets"]]
    by = X[:, c["total length of fwd packets"]] + X[:, c["total length of bwd packets"]]
    holds = np.isclose(X[:, c["packet length mean"]], by / pk, rtol=1e-6)
    assert holds.mean() < 0.5


def test_timing_only_leaves_every_length_column_bit_identical(layout_setup):
    X, g = layout_setup
    for m in (1.5, 2.0, 5.0):
        Y = g.apply(X, "timing", m)
        for name in LENGTH_NAMES:
            j = g.lay.c(name)
            assert j is not None, name
            assert np.array_equal(Y[:, j], X[:, j]), (m, name)


def test_no_undocumented_column_decreases(layout_setup):
    X, g = layout_setup
    for grp in GROUPS:
        for m in (1.5, 5.0):
            Y = g.apply(X, grp, m)
            for name, j in g.lay.pos.items():
                if name in MAY_DECREASE[grp]:
                    continue
                tol = 1e-9 * np.maximum(np.abs(X[:, j]), 1.0)
                bad = np.flatnonzero(Y[:, j] < X[:, j] - tol)
                assert bad.size == 0, (grp, m, name, bad[:5])


def test_documented_decreases_are_only_on_rows_the_group_changes(layout_setup):
    X, g = layout_setup
    Y = g.apply(X, "count", 2.0)
    nf = X[:, g.lay.c("total fwd packets")]
    grow = nf >= 1
    j = g.lay.c("fwd packet length min")
    assert np.all(Y[grow, j] == 0.0) and np.all(Y[~grow, j] == X[~grow, j])
    ms = g.lay.c("min packet length")
    assert np.all(Y[:, ms] <= X[:, ms])


def test_fwd_iat_mean_identity_holds_after_count_when_it_held_before(layout_setup):
    X, g = layout_setup
    nf, fit, fim = (g.lay.c(k) for k in ("total fwd packets", "fwd iat total", "fwd iat mean"))
    held = (X[:, nf] >= 2) & np.isclose(X[:, fim], X[:, fit] / np.maximum(X[:, nf] - 1, 1), rtol=1e-9, atol=1e-9)
    assert held.sum() > 100
    for m in (1.5, 2.0, 5.0):
        Y = g.apply(X, "count", m)
        ok = held & (Y[:, nf] >= 2)
        assert np.allclose(Y[ok, fim], Y[ok, fit] / (Y[ok, nf] - 1), rtol=1e-9, atol=1e-9)
        # Fwd IAT Total, Min, Max and Std are unchanged by the count group.
        for k in ("fwd iat total", "fwd iat min", "fwd iat max", "fwd iat std"):
            assert np.array_equal(Y[:, g.lay.c(k)], X[:, g.lay.c(k)]), k


def test_fwd_iat_mean_identity_holds_after_timing_when_it_held_before(layout_setup):
    X, g = layout_setup
    nf, fit, fim = (g.lay.c(k) for k in ("total fwd packets", "fwd iat total", "fwd iat mean"))
    held = (X[:, nf] >= 2) & np.isclose(X[:, fim], X[:, fit] / np.maximum(X[:, nf] - 1, 1), rtol=1e-9, atol=1e-9)
    Y = g.apply(X, "timing", 2.0)
    ok = held & (X[:, nf] >= 2)
    assert np.allclose(Y[ok, fim], Y[ok, fit] / (Y[ok, nf] - 1), rtol=1e-7, atol=1e-6)


def test_fwd_packet_length_max_is_padded_data_packet_size(layout_setup):
    X, g = layout_setup
    mu0 = X[:, g.lay.c("fwd packet length mean")]
    s0 = X[:, g.lay.c("fwd packet length std")]
    mx0 = X[:, g.lay.c("fwd packet length max")]
    Y = g.apply(X, "length", 5.0)
    data = (X[:, g.lay.c("total fwd packets")] >= 1) & (mu0 > 0)
    a = np.clip(s0 ** 2 / (s0 ** 2 + mu0 ** 2), 0.0, np.minimum(0.999, np.maximum(0.0, 1.0 - mu0 / MTU)))
    d = Y[:, g.lay.c("fwd packet length mean")] / (1.0 - a)
    assert np.allclose(Y[data, g.lay.c("fwd packet length max")], np.maximum(mx0, d)[data], rtol=1e-9)
    assert np.all(Y[data, g.lay.c("fwd packet length max")] >= mx0[data])
