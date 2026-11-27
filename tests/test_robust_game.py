"""Game changes of section 6: closed-form capacity against a dense grid, rho in A, same-seed Sobol rows."""

import numpy as np
import pandas as pd

from idsbench.econ.robust_game import (
    RParams, XG, alert_volume, build_stack, candidates, attack_part, deterrence_x, losses, responses, run_sobol,
    seed_pairs, sample_indicators,
)
from idsbench.robust.defenders import E4_MODELS
from idsbench.robust.evaluate import FPRS
from idsbench.robust.gen2 import BUDGETS
from idsbench.robust.evaluate import budget_label

FAMS = ("A", "B")


def _tables(seed=0, models=("xgb", "iforest")):
    rng = np.random.default_rng(seed)
    clean_rows, e4_rows, thr_rows, mb_rows = [], [], [], []
    for m in models:
        for fpr in FPRS:
            for f in FAMS:
                clean_rows.append({"dataset": "d", "seed": seed, "model": m, "fpr": fpr, "family": f,
                                   "kind": "known", "recall": float(rng.uniform(0.3, 1.0)), "n_family_test": 900,
                                   "auroc": 0.9})
                clean_rows.append({"dataset": "d", "seed": seed, "model": m, "fpr": fpr, "family": f,
                                   "kind": "novel", "recall": float(rng.uniform(0.0, 0.5)), "n_family_test": 900,
                                   "auroc": np.nan})
            thr_rows.append({"dataset": "d", "seed": seed, "model": m, "fpr": fpr, "fpr_test_realised": fpr})
            mb_rows.append({"dataset": "d", "seed": seed, "model": m, "fpr": fpr, "generator": "G1",
                            "mode": "random", "fpr_mut": fpr * 3})
            if m in E4_MODELS:
                for f in FAMS:
                    for g, mult in BUDGETS:
                        for gen in ("G1", "G2"):
                            for att in ("greedy", "strong"):
                                e4_rows.append({"dataset": "d", "seed": seed, "model": m, "fpr": fpr, "family": f,
                                                "generator": gen, "budget": budget_label(g, mult),
                                                "groups": "+".join(g), "multiplier": mult, "attacker": att,
                                                "recall_after": float(rng.uniform(0.0, 1.0))})
    return (pd.DataFrame(clean_rows), pd.DataFrame(e4_rows), pd.DataFrame(thr_rows), pd.DataFrame(mb_rows))


def _stack(seed=0, efficacy=True, models=("xgb", "iforest")):
    c, e, t, m = _tables(seed, models)
    return build_stack(c, e, t, m, FAMS, efficacy, models=models)


def test_closed_form_deterrence_matches_dense_grid():
    S = _stack(0)
    p = RParams()
    xs = deterrence_x(S, p)
    dense = np.arange(1, 0, -1e-4)                     # 1 down to 1e-4, step 1e-4
    XC = np.broadcast_to(dense, (len(S.rows), len(dense)))
    R = responses(S, p, XC, closed_last=False)
    deter = ~(R["att_cap"] | R["att_com"])             # both attacker types abstain
    for t in range(len(S.rows)):
        if not np.isfinite(xs[t]):
            assert not deter[t].any()
            continue
        grid_min = dense[deter[t]].min() if deter[t].any() else np.inf
        assert abs(grid_min - xs[t]) <= 2e-4 + 1e-9, (t, grid_min, xs[t])


def test_closed_form_loss_not_above_any_dense_deterring_point():
    S = _stack(1)
    p = RParams(rho=0.1)
    xs = deterrence_x(S, p)
    dense = np.linspace(1.0, 0.01, 3000)
    XC = np.broadcast_to(dense, (len(S.rows), len(dense)))
    Rd = responses(S, p, XC, closed_last=False)
    Ld = losses(S, p, Rd, attack_part(Rd, p))
    deter = ~(Rd["att_cap"] | Rd["att_com"])
    Xc = xs[:, None]
    Rc = responses(S, p, Xc)
    Lc = losses(S, p, Rc, attack_part(Rc, p))[:, 0]
    for t in range(len(S.rows)):
        if np.isfinite(xs[t]) and deter[t].any():
            assert Lc[t] <= Ld[t][deter[t]].min() + 1e-6 * max(1, abs(Lc[t]))


def test_rho_enters_alert_volume_not_attacker_responses():
    S = _stack(2)
    p0, p1 = RParams(rho=0.0), RParams(rho=0.2)
    R = responses(S, p0, candidates(S, p0))
    part = attack_part(R, p0)
    L0 = losses(S, p0, R, part)
    L1 = losses(S, p1, R, part)
    # Attacker responses do not depend on rho.
    R1 = responses(S, p1, R["XC"])
    assert np.array_equal(R1["att_cap"], R["att_cap"]) and np.array_equal(R1["att_com"], R["att_com"])
    # Only the alert volume moves, so the loss change is exactly the cost coefficient times the volume change.
    A0, A1 = alert_volume(S, p0), alert_volume(S, p1)
    assert np.any(A1 != A0)
    ok = np.isfinite(L0) & np.isfinite(L1)
    assert ok.any()
    coef = (p0.w + p0.cB * R["XC"]) * (A1 - A0)[:, None]
    assert np.allclose((L1 - L0)[ok], coef[ok], rtol=1e-9, atol=1e-9)


def test_seed_pairs_are_fixed_and_recorded():
    a = seed_pairs(list(range(10)))
    b = seed_pairs(list(range(10)))
    assert a == b and len(a[0]) == 2 and len(a[1]) == 2 and a[0] != a[1]


def test_sobol_rows_use_only_the_fixed_pair():
    stacks = {s: _stack(s) for s in (0, 1, 2)}
    pair = (0, 2)
    df, sob = run_sobol(stacks, pair, True, n_base=4, auc_tied=frozenset({"xgb"}), dataset="d")
    assert set(df.seed.unique()) == set(pair)
    assert df.groupby("sample").seed.nunique().eq(2).all()
    assert len(sob) > 0


def test_indicators_are_binary_and_loss_finite():
    S = _stack(3)
    p = RParams()
    ind = sample_indicators(S, S, p, RParams(lam=0.05), frozenset({"xgb"}))
    for k in ("a_mut_nov", "a_weak_reuse", "b_auroc_disjoint", "c_regret", "d_model_change"):
        assert ind[k] in (0.0, 1.0)
    assert np.isfinite(ind["eq_loss"])
    assert XG[0] == 1.0 and XG[-1] <= 0.01 + 1e-9 and np.all(np.diff(XG) < 0)
