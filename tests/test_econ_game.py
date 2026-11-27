"""Game (design section 3): best responses, one alert volume, efficacy, ties, attacker query flag, limits."""

import math

import numpy as np
import pytest

from idsbench.econ.game import (
    ABSTAIN, GameParams, RecallTable, action_set, alert_volume, best_response, capacity_cost,
    efficacy_factor, enumerate_configs, equilibrium, evaluate, feasible, min_recall_capable, solve,
    solve_stack, stack_tables, tied_best, tied_models, tied_ranks,
)
from idsbench.econ.mutation import FPRS, budget_label, budgets


def _table(reuse, novel, mutate, units=(2.0,), labels=("timing,x2",), groups=(), mults=(), fams=None):
    fams = tuple(fams) if fams else tuple(f"f{i}" for i in range(len(reuse)))
    return RecallTable(families=fams, reuse=np.array(reuse), novel=np.array(novel),
                       mutate=np.array(mutate, dtype=float).reshape(len(reuse), len(units)),
                       budget_units=np.array(units), budget_labels=tuple(labels),
                       budget_groups=tuple(groups), budget_mults=tuple(mults))


def _params(**kw):
    base = dict(V=1.0, P=1.0, lam=1.0, kM=0.1, kN=10.0, pi=0.0, N_benign=1e6, N_attack=50.0,
                L=1.0, w=0.0, cB=0.0, efficacy=False)
    base.update(kw)
    return GameParams(**base)


def test_best_response_picks_cheapest_undetected_action():
    # reuse(f1) has recall 0.3; mutate(f0, timing,x2) has recall 0.15 at cost lam*kM*2 = 0.2.
    t = _table(reuse=[0.9, 0.3], novel=[0.8, 0.6], mutate=[[0.15], [0.5]])
    p = _params()
    r = best_response(action_set(t, "worst", True, False), math.inf, 1e-3, p)
    # U(mutate f0) = 0.85 - 0.15 - 0.2 = 0.5 ; U(reuse f1) = 0.7 - 0.3 = 0.4 ; U(novel) < 0
    assert r.label == "mutate(f0,timing,x2)"
    assert r.recall == pytest.approx(0.15)
    assert r.p == pytest.approx(0.15)
    assert r.utility == pytest.approx(0.5)


def test_mutation_cost_flips_the_choice_to_reuse():
    t = _table(reuse=[0.9, 0.3], novel=[0.8, 0.6], mutate=[[0.15], [0.5]])
    r = best_response(action_set(t, "worst", True, False), math.inf, 1e-3, _params(lam=100.0))
    assert r.label == "reuse(f1)"
    assert r.p == pytest.approx(0.3)


def test_commodity_attacker_only_reuses():
    t = _table(reuse=[0.9, 0.3], novel=[0.1, 0.05], mutate=[[0.0], [0.0]])
    r = best_response(action_set(t, "worst", False), math.inf, 1e-3, _params())
    assert r.label == "reuse(f1)"


def test_attacker_abstains_when_utility_is_negative():
    t = _table(reuse=[0.9, 0.8], novel=[0.9, 0.9], mutate=[[0.9], [0.9]])
    r = best_response(action_set(t, "worst", True, False), math.inf, 1e-3, _params())
    assert r.label == ABSTAIN and not r.attacked


def test_tie_between_attack_and_abstain_goes_to_abstain():
    t = _table(reuse=[0.5], novel=[0.9], mutate=[[0.9]])
    r = best_response(action_set(t, "worst", True, False), math.inf, 1e-3, _params())
    assert r.label == ABSTAIN


def test_one_alert_volume_is_used_by_the_attacker_and_the_defender():
    """The attacker's detection probability and the defender's alert cost use the same A (fpr N + N_attack)."""
    t = _table(reuse=[0.6], novel=[0.9], mutate=[[0.9]])
    fpr, B = 1e-3, 100.0
    p = _params(N_benign=1e6, N_attack=50.0, w=2.0)
    A = alert_volume(fpr, p)
    assert A == pytest.approx(1e6 * fpr + 50.0)
    assert B < A
    r = best_response(action_set(t, "worst", False), B, fpr, p)
    assert r.label == "reuse(f0)"
    assert r.p == pytest.approx(0.6 * B / A)
    out = evaluate(t, "xgb", fpr, B, p)
    assert out.alerts == pytest.approx(A)
    assert out.alert_cost == pytest.approx(p.w * A)
    assert out.capable.p == pytest.approx(r.p) or not out.capable.attacked


def test_alert_volume_does_not_depend_on_the_realised_attack_recall():
    p = _params(N_benign=1e5, N_attack=20.0)
    t1 = _table(reuse=[0.1], novel=[0.9], mutate=[[0.9]])
    t2 = _table(reuse=[0.9], novel=[0.9], mutate=[[0.9]])
    assert evaluate(t1, "m", 1e-2, 1e3, p).alerts == evaluate(t2, "m", 1e-2, 1e3, p).alerts


def test_efficacy_factor_timing_and_targets():
    assert efficacy_factor("DoS", ("timing",), 2.0) == pytest.approx(0.5)
    assert efficacy_factor("PortScan", ("timing", "count"), 5.0) == pytest.approx(0.2)
    assert efficacy_factor("BruteForce", ("timing", "length"), 1.5) == pytest.approx(1 / 1.5)
    assert efficacy_factor("DDoS", ("count",), 2.0) == 1.0          # count for DoS/DDoS: unchanged
    assert efficacy_factor("DDoS", ("length",), 2.0) == 1.0
    assert efficacy_factor("WebAttack", ("timing",), 2.0) == 1.0    # not a timing target
    assert efficacy_factor("Bot", ("timing",), 2.0) == 1.0


def test_efficacy_reduces_the_attacker_gain_only_when_enabled():
    fams = ("DoS", "Bot")
    t = _table(reuse=[0.9, 0.9], novel=[0.9, 0.9], mutate=[[0.2], [0.2]], units=(2.0,),
               labels=("timing,x2",), groups=(("timing",),), mults=(2.0,), fams=fams)
    on = action_set(t, "worst", True, True)
    off = action_set(t, "worst", True, False)
    i_dos = on.labels.index("mutate(DoS,timing,x2)")
    i_bot = on.labels.index("mutate(Bot,timing,x2)")
    assert on.eff[i_dos] == pytest.approx(0.5)
    assert on.eff[i_bot] == 1.0
    assert np.all(off.eff == 1.0)
    p = _params(efficacy=True, V=10.0, P=1.0, kM=0.0)
    r_on = best_response(on, math.inf, 1e-3, p)
    # U(mutate DoS) = (1 - 0.2) * 10 * 0.5 = 4; U(mutate Bot) = 8 - 0.2 = 7.8: the attacker picks Bot.
    assert r_on.label == "mutate(Bot,timing,x2)"


def test_efficacy_off_gives_unit_efficacy_in_the_game():
    fams = ("DoS",)
    t = _table(reuse=[0.9], novel=[0.9], mutate=[[0.2]], units=(2.0,), labels=("timing,x2",),
               groups=(("timing",),), mults=(2.0,), fams=fams)
    p = _params(efficacy=False, V=10.0, P=1.0, kM=0.0)
    r = best_response(action_set(t, "worst", True, p.efficacy), math.inf, 1e-3, p)
    # U = (1 - p) V e - p P - cost = 0.8 * 10 - 0.2 * 1 (efficacy 1, no cost)
    assert r.utility == pytest.approx((1 - 0.2) * 10.0 - 0.2)


def test_commodity_attacker_only_reuse_detection_equals_reuse_recall():
    t = _table(reuse=[0.4, 0.2, 0.3], novel=[0.05, 0.05, 0.05], mutate=[[0.01], [0.01], [0.01]])
    out = evaluate(t, "xgb", 1e-3, math.inf, _params(lam=0.0, pi=1.0))
    assert out.p_eq == pytest.approx(0.2)
    assert out.commodity.label == "reuse(f1)"


def test_zero_cost_infinite_capacity_detection_equals_min_capable_recall():
    rng = np.random.default_rng(0)
    for _ in range(20):
        F = int(rng.integers(1, 4))
        K = int(rng.integers(1, 4))
        reuse = rng.uniform(0.0, 0.45, F)
        novel = rng.uniform(0.0, 0.45, F)
        mutate = rng.uniform(0.0, 0.45, (F, K))
        t = _table(reuse, novel, mutate, units=tuple(rng.uniform(1, 3, K)),
                   labels=tuple(f"b{k}" for k in range(K)))
        out = evaluate(t, "xgb", 1e-3, math.inf, _params(lam=0.0, pi=0.0))
        assert out.capable.attacked
        assert out.p_eq == pytest.approx(min(reuse.min(), mutate.min(), novel.min()))


def test_novel_average_mode_uses_mean_unseen_recall():
    t = _table(reuse=[0.9, 0.9], novel=[0.2, 0.6], mutate=[[0.9], [0.9]])
    acts = action_set(t, "average", True)
    i = acts.labels.index("novel(average)")
    assert acts.recall[i] == pytest.approx(0.4)
    worst = action_set(t, "worst", True)
    assert worst.recall[worst.labels.index("novel(f0)")] == pytest.approx(0.2)


def test_capacity_cost_zero_when_cB_zero_even_if_infinite():
    assert capacity_cost(math.inf, 0.0) == 0.0
    assert capacity_cost(100.0, 2.0) == 200.0
    assert math.isinf(capacity_cost(math.inf, 2.0))


def test_solve_returns_the_least_loss_configuration():
    t1 = _table(reuse=[0.9], novel=[0.9], mutate=[[0.9]])
    t2 = _table(reuse=[0.2], novel=[0.2], mutate=[[0.1]])
    p = _params(lam=1.0, pi=0.5, w=0.01, cB=0.001, L=100.0)
    best, outs = solve({"a": {1e-3: t1}, "b": {1e-3: t2}}, p, [100.0, 1e4, math.inf])
    assert best.loss == min(o.loss for o in outs)
    assert best.model == "a"


def test_attainability_gate_excludes_unattainable_configurations():
    ok = _table(reuse=[0.5], novel=[0.5], mutate=[[0.5]])
    bad = _table(reuse=[float("nan")], novel=[0.5], mutate=[[0.5]])
    assert feasible(ok) and not feasible(bad)
    outs = enumerate_configs({"m": {1e-3: ok, 3e-3: bad}}, _params(), [1e4])
    assert {o.fpr for o in outs} == {1e-3}


def test_fpr_grid_adds_5e4_and_every_level_is_attainable_with_20000_threshold_rows():
    """FPR grid: {5e-4, 1e-3, 3e-3, 1e-2}. The conformal quantile index k = ceil((n+1)(1-fpr)) must be <= n
    for the fusion threshold set (n = 20,000 rows); 1e-4 would also be attainable but is not on the grid."""
    from idsbench.feasibility.common import threshold_at_fpr

    assert FPRS == (5e-4, 1e-3, 3e-3, 1e-2)
    rng = np.random.default_rng(0)
    scores = rng.normal(size=20_000)
    for f in FPRS:
        thr, ok = threshold_at_fpr(scores, f)
        assert ok, f
        assert math.ceil(20_001 * (1 - f)) <= 20_000
    assert not threshold_at_fpr(scores, 1e-5)[1]


def test_tied_best_uses_one_percent_relative_tolerance():
    assert tied_best({"a": 100.0, "b": 100.9, "c": 102.0}) == {"a", "b"}
    assert tied_best({"a": 100.0, "b": 101.5}) == {"a"}
    assert tied_best({"a": float("inf"), "b": 3.0}) == {"b"}


def test_tied_ranks_group_values_within_tolerance():
    r = tied_ranks([100.0, 100.5, 102.0, 50.0])
    assert r[3] == 1
    assert r[0] == r[1] == 2
    assert r[2] == 4


def test_attacker_query_flag_is_validated():
    assert GameParams().attacker_query == "score"
    assert GameParams(attacker_query="label").attacker_query == "label"
    with pytest.raises(ValueError):
        GameParams(attacker_query="oracle")


def test_min_recall_capable_includes_mutation_and_novel():
    t = _table(reuse=[0.4], novel=[0.05], mutate=[[0.3]])
    assert min_recall_capable(t) == pytest.approx(0.05)


def test_budget_labels_match_the_measurement_labels():
    labels = [budget_label(g, m) for g, m in budgets()]
    assert len(set(labels)) == 21
    assert "timing+length+count,x5" in labels


# ---- design item 3: capacity grid, item 4: ties, item 9: realised FPR, item 11: Sobol design ----

def test_capacity_grid_is_fine_geometric_plus_infinity():
    from idsbench.econ.sweep import B_GRID

    b = np.asarray(B_GRID)
    assert len(b) == 201 and math.isinf(b[-1])
    fin = b[:-1]
    assert fin[0] == pytest.approx(10.0) and fin[-1] == pytest.approx(1e5)
    assert np.all(np.diff(fin) > 0)
    ratios = fin[1:] / fin[:-1]
    assert np.ptp(ratios) < 1e-9                       # geometric


def test_alert_volume_uses_the_realised_benign_fpr():
    """A = fpr_real * N_benign + N_attack: the table's measured FPR replaces the nominal one."""
    t = _table(reuse=[0.6], novel=[0.9], mutate=[[0.9]])
    t = RecallTable(families=t.families, reuse=t.reuse, novel=t.novel, mutate=t.mutate,
                    budget_units=t.budget_units, budget_labels=t.budget_labels, fpr_real=2e-3)
    p = _params(N_benign=1e5, N_attack=10.0)
    out = evaluate(t, "xgb", 1e-2, 50.0, p)
    assert out.alerts == pytest.approx(2e-3 * 1e5 + 10.0)


def test_vectorised_solver_matches_the_scalar_reference_on_random_tables():
    rng = np.random.default_rng(5)
    grid = [100.0, 1e3, 1e4, math.inf]
    for trial in range(6):
        tables = {}
        F, K = int(rng.integers(1, 4)), int(rng.integers(1, 3))   # shared layout across tables
        units = rng.uniform(1, 3, K)                              # budget costs are the same for all tables
        for m in ("a", "b"):
            tables[m] = {}
            for f in (1e-3, 1e-2):
                t = RecallTable(
                    families=tuple(f"f{i}" for i in range(F)), reuse=rng.uniform(0, 1, F),
                    novel=rng.uniform(0, 1, F), mutate=rng.uniform(0, 1, (F, K)),
                    budget_units=units, budget_labels=tuple(f"b{k}" for k in range(K)),
                    fpr_real=float(f * rng.uniform(0.5, 1.5)))
                tables[m][f] = t
        p = GameParams(V=float(rng.uniform(1, 10)), P=float(rng.uniform(1, 10)), lam=float(rng.uniform(0.1, 2)),
                       kM=float(rng.uniform(0, 5)), kN=float(rng.uniform(0, 20)), pi=float(rng.uniform(0, 1)),
                       N_benign=1e5, N_attack=float(rng.uniform(1, 100)), L=float(rng.uniform(1, 50)),
                       w=float(rng.uniform(0, 2)), cB=float(rng.uniform(0, 2)), efficacy=False)
        S = stack_tables(tables, p, grid)
        out = solve_stack(S, p)
        scalar = {(o.model, o.fpr, o.B): o for o in enumerate_configs(tables, p, grid)}
        for t_i, (m, f) in enumerate(zip(S.models, S.fprs)):
            for g, B in enumerate(grid):
                o = scalar[(m, f, B)]
                assert out["loss"][t_i, g] == pytest.approx(o.loss, rel=1e-9, abs=1e-9), (trial, m, f, B)
                if math.isfinite(o.p_eq):
                    assert out["p_eq"][t_i, g] == pytest.approx(o.p_eq, rel=1e-9, abs=1e-12)


def test_equilibrium_reports_the_whole_loss_tied_model_set_and_is_order_free():
    """Two identical models tie: both are in the tied set, and the representative does not depend on the
    order of the models in the input."""
    t = _table(reuse=[0.3], novel=[0.9], mutate=[[0.9]])
    tables_ab = {"a": {1e-3: t}, "b": {1e-3: t}}
    tables_ba = {"b": {1e-3: t}, "a": {1e-3: t}}
    p = _params(lam=1.0, pi=0.0, w=0.1, cB=0.01)
    grid = [10.0, 1e3, math.inf]
    e1 = equilibrium(stack_tables(tables_ab, p, grid), p)
    e2 = equilibrium(stack_tables(tables_ba, p, grid), p)
    assert e1["tied_models"] == frozenset({"a", "b"})
    assert e1["model"] == e2["model"] == "a"
    assert e1["loss"] == pytest.approx(e2["loss"])


def test_tied_models_set_excludes_clearly_worse_models():
    t_good = _table(reuse=[0.9], novel=[0.9], mutate=[[0.9]])   # high recall: the defender detects more
    t_bad = _table(reuse=[0.1], novel=[0.9], mutate=[[0.9]])
    p = _params(lam=1.0, pi=0.0, w=0.0, cB=0.0)
    outs = enumerate_configs({"good": {1e-3: t_good}, "bad": {1e-3: t_bad}}, p, [math.inf])
    assert tied_models(outs) == frozenset({"good"})
    best, _ = solve({"good": {1e-3: t_good}, "bad": {1e-3: t_bad}}, p, [math.inf])
    assert best.model == "good"


def test_equilibrium_flags_grid_edges_and_no_attack_detection_is_nan():
    t = _table(reuse=[0.2], novel=[0.9], mutate=[[0.9]])
    p = _params(lam=1.0, pi=0.0, V=1.0, P=100.0, kM=1e6, kN=1e6, cB=1.0, w=0.0)
    e = equilibrium(stack_tables({"m": {1e-3: t}}, p, [1e4, 1e5]), p)
    assert e["capable_class"] == ABSTAIN and math.isnan(e["p_eq"])
    assert e["edge_B"] is True and e["edge_fpr"] is True


def test_no_attack_detection_renders_as_text():
    from idsbench.econ.sweep import _fmt

    assert _fmt(float("nan")) == "n/a (no attack)"


def test_worst_case_is_the_minimum_over_score_attackers():
    import pandas as pd

    from idsbench.econ.detection_tables import worst_case_mutation

    rows = []
    for att, rec in (("greedy", 0.4), ("strong", 0.2), ("transfer", 0.3)):
        rows.append({"dataset": "d", "seed": 0, "model": "xgb", "fpr": 1e-3, "family": "F", "n_groups": 1,
                     "groups": "timing", "multiplier": 2.0, "query_mode": "score", "attacker": att,
                     "recall_after": rec, "recall_before": 0.9})
    rows.append({"dataset": "d", "seed": 0, "model": "xgb", "fpr": 1e-3, "family": "F", "n_groups": 1,
                 "groups": "timing", "multiplier": 2.0, "query_mode": "label", "attacker": "label",
                 "recall_after": 0.05, "recall_before": 0.9})
    m = pd.DataFrame(rows)
    w = worst_case_mutation(m, "score")
    assert w.recall_worst.iloc[0] == pytest.approx(0.2)
    wl = worst_case_mutation(m, "label")
    assert wl.recall_worst.iloc[0] == pytest.approx(0.05)


def test_auroc_tie_is_paired_and_bootstrap_based():
    import pandas as pd

    from idsbench.econ.sweep import auroc_tie_table

    rng = np.random.default_rng(0)
    base = 0.99 + rng.normal(0, 5e-4, 10)
    auc = pd.DataFrame({"same": base, "twin": base + rng.normal(0, 1e-6, 10),
                        "clear": base - 0.02})
    tt = auroc_tie_table(auc)["tie"]
    assert tt[("same", "twin")] and tt[("twin", "same")]
    assert not tt[("same", "clear")]
    assert tt[("same", "same")]


def test_loss_tie_and_rank_with_ties_use_the_relative_tolerance():
    from idsbench.econ.sweep import loss_tie_fn, rank_with_ties

    losses = {"a": 100.0, "b": 100.5, "c": 120.0}
    tie = loss_tie_fn(losses)
    assert tie("a", "b") and not tie("a", "c")
    r = rank_with_ties(losses, tie, lambda x, y: x < y)
    assert r == {"a": 1, "b": 1, "c": 3}


def test_kendall_is_nan_for_constant_rankings_and_one_for_identical_orders():
    from idsbench.econ.sweep import kendall

    assert kendall([1, 2, 3, 4], [1, 2, 3, 4]) == pytest.approx(1.0)
    assert math.isnan(kendall([1, 1, 1], [1, 2, 3]))


def test_sobol_design_has_nd2_samples_and_problem_matches_ranges():
    from SALib.sample import sobol as sobol_sample

    from idsbench.econ.sweep import X3_RANGES, _x3_problem

    prob = _x3_problem()
    assert prob["names"] == list(X3_RANGES)
    X = sobol_sample.sample(prob, 64, calc_second_order=False, seed=1)
    assert X.shape == (64 * (len(X3_RANGES) + 2), len(X3_RANGES))
    assert np.all(X >= np.array([b[0] for b in prob["bounds"]]) - 1e-12)


def test_split_keeps_benign_test_disjoint_from_calibration():
    from idsbench.feasibility.common import BENIGN
    from idsbench.feasibility.e2_lofo import _split_sets

    fam = np.array([BENIGN] * 500 + ["A"] * 600)
    sets, fams = _split_sets(fam, seed=3, min_family_rows=500)
    bt, cal, tr = sets[BENIGN]["test"], sets[BENIGN]["cal"], sets[BENIGN]["train"]
    assert len(np.intersect1d(bt, cal)) == 0 and len(np.intersect1d(bt, tr)) == 0
