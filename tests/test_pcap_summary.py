"""Summary tables of the packet-level study: per-seed mutated-benign verdicts and the xgb_robust diagnostic."""

import math

import numpy as np
import pandas as pd

from idsbench.pcap import run_all as R
from idsbench.pcap.evaluate import GENERATORS, MODELS

N = 1000


def _mutben_row(seed, generator, mode, fpr_by_model):
    r = {"seed": seed, "generator": generator, "mode": mode, "n": N}
    for m in MODELS:
        k = int(round(fpr_by_model[m] * N))
        r[f"k_{m}_0.001"] = k
        r[f"fpr_{m}_0.001"] = k / N
    return r


def _mutben_frame(shifts_by_gen, xgb_base=(0.010, 0.012, 0.008, 0.011, 0.009)):
    """One clean row and one random-budget row per generator and seed. ``shifts_by_gen[g]`` is the per-seed shift of
    adv_sym_P from xgb; every other model equals xgb."""
    rows = []
    for s, base in enumerate(xgb_base):
        clean = {m: base for m in MODELS}
        rows.append(_mutben_row(s, "none", "clean", clean))
        for g in GENERATORS:
            vals = {m: base for m in MODELS}
            vals["adv_sym_P"] = base + shifts_by_gen.get(g, [0.0] * len(xgb_base))[s]
            rows.append(_mutben_row(s, g, "random", vals))
    return pd.DataFrame(rows)


def test_mutben_seed_table_verdict_is_paired_over_seeds():
    shifts = {"P": [0.002] * 5}
    tab = R.mutben_seed_table(_mutben_frame(shifts))
    assert len(tab) == 4 * len(MODELS)
    row = tab[(tab.reference == "mutated_P") & (tab.model == "adv_sym_P")].iloc[0]
    assert row.n_seeds == 5
    assert row.seeds_above_xgb == 5 and row.seeds_below_xgb == 0
    # five positive paired differences: the exact two-sided Wilcoxon p for n = 5 is 2/32
    assert math.isclose(row.p_wilcoxon_vs_xgb, 0.0625, rel_tol=1e-9)
    base = np.array([0.010, 0.012, 0.008, 0.011, 0.009]) + 0.002
    assert math.isclose(row.seed_mean, base.mean(), rel_tol=1e-9)
    assert row.boot_ci_lo <= row.seed_mean <= row.boot_ci_hi
    assert math.isclose(row.pooled_fpr, row.pooled_k / row.pooled_n)
    assert row.pooled_n == 5 * N


def test_mutben_seed_table_counts_ties_and_reports_reference_rows():
    shifts = {"G1": [0.001, -0.001, 0.0, 0.001, 0.002]}
    tab = R.mutben_seed_table(_mutben_frame(shifts))
    row = tab[(tab.reference == "mutated_G1") & (tab.model == "adv_sym_P")].iloc[0]
    assert row.seeds_above_xgb == 3 and row.seeds_below_xgb == 1
    assert math.isfinite(row.p_wilcoxon_vs_xgb)
    xgb_rows = tab[tab.model == "xgb"]
    assert xgb_rows.seeds_above_xgb.isna().all() and xgb_rows.p_wilcoxon_vs_xgb.isna().all()
    # identical models: no non-zero difference, so no p-value
    same = tab[(tab.reference == "mutated_P") & (tab.model == "xgb_robust")].iloc[0]
    assert same.seeds_above_xgb == 0 and same.seeds_below_xgb == 0 and math.isnan(same.p_wilcoxon_vs_xgb)


def test_mutben_seed_table_no_difference_gives_no_p_value():
    tab = R.mutben_seed_table(_mutben_frame({}))
    row = tab[(tab.reference == "mutated_P") & (tab.model == "adv_sym_G1")].iloc[0]
    assert row.seeds_above_xgb == 0 and row.seeds_below_xgb == 0
    assert math.isnan(row.p_wilcoxon_vs_xgb)


def test_xgb_robust_table_keeps_infinite_threshold_and_per_family_values():
    families = list(R.FAMILIES)
    thr_rows, clean_rows = [], []
    for s in range(2):
        thr = math.inf if s == 0 else 2.5
        thr_rows.append({"seed": s, "model": "xgb_robust", "fpr": 1e-3, "threshold": thr, "plateau_moved": False,
                         "fpr_test_realised": 0.0 if s == 0 else 0.001})
        for i, f in enumerate(families):
            clean_rows.append({"seed": s, "model": "xgb_robust", "fpr": 1e-3, "family": f,
                               "recall": 0.0 if s == 0 else 0.5 + 0.1 * i, "auroc": 0.98 + 0.001 * i})
            clean_rows.append({"seed": s, "model": "xgb_robust", "fpr": 1e-4, "family": f,
                               "recall": 0.9, "auroc": 0.98 + 0.001 * i})
    out = R.xgb_robust_table(pd.DataFrame(thr_rows), pd.DataFrame(clean_rows))
    assert list(out.seed) == [0, 1]
    assert math.isinf(out.loc[0, "threshold"]) and out.loc[0, "recall " + families[0]] == 0.0
    assert math.isclose(out.loc[1, "recall " + families[-1]], 0.5 + 0.1 * (len(families) - 1))
    assert math.isclose(out.loc[1, "AUROC " + families[0]], 0.98)
    # the 1e-4 rows are not used at FPR 1e-3
    assert "recall " + families[0] in out.columns and not (out["recall " + families[0]] == 0.9).any()
