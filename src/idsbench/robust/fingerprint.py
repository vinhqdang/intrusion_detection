"""Realism diagnostics of the generators (design section 3.3).

1. Fingerprint AUROC: an XGBoost separates benign flows x from their mutated copies G(x). AUROC near 1 means the
   generator leaves a learnable artefact. Per generator and group (the group alone, multiplier drawn per row from
   MULTIPLIERS) and for all groups (random budget per row). Held-out split of the flows: 50% train, 50% test.
2. Cross-generator distance: the same test for G1(x) against G2(x) at matched budgets (the same budget per row).
3. Top features of the 'all groups' fingerprint classifier (gain).
"""

from __future__ import annotations

import zlib

import numpy as np

from idsbench.econ.mutation import apply_group
from idsbench.feasibility.common import xgb_binary
from sklearn.metrics import roc_auc_score

from .defenders import fixed_budget_mutate
from .gen2 import BUDGETS, GROUPS

MULTIPLIERS = (1.5, 2.0, 5.0)


def _per_row_group(apply, X, group: str, rng) -> np.ndarray:
    """Group alone, the multiplier drawn per row."""
    m = rng.choice(MULTIPLIERS, size=len(X))
    Y = np.array(X, dtype=float, copy=True)
    for v in MULTIPLIERS:
        rows = m == v
        if rows.any():
            Y[rows] = apply(X[rows], group, v)
    return Y


def _budget_index_apply(apply, X, bid) -> np.ndarray:
    """Apply the budget with index bid[i] to row i."""
    Y = np.array(X, dtype=float, copy=True)
    for b, (groups, mult) in enumerate(BUDGETS):
        rows = bid == b
        if rows.any():
            Y[rows] = fixed_budget_mutate(apply, X[rows], groups, mult)
    return Y


def _auc_fit(A0, A1, B0, B1, seed: int):
    """Train on the first halves, return (AUROC on the second halves, gain-importance order)."""
    rng = np.random.default_rng([seed, 99])
    n = len(A0)
    perm = rng.permutation(n)
    tr, te = perm[: n // 2], perm[n // 2:]
    Xtr = np.vstack([A0[tr], A1[tr]])
    ytr = np.r_[np.zeros(len(tr)), np.ones(len(tr))]
    Xte = np.vstack([B0[te], B1[te]])
    yte = np.r_[np.zeros(len(te)), np.ones(len(te))]
    clf = xgb_binary(seed)
    clf.set_params(n_estimators=200, max_depth=6)
    clf.fit(Xtr, ytr)
    auc = float(roc_auc_score(yte, clf.predict_proba(Xte)[:, 1]))
    return auc, clf


def fingerprint_rows(dataset: str, Xb: np.ndarray, columns, gens: dict, seed: int, n: int = 20000) -> tuple[list, list]:
    """Rows of the fingerprint and cross-generator tables for one dataset (benign training rows Xb).

    gens maps a name ('G1', 'G2') to its apply(X, group, level) callable.
    """
    rng = np.random.default_rng([seed, 5151])
    take = rng.choice(len(Xb), size=min(n, len(Xb)), replace=False)
    X = np.asarray(Xb[take], dtype=float)
    rows, cross = [], []
    top = {}
    for gname, ap in gens.items():
        for g in GROUPS + ("all",):
            r2 = np.random.default_rng([seed, 5152, zlib.crc32(gname.encode()), GROUPS.index(g) if g in GROUPS else 9])
            if g == "all":
                bid = r2.integers(0, len(BUDGETS), size=len(X))
                Y = _budget_index_apply(ap, X, bid)
            else:
                Y = _per_row_group(ap, X, g, r2)
            auc, clf = _auc_fit(X, Y, X, Y, seed)
            rows.append({"dataset": dataset, "seed": seed, "generator": gname, "group": g, "fingerprint_auroc": auc})
            if g == "all":
                imp = clf.get_booster().get_score(importance_type="gain")
                order = sorted(imp.items(), key=lambda kv: -kv[1])[:5]
                names = [str(columns[int(k[1:])]) if k.startswith("f") and k[1:].isdigit() else k for k, _ in order]
                top[gname] = ", ".join(names)
    for r in rows:
        if r["group"] == "all":
            r["top_features"] = top.get(r["generator"], "")
        else:
            r["top_features"] = ""
    # Cross-generator distance at matched budgets: G1(x) (label 1) against G2(x) (label 0).
    if len(gens) == 2:
        (n1, a1), (n2, a2) = list(gens.items())
        bid = np.random.default_rng([seed, 5153]).integers(0, len(BUDGETS), size=len(X))
        Y1 = _budget_index_apply(a1, X, bid)
        Y2 = _budget_index_apply(a2, X, bid)
        auc, _ = _auc_fit(Y2, Y1, Y2, Y1, seed)
        cross.append({"dataset": dataset, "seed": seed, "pair": f"{n1} vs {n2}", "matched_budget": True,
                      "cross_auroc": auc})
    return rows, cross
