"""Training variants of the robustness study (design section 4).

All variants share the same train/calibration/test split of a seed. Augmentation rows come only from training
folds (``sets[f]["train"]`` of the families in ``fams`` and the benign training rows): a held-out family never
enters, which is what the leave-one-family-out evaluation relies on.

  xgb             clean XGBoost (base model; also the source of the attack-copy greedy path)
  fusion          xgb + benign IsolationForest, Bonferroni fusion of conformal p-values
  iforest         IsolationForest on benign training rows only
  xgb_robust      clean XGBoost on the robust columns (no column G1 or G2 can change or recompute)
  adv_naive_G1    clean + G1 greedy attack copies (full budget)
  adv_sym_G1      clean + G1 greedy attack copies + G1 random-budget benign copies (same count)
  adv_sym_G1G2    clean + attack and benign copies from G1 and G2, half each (same total count as adv_sym_G1)
"""

from __future__ import annotations

import numpy as np

from idsbench.econ.mutation import GROUPS, ROBUST_DROP_DEPENDENT, apply_group, attack_path
from idsbench.feasibility.common import BENIGN, xgb_binary, xgb_margin

from .gen2 import BUDGETS

MODELS = ("xgb", "fusion", "iforest", "xgb_robust", "adv_naive_G1", "adv_sym_G1", "adv_sym_G1G2")
E4_MODELS = ("xgb", "fusion", "xgb_robust", "adv_naive_G1", "adv_sym_G1", "adv_sym_G1G2")
ADV_MODELS = ("adv_naive_G1", "adv_sym_G1", "adv_sym_G1G2")
N_AUG = 2000           # attack copies per training family (and benign copies in total per attack copy)
AUG_MULT = 5.0
# Backward timing and Active features that G2's request-response coupling changes (not in G1's ROBUST list).
G2_COUPLED = ("bwd iat total", "bwd iat mean", "bwd iat max", "active mean", "active max")


def robust_columns(gi, g2_touched_names) -> np.ndarray:
    """Columns of xgb_robust: outside G1's mutated set, outside G2's touched set, outside the dependent list."""
    drop = set(gi.mutated_idx().tolist())
    drop |= set(gi.idx(ROBUST_DROP_DEPENDENT).tolist())
    drop |= set(gi.idx(list(g2_touched_names)).tolist())
    drop |= set(gi.idx(list(G2_COUPLED)).tolist())
    return np.array([i for i in range(len(gi.columns)) if i not in drop], dtype=int)


def apply_fn_g1(gi):
    """G1 as an apply(X, group, level) callable."""
    return lambda X, g, lv: apply_group(X, gi, g, lv)


def augment_attacks(score_fn, Xv: np.ndarray, sets: dict, fams, apply, seed: int, tag: int,
                    n_max: int = N_AUG, mult: float = AUG_MULT) -> np.ndarray:
    """Greedy full-budget mutated copies of up to n_max training attack flows per family (score query of
    ``score_fn``, the base model). Only the training rows of ``fams`` are read."""
    rng = np.random.default_rng([seed, 1717, tag])
    out = []
    for f in fams:
        idx = sets[f]["train"]
        take = np.sort(rng.choice(idx, size=min(n_max, len(idx)), replace=False))
        _, Xm = attack_path(score_fn, Xv[take], None, GROUPS, mult, "score", apply=apply)
        out.append(Xm)
    if not out:
        return np.empty((0, Xv.shape[1]))
    return np.vstack(out)


def augment_benign(Xv: np.ndarray, ben_train: np.ndarray, n: int, apply, seed: int, tag: int) -> np.ndarray:
    """Benign copies with random budgets (benign clients do not optimise against the detector)."""
    rng = np.random.default_rng([seed, 1818, tag])
    take = rng.choice(ben_train, size=min(n, len(ben_train)), replace=False)
    return _random_budget(apply, Xv[take], rng)


def _random_budget(apply, X, rng):
    """Random budget per row using the generic apply callable (G1 or G2)."""
    bid = rng.integers(0, len(BUDGETS), size=len(X))
    Y = np.array(X, dtype=float, copy=True)
    for b, (groups, mult) in enumerate(BUDGETS):
        rows = bid == b
        if not rows.any():
            continue
        Z = Y[rows]
        for g in GROUPS:
            if g in groups:
                Z = apply(Z, g, mult)
        Y[rows] = Z
    return Y


def random_budget_mutate(apply, X, seed: int, tag: int) -> np.ndarray:
    """Benign-test mutation with random budgets (fingerprint test, same distribution as benign augmentation)."""
    return _random_budget(apply, np.asarray(X, dtype=float), np.random.default_rng([seed, 1919, tag]))


def fixed_budget_mutate(apply, X, groups, mult: float) -> np.ndarray:
    """All groups of one budget, in group order, each at level mult."""
    Y = np.asarray(X, dtype=float)
    for g in GROUPS:
        if g in groups:
            Y = apply(Y, g, mult)
    return Y


def fit_xgb(Xv, y, idx, seed: int):
    return xgb_binary(seed).fit(Xv[idx], y[idx])


def fit_known(Xv, y, sets, fams, seed: int, ctx: dict, which=MODELS) -> dict:
    """Score functions of the defenders trained on the training folds of ``fams``.

    ``which`` selects the variants to build (the leave-one-family-out runs may build fewer). Returns a dict of
    score functions Z -> score (margin for xgb-type models) plus the base xgb model under 'base'.
    """
    ben_tr = sets[BENIGN]["train"]
    idx = np.concatenate([ben_tr] + [sets[f]["train"] for f in fams])
    base = fit_xgb(Xv, y, idx, seed)
    base_fn = lambda Z, m=base: xgb_margin(m, Z)
    out = {"xgb": base_fn}
    ridx = ctx["ridx"]
    need_adv = any(m in which for m in ADV_MODELS)
    if "xgb_robust" in which:
        rb = xgb_binary(seed).fit(Xv[idx][:, ridx], y[idx])
        out["xgb_robust"] = lambda Z, m=rb: xgb_margin(m, Z[:, ridx])
    n_aug = int(ctx.get("n_aug", N_AUG))
    if need_adv:
        a1 = augment_attacks(base_fn, Xv, sets, fams, ctx["apply1"], seed, tag=1, n_max=n_aug)
        b1 = augment_benign(Xv, ben_tr, len(a1), ctx["apply1"], seed, tag=1)
        if "adv_naive_G1" in which:
            m = _fit_aug(Xv, y, idx, a1, None, seed)
            out["adv_naive_G1"] = lambda Z, m=m: xgb_margin(m, Z)
        if "adv_sym_G1" in which:
            m = _fit_aug(Xv, y, idx, a1, b1, seed)
            out["adv_sym_G1"] = lambda Z, m=m: xgb_margin(m, Z)
        if "adv_sym_G1G2" in which:
            a1h = augment_attacks(base_fn, Xv, sets, fams, ctx["apply1"], seed, tag=2, n_max=n_aug // 2)
            a2h = augment_attacks(base_fn, Xv, sets, fams, ctx["apply2"], seed, tag=3, n_max=n_aug // 2)
            b1h = augment_benign(Xv, ben_tr, len(a1h), ctx["apply1"], seed, tag=2)
            b2h = augment_benign(Xv, ben_tr, len(a2h), ctx["apply2"], seed, tag=3)
            m = _fit_aug(Xv, y, idx, np.vstack([a1h, a2h]), np.vstack([b1h, b2h]), seed)
            out["adv_sym_G1G2"] = lambda Z, m=m: xgb_margin(m, Z)
    out["base"] = base
    return out


def _fit_aug(Xv, y, idx, attacks, benign, seed):
    parts = [Xv[idx], attacks]
    labels = [y[idx], np.ones(len(attacks), dtype=int)]
    if benign is not None and len(benign):
        parts.append(benign)
        labels.append(np.zeros(len(benign), dtype=int))
    return xgb_binary(seed).fit(np.vstack(parts), np.concatenate(labels))
