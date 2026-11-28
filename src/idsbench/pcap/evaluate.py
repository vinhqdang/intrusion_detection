"""Per-seed evaluation of the packet-level study (design/design_pcap.md sections 4 to 6).

Reuses the robustness machinery: ``robust.defenders`` (training variants, augmentation, random and fixed budgets),
``robust.evaluate`` (plateau-aware thresholds, Wilson intervals), ``robust.fingerprint`` (AUROC helper and matched
budgets), ``econ.mutation`` (greedy and strong attackers, recall) and ``robust.gen2`` (budgets, G2). The only new
pieces are the packet-level generator P (``pcap.pgen``), its defender adv_sym_P, the timeout re-split count and the
realism tables.

Rows returned by ``run_seed`` are plain dicts; ``run_all`` turns them into CSV files.
"""

from __future__ import annotations

import time
import warnings
import zlib
from dataclasses import dataclass

import numpy as np
from sklearn.metrics import roc_auc_score

from idsbench.econ.mutation import (
    apply_group, attack_path, build_group_index, recall_at, recall_from_scores, strong_attack,
)
from idsbench.feasibility.common import BENIGN, xgb_margin
from idsbench.feasibility.e2_lofo import _split_sets
from idsbench.robust.defenders import (
    _fit_aug, _random_budget, augment_attacks, fit_known, fixed_budget_mutate, random_budget_mutate, robust_columns,
)
from idsbench.robust.evaluate import budget_label, budget_units, plateau_threshold, wilson
from idsbench.robust.fingerprint import _auc_fit, _budget_index_apply
from idsbench.robust.gen2 import BUDGETS, G2, TOUCHED

from .extract import FEATURES
from .label import LABELS
from .pgen import PGen

FPRS = (1e-4, 1e-3, 1e-2)
FPR_REF = 1e-3
MIN_FAMILY_ROWS = 500
KNOWN_MODELS = ("xgb", "xgb_robust", "adv_naive_G1", "adv_sym_G1", "adv_sym_G1G2")
MODELS = ("xgb", "xgb_robust", "adv_naive_G1", "adv_sym_G1", "adv_sym_G1G2", "adv_sym_P")
ATTACKERS = ("greedy", "strong", "transfer")
GENERATORS = ("G1", "G2", "P")
N_BENIGN_PKT_TRAIN = 4000       # benign training flows with packets used as sources of P benign copies
N_AUG = 2000                   # attack copies per training family (as in the robustness study)
P_CHECK_ROWS = 2000            # rows used for the P-changed column check
RELERR_ROWS = 3000             # benign rows used for per-feature relative errors
MIN_POOL_TEST = 30_000         # connection flows with packets in the benign test split (mutated-benign FPR)
MUTBEN_N = 30_000              # rows of that pool used for the mutated-benign and realism computations
FI = {n: i for i, n in enumerate(FEATURES)}


@dataclass(frozen=True)
class Config:
    seed: int = 0
    n_flows: int = 500
    n_aug: int = N_AUG


def _crc(s: str) -> int:
    return zlib.crc32(s.encode()) & 0xFFFF_FFFF


def _reset(ap):
    if isinstance(ap, PGen):
        ap.reset()


def p_changed_columns(X, sets, pool_train, pg: PGen, seed: int, log=print) -> list[str]:
    """Columns that P changes on more than 1% of the training flows it can mutate (design section 5)."""
    rng = np.random.default_rng([seed, 5151])
    atk = np.concatenate([sets[f]["train"] for f in sets if f != BENIGN])
    a = rng.choice(atk, size=min(P_CHECK_ROWS, len(atk)), replace=False)
    b = rng.choice(pool_train, size=min(P_CHECK_ROWS, len(pool_train)), replace=False)
    idx = np.concatenate([a, b])
    Y = random_budget_mutate(pg, X[idx], seed, tag=9)
    changed = np.mean(np.abs(Y - X[idx]) > 1e-9 * np.maximum(np.abs(X[idx]), 1.0), axis=0)
    names = [FEATURES[j] for j in np.flatnonzero(changed > 0.01)]
    log(f"    P changes {len(names)} columns on > 1% of training flows")
    return names


def run_seed(cache: dict, X: np.ndarray, label: np.ndarray, cfg: Config, log=print) -> dict:
    t0 = time.time()
    seed = cfg.seed
    names = np.asarray([BENIGN] + list(LABELS[1:]))   # the benign key is shared with the robustness code
    fam = names[label]
    y = (label > 0).astype(int)
    sets, fams = _split_sets(fam, seed, MIN_FAMILY_ROWS)
    pool_rows = np.flatnonzero(cache["pool_row"] >= 0)
    is_pool = np.zeros(len(X), bool)
    is_pool[pool_rows] = True
    gi = build_group_index(FEATURES)
    g2 = G2(FEATURES)
    apply1 = lambda Z, g, lv: apply_group(Z, gi, g, lv)
    pg = PGen(cache, X, seed)
    gens = {"G1": apply1, "G2": g2.apply, "P": pg}
    ben_tr = sets[BENIGN]["train"]
    ben_te = sets[BENIGN]["test"]
    cal = sets[BENIGN]["cal"]
    pool_train = np.intersect1d(ben_tr, pool_rows)
    pool_test = np.intersect1d(ben_te, pool_rows)
    pool_ben_all = np.intersect1d(np.concatenate([ben_tr, ben_te, cal]), pool_rows)
    log(f"[pcap] seed={seed} families={fams} benign train/cal/test={len(ben_tr)}/{len(cal)}/{len(ben_te)} "
        f"pool test={len(pool_test)} ({time.time() - t0:.0f}s)")

    changed = p_changed_columns(X, sets, pool_train, pg, seed, log)
    robust_names = list(TOUCHED) + [c.lower() for c in changed]
    ridx = robust_columns(gi, robust_names)
    ctx = {"ridx": ridx, "apply1": apply1, "apply2": g2.apply, "n_aug": cfg.n_aug}
    fns = fit_known(X, y, sets, fams, seed, ctx, which=KNOWN_MODELS)
    base_fn = fns["xgb"]
    log(f"[pcap] seed={seed} robustness-study defenders trained ({time.time() - t0:.0f}s)")

    # adv_sym_P: P attack copies (greedy against base xgb) and P benign copies with random budgets, equal count
    att_p = augment_attacks(base_fn, X, sets, fams, pg, seed, tag=4, n_max=cfg.n_aug)
    rng = np.random.default_rng([seed, 4444])
    src = rng.choice(pool_train, size=min(N_BENIGN_PKT_TRAIN, len(pool_train)), replace=False)
    pick = src[rng.integers(0, len(src), size=len(att_p))]
    ben_p = _random_budget(pg, X[pick], rng)
    tr_idx = np.concatenate([ben_tr] + [sets[f]["train"] for f in fams])
    m_p = _fit_aug(X, y, tr_idx, att_p, ben_p, seed)
    fns["adv_sym_P"] = lambda Z, m=m_p: xgb_margin(m_p, Z)
    pg.reset()
    log(f"[pcap] seed={seed} adv_sym_P trained: {len(att_p)} attack copies, {len(ben_p)} benign copies "
        f"({time.time() - t0:.0f}s)")

    S = {m: fns[m](X) for m in MODELS}
    cal_scores = {m: S[m][cal] for m in MODELS}
    rows = {k: [] for k in ("thr", "clean", "e4", "mutben", "realism", "relerr", "stats", "timing")}
    thr = {}
    for m in MODELS:
        thr[m] = {}
        for fpr in FPRS:
            t, ok, rc, pl = plateau_threshold(cal_scores[m], fpr)
            if not ok:
                raise RuntimeError(f"seed {seed}: {m} at FPR {fpr:g} not attainable")
            k_test = float(np.sum(S[m][ben_te] > t))
            lo, hi = wilson(k_test, len(ben_te))
            thr[m][fpr] = t
            rows["thr"].append({"seed": seed, "model": m, "fpr": fpr, "threshold": t, "fpr_cal_realised": rc,
                                "plateau_moved": pl, "fpr_test_realised": k_test / len(ben_te),
                                "fpr_test_ci_lo": lo, "fpr_test_ci_hi": hi, "n_benign_test": len(ben_te)})

    # clean recall and AUROC per family (known scenario)
    for f in fams:
        ft = sets[f]["test"]
        for m in MODELS:
            auc = float(roc_auc_score(np.r_[np.zeros(len(ben_te)), np.ones(len(ft))],
                                      np.r_[S[m][ben_te], S[m][ft]]))
            for fpr in FPRS:
                rows["clean"].append({"seed": seed, "model": m, "fpr": fpr, "family": f,
                                      "recall": float(np.mean(S[m][ft] > thr[m][fpr])), "n_family_test": len(ft),
                                      "auroc": auc})
    log(f"[pcap] seed={seed} clean recall done ({time.time() - t0:.0f}s)")

    # E4: attacks on the known models, every generator and budget
    for f in fams:
        ft = sets[f]["test"]
        rng = np.random.default_rng([seed, _crc(f)])
        idx = np.sort(rng.choice(ft, size=min(cfg.n_flows, len(ft)), replace=False))
        Xf = X[idx]
        for gname, ap in gens.items():
            for groups, mult in BUDGETS:
                bl = budget_label(groups, mult)
                strong = {}
                for m in MODELS:
                    _reset(ap)
                    srng = np.random.default_rng([seed, _crc(f), _crc(bl), _crc(gname), _crc("strong"), _crc(m)])
                    strong[m] = strong_attack(fns[m], Xf, None, groups, mult, srng, apply=ap)
                X_src = strong["xgb"][1]
                for m in MODELS:
                    _reset(ap)
                    path, _ = attack_path(fns[m], Xf, None, groups, mult, "score", apply=ap)
                    transfer = fns[m](X_src) if m != "xgb" else None
                    for fpr in FPRS:
                        t = thr[m][fpr]
                        base = {"seed": seed, "model": m, "fpr": fpr, "family": f, "generator": gname,
                                "budget": bl, "groups": "+".join(groups), "multiplier": mult,
                                "units": budget_units(groups, mult), "n_flows": len(idx),
                                "recall_before": float(np.mean(S[m][idx] > t))}
                        rows["e4"].append({**base, "attacker": "greedy", "recall_after": recall_at(path, t, True)})
                        rows["e4"].append({**base, "attacker": "strong",
                                           "recall_after": recall_from_scores(strong[m][0], t, True)})
                        if transfer is not None:
                            rows["e4"].append({**base, "attacker": "transfer",
                                               "recall_after": recall_from_scores(transfer, t, True)})
                _reset(ap)
        log(f"[pcap] seed={seed} E4 family={f} ({time.time() - t0:.0f}s)")

    # mutated-benign FPR on the benign test rows that have packets (same rows for every generator), with counts so
    # that pooled Wilson intervals can be formed; the clean FPR on the same rows is the reference
    if len(pool_test) < MIN_POOL_TEST:
        log(f"    WARNING: benign test pool with packets is {len(pool_test)} < {MIN_POOL_TEST}")
    # a fixed seeded subsample of the pool (at most MUTBEN_N rows) keeps the per-budget mutation affordable
    rs_pool = np.random.default_rng([seed, 6060])
    pool_test = np.sort(rs_pool.choice(pool_test, size=min(MUTBEN_N, len(pool_test)), replace=False))
    Xb = X[pool_test]

    def counts_row(gname, mode, budget, groups, mult, scores):
        r = {"seed": seed, "generator": gname, "mode": mode, "budget": budget, "groups": groups,
             "multiplier": mult, "n": len(next(iter(scores.values())))}
        for m in MODELS:
            for fpr in FPRS:
                k = int(np.sum(scores[m] > thr[m][fpr]))
                r[f"k_{m}_{fpr:g}"] = k
                r[f"fpr_{m}_{fpr:g}"] = k / r["n"]
        return r

    rows["mutben"].append(counts_row("none", "clean", "none", "", float("nan"), {m: S[m][pool_test] for m in MODELS}))
    for gname, ap in gens.items():
        _reset(ap)
        Yr = random_budget_mutate(ap, Xb, seed, tag=_crc(gname) & 0xFF)
        rows["mutben"].append(counts_row(gname, "random", "random", "", float("nan"),
                                         {m: fns[m](Yr) for m in MODELS}))
        for groups, mult in BUDGETS:
            _reset(ap)
            Yfx = fixed_budget_mutate(ap, Xb, groups, mult)
            rows["mutben"].append(counts_row(gname, "fixed", budget_label(groups, mult), "+".join(groups), mult,
                                             {m: fns[m](Yfx) for m in MODELS}))
        _reset(ap)
    log(f"[pcap] seed={seed} mutated benign done ({time.time() - t0:.0f}s)")

    # timing check: realised growth of the forward IAT mean and of the flow duration at each nominal multiplier
    for m_nom in (1.5, 2.0, 5.0):
        Yt = fixed_budget_mutate(pg, Xb, ("timing",), m_nom)
        d0 = Xb[:, FI["Flow Duration"]]
        i0 = Xb[:, FI["Fwd IAT Mean"]]
        tot = Xb[:, FI["Fwd IAT Total"]]
        okd = d0 > 0
        oki = i0 > 0
        rows["timing"].append({
            "seed": seed, "multiplier": m_nom, "n": len(Xb),
            "median_ratio_duration": float(np.median(Yt[okd, FI["Flow Duration"]] / d0[okd])) if okd.any() else float("nan"),
            "median_ratio_fwd_iat_mean": float(np.median(Yt[oki, FI["Fwd IAT Mean"]] / i0[oki])) if oki.any() else float("nan"),
            "mean_added_over_expected": float(np.mean(
                (Yt[tot > 0, FI["Flow Duration"]] - d0[tot > 0]) / ((m_nom - 1.0) * tot[tot > 0]))) if np.any(tot > 0)
            else float("nan"),
        })
    _reset(pg)

    # realism (Q1): fingerprint AUROCs and cross-generator AUROCs on the same benign flows
    rs_real = np.random.default_rng([seed, 7070])
    X0 = X[np.sort(rs_real.choice(pool_ben_all, size=min(MUTBEN_N, len(pool_ben_all)), replace=False))]
    Yp = random_budget_mutate(pg, X0, seed, tag=21)
    Y1 = random_budget_mutate(apply1, X0, seed, tag=22)
    Y2 = random_budget_mutate(g2.apply, X0, seed, tag=23)
    _reset(pg)
    fp = {"P_vs_x": _auc_fit(X0, Yp, X0, Yp, seed)[0], "G1_vs_x": _auc_fit(X0, Y1, X0, Y1, seed)[0],
          "G2_vs_x": _auc_fit(X0, Y2, X0, Y2, seed)[0]}
    rng = np.random.default_rng([seed, 2323])
    bid_rows = X0[rng.choice(len(X0), size=min(RELERR_ROWS, len(X0)), replace=False)]
    bid = rng.integers(0, len(BUDGETS), size=len(bid_rows))
    Z1 = _budget_index_apply(apply1, bid_rows, bid)
    Z2 = _budget_index_apply(g2.apply, bid_rows, bid)
    Zp = _budget_index_apply(pg, bid_rows, bid)
    _reset(pg)
    fp["G1_vs_P"] = _auc_fit(Zp, Z1, Zp, Z1, seed)[0]
    fp["G2_vs_P"] = _auc_fit(Zp, Z2, Zp, Z2, seed)[0]
    for k, v in fp.items():
        rows["realism"].append({"seed": seed, "measure": k, "auroc": float(v)})
    log(f"[pcap] seed={seed} fingerprint AUROCs {({k: round(v, 3) for k, v in fp.items()})}")

    # per-feature relative error |G(x) - P(x)| / |P(x)| at matched budgets, per budget
    group_of = {}
    for gname_ in ("timing", "length", "count"):
        for c in gi.group_columns(gname_):
            group_of[c] = gname_
    relerr_rows = []
    for groups, mult in BUDGETS:
        Pz = fixed_budget_mutate(pg, bid_rows, groups, mult)
        for gname, ap in (("G1", apply1), ("G2", g2.apply)):
            Gz = fixed_budget_mutate(ap, bid_rows, groups, mult)
            den = np.abs(Pz)
            err = np.where(den > 0, np.abs(Gz - Pz) / np.where(den > 0, den, 1.0), np.nan)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                med = np.nanmedian(err, axis=0)
            for j, name in enumerate(FEATURES):
                relerr_rows.append({"seed": seed, "generator": gname, "budget": budget_label(groups, mult),
                                    "multiplier": mult, "groups": "+".join(groups), "feature": name,
                                    "group_of_feature": group_of.get(name, "none"),
                                    "median_rel_err": float(med[j]) if np.isfinite(med[j]) else float("nan"),
                                    "n_rows": len(bid_rows)})
    _reset(pg)
    rows["relerr"] = relerr_rows
    st = pg.stats
    rows["stats"].append({"seed": seed, "p_states": st["states"], "p_timing_states": st["timing_states"],
                          "p_resplit_states": st["resplit_states"],
                          "p_resplit_share": st["resplit_states"] / max(st["timing_states"], 1), "p_calls": st["calls"]})
    log(f"[pcap] seed={seed} done in {time.time() - t0:.0f}s; P states {st['states']}, "
        f"re-split {st['resplit_states']} ({st['resplit_states'] / max(st['states'], 1):.4f})")
    return rows


# ----------------------------------------------------------------------------- population, labels, dedup
def dedup_indices(X: np.ndarray, family: np.ndarray):
    """Leakage-safe pool cleaning before any split. Same three steps as ``feasibility.common.clean_pool``:
    exact duplicates (features and family) keep the first copy; a feature vector seen with both benign and attack
    labels is removed entirely; feature-only duplicates among the survivors keep the first copy.

    Returns (kept positions, per-family counts of rows, exact duplicates, label conflicts, feature duplicates).
    """
    import pandas as pd

    family = np.asarray(family, dtype=object)
    binary = (family != BENIGN).astype(np.int8)
    frame = pd.DataFrame(X)
    h_feat = pd.util.hash_pandas_object(frame, index=False).to_numpy()
    h_full = pd.util.hash_pandas_object(frame.assign(__family=family), index=False).to_numpy()
    exact_dup = pd.Series(h_full).duplicated(keep="first").to_numpy()
    alive = ~exact_dup
    lab = pd.DataFrame({"h": h_feat, "b": binary})[alive]
    n_labels = lab.groupby("h")["b"].nunique()
    conflict_h = n_labels.index[n_labels > 1]
    conflict = alive & np.isin(h_feat, conflict_h)
    alive &= ~conflict
    feat_dup = np.zeros(len(X), dtype=bool)
    idx_alive = np.flatnonzero(alive)
    feat_dup[idx_alive] = pd.Series(h_feat[idx_alive]).duplicated(keep="first").to_numpy()
    alive &= ~feat_dup
    keep = np.flatnonzero(alive)
    per_family = {}
    for f in pd.unique(family):
        m = family == f
        per_family[str(f)] = {"rows": int(m.sum()), "exact_duplicates": int((exact_dup & m).sum()),
                              "label_conflicts": int((conflict & m).sum()),
                              "feature_duplicates": int((feat_dup & m).sum()), "rows_after": int((alive & m).sum())}
    return keep, per_family


def select_view(cache: dict, population: str, rule: str):
    """The rows of one analysis: population ('connection' or 'all') and label rule ('primary' or 'drop').

    Returns a cache-like dict (packets shared, pool_row restricted to the kept rows), the cleaned features, the
    label codes, and the dedup table per family. The split is made afterwards, on this view only.
    """
    lab_all = cache["label"] if rule == "primary" else cache["label_drop"]
    keep = lab_all >= 0
    if population == "connection":
        keep &= cache["connection"]
    idx = np.flatnonzero(keep)
    fam_all = np.asarray([BENIGN] + list(LABELS[1:]))
    fam = fam_all[lab_all[idx]]
    X0 = cache["X"][idx]
    kept, dedup = dedup_indices(X0, fam)
    idx2 = idx[kept]
    view = dict(cache)
    view["pool_row"] = cache["pool_row"][idx2]
    return view, cache["X"][idx2], lab_all[idx2], dedup
