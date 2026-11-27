"""Measurements behind the game: defender recall tables and E4 mutation, one call per (dataset, seed).

Defenders (DEFENDERS). Each one gives reuse(f) (known scenario: family f in training, test rows of f),
novel(f) (leave-one-family-out: f excluded from training and from adversarial augmentation) and
mutate(f, b) (known scenario, attacker queries that model with score or label access):
  xgb              XGBoost on all features (E2 known model).
  fusion           Bonferroni fusion of xgb and IsolationForest (conformal p-values, cal_ref).
  iforest          IsolationForest on benign train only. It has no family knowledge: novel = reuse.
  xgb_robustfeat   XGBoost on the robust columns (mutation.GroupIndex.robust_idx): no column a mutation
                   can change and no column that depends on forward timing or size.
  xgb_adv          XGBoost retrained once on mutated copies of its own training attacks (greedy score-mode
                   against the first-stage xgb, full budget, multiplier AUG_MULT, up to N_AUG train attack
                   flows per family). Evaluated against the three attackers below, not against the
                   augmentation attacker alone.

E4 attackers (score query, per model and budget): greedy (the E4 greedy against the model), strong
(per-group level search, mutation.strong_attack, against the model) and transfer (the strong attacker's
states against xgb, submitted to the model; not run for xgb itself). The label attacker (label query) is a
weak baseline. The game uses the worst case over the score attackers (detection_tables.worst_case_mutation).

Calibration: benign calibration rows (20% of benign) are split into cal_ref (conformal references) and
cal_thr (threshold rows of fusion). Thresholds at FPR in FPRS; all must be attainable (asserted). The benign
test rows (20%) are disjoint from calibration (asserted) and give the realised FPR of each threshold.
Test rows: 30% of each attack family (E2 splitting, `_split_sets`) and 20% of benign.
Outputs are per seed; the game averages or uses one seed (see detection_tables).
"""

from __future__ import annotations

import argparse
import multiprocessing as mp
import time
import zlib
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from idsbench.econ.mutation import (
    FPRS, GROUPS, attack_path, budget_label, budgets, build_group_index, identity_hold_rates, recall_at,
    recall_from_scores, score_path, strong_attack, write_feature_log,
)
from idsbench.feasibility.common import (
    BENIGN, get_pool, iforest_score, load_binary, threshold_at_fpr, xgb_binary, xgb_margin,
)
from idsbench.feasibility.conformal import fused_score, split_calibration
from idsbench.feasibility.e2_lofo import _split_sets
from idsbench.feasibility.e3_crosspair import ALIASES

OUT = Path("results/econ")
DATASETS = ("cicids2017", "cicids2018")
SEEDS_FULL = tuple(range(10))
N_FLOWS_FULL = 1000
CAPS_FULL = (200_000, 10_000)   # (benign, per attack family); benign cal_thr >= 20k rows
CAPS_QUICK = (200_000, 5_000)
MIN_FAMILY_ROWS = 500
MIN_CAL_THR = 20_000
N_AUG = 2000
AUG_MULT = 5.0
DEFENDERS = ("xgb", "fusion", "iforest", "xgb_robustfeat", "xgb_adv")
SCORE_ATTACKERS = ("greedy", "strong", "transfer")


def _crc(s: str) -> int:
    return zlib.crc32(s.encode()) & 0xFFFF_FFFF


def _train_idx(sets: dict, fams, ben_tr: np.ndarray) -> np.ndarray:
    return np.concatenate([ben_tr] + [sets[f]["train"] for f in fams])


def augmentation_rows(score_fn, Xv: np.ndarray, sets: dict, fams, gi, seed: int,
                      n_max: int = N_AUG, mult: float = AUG_MULT):
    """Mutated copies of up to n_max train attack flows per family in ``fams`` (score-mode greedy at the
    full budget). Only the families in ``fams`` are ever read, so a held-out family cannot enter.
    Returns (mutated rows, source family of each row)."""
    rng = np.random.default_rng([seed, 1717])
    Xs, src = [], []
    for f in fams:
        idx = sets[f]["train"]
        take = np.sort(rng.choice(idx, size=min(n_max, len(idx)), replace=False))
        _, Xm = attack_path(score_fn, Xv[take], gi, GROUPS, mult, "score")
        Xs.append(Xm)
        src += [f] * len(take)
    if not Xs:
        return np.empty((0, Xv.shape[1])), np.array([], dtype=object)
    return np.vstack(Xs), np.array(src, dtype=object)


def fit_adversarial(Xv, y, sets: dict, fams, base, gi, seed: int):
    """xgb retrained once on the known training rows of ``fams`` plus their mutated attack copies."""
    idx = _train_idx(sets, fams, sets[BENIGN]["train"])
    Xa, _ = augmentation_rows(lambda Z: xgb_margin(base, Z), Xv, sets, fams, gi, seed)
    X_tr = np.vstack([Xv[idx], Xa])
    y_tr = np.r_[y[idx], np.ones(len(Xa), dtype=int)]
    return xgb_binary(seed).fit(X_tr, y_tr)


def _scores_and_thresholds(fns: dict, Xv, iso_all, cal_full, cal_ref, cal_thr):
    """All-row scores per defender, the fusion references, and the (threshold, attainable) table."""
    S = {m: (iso_all if m == "iforest" else fns[m](Xv)) for m in ("xgb", "xgb_robustfeat",
                                                                    "xgb_adv", "iforest")}
    refs = [S["xgb"][cal_ref], iso_all[cal_ref]]
    S["fusion"] = fused_score(refs, [S["xgb"], iso_all])
    cal = {m: S[m][cal_full] for m in ("xgb", "xgb_robustfeat", "xgb_adv", "iforest")}
    cal["fusion"] = fused_score(refs, [S["xgb"][cal_thr], iso_all[cal_thr]])
    thr = {m: {f: threshold_at_fpr(cal[m], f) for f in FPRS} for m in DEFENDERS}
    return S, thr, refs


def _auc(benign_s, attack_s) -> float:
    return float(roc_auc_score(np.r_[np.zeros(len(benign_s)), np.ones(len(attack_s))],
                               np.r_[benign_s, attack_s]))


def run_dataset_seed(name: str, seed: int, caps: tuple[int, int], n_flows: int):
    """Detection rows (reuse, novel), AUROC rows, E4 mutation rows, the group index and the identity rates."""
    X, y, fam_s, _ = load_binary(name, cap_benign=caps[0], cap_per_family=caps[1], seed=seed)
    fam = fam_s.to_numpy()
    sets, fams = _split_sets(fam, seed, MIN_FAMILY_ROWS)
    Xv = X.to_numpy(dtype=float)
    gi = build_group_index(X.columns, ALIASES.get(name))
    ridx = gi.robust_idx()
    cal_full = sets[BENIGN]["cal"]
    cal_ref, cal_thr = split_calibration(cal_full, seed)
    if len(cal_thr) < MIN_CAL_THR:
        raise ValueError(f"{name} seed {seed}: fusion threshold set has {len(cal_thr)} < {MIN_CAL_THR} rows")
    ben_tr, bt = sets[BENIGN]["train"], sets[BENIGN]["test"]
    ben_te_ok = (len(np.intersect1d(bt, cal_full)) == 0 and len(np.intersect1d(bt, ben_tr)) == 0)
    if not ben_te_ok:
        raise RuntimeError(f"{name} seed {seed}: benign test rows overlap calibration or training")
    iso = IsolationForest(n_estimators=200, random_state=seed).fit(Xv[ben_tr])
    iso_all = iforest_score(iso, Xv)

    def fit_fns(fs):
        idx = _train_idx(sets, fs, ben_tr)
        xg = xgb_binary(seed).fit(Xv[idx], y[idx])
        rb = xgb_binary(seed).fit(Xv[idx][:, ridx], y[idx])
        ad = fit_adversarial(Xv, y, sets, fs, xg, gi, seed)
        fns = {
            "xgb": lambda Z, m=xg: xgb_margin(m, Z),
            "xgb_robustfeat": lambda Z, m=rb: xgb_margin(m, Z[:, ridx]),
            "xgb_adv": lambda Z, m=ad: xgb_margin(m, Z),
            "iforest": lambda Z: iforest_score(iso, Z),
        }
        return fns

    def with_fusion(fns, refs):
        fns = dict(fns)
        fns["fusion"] = lambda Z, r=refs, xf=fns["xgb"]: fused_score(
            r, [xf(Z), iforest_score(iso, Z)])
        return fns

    det, ref_rows, mut_rows = [], [], []

    def det_row(model, fpr, action, f, n, rec, fr):
        return {"dataset": name, "seed": seed, "model": model, "fpr": fpr, "action": action,
                "family": f, "n_test": int(n), "recall": float(rec), "fpr_realized": float(fr),
                "source": "measured"}

    # Known scenario: every family's train part.
    fns_k = fit_fns(fams)
    S_K, thr_K, refs_K = _scores_and_thresholds(fns_k, Xv, iso_all, cal_full, cal_ref, cal_thr)
    fns_k = with_fusion(fns_k, refs_K)
    for m in DEFENDERS:
        for fpr in FPRS:
            if not thr_K[m][fpr][1]:
                raise RuntimeError(f"{name} seed {seed}: {m} at FPR {fpr:g} is not attainable")
    real = {(m, fpr): float(np.mean(S_K[m][bt] > thr_K[m][fpr][0])) for m in DEFENDERS for fpr in FPRS}
    for f in fams:
        ft = sets[f]["test"]
        for m in DEFENDERS:
            ref_rows.append({"dataset": name, "seed": seed, "model": m, "family": f,
                             "auroc": _auc(S_K[m][bt], S_K[m][ft]), "n_benign_test": len(bt),
                             "n_family_test": len(ft)})
            for fpr in FPRS:
                t, _ = thr_K[m][fpr]
                rec = float(np.mean(S_K[m][ft] > t))
                det.append(det_row(m, fpr, f"reuse({f})", f, len(ft), rec, real[(m, fpr)]))

    # Leave-one-family-out: novel(f) from the scenario without f (xgb, robustfeat, adv, fusion).
    for f in fams:
        ft = sets[f]["test"]
        others = [g for g in fams if g != f]
        fns_u = fit_fns(others)
        S_U, thr_U, _ = _scores_and_thresholds(fns_u, Xv, iso_all, cal_full, cal_ref, cal_thr)
        for m in DEFENDERS:
            for fpr in FPRS:
                if m == "iforest":
                    rec = float(np.mean(S_K[m][ft] > thr_K[m][fpr][0]))   # one-class: novel = reuse
                else:
                    t, ok = thr_U[m][fpr]
                    if not ok:
                        raise RuntimeError(f"{name} seed {seed}: unseen {m} at FPR {fpr:g} unattainable")
                    rec = float(np.mean(S_U[m][ft] > t))
                det.append(det_row(m, fpr, f"novel({f})", f, len(ft), rec, real[(m, fpr)]))

    # E4: attacker mutates attack test flows against each known defender.
    rates = identity_hold_rates(Xv, gi)
    for f in fams:
        ft = sets[f]["test"]
        rng = np.random.default_rng([seed, _crc(f)])
        idx = np.sort(rng.choice(ft, size=min(n_flows, len(ft)), replace=False))
        Xf = Xv[idx]
        for groups, mult in budgets():
            bl = budget_label(groups, mult)
            strong = {}
            for m in DEFENDERS:
                srng = np.random.default_rng([seed, _crc(f), _crc(bl), _crc("strong"), _crc(m)])
                strong[m] = strong_attack(fns_k[m], Xf, gi, groups, mult, srng)
            X_src = strong["xgb"][1]
            for m in DEFENDERS:
                fn = fns_k[m]
                before = S_K[m][idx]
                greedy = score_path(fn, Xf, gi, groups, mult, "score")
                lrng = np.random.default_rng([seed, _crc(f), _crc(bl), _crc("label")])
                label = score_path(fn, Xf, gi, groups, mult, "label", lrng)
                transfer = fn(X_src) if m != "xgb" else None
                for fpr in FPRS:
                    t, ok = thr_K[m][fpr]
                    base = {"dataset": name, "seed": seed, "model": m, "fpr": fpr, "family": f,
                            "n_groups": len(groups), "groups": "+".join(groups), "multiplier": mult,
                            "recall_before": float(np.mean(before > t))}
                    mut_rows.append({**base, "query_mode": "score", "attacker": "greedy",
                                     "recall_after": recall_at(greedy, t, ok)})
                    mut_rows.append({**base, "query_mode": "score", "attacker": "strong",
                                     "recall_after": recall_from_scores(strong[m][0], t, ok)})
                    if transfer is not None:
                        mut_rows.append({**base, "query_mode": "score", "attacker": "transfer",
                                         "recall_after": recall_from_scores(transfer, t, ok)})
                    mut_rows.append({**base, "query_mode": "label", "attacker": "label",
                                     "recall_after": recall_at(label, t, ok)})
    return det, ref_rows, mut_rows, gi, rates


MUT_COLS = ["dataset", "seed", "model", "fpr", "family", "n_groups", "groups", "multiplier",
            "query_mode", "attacker", "recall_after", "recall_before"]
DET_COLS = ["dataset", "seed", "model", "fpr", "action", "family", "n_test", "recall", "fpr_realized", "source"]
REF_COLS = ["dataset", "seed", "model", "family", "auroc", "n_benign_test", "n_family_test"]


def _run_dataset(args):
    """All seeds of one dataset (one worker process per dataset)."""
    name, seeds, n_flows, caps = args
    det_all, ref_all, mut_all, rates_all, gi_last = [], [], [], None, None
    for seed in seeds:
        t0 = time.time()
        d, r, m, gi, rates = run_dataset_seed(name, seed, caps, n_flows)
        det_all += d
        ref_all += r
        mut_all += m
        gi_last = gi
        if seed == seeds[0]:
            rates_all = rates
        print(f"[E4] {name} seed={seed} secs={time.time() - t0:.0f}", flush=True)
    return name, det_all, ref_all, mut_all, gi_last, rates_all


def run_e4(out_dir: Path, seeds=SEEDS_FULL, n_flows: int = N_FLOWS_FULL,
           caps: tuple[int, int] = CAPS_FULL, datasets=DATASETS, workers: int = 1):
    """Writes e4_mutation.csv, e4_reference.csv (AUROC), detection_tables.csv and e4_feature_groups.md.

    Datasets run one after another by default (``workers=1``): XGBoost already uses all cores, and two
    processes on a 4-core machine slowed each seed about 12-fold through thread oversubscription.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(name, tuple(seeds), n_flows, caps) for name in datasets]
    if workers > 1 and len(jobs) > 1:
        with mp.get_context("fork").Pool(min(workers, len(jobs))) as pool:
            results = pool.map(_run_dataset, jobs, chunksize=1)
    else:
        results = [_run_dataset(j) for j in jobs]
    det_all, ref_all, mut_all, indexes, rates_all = [], [], [], {}, {}
    for name, d, r, m, gi, rates in results:
        det_all += d
        ref_all += r
        mut_all += m
        indexes[name] = gi
        rates_all[name] = rates
    mut = pd.DataFrame(mut_all)[MUT_COLS]
    mut.to_csv(out_dir / "e4_mutation.csv", index=False)
    pd.DataFrame(ref_all)[REF_COLS].to_csv(out_dir / "e4_reference.csv", index=False)
    det = pd.DataFrame(det_all)[DET_COLS]
    det.to_csv(out_dir / "detection_tables.csv", index=False)
    write_feature_log(out_dir / "e4_feature_groups.md", indexes, rates_all)
    return mut, det


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m idsbench.econ.measure")
    ap.add_argument("--quick", action="store_true", help="1 seed, 300 flows per family")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    out = Path(args.out) if args.out else (OUT / "quick" if args.quick else OUT)
    run_e4(out, seeds=(0,) if args.quick else SEEDS_FULL, n_flows=300 if args.quick else N_FLOWS_FULL,
           caps=CAPS_QUICK if args.quick else CAPS_FULL)


if __name__ == "__main__":
    main()
