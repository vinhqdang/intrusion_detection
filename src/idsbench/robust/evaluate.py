"""Per (dataset, seed) evaluation of the robustness design (section 5).

run_seed returns plain row lists (written by run_all) and raw L-inf distances:
  thr      one row per (model, FPR): threshold, plateau flag, realised calibration and test FPR;
  clean    known-scenario recall per family and LOFO (novel) recall, AUROC on known families;
  e4       recall after greedy / strong / transfer attacks, per generator, budget and FPR;
  mutben   mutated-benign FPR: random budgets, and every fixed budget on a benign subsample;
  ident    identity hold rates of the recomputed features on the original and on fully mutated flows;
  dist     L-inf distances of the strong-attack states (against xgb) in signed-log standardised space.
"""

from __future__ import annotations

import math
import time
import zlib

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from idsbench.econ.mutation import (
    attack_path, apply_group, build_group_index, identity_hold_rates, recall_at, recall_from_scores,
    strong_attack,
)
from idsbench.feasibility.common import BENIGN, iforest_score, load_binary, threshold_at_fpr, xgb_margin
from idsbench.feasibility.conformal import fused_score, split_calibration
from idsbench.feasibility.e2_lofo import _split_sets
from idsbench.feasibility.e3_crosspair import ALIASES

from .defenders import E4_MODELS, MODELS, fit_known, fixed_budget_mutate, random_budget_mutate, robust_columns
from .gen2 import BUDGETS, G2, TOUCHED, flow_uniform

FPRS = (1e-4, 5e-4, 1e-3, 1e-2)
MIN_FAMILY_ROWS = 500
MIN_CAL_THR = 10_000     # 1e-4 must be attainable on the fusion threshold set
ATTACKER_MIN_TEST = 300
ATTACKERS = ("greedy", "strong", "transfer")
N_FIXED_BENIGN = 30_000


def _crc(s: str) -> int:
    return zlib.crc32(s.encode()) & 0xFFFF_FFFF


def budget_label(groups, mult) -> str:
    return "+".join(groups) + f",x{mult:g}"


def budget_units(groups, mult) -> float:
    return len(groups) * math.log2(2.0 * mult)


def plateau_threshold(cal: np.ndarray, fpr: float):
    """(threshold, attainable, realised calibration FPR, plateau moved).

    Split-conformal threshold; when more than 0.5 fpr n calibration scores tie at it, the threshold moves to the
    next distinct score above (alerts are scores strictly above the threshold).
    """
    t, ok = threshold_at_fpr(cal, fpr)
    if not ok:
        return float("inf"), False, float("nan"), False
    n = len(cal)
    plateau = bool(np.count_nonzero(cal == t) > 0.5 * fpr * n)
    if plateau:
        above = cal[cal > t]
        t = float(above.min()) if above.size else float("inf")
    return float(t), True, float(np.mean(cal > t)), plateau


def matched_threshold(cal: np.ndarray, k_target: int):
    """(threshold, alerts): the threshold whose number of calibration scores strictly above it is closest to k_target.
    Candidates are the distinct scores and +inf (no alerts). Ties go to the lower threshold (more alerts)."""
    a = np.sort(np.asarray(cal, dtype=float))
    u = np.unique(a)
    cnt = len(a) - np.searchsorted(a, u, side="right")
    u = np.append(u, np.inf)
    cnt = np.append(cnt, 0)
    j = int(np.argmin(np.abs(cnt - k_target)))
    return float(u[j]), int(cnt[j])


def wilson(k: float, n: float, z: float = 1.959964):
    if n <= 0:
        return float("nan"), float("nan")
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return c - h, c + h


def signed_log(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


def linf_z(X0: np.ndarray, X1: np.ndarray, sd: np.ndarray) -> np.ndarray:
    """max over features of |z(x1) - z(x0)| / sd, z = sign(x) log1p(|x|). The train mean of z cancels in the
    difference, so only the train standard deviation enters."""
    return np.max(np.abs(signed_log(X1) - signed_log(X0)) / sd, axis=1)


def run_seed(name: str, seed: int, cfg, log=print) -> dict:
    t0 = time.time()
    X, y, fam_s, _ = load_binary(name, cap_benign=cfg.benign_cap, cap_per_family=cfg.family_cap, seed=seed)
    fam = fam_s.to_numpy()
    sets, fams = _split_sets(fam, seed, MIN_FAMILY_ROWS)
    Xv = X.to_numpy(dtype=float)
    al = ALIASES.get(name)
    gi = build_group_index(X.columns, al)
    g2 = G2(X.columns, al)
    apply1 = lambda Z, g, lv: apply_group(Z, gi, g, lv)
    gens = (("G1", apply1), ("G2", g2.apply))
    ridx = robust_columns(gi, TOUCHED)
    ctx = {"ridx": ridx, "apply1": apply1, "apply2": g2.apply, "n_aug": cfg.n_aug}

    cal_full = sets[BENIGN]["cal"]
    cal_ref, cal_thr = split_calibration(cal_full, seed)
    if len(cal_thr) < MIN_CAL_THR:
        raise ValueError(f"{name} seed {seed}: fusion threshold set {len(cal_thr)} < {MIN_CAL_THR}")
    ben_tr, bt = sets[BENIGN]["train"], sets[BENIGN]["test"]
    if len(np.intersect1d(bt, cal_full)) or len(np.intersect1d(bt, ben_tr)):
        raise RuntimeError("benign test overlaps calibration or training")
    iso = IsolationForest(n_estimators=200, random_state=seed).fit(Xv[ben_tr])
    iso_all = iforest_score(iso, Xv)
    log(f"[robust] {name} seed={seed} data+iforest {time.time() - t0:.0f}s rows={len(Xv)} families={len(fams)}")

    def with_fusion(fns, refs):
        fns = dict(fns)
        fns["iforest"] = lambda Z: iforest_score(iso, Z)
        fns["fusion"] = lambda Z, r=refs, xf=fns["xgb"]: fused_score(r, [xf(Z), iforest_score(iso, Z)])
        return fns

    train_all = np.concatenate([sets[BENIGN]["train"]] + [sets[f]["train"] for f in fams])
    rng_sd = np.random.default_rng([seed, 4242])
    sub_tr = rng_sd.choice(train_all, size=min(100_000, len(train_all)), replace=False)
    sd_z = signed_log(Xv[sub_tr]).std(axis=0)
    sd_z = np.where(sd_z > 0, sd_z, 1.0)
    rows = {k: [] for k in ("thr", "clean", "e4", "mutben", "ident", "rq2")}
    dist: dict = {}

    # ---------------------------------------------------------------- known scenario
    fns_k = fit_known(Xv, y, sets, fams, seed, ctx, which=MODELS)
    refs_k = [fns_k["xgb"](Xv[cal_ref]), iso_all[cal_ref]]
    fns_k = with_fusion(fns_k, refs_k)
    log(f"[robust] {name} seed={seed} known models {time.time() - t0:.0f}s")
    S = {m: (iso_all if m == "iforest" else fns_k[m](Xv)) for m in MODELS}
    cal_scores = {m: S[m][cal_full] for m in MODELS if m != "fusion"}
    cal_scores["fusion"] = fused_score(refs_k, [S["xgb"][cal_thr], iso_all[cal_thr]])
    thr = {}
    for m in MODELS:
        thr[m] = {}
        cs = cal_scores[m]
        for fpr in FPRS:
            t, ok, rc, pl = plateau_threshold(cs, fpr)
            if not ok:
                raise RuntimeError(f"{name} seed {seed}: {m} at FPR {fpr:g} not attainable")
            k_test = float(np.sum(S[m][bt] > t))
            lo, hi = wilson(k_test, len(bt))
            thr[m][fpr] = t
            rows["thr"].append({"dataset": name, "seed": seed, "model": m, "fpr": fpr, "threshold": t,
                                "fpr_cal_realised": rc, "plateau_moved": pl, "fpr_test_realised": k_test / len(bt),
                                "fpr_test_ci_lo": lo, "fpr_test_ci_hi": hi,
                                "k_test_alerts": k_test, "n_benign_test": len(bt),
                                "n_benign_cal_thr_set": len(cal_thr) if m == "fusion" else len(cal_full)})

    # ---------------------------------------------------------------- RQ2: xgb at xgb_robust's realised calibration FPR
    # xgb_robust's plateau-aware threshold realises k/n calibration alerts on cal_full (the set both non-fusion
    # thresholds are fitted on). xgb's threshold is set to alert on as close to the same number of calibration flows
    # as the distinct scores allow. Both are scored on the known-family test flows (macro over families).
    def macro_recall(model, t):
        return float(np.mean([np.mean(S[model][sets[f]["test"]] > t) for f in fams]))

    for fpr in FPRS:
        t_ref = thr["xgb_robust"][fpr]
        k_ref = int(np.sum(S["xgb_robust"][cal_full] > t_ref))
        t_x, k_x = matched_threshold(S["xgb"][cal_full], k_ref)
        k_test_x = int(np.sum(S["xgb"][bt] > t_x))
        k_test_ref = int(np.sum(S["xgb_robust"][bt] > t_ref))
        rows["rq2"].append({
            "dataset": name, "seed": seed, "fpr": fpr, "n_cal": len(cal_full), "n_benign_test": len(bt),
            "k_cal_ref": k_ref, "fpr_cal_ref": k_ref / len(cal_full),
            "k_cal_xgb": k_x, "fpr_cal_xgb": k_x / len(cal_full), "matched_exact": k_x == k_ref,
            "k_test_ref": k_test_ref, "fpr_test_ref": k_test_ref / len(bt),
            "k_test_xgb": k_test_x, "fpr_test_xgb": k_test_x / len(bt),
            "recall_ref": macro_recall("xgb_robust", t_ref), "recall_xgb_matched": macro_recall("xgb", t_x),
            "recall_xgb_nominal": macro_recall("xgb", thr["xgb"][fpr]),
        })
    log(f"[robust] {name} seed={seed} RQ2 matched {time.time() - t0:.0f}s")


    for f in fams:
        ft = sets[f]["test"]
        for m in MODELS:
            auc = float(roc_auc_score(np.r_[np.zeros(len(bt)), np.ones(len(ft))], np.r_[S[m][bt], S[m][ft]]))
            for fpr in FPRS:
                rows["clean"].append({"dataset": name, "seed": seed, "model": m, "fpr": fpr, "family": f,
                                      "kind": "known", "recall": float(np.mean(S[m][ft] > thr[m][fpr])),
                                      "n_family_test": len(ft), "auroc": auc})
    log(f"[robust] {name} seed={seed} known clean {time.time() - t0:.0f}s")

    # ---------------------------------------------------------------- leave-one-family-out (novel action)
    for f in fams:
        ft = sets[f]["test"]
        others = [g for g in fams if g != f]
        fns_u = fit_known(Xv, y, sets, others, seed, ctx, which=cfg.lofo_models)
        refs_u = [fns_u["xgb"](Xv[cal_ref]), iso_all[cal_ref]]
        fns_u = with_fusion(fns_u, refs_u)
        for m in MODELS:
            if m == "iforest":
                rec = {fpr: float(np.mean(S[m][ft] > thr[m][fpr])) for fpr in FPRS}     # one-class: novel = reuse
            elif m in cfg.lofo_models:
                if m == "fusion":
                    sc_c = fused_score(refs_u, [fns_u["xgb"](Xv[cal_thr]), iso_all[cal_thr]])
                    sc_f = fns_u["fusion"](Xv[ft])
                else:
                    sc_c = fns_u[m](Xv[cal_full])
                    sc_f = fns_u[m](Xv[ft])
                rec = {}
                for fpr in FPRS:
                    t, ok, _, _ = plateau_threshold(sc_c, fpr)
                    if not ok:
                        raise RuntimeError(f"unseen {m} at FPR {fpr:g} not attainable")
                    rec[fpr] = float(np.mean(sc_f > t))
            else:
                continue
            for fpr in FPRS:
                rows["clean"].append({"dataset": name, "seed": seed, "model": m, "fpr": fpr, "family": f,
                                      "kind": "novel", "recall": rec[fpr], "n_family_test": len(ft),
                                      "auroc": float("nan")})
    log(f"[robust] {name} seed={seed} LOFO {time.time() - t0:.0f}s")

    # ---------------------------------------------------------------- E4: attacks on known models
    rows_e4 = rows["e4"]
    for f in fams:
        ft = sets[f]["test"]
        rng = np.random.default_rng([seed, _crc(f)])
        idx = np.sort(rng.choice(ft, size=min(cfg.n_flows, len(ft)), replace=False))
        Xf = Xv[idx]
        for gname, ap in gens:
            for groups, mult in BUDGETS:
                bl = budget_label(groups, mult)
                strong = {}
                for m in E4_MODELS:
                    srng = np.random.default_rng([seed, _crc(f), _crc(bl), _crc(gname), _crc("strong"), _crc(m)])
                    strong[m] = strong_attack(fns_k[m], Xf, None, groups, mult, srng, apply=ap)
                X_src = strong["xgb"][1]
                key = (gname, mult, "+".join(groups))
                d = linf_z(Xf, X_src, sd_z)
                dist.setdefault(key, []).append(d)
                for m in E4_MODELS:
                    path, Xg = attack_path(fns_k[m], Xf, None, groups, mult, "score", apply=ap)
                    transfer = fns_k[m](X_src) if m != "xgb" else None
                    for fpr in FPRS:
                        t = thr[m][fpr]
                        ok = True
                        base = {"dataset": name, "seed": seed, "model": m, "fpr": fpr, "family": f,
                                "generator": gname, "budget": bl, "groups": "+".join(groups),
                                "multiplier": mult, "units": budget_units(groups, mult), "n_flows": len(idx),
                                "recall_before": float(np.mean(S[m][idx] > t))}
                        rows_e4.append({**base, "attacker": "greedy", "recall_after": recall_at(path, t, ok)})
                        rows_e4.append({**base, "attacker": "strong",
                                        "recall_after": recall_from_scores(strong[m][0], t, ok)})
                        if transfer is not None:
                            rows_e4.append({**base, "attacker": "transfer",
                                            "recall_after": recall_from_scores(transfer, t, ok)})
        log(f"[robust] {name} seed={seed} E4 family={f} {time.time() - t0:.0f}s")

    # ---------------------------------------------------------------- mutated-benign FPR
    Xb = Xv[bt]
    Xfix = Xv[bt[:min(N_FIXED_BENIGN, len(bt))]]
    for gi_g, (gname, ap) in enumerate(gens):
        Yr = random_budget_mutate(ap, Xb, seed, tag=gi_g)
        for m in MODELS:
            sc = fns_k[m](Yr) if m != "iforest" else iforest_score(iso, Yr)
            for fpr in FPRS:
                rows["mutben"].append({"dataset": name, "seed": seed, "model": m, "fpr": fpr,
                                       "generator": gname, "mode": "random", "budget": "random",
                                       "groups": "", "multiplier": float("nan"),
                                       "fpr_mut": float(np.mean(sc > thr[m][fpr])), "n": len(Yr)})
        for groups, mult in BUDGETS:
            Yfx = fixed_budget_mutate(ap, Xfix, groups, mult)
            for m in MODELS:
                sc = fns_k[m](Yfx) if m != "iforest" else iforest_score(iso, Yfx)
                for fpr in FPRS:
                    rows["mutben"].append({"dataset": name, "seed": seed, "model": m, "fpr": fpr,
                                           "generator": gname, "mode": "fixed",
                                           "budget": budget_label(groups, mult), "groups": "+".join(groups),
                                           "multiplier": mult, "fpr_mut": float(np.mean(sc > thr[m][fpr])),
                                           "n": len(Yfx)})
    log(f"[robust] {name} seed={seed} mutated benign {time.time() - t0:.0f}s")

    # ---------------------------------------------------------------- identity hold rates
    samp = Xv[ben_tr[:5000]]
    for label, Z in (("original", samp),
                     ("G1 all groups x5", apply_budget_all(apply1, samp)),
                     ("G2 all groups x5", apply_budget_all(g2.apply, samp))):
        for rule, v in identity_hold_rates(Z, gi).items():
            rows["ident"].append({"dataset": name, "seed": seed, "sample": label, "rule": rule,
                                  "rows": v["rows"], "holds": v["holds"]})
    log(f"[robust] {name} seed={seed} done {time.time() - t0:.0f}s")
    return {"rows": rows, "dist": dist}


def apply_budget_all(apply, X):
    Y = np.asarray(X, dtype=float)
    for g in ("timing", "length", "count"):
        Y = apply(Y, g, 5.0)
    return Y

