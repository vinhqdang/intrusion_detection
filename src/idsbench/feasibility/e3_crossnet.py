"""E3: cross-network transfer on the NetFlow shared schema (binary labels).

For each ordered pair (A -> B), including A -> A as the in-domain reference, and seed:
  * XGBoost (margin score) trained on 80% of A's train split; thresholds calibrated on the benign
    rows of the remaining 20% (A calibration);
  * evaluation on B's test split: AUROC, AUPRC, realised FPR on B benign at the A-calibrated
    thresholds (FPR targets 1e-2 and 1e-3), recall on B attacks;
  * conformal + BH at alpha = 0.1 over B's test pool with three p-value variants:
      - unweighted: A-calibration reference;
      - weighted (oracle): domain classifier A-benign-calibration vs B benign rows of a separate B
        split (uses B labels: an upper bound);
      - weighted (label-free): domain classifier A-benign-calibration vs B rows of a separate B split
        whose unweighted p-value (w.r.t. A calibration) is > 0.5 (presumed benign; no B labels).
    The B rows that fit a domain classifier are drawn from the B train split, which is disjoint from
    the B test rows that are evaluated.
Only features common to all loaded datasets are used; identifiers are already removed by the loader.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

from idsbench.feasibility.common import (
    NETFLOW_KEYS, e3_tables_md, load_binary, split_no_overlap, threshold_at_fpr,
    xgb_binary, xgb_margin,
)
from idsbench.feasibility.conformal import (
    benjamini_hochberg, conformal_pvalues, effective_sample_size, fit_domain_model,
    weighted_conformal_pvalues,
)

OUT = Path("results/feasibility")
FPRS = (1e-2, 1e-3)
SEEDS_FULL = (0, 1, 2)
CAPS_FULL = (300_000, 50_000)
CAPS_QUICK = (20_000, 5_000)
FIT_CAP = 50_000  # max rows used to fit each domain classifier


def _cap(idx: np.ndarray, cap: int, rng: np.random.Generator) -> np.ndarray:
    if len(idx) > cap:
        idx = rng.choice(idx, size=cap, replace=False)
    return np.sort(idx)


def _load_sets(names: list[str], cap_b: int, cap_f: int, seed: int) -> tuple[dict, dict]:
    sets, skipped = {}, {}
    for name in names:
        try:
            sets[name] = load_binary(name, cap_benign=cap_b, cap_per_family=cap_f, seed=seed)
        except Exception as e:
            skipped[name] = f"{type(e).__name__}: {e}"
    return sets, skipped


def run_pair(A: str, B: str, data: dict, cols: list[str], seed: int) -> dict:
    XA_df, yA, famA, _ = data[A]
    XB_df, yB, famB, _ = data[B]
    XA = XA_df[cols].to_numpy()
    XB = XB_df[cols].to_numpy()
    trA, _, _ = split_no_overlap(XA_df[cols], famA.to_numpy(), seed)
    fitA, calA = train_test_split(trA, test_size=0.2, random_state=seed, stratify=yA[trA])
    model = xgb_binary(seed).fit(XA[fitA], yA[fitA])
    cal_benign = calA[yA[calA] == 0]
    cal_scores = xgb_margin(model, XA[cal_benign])

    # B split: evaluated rows (teB) and disjoint train rows (trB) used only to fit domain classifiers.
    trB, teB, _ = split_no_overlap(XB_df[cols], famB.to_numpy(), seed)
    yBt = yB[teB]
    sB = xgb_margin(model, XB[teB])
    row = {"A": A, "B": B, "seed": seed, "n_A_cal_benign": int(len(cal_benign)),
           "n_B_test": int(len(teB)), "n_B_attack": int(yBt.sum()),
           "auroc": roc_auc_score(yBt, sB), "auprc": average_precision_score(yBt, sB)}
    bmask = yBt == 0
    for fpr in FPRS:
        thr, ok = threshold_at_fpr(cal_scores, fpr)
        row[f"thr_attainable_{fpr:g}"] = ok
        row[f"realized_fpr_B_{fpr:g}"] = float(np.mean(sB[bmask] > thr)) if ok else np.nan
        row[f"recall_B_{fpr:g}"] = float(np.mean(sB[~bmask] > thr)) if ok else np.nan

    # Domain-classifier candidates: B train rows (disjoint from teB). For A == B the A calibration
    # rows are excluded as well, so the classifier never sees the calibration rows it reweights.
    cand = trB
    if A == B:
        cand = cand[~np.isin(cand, calA)]
    rng = np.random.default_rng([seed, 29])
    oracle_idx = _cap(cand[yB[cand] == 0], FIT_CAP, rng)
    s_cand = xgb_margin(model, XB[cand])
    presumed = conformal_pvalues(cal_scores, s_cand) > 0.5
    labelfree_idx = _cap(cand[presumed], FIT_CAP, rng)
    if min(len(oracle_idx), len(labelfree_idx)) < 100:
        raise RuntimeError(f"{A}->{B}: too few rows to fit a domain classifier")
    row["n_fit_oracle"] = int(len(oracle_idx))
    row["n_fit_labelfree"] = int(len(labelfree_idx))
    row["labelfree_presumed_frac_of_B_train"] = float(presumed.mean())

    weights = {"unweighted": (np.ones(len(cal_scores)), np.ones(len(sB)))}
    for label, fit_idx in (("weighted_oracle", oracle_idx), ("weighted_labelfree", labelfree_idx)):
        wfn = fit_domain_model(XA[cal_benign], XB[fit_idx], seed)
        weights[label] = (wfn(XA[cal_benign]), wfn(XB[teB]))
    for label in ("unweighted", "weighted_oracle", "weighted_labelfree"):
        w_cal, w_B = weights[label]
        if label == "unweighted":
            p = conformal_pvalues(cal_scores, sB)
        else:
            p = weighted_conformal_pvalues(cal_scores, w_cal, sB, w_B)
        rej = benjamini_hochberg(p, alpha=0.1)
        row[f"conf_{label}_fdr"] = float((rej & bmask).sum() / max(rej.sum(), 1))
        row[f"conf_{label}_power"] = float(rej[~bmask].mean()) if (~bmask).any() else np.nan
        row[f"conf_{label}_n_rejected"] = int(rej.sum())
        row[f"w_{label}_mean_cal"] = float(w_cal.mean())
        row[f"w_{label}_mean_B"] = float(w_B.mean())
        row[f"w_{label}_ess_cal"] = effective_sample_size(w_cal)
    return row


def main(argv: list[str] | None = None) -> tuple[pd.DataFrame, dict]:
    ap = argparse.ArgumentParser(prog="python -m idsbench.feasibility.e3_crossnet")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    seeds = [0] if args.quick else list(SEEDS_FULL)
    cap_b, cap_f = CAPS_QUICK if args.quick else CAPS_FULL
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows, skipped_all = [], {}
    names, cols = [], []
    for seed in seeds:
        data, skipped = _load_sets(list(NETFLOW_KEYS), cap_b, cap_f, seed)
        skipped_all = skipped
        names = list(data)
        if not names:
            raise RuntimeError("no NetFlow dataset could be loaded")
        cols = sorted(set.intersection(*[set(data[n][0].columns) for n in names]))
        for A in names:
            for B in names:
                t0 = time.time()
                rows.append(run_pair(A, B, data, cols, seed))
                print(f"[E3] {A} -> {B} seed={seed} auroc={rows[-1]['auroc']:.4f} "
                      f"secs={time.time() - t0:.0f}", flush=True)
    df = pd.DataFrame(rows)
    df.to_csv(out / "e3_crossnet.csv", index=False)
    md = "# E3 cross-network\n\n" + e3_tables_md(df, names, len(cols), skipped_all)
    (out / "e3_crossnet.md").write_text(md)
    print(md, flush=True)
    return df, skipped_all


if __name__ == "__main__":
    main()
