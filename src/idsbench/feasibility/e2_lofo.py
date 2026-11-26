"""E2: leave-one-family-out. Can a detector trained without family f flag f?

Per seed (the seed drives the per-family subsampling, the splits and the models). Benign rows:
60% train / 20% calibration / 20% test. Attack families with >= 500 rows: 70% train / 30% test.
For each family f the unseen model is trained on benign train + the other families' train parts
(f excluded); the known model on all families' train parts. Scores (higher = more anomalous):
  xgb    = XGBoost margin (log-odds) of the unseen model;
  iso    = -score_samples of an IsolationForest fitted on benign train only;
  fusion = -min(p_xgb, p_iso), Bonferroni-style, with conformal p-values.

Calibration sets. The benign calibration rows are split at random into two disjoint halves:
  cal_ref: reference set of every conformal p-value (both models and the fusion);
  cal_thr: the threshold set. Single-model thresholds come from the full calibration set (their
           scores are not p-values); the fusion threshold is set on the fused scores of cal_thr,
           which are computed against cal_ref. Thresholds at FPR in {1e-2, 1e-3, 1e-4}; attainability
           is reported.
Conformal + BH over the pooled test set (benign test + known test + family-f test) at alpha in
{0.01, 0.1}: realised FDR, power on f, power on known. Fusion p-value = min(1, 2 min(p_xgb, p_iso)).
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

from idsbench.feasibility.common import (
    BENIGN, DATASET_LOADERS, iforest_score, load_binary, mean_std, threshold_at_fpr, xgb_binary,
    xgb_margin,
)
from idsbench.feasibility.conformal import (
    benjamini_hochberg, conformal_pvalues, fused_score, split_calibration,
)

OUT = Path("results/feasibility")
SEEDS_FULL = (0, 1, 2)
CAPS_FULL = (50_000, 10_000)   # (benign, per attack family)
CAPS_QUICK = (20_000, 5_000)
FPRS = (1e-2, 1e-3, 1e-4)
ALPHAS = (0.01, 0.1)
MODELS = ("xgb", "iso", "fusion")


def _split_sets(fam: np.ndarray, seed: int, min_family_rows: int) -> tuple[dict, list[str]]:
    rng = np.random.default_rng(seed)
    sets: dict[str, dict[str, np.ndarray]] = {}
    ben = rng.permutation(np.flatnonzero(fam == BENIGN))
    n = len(ben)
    sets[BENIGN] = {"train": ben[: int(0.6 * n)], "cal": ben[int(0.6 * n): int(0.8 * n)],
                    "test": ben[int(0.8 * n):]}
    fams = []
    for f in pd.unique(fam):
        if f == BENIGN:
            continue
        idx = np.flatnonzero(fam == f)
        if len(idx) < min_family_rows:
            continue
        idx = rng.permutation(idx)
        cut = int(0.7 * len(idx))
        sets[f] = {"train": idx[:cut], "test": idx[cut:]}
        fams.append(f)
    return sets, fams


def _recall_fpr_rows(base: dict, scores: dict, model: str, cal_scores: np.ndarray,
                     cal_source: str, auroc: float) -> list:
    rows = []
    for fpr in FPRS:
        thr, ok = threshold_at_fpr(cal_scores, fpr)
        rows.append({**base, "model": model, "fpr_target": fpr, "threshold_attainable": ok,
                     "n_threshold_cal": int(len(cal_scores)),
                     "realized_fpr_benign_test": float(np.mean(scores["bt"] > thr)) if ok else np.nan,
                     "recall_unseen": float(np.mean(scores["ft"] > thr)) if ok else np.nan,
                     "recall_known": float(np.mean(scores["kt"] > thr)) if ok else np.nan,
                     "auroc_unseen": auroc, "calibration_source": cal_source})
    return rows


def run_dataset(name: str, seeds: list[int], cap_benign: int, cap_per_family: int,
                min_family_rows: int = 500) -> tuple[list[dict], list[dict]]:
    rows, conf_rows = [], []
    for seed in seeds:
        t0 = time.time()
        X, y, fam_s, meta = load_binary(name, cap_benign=cap_benign, cap_per_family=cap_per_family,
                                        seed=seed)
        fam = fam_s.to_numpy()
        counts = pd.Series(fam[fam != BENIGN]).value_counts()
        if (counts >= min_family_rows).sum() < 3:
            raise ValueError(f"fewer than 3 attack families with >= {min_family_rows} rows")
        Xv = X.to_numpy()
        sets, fams = _split_sets(fam, seed, min_family_rows)
        cal_full = sets[BENIGN]["cal"]
        cal_ref, cal_thr = split_calibration(cal_full, seed)
        ben_tr = sets[BENIGN]["train"]
        bt = sets[BENIGN]["test"]
        iso = IsolationForest(n_estimators=200, random_state=seed).fit(Xv[ben_tr])
        iso_all = iforest_score(iso, Xv)
        known_idx = np.concatenate([ben_tr] + [sets[f]["train"] for f in fams])
        known_model = xgb_binary(seed).fit(Xv[known_idx], y[known_idx])
        known_all = xgb_margin(known_model, Xv)
        for f in fams:
            unseen_idx = np.concatenate([ben_tr] + [sets[g]["train"] for g in fams if g != f])
            unseen_model = xgb_binary(seed).fit(Xv[unseen_idx], y[unseen_idx])
            xgb_all = xgb_margin(unseen_model, Xv)
            kt = np.concatenate([sets[g]["test"] for g in fams if g != f])
            ft = sets[f]["test"]
            base = {"dataset": name, "seed": seed, "family": f, "n_unseen_test": len(ft),
                    "n_known_test": len(kt), "n_benign_test": len(bt), "n_benign_cal": len(cal_full),
                    "n_benign_cal_ref": len(cal_ref), "n_benign_cal_thr": len(cal_thr),
                    "dup_frac": meta["dup_frac"], "conflict_frac": meta["conflict_frac"]}
            arrays = {"xgb": xgb_all, "iso": iso_all}
            qidx = {"bt": bt, "kt": kt, "ft": ft}
            S = {m: {"bt": a[bt], "kt": a[kt], "ft": a[ft]} for m, a in arrays.items()}
            S["xgb"]["cal"] = xgb_all[cal_full]
            S["iso"]["cal"] = iso_all[cal_full]
            # Fusion: references = cal_ref; threshold set = cal_thr; query rows never in either.
            refs = [xgb_all[cal_ref], iso_all[cal_ref]]
            S["fusion"] = {"cal": fused_score(refs, [xgb_all[cal_thr], iso_all[cal_thr]])}
            for k, idx in qidx.items():
                S["fusion"][k] = fused_score(refs, [xgb_all[idx], iso_all[idx]])
            for model in MODELS:
                auc_f = roc_auc_score(np.r_[np.zeros(len(bt)), np.ones(len(ft))],
                                      np.r_[S[model]["bt"], S[model]["ft"]])
                src = "benign_cal_thr_fused" if model == "fusion" else "benign_cal"
                rows += _recall_fpr_rows(base, S[model], f"{model}_unseen", S[model]["cal"],
                                         src, auc_f)
            # Known scenario: xgb with f included, same splits and the full benign calibration set.
            Sk = {"bt": known_all[bt], "kt": known_all[kt], "ft": known_all[ft]}
            Sk_cal = known_all[cal_full]
            auc_k = roc_auc_score(np.r_[np.zeros(len(bt)), np.ones(len(ft))],
                                  np.r_[Sk["bt"], Sk["ft"]])
            rows += _recall_fpr_rows(base, Sk, "xgb_known", Sk_cal, "benign_cal", auc_k)
            # Conformal + BH on the pooled test set; all conformal p-values use cal_ref.
            pool_idx = np.concatenate([bt, kt, ft])
            is_attack = np.r_[np.zeros(len(bt), bool), np.ones(len(kt) + len(ft), bool)]
            is_f = np.r_[np.zeros(len(bt) + len(kt), bool), np.ones(len(ft), bool)]
            is_known = np.r_[np.zeros(len(bt), bool), np.ones(len(kt), bool), np.zeros(len(ft), bool)]
            p_xgb = conformal_pvalues(arrays["xgb"][cal_ref], arrays["xgb"][pool_idx])
            p_iso = conformal_pvalues(arrays["iso"][cal_ref], arrays["iso"][pool_idx])
            pv = {"xgb": p_xgb, "fusion": np.minimum(1.0, 2 * np.minimum(p_xgb, p_iso))}
            for model, p in pv.items():
                for alpha in ALPHAS:
                    rej = benjamini_hochberg(p, alpha)
                    n_rej = max(int(rej.sum()), 1)
                    conf_rows.append({**base, "model": model, "alpha": alpha,
                                      "fdr_realized": float((rej & ~is_attack).sum() / n_rej),
                                      "power_unseen": float(rej[is_f].mean()),
                                      "power_known": float(rej[is_known].mean())})
        print(f"[E2] {name} seed={seed} families={fams} secs={time.time() - t0:.0f}", flush=True)
    return rows, conf_rows


def write_markdown(df: pd.DataFrame, conf: pd.DataFrame, path: Path) -> str:
    out = ["# E2 leave-one-family-out (recall at FPR 1e-3)\n"]
    for name, g in df[df.fpr_target == 1e-3].groupby("dataset", sort=False):
        lines = [f"## {name}", "",
                 "| family | XGB recall unseen | XGB recall when known | IForest recall | "
                 "fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |",
                 "|---|---|---|---|---|---|---|"]

        def pick(model, col):
            return g[(g.family == f) & (g.model == model)][col]

        for f in pd.unique(g.family):
            lines.append(
                f"| {f} | {mean_std(pick('xgb_unseen', 'recall_unseen'), 3)} | "
                f"{mean_std(pick('xgb_known', 'recall_unseen'), 3)} | "
                f"{mean_std(pick('iso_unseen', 'recall_unseen'), 3)} | "
                f"{mean_std(pick('fusion_unseen', 'recall_unseen'), 3)} | "
                f"{mean_std(pick('xgb_unseen', 'auroc_unseen'), 3)} | "
                f"{mean_std(pick('iso_unseen', 'auroc_unseen'), 3)} |")
        out += lines + [""]
    out += ["## Realised FPR on benign test at target 1e-3 (unseen-model thresholds)", "",
            "| dataset | family | XGB | IForest | fusion (calibrated on cal_thr) |", "|---|---|---|---|---|"]
    g3 = df[df.fpr_target == 1e-3]
    for (d, f), h in g3.groupby(["dataset", "family"], sort=False):
        cells = [mean_std(h[h.model == m].realized_fpr_benign_test, 5)
                 for m in ("xgb_unseen", "iso_unseen", "fusion_unseen")]
        out.append(f"| {d} | {f} | " + " | ".join(cells) + " |")
    if len(conf):
        out += ["", "## Conformal + BH on the pooled test set (mean over seeds)", "",
                "| dataset | family | model | alpha | realized FDR | power unseen | power known |",
                "|---|---|---|---|---|---|---|"]
        agg = conf.groupby(["dataset", "family", "model", "alpha"], sort=False).agg(
            fdr=("fdr_realized", "mean"), pu=("power_unseen", "mean"), pk=("power_known", "mean"))
        for (d, f, m, a), r in agg.iterrows():
            out.append(f"| {d} | {f} | {m} | {a} | {r.fdr:.4f} | {r.pu:.3f} | {r.pk:.3f} |")
    md = "\n".join(out) + "\n"
    path.write_text(md)
    return md


def main(argv: list[str] | None = None) -> tuple[pd.DataFrame, dict]:
    ap = argparse.ArgumentParser(prog="python -m idsbench.feasibility.e2_lofo")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    seeds = [0] if args.quick else list(SEEDS_FULL)
    cap_b, cap_f = CAPS_QUICK if args.quick else CAPS_FULL
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows, conf, skipped = [], [], {}
    for name in DATASET_LOADERS:
        try:
            r, c = run_dataset(name, seeds, cap_b, cap_f)
            rows += r
            conf += c
        except Exception as e:
            skipped[name] = f"{type(e).__name__}: {e}"
            print(f"[E2] SKIP {name}: {skipped[name]}", flush=True)
    df, cdf = pd.DataFrame(rows), pd.DataFrame(conf)
    df.to_csv(out / "e2_lofo.csv", index=False)
    cdf.to_csv(out / "e2_lofo_conformal.csv", index=False)
    md = write_markdown(df, cdf, out / "e2_lofo.md") if len(df) else "(no datasets)\n"
    print(md, flush=True)
    return df, skipped


if __name__ == "__main__":
    main()
