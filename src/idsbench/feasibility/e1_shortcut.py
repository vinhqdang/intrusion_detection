"""E1: shortcut index. Is the benchmark saturated by one or two features?

Per dataset and seed (the seed drives the per-family subsampling and the split): XGBoost, best
single feature (by train AUROC, either sign), depth-1 and depth-2 decision trees, and per-family
best single feature (one-vs-benign, families with at least 100 test rows; the feature is chosen on
train rows and reported with its test AUROC).
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, balanced_accuracy_score, f1_score, roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from idsbench.feasibility.common import (
    BENIGN, DATASET_LOADERS, best_single_feature, load_binary, mean_std, split_no_overlap,
    xgb_binary, xgb_margin,
)

OUT = Path("results/feasibility")
SEEDS_FULL = (0, 1, 2)
CAPS_FULL = (300_000, 50_000)   # (benign, per attack family)
CAPS_QUICK = (20_000, 5_000)


def _single_feature_test_auc(Xte: np.ndarray, yte: np.ndarray, j: int, sign: int) -> float:
    return float(roc_auc_score(yte, sign * Xte[:, j]))


def run_dataset(name: str, seeds: list[int], cap_benign: int, cap_per_family: int,
                min_family_test: int = 100) -> list[dict]:
    rows = []
    for seed in seeds:
        t0 = time.time()
        X, y, fam_s, meta = load_binary(name, cap_benign=cap_benign, cap_per_family=cap_per_family,
                                        seed=seed)
        cols = list(X.columns)
        Xv = X.to_numpy()
        fam = fam_s.to_numpy()
        tr, te, n_overlap = split_no_overlap(X, fam, seed)
        Xtr, Xte, ytr, yte = Xv[tr], Xv[te], y[tr], y[te]
        base = {"dataset": name, "seed": seed, "n_rows": int(len(X)), "n_train": int(len(tr)),
                "n_test": int(len(te)), "dup_frac": meta["dup_frac"],
                "conflict_frac": meta["conflict_frac"], "n_conflict": meta["n_conflict"],
                "n_test_overlap": n_overlap}

        model = xgb_binary(seed).fit(Xtr, ytr)
        m = xgb_margin(model, Xte)
        rows.append({**base, "scope": "binary", "method": "xgb",
                     "auroc": roc_auc_score(yte, m), "auprc": average_precision_score(yte, m),
                     "macro_f1": f1_score(yte, (m >= 0).astype(int), average="macro")})

        j, sign, tr_auc = best_single_feature(Xtr, ytr, cols)
        rows.append({**base, "scope": "binary", "method": "best_single_feature",
                     "feature": cols[j], "train_auroc": tr_auc,
                     "auroc": _single_feature_test_auc(Xte, yte, j, sign)})

        for depth in (1, 2):
            clf = DecisionTreeClassifier(max_depth=depth, random_state=seed).fit(Xtr, ytr)
            rows.append({**base, "scope": "binary", "method": f"depth{depth}_tree",
                         "auroc": roc_auc_score(yte, clf.predict_proba(Xte)[:, 1]),
                         "balanced_accuracy": balanced_accuracy_score(yte, clf.predict(Xte))})

        fam_tr, fam_te = fam[tr], fam[te]
        for f in pd.unique(fam_te):
            if f == BENIGN or (fam_te == f).sum() < min_family_test:
                continue
            m_tr = (fam_tr == BENIGN) | (fam_tr == f)
            m_te = (fam_te == BENIGN) | (fam_te == f)
            yf_tr = (fam_tr[m_tr] == f).astype(int)
            yf_te = (fam_te[m_te] == f).astype(int)
            j, sign, tr_auc = best_single_feature(Xtr[m_tr], yf_tr, cols)
            rows.append({**base, "scope": f, "method": "best_single_feature", "feature": cols[j],
                         "train_auroc": tr_auc,
                         "auroc": float(roc_auc_score(yf_te, sign * Xte[m_te][:, j]))})
        xgb_row = next(r for r in rows if r["seed"] == seed and r["method"] == "xgb")
        print(f"[E1] {name} seed={seed} n={len(X)} xgb_auc={xgb_row['auroc']:.4f} "
              f"secs={time.time() - t0:.0f}", flush=True)
    return rows


def family_hits(df: pd.DataFrame, g: pd.DataFrame) -> dict:
    """Per seed: families evaluated, families with a single-feature AUROC >= 0.99, and the ratio."""
    fam = g[(g.method == "best_single_feature") & (g.scope != "binary")]
    per_seed = []
    for seed, h in fam.groupby("seed", sort=True):
        n_eval = int(h.scope.nunique())
        hits = int((h.auroc >= 0.99).sum())
        per_seed.append({"seed": int(seed), "n_eval": n_eval, "hits": hits,
                         "frac": hits / n_eval if n_eval else np.nan})
    hits = np.array([p["hits"] for p in per_seed], dtype=float)
    denoms = [p["n_eval"] for p in per_seed]
    fracs = np.array([p["frac"] for p in per_seed], dtype=float)
    return {"per_seed": per_seed, "hits_mean": float(hits.mean()) if len(hits) else np.nan,
            "hits_sd": float(hits.std(ddof=1)) if len(hits) > 1 else 0.0,
            "frac_mean": float(np.nanmean(fracs)) if len(fracs) else np.nan,
            "denoms": denoms}


def _families_cell(info: dict) -> str:
    if not info["per_seed"]:
        return "n/a"
    d = info["denoms"]
    den = f"{d[0]}" if len(set(d)) == 1 else "/".join(map(str, d))
    sd = f" ± {info['hits_sd']:.1f}" if len(info["per_seed"]) > 1 else ""
    return (f"{info['hits_mean']:.1f}{sd} of {den} "
            f"({100 * info['frac_mean']:.0f}% of families, per seed = count / evaluated)")


def write_markdown(df: pd.DataFrame, path: Path) -> str:
    """One row per dataset: dataset | n | dedup% | conflict% | XGB | depth-2 | best feature | families."""
    lines = ["| dataset | n | dedup % | conflict % | XGB AUROC | depth-2 AUROC | "
             "best-1-feature AUROC (name) | #families with single-feature AUROC >= 0.99 |",
             "|---|---|---|---|---|---|---|---|"]
    for name, g in df.groupby("dataset", sort=False):
        xgb = g[(g.method == "xgb")]
        d2 = g[(g.method == "depth2_tree")]
        bf = g[(g.method == "best_single_feature") & (g.scope == "binary")]
        feats = ", ".join(f"{k} ({v})" for k, v in bf.feature.value_counts().items())
        info = family_hits(df, g)
        lines.append(
            f"| {name} | {int(xgb.n_rows.iloc[0]):,} | {100 * xgb.dup_frac.iloc[0]:.2f} | "
            f"{100 * xgb.conflict_frac.iloc[0]:.2f} | {mean_std(xgb.auroc)} | {mean_std(d2.auroc)} | "
            f"{mean_std(bf.auroc)} ({feats}) | {_families_cell(info)} |")
    md = "\n".join(lines) + "\n"
    path.write_text("# E1 shortcut index\n\n" + md)
    return md


def main(argv: list[str] | None = None) -> tuple[pd.DataFrame, dict]:
    ap = argparse.ArgumentParser(prog="python -m idsbench.feasibility.e1_shortcut")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    seeds = [0] if args.quick else list(SEEDS_FULL)
    cap_b, cap_f = CAPS_QUICK if args.quick else CAPS_FULL
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows, skipped = [], {}
    for name in DATASET_LOADERS:
        try:
            rows += run_dataset(name, seeds, cap_b, cap_f)
        except Exception as e:  # log and continue with the next dataset
            skipped[name] = f"{type(e).__name__}: {e}"
            print(f"[E1] SKIP {name}: {skipped[name]}", flush=True)
    df = pd.DataFrame(rows)
    df.to_csv(out / "e1_shortcut.csv", index=False)
    md = write_markdown(df, out / "e1_shortcut.md") if len(df) else "(no datasets)\n"
    print(md, flush=True)
    return df, skipped


if __name__ == "__main__":
    main()
