"""Shared helpers for the feasibility experiments: cached pools, splits, models, thresholds, tables."""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from idsbench.data import load_dataset

CACHE_DIR = Path("data/feasibility_cache")
BENIGN = "Benign"
# Bump when the cleaning rules change: cached pools with another version are rebuilt.
CACHE_VERSION = 2

# name -> (registry loader, kwargs). The NetFlow reported name is the v2 fallback actually loaded.
DATASET_LOADERS: dict[str, tuple[str, dict]] = {
    "cicids2017": ("cicids2017", {"label": "family", "n_per_class_cap": None}),
    "cicids2018": ("cicids2018", {"label": "family", "n_per_class_cap": 500_000}),
    "ciciot2023": ("ciciot2023", {"label": "8class", "n_per_class_cap": None}),
    "ciciomt2024": ("ciciomt2024", {"label": "family", "n_per_class_cap": None}),
    "edgeiiot": ("edgeiiot", {"label": "fine", "n_per_class_cap": None}),
    "NF-ToN-IoT-v2": ("netflow_v3", {"dataset": "NF-ToN-IoT-v2", "label": "fine",
                                     "n_per_class_cap": None}),
    "NF-UNSW-NB15-v3": ("netflow_v3", {"dataset": "NF-UNSW-NB15-v3", "label": "fine",
                                       "n_per_class_cap": None}),
    "NF-CICIDS2018-v3": ("netflow_v3", {"dataset": "NF-CICIDS2018-v3", "label": "fine",
                                        "n_per_class_cap": None}),
}
NETFLOW_KEYS = ("NF-ToN-IoT-v2", "NF-UNSW-NB15-v3", "NF-CICIDS2018-v3")


def clean_pool(X: pd.DataFrame, family) -> tuple[pd.DataFrame, np.ndarray, dict]:
    """Pool cleaning shared by E1, E2, E3 and the cross-pair experiment. Runs before any split.

    1. exact duplicates (features + family): keep the first copy;
    2. label conflicts: every row whose exact feature vector occurs with both benign and attack
       labels is removed (all copies, because no label can be trusted for that vector);
    3. feature-only duplicates among the survivors (same vector, different attack family, same
       binary label): keep the first copy.
    After step 3 each feature vector occurs at most once, so no train/test split can share one.
    Returns (cleaned features with a fresh index, cleaned family array, removal counts).
    """
    family = np.asarray(family, dtype=object)
    binary = (family != BENIGN).astype(np.int8)
    h_feat = pd.util.hash_pandas_object(X, index=False).to_numpy()
    h_full = pd.util.hash_pandas_object(X.assign(__family=family), index=False).to_numpy()
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
    counts = {"n_exact_duplicates": int(exact_dup.sum()), "n_conflict": int(conflict.sum()),
              "n_conflict_vectors": int(len(conflict_h)),
              "n_feature_duplicates": int(feat_dup.sum()), "n_rows_clean": int(len(keep))}
    return X.iloc[keep].reset_index(drop=True), family[keep], counts


def _build_pool(name: str) -> tuple[pd.DataFrame, dict]:
    """Load one dataset, convert to numeric float32, drop constant columns, then clean the pool."""
    loader, kwargs = DATASET_LOADERS[name]
    bundle = load_dataset(loader, **kwargs)
    X = bundle["X"]
    normal = bundle["normal_label"]
    y = np.asarray(bundle["y"]).astype(str)
    n_loaded = len(X)
    X = pd.DataFrame({c: pd.to_numeric(X[c], errors="coerce").to_numpy(dtype="float64",
                                                                      na_value=np.nan)
                      for c in X.columns})
    n_inf = int(np.isinf(X.to_numpy()).sum())
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna(axis=1, how="all")
    n_const = 0
    const = [c for c in X.columns if X[c].nunique(dropna=True) <= 1]
    if const:
        n_const = len(const)
        X = X.drop(columns=const)
    n_nan = int(X.isna().sum().sum())
    X = X.astype(np.float32).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    family = np.where(y == normal, BENIGN, y)
    X, family, counts = clean_pool(X, family)
    pool = X.copy()
    pool["family"] = family
    removed = counts["n_exact_duplicates"] + counts["n_feature_duplicates"]
    meta = {
        "dataset": name, "loader": loader, "source": bundle["meta"].get("source"),
        "files": bundle["meta"].get("files"), "mirror_note": bundle["meta"].get("mirror_note"),
        "cleaning_version": CACHE_VERSION,
        "n_rows_loaded": int(n_loaded), "n_features": int(X.shape[1]),
        "n_inf_replaced": n_inf, "n_nan_filled": n_nan, "n_constant_dropped": n_const,
        **counts,
        "dup_frac": float(removed / max(n_loaded, 1)),
        "conflict_frac": float(counts["n_conflict"] / max(n_loaded, 1)),
        "n_rows_pool": int(len(X)),
        "family_counts_pool": {str(k): int(v) for k, v in pd.Series(family).value_counts().items()},
    }
    return pool, meta


def get_pool(name: str) -> tuple[pd.DataFrame, dict]:
    """Return the cleaned pool for a dataset (building and caching it once per cleaning version)."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{name}.parquet"
    meta_path = CACHE_DIR / f"{name}.json"
    if path.exists() and meta_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("cleaning_version") == CACHE_VERSION:
            return pd.read_parquet(path), meta
    pool, meta = _build_pool(name)
    pool.to_parquet(path, index=False)
    meta_path.write_text(json.dumps(meta, indent=1, default=str))
    return pool, meta


def pool_meta(name: str) -> dict:
    """Metadata of a cleaned pool (reads the JSON cache when present)."""
    meta_path = CACHE_DIR / f"{name}.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("cleaning_version") == CACHE_VERSION:
            return meta
    return get_pool(name)[1]


def load_binary(name: str, *, cap_benign: int = 300_000, cap_per_family: int = 50_000,
                seed: int) -> tuple[pd.DataFrame, np.ndarray, pd.Series, dict]:
    """Binary benign-vs-attack view of a dataset, capped per family with the run seed.

    Returns (X float32 DataFrame, y_bin with 0 = benign and 1 = attack, family Series with
    'Benign' for benign rows, meta dict).
    """
    pool, meta = get_pool(name)
    family = pool.pop("family").to_numpy()
    rng = np.random.default_rng(seed)
    keep = []
    for fam in pd.unique(family):
        idx = np.flatnonzero(family == fam)
        cap = cap_benign if fam == BENIGN else cap_per_family
        if cap is not None and len(idx) > cap:
            idx = rng.choice(idx, size=cap, replace=False)
        keep.append(np.sort(idx))
    keep = np.concatenate(keep)
    X = pool.iloc[keep].reset_index(drop=True)
    fam_out = pd.Series(family[keep], name="family")
    y = (fam_out != BENIGN).to_numpy().astype(int)
    meta = {**meta, "seed": seed, "cap_benign": cap_benign, "cap_per_family": cap_per_family,
            "n_rows_after_caps": int(len(X)),
            "family_counts_after_caps": {str(k): int(v) for k, v in fam_out.value_counts().items()}}
    return X, y, fam_out, meta


def split_no_overlap(X: pd.DataFrame, y, seed: int, test_size: float = 0.3
                     ) -> tuple[np.ndarray, np.ndarray, int]:
    """Stratified train/test split on ``y``.

    Pool cleaning (clean_pool) already removed duplicates and label conflicts, so no test feature
    vector can occur in train. The overlap is still counted and must be 0; a non-zero count raises.
    Returns (train_idx, test_idx, n_overlap).
    """
    y = np.asarray(y)
    idx = np.arange(len(X))
    _, counts = np.unique(y, return_counts=True)
    strat = y if counts.min() >= 2 else None
    tr, te = train_test_split(idx, test_size=test_size, random_state=seed, stratify=strat)
    h_tr = pd.util.hash_pandas_object(X.iloc[tr], index=False).to_numpy()
    h_te = pd.util.hash_pandas_object(X.iloc[te], index=False).to_numpy()
    n_overlap = int(np.isin(h_te, h_tr).sum())
    if n_overlap:
        raise RuntimeError(f"{n_overlap} test rows share a feature vector with train; "
                           "pool cleaning is broken")
    return tr, te, n_overlap


def xgb_binary(seed: int = 0) -> XGBClassifier:
    return XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, tree_method="hist",
                         n_jobs=4, eval_metric="logloss", random_state=seed, verbosity=0)


def xgb_margin(model, X) -> np.ndarray:
    """XGBoost raw margin (log-odds) as float64. Used as the score: probabilities saturate at 1.0."""
    return np.asarray(model.predict(X, output_margin=True), dtype=np.float64)


def iforest_score(model, X) -> np.ndarray:
    """Anomaly score of an IsolationForest (higher = more anomalous), float64."""
    return -np.asarray(model.score_samples(X), dtype=np.float64)


def threshold_at_fpr(benign_scores, fpr: float) -> tuple[float, bool]:
    """Alarm threshold with realised FPR <= fpr on fresh benign data (split-conformal quantile).

    k = ceil((n+1)(1-fpr)); the threshold is the k-th smallest calibration score, so the fraction
    of calibration scores strictly above it is at most fpr. If k > n the level is not attainable:
    returns (+inf, False).
    """
    s = np.sort(np.asarray(benign_scores, dtype=float))
    n = len(s)
    k = math.ceil((n + 1) * (1.0 - fpr))
    if k > n or k < 1:
        return float("inf"), False
    return float(s[k - 1]), True


def auc_columns(X, y) -> np.ndarray:
    """Mann-Whitney AUROC of every column against binary y (vectorised, ties averaged)."""
    X = np.asarray(X, dtype=float)
    y = np.asarray(y).astype(bool)
    n1 = int(y.sum())
    n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return np.full(X.shape[1], np.nan)
    R = rankdata(X, axis=0)
    return (R[y].sum(axis=0) - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def best_single_feature(X_train, y_train, columns: list[str]) -> tuple[int, int, float]:
    """Feature with the highest train AUROC (either sign). Returns (index, sign, train_auc)."""
    a = auc_columns(X_train, y_train)
    score = np.maximum(a, 1 - a)
    j = int(np.nanargmax(score))
    return j, (1 if a[j] >= 0.5 else -1), float(score[j])


def mean_std(values, digits: int = 4) -> str:
    """'mean ± sd' over the finite entries (sd omitted for a single value; 'n/a' when empty)."""
    v = pd.to_numeric(pd.Series(values), errors="coerce").dropna().to_numpy(dtype=float)
    if len(v) == 0:
        return "n/a"
    if len(v) == 1:
        return f"{v[0]:.{digits}f}"
    return f"{v.mean():.{digits}f} ± {v.std(ddof=1):.{digits}f}"


def demote_headings(md: str, levels: int = 1) -> str:
    """Add ``levels`` '#' characters to every markdown heading (capped at six)."""
    out = []
    for line in md.splitlines():
        if line.startswith("#"):
            hashes = len(line) - len(line.lstrip("#"))
            new = min(hashes + levels, 6)
            line = "#" * new + line[hashes:]
        out.append(line)
    return "\n".join(out)


VARIANTS = ("unweighted", "weighted_oracle", "weighted_labelfree")
VARIANT_TITLES = {"unweighted": "unweighted", "weighted_oracle": "weighted (oracle)",
                  "weighted_labelfree": "weighted (label-free)"}


def e3_tables_md(df: pd.DataFrame, names: list[str], n_cols: int, skipped: dict) -> str:
    """Markdown tables shared by E3 cross-network and E3 cross-pair (rows = train A, cols = test B)."""
    lines = ["## AUROC matrix (rows = train A, cols = test B)", "",
             "| A \\ B | " + " | ".join(names) + " |", "|---" * (len(names) + 1) + "|"]
    for a in names:
        cells = []
        for b in names:
            g = df[(df.A == a) & (df.B == b)]
            cells.append(mean_std(g.auroc) if len(g) else "not run")
        lines.append(f"| {a} | " + " | ".join(cells) + " |")
    lines += ["", "## Target FPR vs realised FPR on B benign (A-calibrated thresholds)", "",
              "| A -> B | target 1e-2 realised | target 1e-3 realised | recall B @1e-3 |",
              "|---|---|---|---|"]
    for (a, b), g in df.groupby(["A", "B"], sort=False):
        lines.append(f"| {a} -> {b} | {mean_std(g['realized_fpr_B_0.01'])} | "
                     f"{mean_std(g['realized_fpr_B_0.001'])} | {mean_std(g['recall_B_0.001'])} |")
    lines += ["", "## Conformal + BH (alpha = 0.1) on B: unweighted vs weighted (two variants)", "",
              "Weighted (oracle) fits the domain classifier on B benign rows (uses B labels: upper "
              "bound). Weighted (label-free) fits it on B rows whose unweighted p-value is > 0.5 "
              "(presumed benign; no B labels). Weights: mean over A calibration, and effective "
              "sample size (sum w)^2 / sum w^2 of A calibration (unweighted ESS = n calibration).", "",
              "| A -> B | unweighted FDR | unweighted power | oracle FDR | oracle power | "
              "label-free FDR | label-free power | mean w cal (oracle / label-free) | "
              "ESS cal (oracle / label-free) |",
              "|---|---|---|---|---|---|---|---|---|"]
    for (a, b), g in df.groupby(["A", "B"], sort=False):
        lines.append(
            f"| {a} -> {b} | {mean_std(g.conf_unweighted_fdr)} | {mean_std(g.conf_unweighted_power)} | "
            f"{mean_std(g.conf_weighted_oracle_fdr)} | {mean_std(g.conf_weighted_oracle_power)} | "
            f"{mean_std(g.conf_weighted_labelfree_fdr)} | {mean_std(g.conf_weighted_labelfree_power)} | "
            f"{mean_std(g.w_weighted_oracle_mean_cal, 3)} / {mean_std(g.w_weighted_labelfree_mean_cal, 3)} | "
            f"{mean_std(g.w_weighted_oracle_ess_cal, 0)} / {mean_std(g.w_weighted_labelfree_ess_cal, 0)} |")
    lines += ["", f"Shared features used: {n_cols}.",
              "Datasets not loaded: " + ("; ".join(f"{k}: {v}" for k, v in skipped.items()) or "none")]
    return "\n".join(lines) + "\n"
