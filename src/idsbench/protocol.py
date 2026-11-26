"""Leakage-safe ("clean") and leakage-prone ("leaky") evaluation protocols.

clean: split raw data first, fit the preprocessor and the sampler on training rows only.
leaky: fit the preprocessor and resample ALL rows, then split, so synthetic points derived from
       test neighbours can land in the training set and synthetic points can land in the test set.
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

PROTOCOLS = ("clean", "leaky")
VAL_SIZE = 0.2


def _as_frame(X: Any) -> pd.DataFrame:
    if isinstance(X, pd.DataFrame):
        return X.reset_index(drop=True)
    arr = np.asarray(X)
    return pd.DataFrame(arr, columns=[f"f{i}" for i in range(arr.shape[1])])


def _stratify_or_none(y: np.ndarray) -> np.ndarray | None:
    """Stratify only when every class has at least two rows."""
    _, counts = np.unique(y, return_counts=True)
    return y if counts.min() >= 2 else None


class Preprocessor:
    """One-hot encode string columns and min-max scale numeric columns.

    Fitted only on the rows it is given; unseen categories become all-zero rows.
    """

    def __init__(self) -> None:
        self.ct_: ColumnTransformer | None = None
        self.cat_cols_: list[str] = []
        self.num_cols_: list[str] = []

    def fit(self, X: Any) -> "Preprocessor":
        X = _as_frame(X)
        self.cat_cols_ = list(X.select_dtypes(include=["object", "category", "string"]).columns)
        self.num_cols_ = [c for c in X.columns if c not in self.cat_cols_]
        transformers = []
        if self.cat_cols_:
            transformers.append(
                ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), self.cat_cols_)
            )
        if self.num_cols_:
            transformers.append(("num", MinMaxScaler(), self.num_cols_))
        self.ct_ = ColumnTransformer(transformers, sparse_threshold=0.0)
        self.ct_.fit(X)
        return self

    def transform(self, X: Any) -> np.ndarray:
        if self.ct_ is None:
            raise RuntimeError("Preprocessor must be fitted before transform")
        return np.asarray(self.ct_.transform(_as_frame(X)), dtype=np.float64)

    def fit_transform(self, X: Any) -> np.ndarray:
        return self.fit(X).transform(X)


def _drop_exact_duplicates(X: Any, y: Any) -> tuple[pd.DataFrame, np.ndarray, int]:
    """Drop rows identical in every feature and label (keep first). Returns the removed count."""
    X = _as_frame(X)
    y = np.asarray(y)
    tmp = X.copy()
    tmp["__label__"] = y
    keep = ~tmp.duplicated(keep="first").to_numpy()
    return X.loc[keep].reset_index(drop=True), y[keep], int((~keep).sum())


def _matches_any(A: pd.DataFrame, B: pd.DataFrame) -> np.ndarray:
    """Boolean mask over rows of A whose feature values exactly equal some row of B."""
    if len(B) == 0 or len(A) == 0:
        return np.zeros(len(A), dtype=bool)
    return np.asarray(pd.MultiIndex.from_frame(A).isin(pd.MultiIndex.from_frame(B)))


def _row_hashes(Z: np.ndarray) -> np.ndarray:
    return pd.util.hash_pandas_object(pd.DataFrame(Z), index=False).to_numpy()


def _count_novel(Z_new: np.ndarray, Z_pool: np.ndarray) -> int:
    """Rows of Z_new that exactly match no row of Z_pool (64-bit row hashes)."""
    if len(Z_new) == 0:
        return 0
    return int(np.isin(_row_hashes(Z_new), _row_hashes(Z_pool), invert=True).sum())


def split(X: Any, y: Any, test_size: float = 0.3, seed: int = 0, dedup: bool = False,
          stratify: bool = True) -> tuple[pd.DataFrame, pd.DataFrame, np.ndarray, np.ndarray, int]:
    """Stratified train/test split of raw rows.

    If ``dedup``: exact duplicate rows (features + label) are removed before splitting, and any
    test row whose features exactly match a training row is removed from test.
    Returns (X_train, X_test, y_train, y_test, n_cross_split_duplicates_removed).
    """
    X = _as_frame(X)
    y = np.asarray(y)
    if dedup:
        X, y, _ = _drop_exact_duplicates(X, y)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=seed,
        stratify=_stratify_or_none(y) if stratify else None,
    )
    X_tr = X_tr.reset_index(drop=True)
    X_te = X_te.reset_index(drop=True)
    n_cross = 0
    if dedup:
        mask = _matches_any(X_te, X_tr)
        n_cross = int(mask.sum())
        X_te = X_te.loc[~mask].reset_index(drop=True)
        y_te = y_te[~mask]
    return X_tr, X_te, y_tr, y_te, n_cross


def _dedup_official(X_tr: pd.DataFrame, y_tr: np.ndarray, X_te: pd.DataFrame, y_te: np.ndarray
                    ) -> tuple[pd.DataFrame, np.ndarray, pd.DataFrame, np.ndarray, int]:
    """Dedup inside train and test, then drop test rows whose features appear in train."""
    X_tr, y_tr, _ = _drop_exact_duplicates(X_tr, y_tr)
    X_te, y_te, _ = _drop_exact_duplicates(X_te, y_te)
    mask = _matches_any(X_te, X_tr)
    X_te = X_te.loc[~mask].reset_index(drop=True)
    return X_tr, y_tr, X_te, y_te[~mask], int(mask.sum())


def _fit_predict(model: Any, X_tr: np.ndarray, y_tr: np.ndarray, X_val: np.ndarray,
                 y_val: np.ndarray, X_te: np.ndarray) -> tuple[np.ndarray, np.ndarray | None, float, float]:
    t0 = time.perf_counter()
    if getattr(model, "needs_validation", False):
        model.fit(X_tr, y_tr, X_val, y_val)
    else:
        model.fit(X_tr, y_tr)
    fit_s = time.perf_counter() - t0
    t1 = time.perf_counter()
    y_pred = np.asarray(model.predict(X_te)).astype(int)
    pred_ms = (time.perf_counter() - t1) * 1000.0 / max(len(X_te), 1)
    y_proba = np.asarray(model.predict_proba(X_te)) if hasattr(model, "predict_proba") else None
    return y_pred, y_proba, fit_s, pred_ms


def run_protocol(protocol: str, X: Any, y: Any, sampler: Any, model_factory: Any, seed: int,
                 X_test: Any = None, y_test: Any = None, dedup: bool = False,
                 val_size: float = VAL_SIZE, test_size: float = 0.3) -> dict:
    """Run one leakage protocol end to end and return predictions, timings and counts.

    Args:
        protocol: "clean" or "leaky".
        X, y: raw training features (DataFrame) and integer-encoded labels.
        sampler: object with ``fit_resample(X, y)`` on dense float arrays.
        model_factory: zero-argument callable returning a fresh model.
        seed: random seed for splits.
        X_test, y_test: optional official test split (e.g. NSL-KDD KDDTest+). For ``leaky`` the
            two sets are concatenated and re-split randomly.
        dedup: remove exact duplicates (and, for clean, cross-split duplicates).
    """
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {PROTOCOLS}, got {protocol!r}")
    if (X_test is None) != (y_test is None):
        raise ValueError("X_test and y_test must be given together")
    X = _as_frame(X)
    y = np.asarray(y).astype(int)
    if X_test is not None:
        X_test = _as_frame(X_test)
        y_test = np.asarray(y_test).astype(int)

    counts: dict[str, Any] = {}
    if protocol == "clean":
        if X_test is not None:
            X_tr, y_tr, X_te, y_te = X, y, X_test, y_test
            if dedup:
                X_tr, y_tr, X_te, y_te, n_cross = _dedup_official(X_tr, y_tr, X_te, y_te)
            else:
                n_cross = 0
        else:
            X_tr, X_te, y_tr, y_te, n_cross = split(X, y, test_size=test_size, seed=seed, dedup=dedup)
        counts["n_cross_dup_removed"] = n_cross
        pre = Preprocessor().fit(X_tr)
        Z_tr = pre.transform(X_tr)
        Z_te = pre.transform(X_te)
        # Validation: stratified hold-out of the pre-resampling training rows (never resampled).
        Z_fit, Z_val, y_fit, y_val = train_test_split(
            Z_tr, y_tr, test_size=val_size, random_state=seed, stratify=_stratify_or_none(y_tr))
        t0 = time.perf_counter()
        Z_train, y_train = sampler.fit_resample(Z_fit, y_fit)
        resample_s = time.perf_counter() - t0
        counts["n_synthetic_train"] = _count_novel(Z_train, Z_fit)
        counts["n_synthetic_test"] = 0
        counts["n_rows_used"] = int(len(y_tr) + len(y_te))
    else:
        if X_test is not None:
            X_all = pd.concat([X, X_test], ignore_index=True)
            y_all = np.concatenate([y, y_test])
        else:
            X_all, y_all = X, y
        n_dedup = 0
        if dedup:
            X_all, y_all, n_dedup = _drop_exact_duplicates(X_all, y_all)
        pre = Preprocessor().fit(X_all)
        Z_all = pre.transform(X_all)
        t0 = time.perf_counter()
        Z_res, y_res = sampler.fit_resample(Z_all, y_all)
        resample_s = time.perf_counter() - t0
        Z_trv, Z_te, y_trv, y_te = train_test_split(
            Z_res, y_res, test_size=test_size, random_state=seed, stratify=_stratify_or_none(y_res))
        Z_train, Z_val, y_train, y_val = train_test_split(
            Z_trv, y_trv, test_size=val_size, random_state=seed, stratify=_stratify_or_none(y_trv))
        counts["n_synthetic_train"] = _count_novel(Z_train, Z_all)
        counts["n_synthetic_test"] = _count_novel(Z_te, Z_all)
        counts["n_cross_dup_removed"] = 0
        counts["n_dedup_removed"] = int(n_dedup)
        counts["n_rows_used"] = int(len(y_all))

    y_pred, y_proba, fit_s, pred_ms = _fit_predict(
        model_factory(), Z_train, y_train, Z_val, y_val, Z_te)
    return {
        "protocol": protocol,
        "dedup": bool(dedup),
        "y_true": np.asarray(y_te).astype(int),
        "y_pred": y_pred,
        "y_proba": y_proba,
        "fit_seconds": float(fit_s),
        "resample_seconds": float(resample_s),
        "predict_ms_per_sample": float(pred_ms),
        "n_train_after_resample": int(len(y_train)),
        "n_test": int(len(y_te)),
        **{k: int(v) for k, v in counts.items()},
    }
