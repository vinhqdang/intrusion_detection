import numpy as np
import pandas as pd

from idsbench.data import make_synthetic
from idsbench.models import get_model
from idsbench.protocol import Preprocessor, run_protocol, split
from idsbench.samplers import get_sampler


def _data(seed=0):
    X, y = make_synthetic(n=1500, seed=seed)
    return X, y.to_numpy().astype(int)


def test_leaky_and_clean_both_run_and_return_metrics():
    X, y = _data()
    for protocol in ("clean", "leaky"):
        res = run_protocol(protocol, X, y, get_sampler("smote", 0),
                           lambda: get_model("lgbm", 0), seed=0, dedup=False)
        assert len(res["y_pred"]) == len(res["y_true"]) > 0
        assert res["y_proba"].shape[1] == len(np.unique(y))
        assert res["fit_seconds"] >= 0 and res["predict_ms_per_sample"] >= 0
        assert res["n_train_after_resample"] > 0


def test_leaky_puts_synthetic_rows_in_test_and_clean_does_not():
    X, y = _data(seed=1)
    leaky = run_protocol("leaky", X, y, get_sampler("smote", 1),
                         lambda: get_model("lr", 1), seed=1)
    clean = run_protocol("clean", X, y, get_sampler("smote", 1),
                         lambda: get_model("lr", 1), seed=1)
    assert leaky["n_synthetic_test"] > 0
    assert clean["n_synthetic_test"] == 0


def test_dedup_removes_cross_split_duplicates_exactly():
    base = pd.DataFrame({"a": np.arange(20.0), "b": np.arange(20.0) * 2})
    # Training side: 20 unique rows. Test side: 5 copies of training rows plus 5 new rows.
    X_tr = base.copy()
    y_tr = np.zeros(20, dtype=int)
    X_te = pd.concat([base.iloc[:5], pd.DataFrame({"a": np.arange(100.0, 105.0),
                                                  "b": np.zeros(5)})], ignore_index=True)
    y_te = np.zeros(10, dtype=int)
    from idsbench.protocol import _dedup_official
    Xtr2, ytr2, Xte2, yte2, n_cross = _dedup_official(X_tr, y_tr, X_te, y_te)
    assert n_cross == 5 and len(Xte2) == 5 and len(yte2) == 5
    merged = Xte2.merge(Xtr2, on=["a", "b"])
    assert len(merged) == 0


def test_split_dedup_has_no_feature_overlap_and_drops_within_duplicates():
    rng = np.random.default_rng(0)
    base = pd.DataFrame(rng.normal(size=(100, 3)), columns=["x", "y", "z"])
    # Same features with two labels (not exact duplicates) and exact duplicates of each row.
    X = pd.concat([base, base, base], ignore_index=True)
    y = np.r_[np.zeros(100, int), np.ones(100, int), np.ones(100, int)]
    X_tr, X_te, y_tr, y_te, n_cross = split(X, y, test_size=0.3, seed=0, dedup=True)
    assert n_cross >= 0
    overlap = X_te.merge(X_tr, on=["x", "y", "z"])
    assert len(overlap) == 0
    assert len(X_tr) + len(X_te) <= 200  # exact duplicates (features + label) removed


def test_preprocessor_fits_only_on_given_rows():
    X_tr = pd.DataFrame({"c": ["a", "b", "a"], "n": [0.0, 5.0, 10.0]})
    X_te = pd.DataFrame({"c": ["z"], "n": [20.0]})
    pre = Preprocessor().fit(X_tr)
    Z = pre.transform(X_te)
    assert Z.shape == (1, 3)                     # 2 one-hot cols seen in train + 1 numeric
    assert np.allclose(Z[0, :2], 0.0)            # unseen category -> all zeros
    assert Z[0, 2] > 1.0                         # scaled with train min/max (not refit on test)
