import numpy as np
import pandas as pd

from idsbench.feasibility.common import BENIGN, clean_pool, split_no_overlap, xgb_binary, xgb_margin


def _toy():
    # rows 0,1: identical vector, same family (exact duplicate)
    # rows 2,3: identical vector, benign vs attack (label conflict: both removed)
    # rows 4,5: identical vector, two attack families (feature-only duplicate: one kept)
    X = pd.DataFrame({"a": [1.0, 1.0, 2.0, 2.0, 3.0, 3.0, 4.0, 5.0],
                      "b": [0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 2.0, 3.0]}, dtype=np.float32)
    fam = np.array([BENIGN, BENIGN, BENIGN, "DoS", "DoS", "PortScan", BENIGN, "DoS"], dtype=object)
    return X, fam


def test_clean_pool_removes_duplicates_and_conflicts():
    X, fam = _toy()
    Xc, fc, counts = clean_pool(X, fam)
    assert counts["n_exact_duplicates"] == 1
    assert counts["n_conflict"] == 2 and counts["n_conflict_vectors"] == 1
    assert counts["n_feature_duplicates"] == 1
    assert len(Xc) == len(fc) == 4
    assert not Xc.duplicated().any()


def test_no_test_vector_in_train_after_cleaning():
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.integers(0, 5, size=(3000, 3)).astype(np.float32), columns=list("abc"))
    fam = np.where(X.sum(axis=1) > 6, "DoS", BENIGN).astype(object)
    Xc, fc, counts = clean_pool(X, fam)
    tr, te, n_overlap = split_no_overlap(Xc, fc, seed=1)
    assert n_overlap == 0
    assert len(set(tr) & set(te)) == 0


def test_margin_score_is_not_saturated_and_matches_sign_of_probability():
    rng = np.random.default_rng(1)
    X = rng.normal(size=(2000, 4))
    y = (X[:, 0] + 0.1 * rng.normal(size=2000) > 0).astype(int)
    model = xgb_binary(0).fit(X, y)
    m = xgb_margin(model, X)
    p = model.predict_proba(X)[:, 1]
    assert m.dtype == np.float64
    assert np.all((m >= 0) == (p >= 0.5))
    assert len(np.unique(m)) > 100  # margins keep resolution where probabilities saturate
