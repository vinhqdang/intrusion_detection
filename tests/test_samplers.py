import numpy as np

from idsbench.cgan import CGANSampler
from idsbench.data import make_synthetic
from idsbench.samplers import get_sampler


def _imbalanced(seed=0):
    X, y = make_synthetic(n=600, n_classes=3, weights=[0.7, 0.2, 0.1], seed=seed)
    X = X.drop(columns=["proto"]).to_numpy()
    return X, y.to_numpy().astype(int)


def test_smote_and_ros_are_roughly_balanced():
    X, y = _imbalanced()
    for name in ("ros", "smote"):
        Xr, yr = get_sampler(name, 0).fit_resample(X, y)
        counts = np.bincount(yr)
        assert counts.min() / counts.max() >= 0.9, (name, counts)
        assert len(Xr) == len(yr)


def test_smote_skips_tiny_classes_and_handles_small_counts():
    X = np.vstack([np.random.default_rng(0).normal(size=(30, 2)), np.array([[9.0, 9.0]])])
    y = np.r_[np.zeros(30, int), np.ones(1, int)]
    Xr, yr = get_sampler("smote", 0).fit_resample(X, y)   # class with 1 row is skipped
    assert len(yr) == len(X)


def test_cgan_sampler_runs_one_epoch_on_tiny_data():
    X, y = _imbalanced()
    X, y = X[:120], y[:120]
    s = CGANSampler(seed=0, epochs=1, max_per_class=50)
    Xr, yr = s.fit_resample(X, y)
    assert len(yr) > len(y)
    assert set(np.unique(yr)) == set(np.unique(y))
    assert Xr.shape[1] == X.shape[1]
    assert np.all(Xr[len(X):] >= 0) and np.all(Xr[len(X):] <= 1)


def test_cgan_mcfilter_chain_runs_one_epoch():
    X, y = _imbalanced()
    X, y = X[:150], y[:150]
    Xr, yr = get_sampler("smote_tomek_cgan_mcfilter", 0, cgan_epochs=1).fit_resample(X, y)
    assert len(yr) >= 1 and Xr.shape[1] == X.shape[1]
    Xc, yc = get_sampler("cgan_mcfilter", 0, cgan_epochs=1, max_per_class=40).fit_resample(X, y)
    assert len(yc) >= len(y)
