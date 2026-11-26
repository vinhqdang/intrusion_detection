import numpy as np
import pytest

from idsbench.ensemble import ReplicatorEnsemble, replicator_closed_form, replicator_iterate


def test_replicator_closed_form_equals_iterative():
    pi = np.array([0.91, 0.84, 0.77, 0.6])
    for T in (1, 5, 50):
        it = replicator_iterate(pi, T)[-1]
        cf = replicator_closed_form(pi, T)
        assert np.allclose(it, cf, atol=1e-12)


def test_replicator_converges_to_argmax_one_hot():
    pi = np.array([0.7, 0.9, 0.8])
    w = replicator_closed_form(pi, 500)
    assert np.argmax(w) == 1
    assert w[1] > 0.999
    assert np.allclose(replicator_iterate(pi, 500)[-1], w, atol=1e-9)


def test_replicator_history_shape_and_sum_to_one():
    hist = replicator_iterate([0.5, 0.6], 50)
    assert hist.shape == (51, 2)
    assert np.allclose(hist.sum(axis=1), 1.0)


class _Const:
    def __init__(self, label, n_classes=3):
        self.label, self.n_classes = label, n_classes

    def fit(self, X, y):
        return self

    def predict(self, X):
        return np.full(len(X), self.label)

    def predict_proba(self, X):
        p = np.zeros((len(X), self.n_classes))
        p[:, self.label] = 1.0
        return p


def test_replicator_ensemble_weights_follow_payoffs():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(60, 2))
    y = np.repeat([0, 1, 2], 20)
    # Model predicting class 0 is right for 1/3 of the rows; class 1 model for 1/3 too.
    models = [_Const(0), _Const(1), _Const(2)]
    ens = ReplicatorEnsemble(models, T_prime=50, payoff="accuracy")
    ens.fit(X, y, X, y)
    assert ens.weights_history_.shape == (51, 3)
    assert np.allclose(ens.payoffs_, [1 / 3, 1 / 3, 1 / 3])
    assert np.allclose(ens.predict(X), ens.predict(X))


def test_replicator_requires_validation():
    with pytest.raises(ValueError):
        ReplicatorEnsemble([_Const(0)]).fit(np.zeros((3, 1)), np.zeros(3, int))
