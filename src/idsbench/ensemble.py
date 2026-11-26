"""Ensembles: soft vote, weighted hard vote and replicator-dynamics weighted vote."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.metrics import f1_score


class _BaseEnsemble:
    """Common fit logic. ``needs_validation`` tells the protocol to pass a validation split."""

    needs_validation = False

    def __init__(self, models: Sequence[Any]) -> None:
        self.models = list(models)
        self.n_classes_: int | None = None

    def _fit_bases(self, X: np.ndarray, y: np.ndarray) -> None:
        for model in self.models:
            model.fit(X, y)
        self.n_classes_ = int(np.max(y)) + 1


class SoftVoteEnsemble(_BaseEnsemble):
    """Average of base-model class probabilities."""

    def fit(self, X_tr: np.ndarray, y_tr: np.ndarray, X_val: Any = None, y_val: Any = None
            ) -> "SoftVoteEnsemble":
        self._fit_bases(X_tr, y_tr)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.mean([m.predict_proba(X) for m in self.models], axis=0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.predict_proba(X).argmax(axis=1)


class HardVoteEnsemble(_BaseEnsemble):
    """Weighted majority vote over base-model labels: argmax_c sum_j w_j 1[f_j(x) = c]."""

    def __init__(self, models: Sequence[Any], weights: Sequence[float] | None = None) -> None:
        super().__init__(models)
        self.weights = None if weights is None else np.asarray(weights, dtype=float)
        self.weights_: np.ndarray | None = None

    def fit(self, X_tr: np.ndarray, y_tr: np.ndarray, X_val: Any = None, y_val: Any = None
            ) -> "HardVoteEnsemble":
        self._fit_bases(X_tr, y_tr)
        w = np.ones(len(self.models)) if self.weights is None else self.weights
        self.weights_ = w / w.sum()
        return self

    def _votes(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        votes = np.zeros((n, self.n_classes_))
        for w, model in zip(self.weights_, self.models):
            pred = np.asarray(model.predict(X)).astype(int)
            votes[np.arange(n), pred] += w
        return votes

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self._votes(X).argmax(axis=1)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Normalised weighted vote shares (not calibrated probabilities)."""
        v = self._votes(X)
        return v / v.sum(axis=1, keepdims=True)


def replicator_iterate(pi: Sequence[float], T: int, w0: Sequence[float] | None = None) -> np.ndarray:
    """Iterate w <- w * pi / sum(w * pi) for T steps. Returns history of shape (T+1, K)."""
    pi = np.asarray(pi, dtype=float)
    K = len(pi)
    w = np.full(K, 1.0 / K) if w0 is None else np.asarray(w0, dtype=float) / np.sum(w0)
    hist = [w.copy()]
    for _ in range(T):
        denom = float(np.sum(w * pi))
        if denom > 0:
            w = w * pi / denom
        hist.append(w.copy())
    return np.array(hist)


def replicator_closed_form(pi: Sequence[float], T: int) -> np.ndarray:
    """Closed form of replicator_iterate from uniform start: w_j(T) proportional to pi_j**T.

    Computed in log space for stability. Converges to the one-hot vector on the best payoff.
    """
    pi = np.asarray(pi, dtype=float)
    if np.all(pi <= 0):
        return np.full(len(pi), 1.0 / len(pi))
    with np.errstate(divide="ignore"):
        a = T * np.log(pi)
    a = a - np.max(a)
    w = np.exp(a)
    return w / w.sum()


class ReplicatorEnsemble(_BaseEnsemble):
    """Weighted hard vote whose weights come from T' replicator-dynamics steps.

    Payoff pi_j is each base model's accuracy (1 - error) or macro-F1 on the validation split.
    Note: from a uniform start the weights equal pi_j**T' normalised, so the dynamics converge
    to the single best model as T' grows (see replicator_closed_form).
    """

    needs_validation = True

    def __init__(self, models: Sequence[Any], T_prime: int = 50, payoff: str = "accuracy") -> None:
        super().__init__(models)
        if payoff not in ("accuracy", "macro_f1"):
            raise ValueError("payoff must be 'accuracy' or 'macro_f1'")
        self.T_prime = T_prime
        self.payoff = payoff
        self.payoffs_: np.ndarray | None = None
        self.weights_history_: np.ndarray | None = None
        self.weights_: np.ndarray | None = None

    def _payoff(self, model: Any, X: np.ndarray, y: np.ndarray) -> float:
        pred = np.asarray(model.predict(X)).astype(int)
        if self.payoff == "accuracy":
            return float(np.mean(pred == y))
        return float(f1_score(y, pred, average="macro", zero_division=0))

    def fit(self, X_tr: np.ndarray, y_tr: np.ndarray, X_val: Any = None, y_val: Any = None
            ) -> "ReplicatorEnsemble":
        if X_val is None or y_val is None:
            raise ValueError("ReplicatorEnsemble needs a validation split for its payoffs")
        self._fit_bases(X_tr, y_tr)
        self.payoffs_ = np.array([self._payoff(m, X_val, np.asarray(y_val).astype(int))
                                  for m in self.models])
        self.weights_history_ = replicator_iterate(self.payoffs_, self.T_prime)
        self.weights_ = self.weights_history_[-1]
        return self

    def _votes(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        votes = np.zeros((n, self.n_classes_))
        for w, model in zip(self.weights_, self.models):
            pred = np.asarray(model.predict(X)).astype(int)
            votes[np.arange(n), pred] += w
        return votes

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self._votes(X).argmax(axis=1)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Normalised weighted vote shares (not calibrated probabilities)."""
        v = self._votes(X)
        return v / v.sum(axis=1, keepdims=True)
