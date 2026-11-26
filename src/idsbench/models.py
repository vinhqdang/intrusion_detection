"""Model zoo factory. Labels are integer-encoded by the runner before fitting."""

from __future__ import annotations

from typing import Any

from lightgbm import LGBMClassifier
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier

from .ensemble import HardVoteEnsemble, ReplicatorEnsemble, SoftVoteEnsemble

ENSEMBLE_BASES = ("rf", "xgb", "lgbm", "mlp")
MODEL_NAMES = ("lr", "nb", "rf", "et", "xgb", "lgbm", "mlp", "lgbm_balanced",
               "soft_vote", "replicator")


def _base(name: str, seed: int) -> Any:
    if name == "lr":
        return LogisticRegression(max_iter=2000, random_state=seed)
    if name == "nb":
        return GaussianNB()
    if name == "rf":
        return RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=seed)
    if name == "et":
        return ExtraTreesClassifier(n_estimators=300, n_jobs=-1, random_state=seed)
    if name == "xgb":
        return XGBClassifier(n_estimators=400, tree_method="hist", n_jobs=4,
                             random_state=seed, eval_metric="mlogloss", verbosity=0)
    if name == "lgbm":
        return LGBMClassifier(n_estimators=400, verbose=-1, random_state=seed)
    if name == "lgbm_balanced":
        return LGBMClassifier(n_estimators=400, verbose=-1, random_state=seed,
                              class_weight="balanced")
    if name == "mlp":
        return MLPClassifier(hidden_layer_sizes=(256, 128), early_stopping=True,
                             max_iter=200, random_state=seed)
    raise ValueError(f"Unknown model {name!r}")


def get_model(name: str, seed: int = 0, n_classes: int | None = None) -> Any:
    """Return a fresh, unfitted model. ``n_classes`` is informational (sklearn infers it)."""
    if name == "soft_vote":
        return SoftVoteEnsemble([_base(b, seed) for b in ENSEMBLE_BASES])
    if name == "hard_vote":
        return HardVoteEnsemble([_base(b, seed) for b in ENSEMBLE_BASES])
    if name == "replicator":
        return ReplicatorEnsemble([_base(b, seed) for b in ENSEMBLE_BASES], T_prime=50,
                                  payoff="accuracy")
    return _base(name, seed)
