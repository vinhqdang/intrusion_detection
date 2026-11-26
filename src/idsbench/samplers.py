"""Imbalance handling: none, random oversampling, SMOTE family and conditional-GAN augmentation."""

from __future__ import annotations

from typing import Any

import numpy as np
from imblearn.combine import SMOTETomek
from imblearn.over_sampling import SMOTE, RandomOverSampler

from .cgan import CGANSampler, augment

SAMPLER_NAMES = (
    "none", "ros", "smote", "smote_tomek", "cgan", "cgan_mcfilter", "smote_tomek_cgan_mcfilter",
)


def _smote_plan(y: np.ndarray) -> tuple[dict, int] | None:
    """Target counts for SMOTE and k_neighbors; classes with fewer than 2 rows are skipped."""
    classes, counts = np.unique(y, return_counts=True)
    maj = counts.max()
    targets = {c: int(maj) for c, n in zip(classes, counts) if 2 <= n < maj}
    if not targets:
        return None
    n_min = min(n for c, n in zip(classes, counts) if c in targets)
    return targets, int(min(5, n_min - 1))


class NoSampler:
    """Identity: returns the training data unchanged."""

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        return np.asarray(X).copy(), np.asarray(y).copy()


class RandomOversampler:
    """Random duplication of minority rows up to the majority count."""

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        return RandomOverSampler(random_state=self.seed).fit_resample(X, y)


class SmoteSampler:
    """SMOTE to the majority count, with k_neighbors = min(5, n_min - 1)."""

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        plan = _smote_plan(np.asarray(y))
        if plan is None:
            return NoSampler().fit_resample(X, y)
        targets, k = plan
        return SMOTE(sampling_strategy=targets, k_neighbors=k,
                     random_state=self.seed).fit_resample(X, y)


class SmoteTomekSampler:
    """SMOTE followed by removal of Tomek links (imblearn SMOTETomek)."""

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        plan = _smote_plan(np.asarray(y))
        if plan is None:
            return NoSampler().fit_resample(X, y)
        targets, k = plan
        return SMOTETomek(
            sampling_strategy=targets,
            smote=SMOTE(sampling_strategy=targets, k_neighbors=k, random_state=self.seed),
            random_state=self.seed,
        ).fit_resample(X, y)


class SmoteTomekCGANSampler:
    """LITE-GEN-style chain.

    1. SMOTE-Tomek on the real rows (balances classes, cleans overlapping pairs).
    2. A conditional GAN trained on the real rows generates ``gen_fraction`` times the number of
       rows SMOTE added per class (capped at ``max_per_class``). This is an interpretation of
       "cGAN augmentation" on top of SMOTE-Tomek, which already balances the classes.
    3. Generated rows are kept only if they pass the MC-dropout variance filter (rule
       "lite_gen"), with the real rows as reference.
    """

    def __init__(self, seed: int = 0, epochs: int = 50, gen_fraction: float = 0.5,
                 max_per_class: int = 20000, filter_rule: str = "lite_gen") -> None:
        self.seed = seed
        self.epochs = epochs
        self.gen_fraction = gen_fraction
        self.max_per_class = max_per_class
        self.filter_rule = filter_rule
        self.stats_: dict = {}

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)
        classes, y_idx = np.unique(y, return_inverse=True)
        K = len(classes)
        X1, y1 = SmoteTomekSampler(self.seed).fit_resample(X, y)
        orig = np.bincount(y_idx, minlength=K)
        after = np.bincount(np.searchsorted(classes, y1), minlength=K)
        gen = {c: min(int(self.gen_fraction * (after[c] - orig[c])), self.max_per_class)
               for c in range(K) if after[c] > orig[c]}
        if not gen or sum(gen.values()) == 0:
            self.stats_ = {"n_generated": 0}
            return X1, y1
        Xs, ys, self.stats_ = augment(X, y_idx, K, gen, epochs=self.epochs, seed=self.seed,
                                      mc_filter=True, rule=self.filter_rule)
        if len(ys) == 0:
            return X1, y1
        return np.vstack([X1, Xs]), np.concatenate([y1, classes[ys]])


def get_sampler(name: str, seed: int = 0, cgan_epochs: int = 50, **kwargs: Any) -> Any:
    """Build a sampler by name (see SAMPLER_NAMES)."""
    if name == "none":
        return NoSampler()
    if name == "ros":
        return RandomOversampler(seed)
    if name == "smote":
        return SmoteSampler(seed)
    if name == "smote_tomek":
        return SmoteTomekSampler(seed)
    if name == "cgan":
        return CGANSampler(seed=seed, epochs=cgan_epochs, **kwargs)
    if name == "cgan_mcfilter":
        return CGANSampler(seed=seed, epochs=cgan_epochs, mc_filter=True, **kwargs)
    if name == "smote_tomek_cgan_mcfilter":
        return SmoteTomekCGANSampler(seed=seed, epochs=cgan_epochs, **kwargs)
    raise ValueError(f"Unknown sampler {name!r}; choose from {SAMPLER_NAMES}")
