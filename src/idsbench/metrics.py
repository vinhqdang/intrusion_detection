"""Classification metrics, including binary FPR/FNR against the normal class."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.metrics import (
    balanced_accuracy_score,
    confusion_matrix,
    accuracy_score,
    f1_score,
    matthews_corrcoef,
    precision_recall_fscore_support,
)


def compute_metrics(y_true: Any, y_pred: Any, labels: Sequence[Any], normal_label: Any) -> dict:
    """Return accuracy, balanced accuracy, macro/weighted scores, MCC, per-class scores,
    FPR (normal predicted as any attack / all normal), FNR (attack predicted as normal /
    all attacks) and the confusion matrix (rows = true, columns = predicted, in ``labels``
    order).
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    labels = list(labels)
    if normal_label not in labels:
        raise ValueError("normal_label must be one of labels")
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    normal = y_true == normal_label
    attack = ~normal
    fpr = float(np.mean(y_pred[normal] != normal_label)) if normal.any() else float("nan")
    fnr = float(np.mean(y_pred[attack] == normal_label)) if attack.any() else float("nan")
    per_class = {
        str(lab): {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                   "support": int(s[i])}
        for i, lab in enumerate(labels)
    }
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(np.mean(p)),
        "macro_recall": float(np.mean(r)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=labels, average="weighted",
                                      zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "fpr": fpr,
        "fnr": fnr,
        "per_class": per_class,
        "labels": [str(lab) for lab in labels],
        "confusion": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }
