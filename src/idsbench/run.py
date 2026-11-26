"""CLI experiment runner.

    python -m idsbench.run --config configs/nslkdd_leakage.yaml [--quick]

Runs the cross product of protocols x dedup x samplers x models x seeds. One JSON line per run
goes to results/raw/<name>.jsonl (finished runs are skipped on re-launch). A markdown and a CSV
summary (mean and std over seeds) are written to results/<name>_summary.{md,csv}.
--quick uses seed 0, model lgbm and at most 5000 rows per class, for smoke tests.
Run from the repository root so that the relative data/ and results/ paths resolve.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from sklearn.preprocessing import LabelEncoder

from .data import cap_per_class, load_dataset
from .metrics import compute_metrics
from .models import get_model
from .protocol import run_protocol
from .samplers import get_sampler

QUICK_CAP = 5000
QUICK_SEEDS = [0]
QUICK_MODELS = ["lgbm"]
MINORITY_SHARE = 0.10
SUMMARY_METRICS = ["macro_f1", "accuracy", "mcc", "balanced_accuracy", "fpr", "fnr"]
COUNT_FIELDS = ["n_train_after_resample", "n_synthetic_train", "n_synthetic_test",
                "n_cross_dup_removed", "n_dedup_removed", "n_rows_used"]


def _log(msg: str) -> None:
    print(msg, flush=True)


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, float) and math.isnan(obj):
        return None
    return obj


def _load(ds_cfg: dict, quick: bool) -> dict:
    """Load one registered dataset (see data.DATASETS). --quick caps rows per class at 5000."""
    kwargs = {k: v for k, v in ds_cfg.items() if k != "name"}
    if quick:
        kwargs["n_per_class_cap"] = QUICK_CAP
    bundle = load_dataset(ds_cfg["name"], **kwargs)
    if quick and bundle["X_test"] is not None:
        bundle["X"], bundle["y"] = cap_per_class(bundle["X"], bundle["y"], QUICK_CAP, seed=0)
        bundle["X_test"], bundle["y_test"] = cap_per_class(bundle["X_test"], bundle["y_test"],
                                                           QUICK_CAP, seed=0)
    return bundle


def _load_bundle(cfg: dict, quick: bool) -> dict:
    """Single-dataset bundle, or a cross-dataset bundle (train_dataset / test_dataset).

    Cross-dataset: both datasets are restricted to their shared feature columns, must be binary
    (labels benign/attack), and the test dataset becomes the official test split.
    """
    if "train_dataset" not in cfg:
        return _load(cfg["dataset"], quick)
    if "test_dataset" not in cfg:
        raise ValueError("cross-dataset config needs both train_dataset and test_dataset")
    tr = _load(cfg["train_dataset"], quick)
    te = _load(cfg["test_dataset"], quick)
    cols = [c for c in tr["X"].columns if c in set(te["X"].columns)]
    if len(cols) < 5:
        raise ValueError(f"only {len(cols)} shared feature columns between the two datasets")
    for name, b in (("train", tr), ("test", te)):
        labels = set(np.unique(np.asarray(b["y"]).astype(str)))
        if not labels <= {"benign", "attack"}:
            raise ValueError(f"{name} labels must be binary benign/attack, got {sorted(labels)}")
    return {"X": tr["X"][cols], "y": tr["y"], "X_test": te["X"][cols], "y_test": te["y"],
            "normal_label": "benign",
            "meta": {"train": tr["meta"], "test": te["meta"], "n_shared_features": len(cols)}}


def _run_one(protocol: str, dedup: bool, sampler_name: str, model_name: str, seed: int,
             cgan_epochs: int, bundle: dict, enc: LabelEncoder, y_int: np.ndarray,
             y_test_int: np.ndarray | None) -> tuple[dict, dict]:
    sampler = get_sampler(sampler_name, seed=seed, cgan_epochs=cgan_epochs)
    n_classes = len(enc.classes_)
    t0 = time.perf_counter()
    res = run_protocol(
        protocol, bundle["X"], y_int, sampler,
        lambda: get_model(model_name, seed=seed, n_classes=n_classes),
        seed, X_test=bundle["X_test"], y_test=y_test_int, dedup=dedup,
    )
    wall = time.perf_counter() - t0
    metrics = compute_metrics(enc.inverse_transform(res["y_true"]),
                              enc.inverse_transform(res["y_pred"]),
                              labels=list(enc.classes_), normal_label=bundle["normal_label"])
    record_extra = {
        "timings": {"fit_seconds": res["fit_seconds"], "resample_seconds": res["resample_seconds"],
                    "predict_ms_per_sample": res["predict_ms_per_sample"], "wall_seconds": wall},
        "counts": {k: res[k] for k in COUNT_FIELDS if k in res},
    }
    return metrics, record_extra


def _flatten(rec: dict) -> dict:
    row = {**rec["config"], **{m: rec["metrics"][m] for m in SUMMARY_METRICS}}
    for cls in rec["dataset"]["minority_classes"]:
        row[f"f1_{cls}"] = rec["metrics"]["per_class"][cls]["f1"]
    row["fit_seconds"] = rec["timings"]["fit_seconds"]
    row["n_synthetic_test"] = rec["counts"].get("n_synthetic_test")
    return row


def _fmt(mean: float, std: float) -> str:
    if mean is None or (isinstance(mean, float) and math.isnan(mean)):
        return "-"
    if std is None or (isinstance(std, float) and math.isnan(std)):
        return f"{mean:.4f}"
    return f"{mean:.4f} ± {std:.4f}"


def _summarise(jsonl: Path, out_stem: Path) -> pd.DataFrame:
    recs = [json.loads(line) for line in jsonl.read_text().splitlines() if line.strip()]
    if not recs:
        raise RuntimeError(f"no records in {jsonl}")
    df = pd.DataFrame([_flatten(r) for r in recs])
    minority = recs[0]["dataset"]["minority_classes"]
    value_cols = [c for c in df.columns if c in SUMMARY_METRICS or c.startswith("f1_")
                  or c in ("fit_seconds", "n_synthetic_test")]
    group_cols = ["protocol", "dedup", "sampler", "model"]
    rows = []
    for keys, grp in df.groupby(group_cols, sort=False):
        row = dict(zip(group_cols, keys))
        row["n_seeds"] = int(len(grp))
        for col in value_cols:
            vals = grp[col].astype(float)
            row[f"{col}_mean"] = float(vals.mean())
            row[f"{col}_std"] = float(vals.std(ddof=1)) if len(vals) > 1 else float("nan")
        rows.append(row)
    summary = pd.DataFrame(rows)
    summary.to_csv(out_stem.with_suffix(".csv"), index=False)

    f1_cols = [f"f1_{c}" for c in minority]
    header = ["Protocol", "Dedup", "Sampler", "Model", "Seeds", "Macro-F1", "Accuracy", "MCC",
              "FPR", "FNR"] + [f"F1 {c}" for c in minority] + ["Synthetic in test"]
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for r in rows:
        cells = [r["protocol"], str(r["dedup"]).lower(), r["sampler"], r["model"], str(r["n_seeds"])]
        cells += [_fmt(r[f"{m}_mean"], r[f"{m}_std"]) for m in
                  ["macro_f1", "accuracy", "mcc", "fpr", "fnr"]]
        cells += [_fmt(r[f"f1_{c}_mean"], r[f"f1_{c}_std"]) for c in minority]
        cells += [_fmt(r.get("n_synthetic_test_mean"), r.get("n_synthetic_test_std"))]
        lines.append("| " + " | ".join(cells) + " |")
    out_stem.with_suffix(".md").write_text(
        f"# {out_stem.name}\n\nMean ± sample std over seeds. Minority classes "
        f"(share < {MINORITY_SHARE:.0%} of training data): {', '.join(minority) or 'none'}.\n\n"
        + "\n".join(lines) + "\n")
    _log("\n".join(lines))
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m idsbench.run")
    ap.add_argument("--config", required=True, help="YAML experiment config")
    ap.add_argument("--quick", action="store_true", help="smoke test: seed 0, lgbm, 5000 rows/class")
    args = ap.parse_args(argv)

    cfg = yaml.safe_load(Path(args.config).read_text())
    name = cfg["name"] + ("_quick" if args.quick else "")
    protocols = cfg.get("protocols", ["clean"])
    dedups = [bool(d) for d in cfg.get("dedup", [False])]
    samplers = cfg.get("samplers", ["none"])
    models = cfg.get("models", ["lgbm"])
    seeds = cfg.get("seeds", [0])
    cgan_epochs = int(cfg.get("cgan", {}).get("epochs", 50))
    if args.quick:
        seeds, models = QUICK_SEEDS, QUICK_MODELS

    raw_dir = Path("results/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    jsonl = raw_dir / f"{name}.jsonl"
    done = set()
    if jsonl.exists():
        for line in jsonl.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["key"])

    _log(f"[idsbench] config={args.config} name={name} quick={args.quick}")
    bundle = _load_bundle(cfg, args.quick)
    if bundle["meta"]:
        _log(f"[idsbench] dataset meta: {json.dumps(_jsonable(bundle['meta']), default=str)}")
    y_all = pd.concat([bundle["y"], bundle["y_test"]]) if bundle["y_test"] is not None else bundle["y"]
    enc = LabelEncoder().fit(np.asarray(y_all))
    y_int = enc.transform(np.asarray(bundle["y"]))
    y_test_int = None if bundle["y_test"] is None else enc.transform(np.asarray(bundle["y_test"]))
    shares = pd.Series(np.asarray(bundle["y"])).value_counts(normalize=True)
    minority = [str(c) for c in enc.classes_ if shares.get(c, 0.0) < MINORITY_SHARE]
    ds_name = (cfg["dataset"]["name"] if "dataset" in cfg else
               f"{cfg['train_dataset']['name']}->{cfg['test_dataset']['name']}")
    dataset_info = {"name": ds_name, "classes": [str(c) for c in enc.classes_],
                    "minority_classes": minority, "quick": args.quick,
                    "n_train_rows": int(len(bundle["y"])),
                    "n_test_rows": None if bundle["y_test"] is None else int(len(bundle["y_test"]))}

    runs = list(itertools.product(protocols, dedups, samplers, models, seeds))
    _log(f"[idsbench] {len(runs)} runs; {len(done)} already in {jsonl}")
    for i, (protocol, dedup, sampler_name, model_name, seed) in enumerate(runs, 1):
        config = {"protocol": protocol, "dedup": dedup, "sampler": sampler_name,
                  "model": model_name, "seed": int(seed), "cgan_epochs": cgan_epochs}
        key = json.dumps(config, sort_keys=True)
        if key in done:
            _log(f"[{i}/{len(runs)}] skip (done) {key}")
            continue
        _log(f"[{i}/{len(runs)}] run {key}")
        metrics, extra = _run_one(protocol, dedup, sampler_name, model_name, seed, cgan_epochs,
                                  bundle, enc, y_int, y_test_int)
        record = {"key": key, "config": config, "dataset": dataset_info,
                  "metrics": metrics, **extra}
        with jsonl.open("a") as fh:
            fh.write(json.dumps(_jsonable(record)) + "\n")
        _log(f"    macro_f1={metrics['macro_f1']:.4f} mcc={metrics['mcc']:.4f} "
             f"fpr={metrics['fpr']:.4f} fnr={metrics['fnr']:.4f} "
             f"fit={extra['timings']['fit_seconds']:.1f}s")

    out_stem = Path("results") / f"{name}_summary"
    _summarise(jsonl, out_stem)
    _log(f"[idsbench] wrote {out_stem.with_suffix('.csv')} and {out_stem.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
