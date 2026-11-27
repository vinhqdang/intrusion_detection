"""Detection tables r[dataset, model, fpr, action] for the game, from the E4 measurement outputs.

Sources (all written by measure.run_e4 in results/econ):
  detection_tables.csv  one row per (dataset, seed, model, fpr, action, family): reuse(f) (known scenario),
                        novel(f) (leave-one-family-out), the number of test flows and the realised benign-test
                        FPR of the threshold (fpr_realized, used in the alert volume A).
  e4_mutation.csv       recall_after of mutate(f, b) per (dataset, seed, model, fpr, family, budget, query_mode,
                        attacker). Score-query attackers: greedy, strong, transfer (from xgb). Label attacker:
                        label (weak baseline, its own query mode).
  e4_reference.csv      AUROC of the known scenario per (dataset, seed, model, family).

Capable attacker's mutation recall: worst case over the attackers of the query mode (the game uses the minimum
recall, i.e. the strongest attack the defender must survive). Families with fewer than ATTACKER_MIN_TEST test
flows in any seed are not offered to the attacker (excluded_families).

Tables are averaged over seeds (build_recall_tables with seed=None) or built for one seed (seed=k).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from idsbench.econ.game import RecallTable
from idsbench.econ.measure import DEFENDERS
from idsbench.econ.mutation import FPRS, budget_label, budget_units, budgets

ATTACKER_MIN_TEST = 300
SCORE_ATTACKERS = ("greedy", "strong", "transfer")
KEYS = ["dataset", "model", "fpr", "action", "family"]
OUT = Path("results/econ")


def summarise(long: pd.DataFrame) -> pd.DataFrame:
    g = long.groupby(KEYS, sort=True)
    return g.agg(recall_mean=("recall", "mean"), recall_std=("recall", "std"),
                 n_seeds=("recall", "count"), n_test=("n_test", "mean"),
                 fpr_realized_mean=("fpr_realized", "mean"), fpr_realized_std=("fpr_realized", "std")).reset_index()


def excluded_families(long: pd.DataFrame, dataset: str) -> list[str]:
    r = long[(long.dataset == dataset) & long.action.str.startswith("reuse(")]
    small = r.groupby("family").n_test.min()
    return sorted(small[small < ATTACKER_MIN_TEST].index.tolist())


def auc_summary(e4_reference: pd.DataFrame, dataset: str) -> pd.DataFrame:
    """Per model: mean over families of the known-scenario AUROC, per seed, then mean/sd over seeds."""
    per_seed = auc_per_seed(e4_reference, dataset)
    return per_seed.groupby("model").auroc.agg(["mean", "std", "count"]).reset_index()


def auc_per_seed(e4_reference: pd.DataFrame, dataset: str) -> pd.DataFrame:
    """Columns model, seed, auroc: mean over families of the known-scenario AUROC for one seed."""
    r = e4_reference[e4_reference.dataset == dataset]
    return r.groupby(["model", "seed"]).auroc.mean().reset_index()


def seeds_of(long: pd.DataFrame, dataset: str) -> list[int]:
    return sorted(int(s) for s in long[long.dataset == dataset].seed.unique())


def worst_case_mutation(mutation: pd.DataFrame, query: str = "score") -> pd.DataFrame:
    """Per (dataset, seed, model, fpr, family, budget label): recall after the worst attacker of the query mode.

    For the score query the minimum over greedy, strong and transfer; the label query has one attacker.
    Also returns the recall of each attacker (columns greedy, strong, transfer, label where present).
    """
    m = mutation[mutation.query_mode == query].copy()
    m["budget"] = m.groups + ",x" + m.multiplier.map(lambda v: f"{v:g}")
    key = ["dataset", "seed", "model", "fpr", "family", "budget"]
    per = m.pivot_table(index=key, columns="attacker", values="recall_after", aggfunc="first")
    per = per.reset_index()
    cols = [c for c in ("greedy", "strong", "transfer", "label") if c in per.columns]
    per["recall_worst"] = per[cols].min(axis=1, skipna=True)
    before = m.groupby(["dataset", "seed", "model", "fpr", "family"]).recall_before.first().reset_index()
    per = per.merge(before, on=["dataset", "seed", "model", "fpr", "family"], how="left")
    return per


def build_recall_tables(long: pd.DataFrame, mutation: pd.DataFrame, dataset: str,
                        models=DEFENDERS, fprs=FPRS, mutation_query: str = "score",
                        seed: int | None = None) -> dict[str, dict[float, RecallTable]]:
    """RecallTable per model and FPR for one dataset: seed-averaged, or one seed when ``seed`` is given."""
    excl = set(excluded_families(long, dataset))
    d = long[(long.dataset == dataset) & ~long.family.isin(excl)]
    if seed is not None:
        d = d[d.seed == seed]
    rec = d.groupby(["model", "fpr", "action"]).recall.mean()
    real = d.groupby(["model", "fpr"]).fpr_realized.mean()
    fams = sorted(d[d.action.str.startswith("reuse(")].family.unique())
    bud = budgets()
    labels = tuple(budget_label(g, m) for g, m in bud)
    units = np.array([budget_units(g, m) for g, m in bud], dtype=float)
    groups = tuple(tuple(g) for g, _ in bud)
    mults = tuple(float(m) for _, m in bud)
    mut = worst_case_mutation(mutation[(mutation.dataset == dataset) & ~mutation.family.isin(excl)],
                              mutation_query)
    if seed is not None:
        mut = mut[mut.seed == seed]
    mrec = mut.groupby(["model", "fpr", "family", "budget"]).recall_worst.mean()
    mrec_d = {k: float(v) for k, v in mrec.items()}
    rec_d = {k: float(v) for k, v in rec.items()}
    real_d = {k: float(v) for k, v in real.items()}
    tables: dict[str, dict[float, RecallTable]] = {}
    for model in models:
        tables[model] = {}
        has_mut = model in set(mut.model)
        for fpr in fprs:
            fk = round(float(fpr), 9)

            def lk(action: str) -> float:
                return rec_d.get((model, fk, action), float("nan"))

            reuse = np.array([lk(f"reuse({f})") for f in fams])
            novel = np.array([lk(f"novel({f})") for f in fams])
            fr = real_d.get((model, fk), float("nan"))
            if has_mut:
                M = np.array([[mrec_d.get((model, fk, f, lab), float("nan")) for lab in labels]
                              for f in fams], dtype=float).reshape(len(fams), len(labels))
                tables[model][fpr] = RecallTable(
                    families=tuple(fams), reuse=reuse, novel=novel, mutate=M, budget_units=units,
                    budget_labels=labels, budget_groups=groups, budget_mults=mults, fpr_real=fr)
            else:
                tables[model][fpr] = RecallTable(
                    families=tuple(fams), reuse=reuse, novel=novel,
                    mutate=np.zeros((len(fams), 0)), budget_units=np.zeros(0), budget_labels=(),
                    fpr_real=fr)
    return tables
