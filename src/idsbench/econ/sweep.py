"""X2 (equilibrium vs AUROC), X3 (sensitivity, Sobol), X4 (AI uplift) and the E4 headline table.

Solver: every equilibrium is the strong Stackelberg solution over the defender's (model, nominal FPR, B) on the
measured tables of one seed (the attacker knows the deployed detector; design 3.3). The mean-table solve is a
secondary row. B runs over a geometric grid (B_GRID); exact ties are not broken by enumeration order.

Tie rules (used by X2 and by indicator b):
  loss tie: two models tie when their losses differ by at most LOSS_TIE_REL (relative);
  AUROC tie: two models tie when the paired difference of their seed-mean AUROC has a 95% bootstrap
  interval over seeds that contains 0, or |mean difference| < AUROC_TOL.
  Rank of a model = 1 + number of models that are significantly better (not tied) on the same measure.

X2: per dataset and attacker query: AUROC, per-seed optimum per model, loss-tied set, Kendall tau with a
    bootstrap CI over seeds; the mean-table solve as a secondary row.
X3: Saltelli/Sobol design (SALib, seed fixed) over log-uniform ranges. Per sample, the equilibrium is solved
    per seed in a random subset of SEEDS_PER_SAMPLE seeds, at lam = 1 and lam = LAM_LOW. Indicators:
    (a) mutate/novel capable action with recall < mean reuse recall - 0.2; (a_weak) reuse of a weak known
    family; (b) the AUROC-tied set and the loss-tied set are disjoint; (c) regret: the lam = 1 optimum costs more
    than 1% above the optimum at lam = LAM_LOW; (c_cfg) the optimal (model, FPR, B) changes; (c_act) the
    capable attacker's action class changes.
X4: AI uplift lam from 1 to 0.01 (20 log points), per seed and on the mean tables.
"""

from __future__ import annotations

import math
import multiprocessing as mp
from dataclasses import asdict, replace
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import kendalltau
from SALib.analyze import sobol as sobol_analyze
from SALib.sample import sobol as sobol_sample

from idsbench.econ.detection_tables import auc_per_seed, build_recall_tables, seeds_of
from idsbench.econ.game import (
    LOSS_TIE_REL, GameParams, equilibrium, model_detail, share_tensor, solve_stack, stack_tables,
)
from idsbench.econ.measure import DATASETS, DEFENDERS
from idsbench.econ.mutation import FPRS

B_GRID = tuple(float(b) for b in np.r_[np.geomspace(10.0, 1e5, 200), np.inf])
FPR_REF = 1e-3
LAM_LOW = 0.05
N_BASE = 4096
SOBOL_SEED = 20261127
SEEDS_PER_SAMPLE = 2
AUROC_TOL = 1e-4
BOOT = 2000
REGRET_REL = 0.01
A_GAP = 0.2
X3_RANGES = {
    "V/P": (0.05, 5.0),          # reference 0.5 (V fixed)
    "L": (100.0, 10_000.0),      # reference 1000
    "w": (0.05, 5.0),            # reference 0.5
    "kM": (10.0, 1000.0),        # reference 100
    "kN": (300.0, 30_000.0),     # reference 3000
    "pi": (0.01, 1.0),           # reference 0.5
    "N_attack": (10.0, 1000.0),  # reference 50
    "cB": (0.2, 20.0),           # reference 2
    "N_benign": (1e5, 1e7),      # reference 1e6
}
CLASSES = ("reuse", "mutate", "novel", "abstain")
EDGE_B = (B_GRID[0], B_GRID[-2], B_GRID[-1])


# ----------------------------------------------------------------------------- helpers
def bootstrap_ci(values, n: int = BOOT, seed: int = 0) -> tuple[float, float, float]:
    """Mean and 95% percentile bootstrap interval over the entries (seeds or samples)."""
    v = np.asarray(values, dtype=float)
    v = v[np.isfinite(v)]
    if len(v) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    means = v[rng.integers(0, len(v), size=(n, len(v)))].mean(axis=1)
    return float(v.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def kendall(a, b) -> float:
    a, b = np.asarray(a, float), np.asarray(b, float)
    if len(a) < 2 or np.ptp(a) == 0 or np.ptp(b) == 0:
        return float("nan")
    return float(kendalltau(a, b).statistic)


def auroc_tie_table(auc: pd.DataFrame) -> dict:
    """auc: rows = seeds, columns = models (seed-level mean AUROC over families). Returns pairwise tie
    flags and mean differences: tie[(m, n)] is True when the paired seed differences have a 95% bootstrap
    interval containing 0, or |mean difference| < AUROC_TOL."""
    tie, diff = {}, {}
    for m in auc.columns:
        for n in auc.columns:
            d = (auc[m] - auc[n]).to_numpy(float)
            mu, lo, hi = bootstrap_ci(d)
            tie[(m, n)] = bool(abs(mu) < AUROC_TOL or (lo <= 0.0 <= hi))
            diff[(m, n)] = mu
    return {"tie": tie, "diff": diff}


def auroc_best_and_tied(auc: pd.DataFrame) -> tuple[str, frozenset]:
    means = auc.mean(axis=0)
    best = str(means.idxmax())
    tt = auroc_tie_table(auc)["tie"]
    return best, frozenset(m for m in auc.columns if tt[(m, best)])


def rank_with_ties(values: dict, tie_fn, better) -> dict:
    """1 + number of models significantly better (not tied) than each model. better(a, b) is True when a
    is better than b on the measure."""
    out = {}
    for m in values:
        out[m] = 1 + sum(1 for n in values if n != m and better(values[n], values[m]) and not tie_fn(m, n))
    return out


def loss_tie_fn(losses: dict):
    def tie(m, n):
        a, b = losses[m], losses[n]
        if not (math.isfinite(a) and math.isfinite(b)):
            return False
        lo = min(a, b)
        return max(a, b) <= lo + LOSS_TIE_REL * abs(lo)
    return tie


def _fmt(x) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "n/a (no attack)"
    return f"{x:.4f}"


def _fmtB(b) -> str:
    return "inf" if math.isinf(b) else f"{b:g}"


def _fmt_money(x) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:,.1f}"


def _params_str(p: GameParams) -> str:
    return ", ".join(f"{k}={v:g}" if isinstance(v, float) else f"{k}={v}" for k, v in asdict(p).items())


def _pct_ci(v) -> str:
    m, lo, hi = bootstrap_ci(v)
    if math.isnan(m):
        return "n/a"
    return f"{m:.4f} [{lo:.4f}, {hi:.4f}]"


def _mode(values) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "n/a"
    u, c = np.unique(np.asarray(vals, dtype=object).astype(str), return_counts=True)
    return str(u[int(np.argmax(c))])


def _seeds_tables(long, mutation, ds, query, seeds):
    return {s: build_recall_tables(long, mutation, ds, mutation_query=query, seed=s) for s in seeds}


# ----------------------------------------------------------------------------- X2
def run_x2(long: pd.DataFrame, mutation: pd.DataFrame, e4_reference: pd.DataFrame,
           params: GameParams, query: str) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    p = replace(params, attacker_query=query)
    rows, eq_rows, notes = [], [], []
    for ds in DATASETS:
        seeds = seeds_of(long, ds)
        auc = auc_per_seed(e4_reference, ds).pivot(index="seed", columns="model", values="auroc")[list(DEFENDERS)]
        auc_mean = auc.mean(axis=0)
        best_auc, auc_tied = auroc_best_and_tied(auc)
        tt = auroc_tie_table(auc)["tie"]
        per_seed_loss, per_seed_det, per_seed_tau, per_seed_eq = {m: [] for m in DEFENDERS}, {m: [] for m in DEFENDERS}, [], []
        per_seed_model_det = {m: [] for m in DEFENDERS}
        eq_det, eq_loss, eq_model, eq_tied, edges_B, edges_f = [], [], [], [], [], []
        tie_counts = {m: 0 for m in DEFENDERS}
        class_counts = {}
        for s in seeds:
            S = stack_tables(build_recall_tables(long, mutation, ds, mutation_query=query, seed=s), p, B_GRID)
            out = solve_stack(S, p)
            eq = equilibrium(S, p, out)
            losses = {m: eq["model_loss"].get(m, math.inf) for m in DEFENDERS}
            tie_fn = loss_tie_fn(losses)
            aucs = {m: float(auc.loc[s, m]) for m in DEFENDERS}
            r_auc = rank_with_ties(aucs, lambda a, b: auroc_tie_fn(tt, a, b), lambda a, b: a > b)
            r_loss = rank_with_ties(losses, tie_fn, lambda a, b: a < b)
            per_seed_tau.append(kendall([-r_auc[m] for m in DEFENDERS], [-r_loss[m] for m in DEFENDERS]))
            for m in DEFENDERS:
                if m in eq["model_t"]:
                    md = model_detail(S, out, eq, m)
                    per_seed_loss[m].append(md["loss"])
                    per_seed_model_det[m].append(md["p_eq"])
                else:
                    per_seed_loss[m].append(math.inf)
                    per_seed_model_det[m].append(float("nan"))
            for m in eq["tied_models"]:
                tie_counts[m] += 1
            eq_det.append(eq["p_eq"]); eq_loss.append(eq["loss"]); eq_model.append(eq["model"])
            eq_tied.append("+".join(sorted(eq["tied_models"])))
            edges_B.append(eq["edge_B"]); edges_f.append(eq["edge_fpr"])
            class_counts[eq["capable_class"]] = class_counts.get(eq["capable_class"], 0) + 1
        # Secondary: the mean-table solve.
        Sm = stack_tables(build_recall_tables(long, mutation, ds, mutation_query=query), p, B_GRID)
        om = solve_stack(Sm, p)
        em = equilibrium(Sm, p, om)
        mean_losses = {m: em["model_loss"].get(m, math.inf) for m in DEFENDERS}
        r_auc_mean = rank_with_ties({m: float(auc_mean[m]) for m in DEFENDERS},
                                    lambda a, b: auroc_tie_fn(tt, a, b), lambda a, b: a > b)
        r_loss_mean = rank_with_ties(mean_losses, loss_tie_fn(mean_losses), lambda a, b: a < b)
        tau_m, tau_lo, tau_hi = bootstrap_ci(per_seed_tau)
        for m in DEFENDERS:
            lm, llo, lhi = bootstrap_ci(per_seed_loss[m])
            dm, dlo, dhi = bootstrap_ci(per_seed_model_det[m])
            md_mean = model_detail(Sm, om, em, m) if m in em["model_t"] else None
            rows.append({
                "dataset": ds, "attacker_query": query, "model": m,
                "auc_mean": float(auc_mean[m]), "auc_sd_over_seeds": float(auc[m].std(ddof=1)),
                "auroc_tied_with_best": m in auc_tied, "auroc_best": best_auc,
                "loss_mean": lm, "loss_ci_lo": llo, "loss_ci_hi": lhi,
                "detection_mean": dm, "detection_ci_lo": dlo, "detection_ci_hi": dhi,
                "share_seeds_in_loss_tied_set": tie_counts[m] / len(seeds),
                "mean_table_loss": md_mean["loss"] if md_mean else float("nan"),
                "mean_table_fpr": md_mean["fpr"] if md_mean else float("nan"),
                "mean_table_B": md_mean["B"] if md_mean else float("nan"),
                "mean_table_detection": md_mean["p_eq"] if md_mean else float("nan"),
                "mean_table_avg_reuse_recall": md_mean["mean_reuse"] if md_mean else float("nan"),
                "mean_table_min_capable_recall": md_mean["min_capable_recall"] if md_mean else float("nan"),
                "auc_rank_tied": r_auc_mean[m], "loss_rank_tied_mean_table": r_loss_mean[m],
                "in_mean_table_tied_set": m in em["tied_models"],
            })
        notes.append(
            f"{ds} ({query}): Kendall tau(AUROC rank, loss rank), tie-aware, per seed mean "
            f"{tau_m:.3f} [bootstrap 95%: {tau_lo:.3f}, {tau_hi:.3f}] over {len(seeds)} seeds; "
            f"mean-table tau {kendall([-r_auc_mean[m] for m in DEFENDERS], [-r_loss_mean[m] for m in DEFENDERS]):.3f}. "
            f"AUROC-best model {best_auc}; AUROC-tied set {sorted(auc_tied)}.")
        dm, dlo, dhi = bootstrap_ci(eq_det)
        lm, llo, lhi = bootstrap_ci(eq_loss)
        eq_rows.append({
            "dataset": ds, "attacker_query": query, "n_seeds": len(seeds),
            "eq_model_mode": _mode(eq_model), "eq_model_counts": "; ".join(
                f"{m}:{eq_model.count(m)}" for m in DEFENDERS if m in eq_model),
            "eq_tied_set_mode": _mode(eq_tied), "eq_detection_mean": dm, "eq_detection_ci_lo": dlo,
            "eq_detection_ci_hi": dhi, "eq_loss_mean": lm, "eq_loss_ci_lo": llo, "eq_loss_ci_hi": lhi,
            "capable_class_mode": _mode(list(np.repeat(list(class_counts), list(class_counts.values())))),
            "share_seeds_on_B_edge": float(np.mean(edges_B)), "share_seeds_on_fpr_edge": float(np.mean(edges_f)),
            "kendall_tau_mean": tau_m, "kendall_tau_ci_lo": tau_lo, "kendall_tau_ci_hi": tau_hi,
            "mean_table_eq_model": em["model"], "mean_table_eq_fpr": em["fpr"], "mean_table_eq_B": em["B"],
            "mean_table_eq_detection": em["p_eq"], "mean_table_eq_loss": em["loss"],
            "mean_table_eq_tied_set": "+".join(sorted(em["tied_models"])),
            "mean_table_kendall_tau": kendall([-r_auc_mean[m] for m in DEFENDERS],
                                              [-r_loss_mean[m] for m in DEFENDERS]),
        })
    return pd.DataFrame(rows), pd.DataFrame(eq_rows), notes


def auroc_tie_fn(tt: dict, a: str, b: str) -> bool:
    return bool(tt[(a, b)])


def write_x2(df: pd.DataFrame, eq: pd.DataFrame, notes: list[str], path: Path, params: GameParams) -> None:
    lines = ["# X2 equilibrium loss versus AUROC", "",
             f"Reference parameters (illustrative, see GameParams): {_params_str(params)}.", "",
             "Primary: per seed, the equilibrium is solved on that seed's recall tables (the attacker knows the "
             "deployed detector). Each model's optimum is the lowest loss over its FPR and B (defender solves "
             "with that model only). Loss is reported as mean and bootstrap 95% interval over seeds. "
             "'Loss-tied share' is the share of seeds in which the model is in the loss-tied set (within "
             f"{LOSS_TIE_REL:.0%} of the lowest loss). AUROC: mean over families of the known-scenario AUROC; "
             "tied with the best when the paired difference over seeds has a 95% bootstrap interval containing "
             f"0 or |mean difference| < {AUROC_TOL:g}. Secondary: the solve on seed-mean tables.", ""]
    for q in ("score", "label"):
        lines += [f"## Attacker query: {q}", ""]
        for ds in DATASETS:
            g = df[(df.dataset == ds) & (df.attacker_query == q)]
            e = eq[(eq.dataset == ds) & (eq.attacker_query == q)].iloc[0]
            lines += [f"### {ds}", "",
                      "| model | AUROC (mean ± sd) | AUROC-tied with best | loss, per seed (mean [95% CI]) | "
                      "loss-tied share | detection, per seed (mean [95% CI]) | mean-table loss | mean-table opt FPR, B | "
                      "mean-table in loss-tied set |",
                      "|---|---|---|---|---|---|---|---|---|"]
            for r in g.itertuples(index=False):
                lines.append(
                    f"| {r.model} | {r.auc_mean:.4f} ± {r.auc_sd_over_seeds:.4f} | "
                    f"{'yes' if r.auroc_tied_with_best else 'no'} | {r.loss_mean:,.1f} "
                    f"[{r.loss_ci_lo:,.1f}, {r.loss_ci_hi:,.1f}] | {r.share_seeds_in_loss_tied_set:.2f} | "
                    f"{_fmt(r.detection_mean)} [{_fmt(r.detection_ci_lo)}, {_fmt(r.detection_ci_hi)}] | "
                    f"{_fmt_money(r.mean_table_loss)} | {r.mean_table_fpr:g}, {_fmtB(r.mean_table_B)} | "
                    f"{'yes' if r.in_mean_table_tied_set else 'no'} |")
            lines += ["", f"Per-seed equilibrium over {e.n_seeds} seeds: modal model {e.eq_model_mode} "
                      f"({e.eq_model_counts}); modal loss-tied set {e.eq_tied_set_mode}; detection "
                      f"{e.eq_detection_mean:.4f} [{e.eq_detection_ci_lo:.4f}, {e.eq_detection_ci_hi:.4f}]; loss "
                      f"{e.eq_loss_mean:,.1f} [{e.eq_loss_ci_lo:,.1f}, {e.eq_loss_ci_hi:,.1f}]; modal capable class "
                      f"{e.capable_class_mode}; optimum on a B-grid edge in {e.share_seeds_on_B_edge:.2f} of seeds, "
                      f"on an FPR-grid edge in {e.share_seeds_on_fpr_edge:.2f}.", "",
                      f"Secondary (seed-mean tables): model {e.mean_table_eq_model}, FPR {e.mean_table_eq_fpr:g}, "
                      f"B {_fmtB(e.mean_table_eq_B)}, detection {_fmt(e.mean_table_eq_detection)}, loss "
                      f"{e.mean_table_eq_loss:,.1f}; loss-tied set {e.mean_table_eq_tied_set}.", ""]
    lines += ["## Kendall tau (AUROC rank vs loss rank, 5 models, tie-aware)", ""]
    lines += [f"- {n}" for n in notes]
    lines += ["", "Loss is the defender's expected loss per day (currency), at the optimum over configurations."]
    path.write_text("\n".join(lines) + "\n")
    pd.concat([df, eq.assign(model="EQUILIBRIUM")], ignore_index=True).to_csv(path.with_suffix(".csv"),
                                                                             index=False)


# ----------------------------------------------------------------------------- X3
def _x3_problem() -> dict:
    names = list(X3_RANGES)
    return {"num_vars": len(names), "names": names,
            "bounds": [[math.log10(X3_RANGES[k][0]), math.log10(X3_RANGES[k][1])] for k in names]}


def _sample_params(base: GameParams, kw: dict, efficacy: bool, lam: float) -> GameParams:
    return replace(base, V=base.V, P=base.V / kw["V/P"], L=kw["L"], w=kw["w"], kM=kw["kM"],
                   kN=kw["kN"], pi=kw["pi"], N_attack=kw["N_attack"], cB=kw["cB"],
                   N_benign=kw["N_benign"], efficacy=efficacy, lam=lam)


def _sample_seeds(i: int, seeds: list[int]) -> list[int]:
    rng = np.random.default_rng([SOBOL_SEED, i, 7])
    k = min(SEEDS_PER_SAMPLE, len(seeds))
    return sorted(int(s) for s in rng.choice(seeds, size=k, replace=False))


_CTX: dict = {}


def _x3_eval(i: int) -> list[dict]:
    """Per-seed indicator rows for Sobol sample i (uses the context set before the fork)."""
    c = _CTX
    kw = dict(zip(c["names"], c["theta"][i]))
    base = c["base"]
    p1 = _sample_params(base, kw, c["efficacy"], lam=1.0)
    pL = _sample_params(base, kw, c["efficacy"], lam=LAM_LOW)
    res = []
    for s in _sample_seeds(i, c["seeds"]):
        S = c["stacks"][s]
        pm = share_tensor(S, p1)                    # shared by lam = 1 and lam = LAM_LOW
        out1 = solve_stack(S, p1, pm)
        e1 = equilibrium(S, p1, out1)
        outL = solve_stack(S, pL, pm)
        eL = equilibrium(S, pL, outL)
        t1, g1 = e1["t"], e1["g"]
        loss_low_d1 = float(outL["loss"][t1, g1])
        attacked = bool(e1["attacked"])
        r_star, mean_reuse = e1["capable_recall"], e1["mean_reuse"]
        weak = attacked and math.isfinite(mean_reuse) and r_star < mean_reuse - A_GAP
        cls = e1["capable_class"]
        row = {"seed": s, "eq_loss": e1["loss"], "eq_model": e1["model"], "eq_fpr": e1["fpr"], "eq_B": e1["B"],
               "eq_detection": e1["p_eq"], "capable_class": cls, "capable_recall": r_star,
               "mean_reuse_recall": mean_reuse, "attacked": attacked,
               "a_mut_nov": float(weak and cls in ("mutate", "novel")),
               "a_weak_reuse": float(weak and cls == "reuse"),
               "b_auroc_disjoint": float(len(c["auc_tied"] & e1["tied_models"]) == 0),
               "c_regret": float(loss_low_d1 > eL["loss"] * (1.0 + REGRET_REL)),
               "c_cfg": float((e1["model"], e1["fpr"], e1["B"]) != (eL["model"], eL["fpr"], eL["B"])),
               "c_act": float(cls != eL["capable_class"]),
               "lam_low_loss_of_d1": loss_low_d1, "lam_low_loss": eL["loss"],
               "lam_low_model": eL["model"], "lam_low_fpr": eL["fpr"], "lam_low_B": eL["B"],
               "lam_low_class": eL["capable_class"],
               "edge_B": float(e1["edge_B"]), "edge_fpr": float(e1["edge_fpr"]),
               "n_tied_models": len(e1["tied_models"]),
               "tied_models": "+".join(sorted(e1["tied_models"]))}
        for m in DEFENDERS:
            row[f"tied_{m}"] = float(m in e1["tied_models"])
        for k in CLASSES:
            row[f"class_{k}"] = float(cls == k)
        res.append(row)
    return res


def _x3_chunk(idx: list[int]) -> list[tuple[int, list[dict]]]:
    return [(i, _x3_eval(i)) for i in idx]


def _run_samples(n_samples: int, workers: int) -> list[tuple[int, list[dict]]]:
    chunks = [list(range(k, n_samples, workers * 8)) for k in range(workers * 8)]
    chunks = [c for c in chunks if c]
    if workers <= 1:
        return [r for c in chunks for r in _x3_chunk(c)]
    with mp.get_context("fork").Pool(workers) as pool:
        parts = pool.map(_x3_chunk, chunks, chunksize=1)
    return [r for part in parts for r in part]


def run_x3(long: pd.DataFrame, mutation: pd.DataFrame, e4_reference: pd.DataFrame, base: GameParams,
           efficacy: bool, n_base: int = N_BASE, workers: int = 1) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Sobol design and per-sample indicators for one efficacy setting. Returns (sample table, sobol table)."""
    problem = _x3_problem()
    names = problem["names"]
    theta = 10 ** sobol_sample.sample(problem, n_base, calc_second_order=False, seed=SOBOL_SEED)
    rows, sob_rows = [], []
    q = base.attacker_query
    for ds in DATASETS:
        seeds = seeds_of(long, ds)
        auc = auc_per_seed(e4_reference, ds).pivot(index="seed", columns="model", values="auroc")[list(DEFENDERS)]
        _, auc_tied = auroc_best_and_tied(auc)
        stacks = {}
        for s in seeds:
            stacks[s] = stack_tables(build_recall_tables(long, mutation, ds, mutation_query=q, seed=s),
                                     replace(base, efficacy=efficacy), B_GRID)
        _CTX.clear()
        _CTX.update({"names": names, "theta": theta, "base": base, "efficacy": efficacy,
                     "seeds": seeds, "stacks": stacks, "auc_tied": set(auc_tied)})
        results = _run_samples(len(theta), workers)
        for i, rs in sorted(results, key=lambda x: x[0]):
            kw = dict(zip(names, theta[i]))
            for r in rs:
                rows.append({"dataset": ds, "efficacy": efficacy, "sample": i,
                             **{k: float(v) for k, v in kw.items()}, "P": base.V / kw["V/P"], **r})
        df_ds = pd.DataFrame([r for r in rows if r["dataset"] == ds and r["efficacy"] == efficacy])
        sob_rows += _sobol_rows(problem, df_ds, ds, efficacy, n_base)
    _CTX.clear()
    return pd.DataFrame(rows), pd.DataFrame(sob_rows)


def _sample_level(df: pd.DataFrame, n_base: int) -> dict[str, np.ndarray]:
    """Sample-level outputs: mean over the sample's seeds (log10 of the mean loss)."""
    g = df.groupby("sample", sort=True)
    out = {"log10_loss": np.log10(g.eq_loss.mean().to_numpy(float)),
           "a_mut_nov": g.a_mut_nov.mean().to_numpy(float),
           "b_auroc_disjoint": g.b_auroc_disjoint.mean().to_numpy(float),
           "c_regret": g.c_regret.mean().to_numpy(float)}
    for m in DEFENDERS:
        out[f"tied_{m}"] = g[f"tied_{m}"].mean().to_numpy(float)
    for c in CLASSES:
        out[f"class_{c}"] = g[f"class_{c}"].mean().to_numpy(float)
    return out


def _sobol_rows(problem, df: pd.DataFrame, ds: str, efficacy: bool, n_base: int) -> list[dict]:
    rows = []
    outs = _sample_level(df, n_base)
    for name, Y in outs.items():
        prev = float(np.nanmean(Y)) if name != "log10_loss" else float("nan")
        if name != "log10_loss" and (prev < 0.05 or prev > 0.95):
            rows.append({"dataset": ds, "efficacy": efficacy, "output": name, "parameter": "*",
                         "S1": float("nan"), "S1_conf": float("nan"), "ST": float("nan"), "ST_conf": float("nan"),
                         "output_mean": prev, "output_var": float(np.nanvar(Y)), "status": "dropped (prevalence)"})
            continue
        if np.nanstd(Y) == 0:
            res = {"S1": np.full(problem["num_vars"], np.nan), "S1_conf": np.full(problem["num_vars"], np.nan),
                   "ST": np.full(problem["num_vars"], np.nan), "ST_conf": np.full(problem["num_vars"], np.nan)}
        else:
            r = sobol_analyze.analyze(problem, Y, calc_second_order=False, num_resamples=100, conf_level=0.95,
                                      print_to_console=False, seed=SOBOL_SEED)
            res = {k: np.asarray(r[k]) for k in ("S1", "S1_conf", "ST", "ST_conf")}
        for j, par in enumerate(problem["names"]):
            rows.append({"dataset": ds, "efficacy": efficacy, "output": name, "parameter": par,
                         "S1": float(res["S1"][j]), "S1_conf": float(res["S1_conf"][j]),
                         "ST": float(res["ST"][j]), "ST_conf": float(res["ST_conf"][j]),
                         "output_mean": float(np.nanmean(Y)), "output_var": float(np.nanvar(Y)),
                         "status": "kept"})
    return rows


def x3_fractions(df: pd.DataFrame) -> dict:
    """Per dataset and efficacy setting: fraction of sample-seeds for each indicator, with bootstrap CIs over
    samples (the sample is the resampling unit)."""
    out = {}
    for (ds, eff), g in df.groupby(["dataset", "efficacy"]):
        per_sample = g.groupby("sample")
        f = {"n": int(len(g)), "n_samples": int(g["sample"].nunique())}
        f["attack_share"] = float(g.attacked.mean())
        f["deterrence"] = float(1.0 - g.attacked.mean())
        for k in ("a_mut_nov", "a_weak_reuse", "b_auroc_disjoint", "c_regret", "c_cfg", "c_act"):
            if k in g:
                s = per_sample[k].mean().to_numpy(float)
                m, lo, hi = bootstrap_ci(s)
                f[k] = (m, lo, hi)
        f["edge_B"] = float(g.edge_B.mean())
        f["edge_fpr"] = float(g.edge_fpr.mean())
        out[(ds, bool(eff))] = f
    return out


def _x3_ci(t) -> str:
    return f"{t[0]:.3f} [{t[1]:.3f}, {t[2]:.3f}]"


X3_DROP_COLS = ("tied_models", "lam_low_model", "lam_low_class", "lam_low_fpr", "lam_low_B",
                "lam_low_loss_of_d1", "lam_low_loss")


def write_x3(df: pd.DataFrame, sob: pd.DataFrame, base: GameParams, path: Path, n_base: int,
             seeds_per_sample: int = SEEDS_PER_SAMPLE) -> dict:
    fr = x3_fractions(df)
    n_samp = n_base * (len(X3_RANGES) + 2)
    lines = ["# X3 sensitivity of the qualitative conclusions", "",
             f"Sobol design (SALib sobol sampler, seed {SOBOL_SEED}): N = {n_base} base points, "
             f"{n_samp} samples per dataset and efficacy setting; first-order (S1) and total (ST) indices from "
             "SALib's analysis with 95% bootstrap confidence intervals (100 resamples). Log-uniform ranges: " +
             "; ".join(f"{k} in [{a:g}, {b:g}]" for k, (a, b) in X3_RANGES.items()) +
             f". Fixed: V = {base.V:g}, novel mode = {base.novel_mode}, attacker query = {base.attacker_query}. "
             f"Each sample is solved per seed on a random subset of {seeds_per_sample} of the 10 seeds (the "
             "per-seed tables; the subset is drawn per sample, so seed variation enters the outputs). "
             f"lam = 1 for the optimum and lam = {LAM_LOW:g} for indicator (c). Efficacy is run as a separate "
             "setting (off, on).", "",
             "Indicators (share of sample-seeds; bootstrap 95% interval over samples):", "",
             "- (a) mut_nov: the capable attacker's chosen action is mutate or novel and its recall is more than "
             f"{A_GAP} below the mean reuse recall of the chosen model and FPR;",
             f"- (a_weak) weak known family exploited: the chosen action is reuse(f) and its recall is more than "
             f"{A_GAP} below the mean reuse recall (reported separately);",
             "- (b) the AUROC-tied set and the loss-tied set are disjoint (AUROC ties: paired-seed bootstrap);",
             f"- (c) regret: the lam = 1 optimum costs more than {REGRET_REL:.0%} above the optimal loss at "
             f"lam = {LAM_LOW:g};",
             f"- (c_cfg) the optimal (model, FPR, B) differs between lam = 1 and lam = {LAM_LOW:g} (old indicator);",
             f"- (c_act) the capable attacker's action class differs between the two optima (comparison);",
             "- deterrence: the capable attacker abstains at the optimum.", "",
             "Grid edges: share of sample-seeds whose optimum is on the B grid edge (B = 10, 1e5 or inf) or on the "
             "FPR grid edge (5e-4 or 1e-2).", "",
             "| dataset | efficacy | n (sample-seeds) | (a) mut_nov | (a_weak) | attack share | deterrence | (b) | "
             "(c) regret | (c_cfg) | (c_act) | B edge | FPR edge |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for (ds, eff), f in fr.items():
        lines.append(f"| {ds} | {'on' if eff else 'off'} | {f['n']} | {_x3_ci(f['a_mut_nov'])} | "
                     f"{_x3_ci(f['a_weak_reuse'])} | {f['attack_share']:.3f} | {f['deterrence']:.3f} | "
                     f"{_x3_ci(f['b_auroc_disjoint'])} | {_x3_ci(f['c_regret'])} | {_x3_ci(f['c_cfg'])} | "
                     f"{_x3_ci(f['c_act'])} | {f['edge_B']:.3f} | {f['edge_fpr']:.3f} |")
    lines += ["", "## Sobol indices (S1 ± 95% CI / ST ± 95% CI), per dataset and efficacy setting", ""]
    for (ds, eff) in fr:
        g = sob[(sob.dataset == ds) & (sob.efficacy == eff)]
        lines += [f"### {ds}, efficacy {'on' if eff else 'off'}", "",
                  "| output | status | output mean | output variance | " +
                  " | ".join(f"{p}: S1 / ST" for p in X3_RANGES) + " |",
                  "|---|---|---|---|" + "---|" * len(X3_RANGES)]
        for o in g.output.unique():
            h = g[g.output == o]
            status = h.status.iloc[0]
            if status.startswith("dropped"):
                lines.append(f"| {o} | {status} (mean {h.output_mean.iloc[0]:.3f}) | | | " +
                             " | ".join("" for _ in X3_RANGES) + " |")
                continue
            h = h.set_index("parameter")
            mean, var = h.output_mean.iloc[0], h.output_var.iloc[0]
            cells = [f"{_ci(h.loc[p, 'S1'], h.loc[p, 'S1_conf'])} / {_ci(h.loc[p, 'ST'], h.loc[p, 'ST_conf'])}"
                     for p in X3_RANGES]
            lines.append(f"| {o} | {status} | {mean:.4f} | {var:.4g} | " + " | ".join(cells) + " |")
        lines.append("")
    path.write_text("\n".join(lines) + "\n")
    # The per-sample table is large; keep the columns the summary needs, gzip-compressed.
    df.drop(columns=[c for c in X3_DROP_COLS if c in df.columns]).to_csv(
        path.with_name("x3.csv.gz"), index=False, float_format="%.6g", compression="gzip")
    sob.to_csv(path.with_name("x3_sobol.csv"), index=False)
    return fr


def _ci(x, c) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "n/a"
    return f"{x:.3f} ± {c:.3f}" if c == c else f"{x:.3f}"


# ----------------------------------------------------------------------------- X4
def run_x4(long: pd.DataFrame, mutation: pd.DataFrame, params: GameParams) -> pd.DataFrame:
    lams = np.logspace(0, -2, 20)
    rows = []
    for ds in DATASETS:
        seeds = seeds_of(long, ds)
        stacks = {s: stack_tables(build_recall_tables(long, mutation, ds, mutation_query=params.attacker_query,
                                                      seed=s), params, B_GRID) for s in seeds}
        mean_stack = stack_tables(build_recall_tables(long, mutation, ds, mutation_query=params.attacker_query),
                                  params, B_GRID)
        loss1 = {}
        for lam in lams:
            p = replace(params, lam=float(lam))
            seed_eq = []
            for s in seeds:
                e = equilibrium(stacks[s], p)
                if s not in loss1 and lam == lams[0]:
                    loss1[s] = e["loss"]
                seed_eq.append((s, e))
            rows.append(_x4_row(ds, lam, seed_eq, loss1, False))
            em = equilibrium(mean_stack, p)
            rows.append(_x4_mean_row(ds, lam, em))
    return pd.DataFrame(rows)


def _x4_row(ds, lam, seed_eq, loss1, _):
    losses = [e["loss"] for _, e in seed_eq]
    price = [e["loss"] / loss1[s] for s, e in seed_eq]
    det = [e["p_eq"] for _, e in seed_eq]
    lm, llo, lhi = bootstrap_ci(losses)
    pm, plo, phi = bootstrap_ci(price)
    dm, dlo, dhi = bootstrap_ci(det)
    return {"dataset": ds, "lam": float(lam), "row": "per-seed", "n_seeds": len(seed_eq),
            "opt_model_mode": _mode([e["model"] for _, e in seed_eq]),
            "opt_fpr_mode": _mode([f"{e['fpr']:g}" for _, e in seed_eq]),
            "opt_B_mode": _mode([_fmtB(e["B"]) for _, e in seed_eq]),
            "capable_class_mode": _mode([e["capable_class"] for _, e in seed_eq]),
            "capable_class_shares": "; ".join(f"{c}:{sum(1 for _, e in seed_eq if e['capable_class'] == c)}"
                                              for c in CLASSES if any(e['capable_class'] == c for _, e in seed_eq)),
            "eq_loss_mean": lm, "eq_loss_ci_lo": llo, "eq_loss_ci_hi": lhi,
            "price_of_uplift_mean": pm, "price_ci_lo": plo, "price_ci_hi": phi,
            "eq_detection_mean": dm, "eq_detection_ci_lo": dlo, "eq_detection_ci_hi": dhi,
            "share_seeds_on_B_edge": float(np.mean([e["edge_B"] for _, e in seed_eq])),
            "share_seeds_on_fpr_edge": float(np.mean([e["edge_fpr"] for _, e in seed_eq]))}


def _x4_mean_row(ds, lam, e):
    return {"dataset": ds, "lam": float(lam), "row": "mean-table", "n_seeds": 1,
            "opt_model_mode": e["model"], "opt_fpr_mode": f"{e['fpr']:g}", "opt_B_mode": _fmtB(e["B"]),
            "capable_class_mode": e["capable_class"], "capable_class_shares": "", "eq_loss_mean": e["loss"],
            "eq_loss_ci_lo": float("nan"), "eq_loss_ci_hi": float("nan"), "price_of_uplift_mean": float("nan"),
            "price_ci_lo": float("nan"), "price_ci_hi": float("nan"), "eq_detection_mean": e["p_eq"],
            "eq_detection_ci_lo": float("nan"), "eq_detection_ci_hi": float("nan"),
            "share_seeds_on_B_edge": float(e["edge_B"]), "share_seeds_on_fpr_edge": float(e["edge_fpr"])}


def switch_points(x4: pd.DataFrame) -> dict[str, list[tuple[float, str, str]]]:
    """Per dataset, the geometric midpoints of lam where the modal capable action class changes (per-seed rows)."""
    out = {}
    for ds, g in x4[x4.row == "per-seed"].groupby("dataset"):
        g = g.sort_values("lam", ascending=False).reset_index(drop=True)
        sw = []
        for i in range(1, len(g)):
            if g.capable_class_mode[i] != g.capable_class_mode[i - 1]:
                sw.append((math.sqrt(g.lam[i] * g.lam[i - 1]), g.capable_class_mode[i - 1], g.capable_class_mode[i]))
        out[ds] = sw
    return out


def write_x4(x4: pd.DataFrame, sw: dict, path: Path, params: GameParams) -> None:
    lines = ["# X4 AI uplift lam from 1 to 0.01 (20 log points)", "",
             f"Reference parameters: {_params_str(params)}. Primary rows: the equilibrium is solved per seed "
             "(modes over seeds, mean and bootstrap 95% interval over seeds). Price of uplift = loss(lam) / loss(1) "
             "for the same seed. Mean-table rows are the secondary solve on seed-mean tables.", ""]
    for ds, g in x4.groupby("dataset"):
        lines += [f"## {ds}", "", "| lam | row | optimal model (mode) | FPR (mode) | B (mode) | loss (mean [95% CI]) | "
                  "price of uplift (mean [95% CI]) | eq detection (mean [95% CI]) | capable class (mode; seed counts) | "
                  "B-edge share | FPR-edge share |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in g.itertuples(index=False):
            loss = _fmt_money(r.eq_loss_mean) + (f" [{_fmt_money(r.eq_loss_ci_lo)}, {_fmt_money(r.eq_loss_ci_hi)}]"
                                                 if r.row == "per-seed" else "")
            price = "n/a" if math.isnan(r.price_of_uplift_mean) else (
                f"{r.price_of_uplift_mean:.3f} [{r.price_ci_lo:.3f}, {r.price_ci_hi:.3f}]"
                if r.row == "per-seed" else "n/a")
            det = _fmt(r.eq_detection_mean) + (f" [{_fmt(r.eq_detection_ci_lo)}, {_fmt(r.eq_detection_ci_hi)}]"
                                               if r.row == "per-seed" else "")
            shares = f"; {r.capable_class_shares}" if r.capable_class_shares else ""
            lines.append(f"| {r.lam:.4g} | {r.row} | {r.opt_model_mode} | {r.opt_fpr_mode} | {r.opt_B_mode} | "
                         f"{loss} | {price} | {det} | {r.capable_class_mode}{shares} | "
                         f"{r.share_seeds_on_B_edge:.2f} | {r.share_seeds_on_fpr_edge:.2f} |")
        lines.append("")
        pts = sw.get(ds, [])
        lines.append("Capable-attacker modal class switches (lam at the geometric midpoint): " +
                     ("; ".join(f"{a} -> {b} at lam = {m:.3g}" for m, a, b in pts) or "none") + ".")
        lines.append("")
    path.write_text("\n".join(lines) + "\n")
    x4.to_csv(path.with_suffix(".csv"), index=False)


# ----------------------------------------------------------------------------- E4 headline
def e4_headline(mutation: pd.DataFrame, query: str = "score", fpr: float = FPR_REF) -> pd.DataFrame:
    """Per dataset, model and family at one FPR: recall before the attack, and after the best budget of each
    attacker (lowest mean over seeds), plus the worst case (minimum over attackers per budget and seed)."""
    m = mutation[np.isclose(mutation.fpr, fpr) & (mutation.query_mode == query)].copy()
    m["budget"] = m.groups + ",x" + m.multiplier.map(lambda v: f"{v:g}")
    before = m.groupby(["dataset", "model", "family", "seed"]).recall_before.first()
    attackers = sorted(m.attacker.unique())
    rows = []
    for (ds, mod, fam), _ in before.groupby(level=[0, 1, 2]):
        b_vals = before.loc[(ds, mod, fam)].to_numpy()
        row = {"dataset": ds, "model": mod, "family": fam,
               "recall_before_mean": float(np.mean(b_vals)),
               "recall_before_sd": float(np.std(b_vals, ddof=1)) if len(b_vals) > 1 else float("nan"),
               "n_seeds": int(len(b_vals))}
        per_att = {}
        for a in attackers:
            sub = m[(m.dataset == ds) & (m.model == mod) & (m.family == fam) & (m.attacker == a)]
            if sub.empty:
                continue
            pb = sub.groupby(["budget", "seed"]).recall_after.mean()
            by_budget = pb.groupby(level="budget").mean()
            best = by_budget.idxmin()
            after = pb.xs(best, level="budget").to_numpy()
            per_att[a] = (best, after)
            row[f"{a}_best_budget"] = best
            row[f"{a}_recall_after_mean"] = float(np.mean(after))
            row[f"{a}_recall_after_sd"] = float(np.std(after, ddof=1)) if len(after) > 1 else float("nan")
        if per_att:
            worst = m[(m.dataset == ds) & (m.model == mod) & (m.family == fam)
                      & m.attacker.isin(attackers)].groupby(["budget", "seed"]).recall_after.min()
            wb = worst.groupby(level="budget").mean().idxmin()
            wa = worst.xs(wb, level="budget").to_numpy()
            row["worst_budget"] = wb
            row["worst_recall_after_mean"] = float(np.mean(wa))
            row["worst_recall_after_sd"] = float(np.std(wa, ddof=1)) if len(wa) > 1 else float("nan")
        rows.append(row)
    return pd.DataFrame(rows)


def write_headline(h: pd.DataFrame, path: Path, query: str) -> None:
    h.to_csv(path.with_suffix(".csv"), index=False)
    def pm(m, s):
        if m is None or (isinstance(m, float) and math.isnan(m)):
            return "n/a"
        return f"{m:.3f} ± {s:.3f}" if s == s else f"{m:.3f}"

    lines = [f"# E4 headline: recall before and after the attack (FPR {FPR_REF:g}, query = {query})", "",
             "Recall of attack flows at the defender's threshold (known scenario). For each attacker the budget "
             "with the lowest mean recall over seeds is shown (the best budget for that attacker); mean ± sd over "
             "seeds. The worst case takes, per budget and seed, the minimum over the attackers of the query mode, "
             "then the best budget. Attackers: greedy (the E4 greedy, score access), strong (per-group level "
             "search, score access), transfer (strong attack found on xgb, submitted to the model; not run for "
             "xgb itself). The label attacker is a weak baseline (query = label) and appears only in the label "
             "file.", "",
             "| dataset | model | family | recall before | greedy: best budget, after | strong: best budget, after | "
             "transfer: best budget, after | worst case: best budget, after | seeds |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in h.itertuples(index=False):
        def cell(a):
            b = getattr(r, f"{a}_best_budget", None) if hasattr(r, f"{a}_best_budget") else None
            if b is None or (isinstance(b, float) and math.isnan(b)):
                return "n/a"
            return f"{b}: {pm(getattr(r, f'{a}_recall_after_mean'), getattr(r, f'{a}_recall_after_sd'))}"
        wb = getattr(r, "worst_budget", None)
        worst = "n/a" if not isinstance(wb, str) else f"{wb}: {pm(r.worst_recall_after_mean, r.worst_recall_after_sd)}"
        lines.append(f"| {r.dataset} | {r.model} | {r.family} | "
                     f"{pm(r.recall_before_mean, r.recall_before_sd)} | {cell('greedy')} | {cell('strong')} | "
                     f"{cell('transfer')} | {worst} | {r.n_seeds} |")
    path.write_text("\n".join(lines) + "\n")


# ----------------------------------------------------------------------------- SUMMARY
def _verdict(t) -> str:
    """'holds' when the bootstrap interval lies above 0.5, 'does not hold' below it, else 'inconclusive'."""
    m, lo, hi = t
    if lo > 0.5:
        return "holds on most of the grid"
    if hi < 0.5:
        return "does not hold on most of the grid"
    return "inconclusive (interval contains 0.5)"


def write_summary(fr: dict, sob: pd.DataFrame, x2: pd.DataFrame, eq: pd.DataFrame, x4: pd.DataFrame,
                  headline: pd.DataFrame, path: Path, meta: dict) -> None:
    L = []
    L += ["# Summary: game-theoretic evaluation of ML-IDS", ""]
    L += [f"Profile: {meta['profile']}. E4 and defender seeds {meta['seeds']}; {meta['n_flows']} attack test flows "
          f"per family; benign cap {meta['caps'][0]:,}, family cap {meta['caps'][1]:,}. Sobol base N = "
          f"{meta['n_base']} ({meta['n_base'] * (len(X3_RANGES) + 2)} samples per dataset and efficacy setting), "
          f"{SEEDS_PER_SAMPLE} random seeds per sample. FPR grid {FPRS}; B grid: 200 geometric points in "
          f"[10, 1e5] plus infinity. Attacker-excluded families (fewer than 300 test flows in a seed): "
          + "; ".join(f"{k}: {', '.join(v) or 'none'}" for k, v in meta["excluded"].items()) + ".", ""]
    L += ["## What changed in this round", "",
          "- Derived features are recomputed by delta updates (Flow IAT Mean, Fwd IAT Mean, Down/Up Ratio, "
          "Packet Length Variance/Std) or approximated and labelled (Fwd Packet Length Std, Flow IAT Std/Min). "
          "min_seg_size_forward is removed from the length group. Identity hold rates: `e4_feature_groups.md`.",
          "- xgb_robustfeat uses an explicit robust column list (no mutated, derived or timing/size-dependent column).",
          "- The FPR grid has 5e-4 added; the capacity grid is 200 geometric points plus infinity; the defender "
          "optimum is exact on that grid; edge hits are reported.",
          "- Exact ties are reported as sets (loss within 1%; AUROC within paired-seed noise), not broken by order.",
          "- The realised benign-test FPR of each threshold enters the alert volume A.",
          "- Attackers: greedy, strong (per-group level search, two starts) and transfer from xgb, for every "
          "model. The game uses the worst case over the score attackers. The label attacker is a weak, "
          "non-adaptive baseline.",
          "- Equilibria are solved per seed on each seed's own recall tables; the seed-mean solve is a secondary row.",
          "- Sobol outputs and indicators: see X3 below. Indicator (a) covers mutate and novel actions only; reuse "
          "of a weak known family is reported separately.", ""]
    L += ["## Headline E4 (xgb and xgb_adv, FPR 1e-3, score query)", "",
          "Recall of attack flows before and after the attack (mean ± sd over seeds). After = worst case over "
          "greedy, strong and transfer, at the budget that is worst on average.", "",
          "| dataset | model | family | recall before | worst-case recall after | budget |", "|---|---|---|---|---|---|"]
    hl = headline[headline.model.isin(["xgb", "xgb_adv"])]
    for r in hl.itertuples(index=False):
        wa = getattr(r, "worst_recall_after_mean", float("nan"))
        ws = getattr(r, "worst_recall_after_sd", float("nan"))
        wb = getattr(r, "worst_budget", "n/a")
        L.append(f"| {r.dataset} | {r.model} | {r.family} | {r.recall_before_mean:.3f} ± {r.recall_before_sd:.3f} | "
                 f"{wa:.3f} ± {ws:.3f} | {wb} |" if not math.isnan(wa) else
                 f"| {r.dataset} | {r.model} | {r.family} | {r.recall_before_mean:.3f} | n/a | n/a |")
    L += ["", "Full table with per-attacker columns: `e4_headline.md`.", ""]
    L += ["## X2: equilibrium loss versus AUROC (score query)", ""]
    for ds in DATASETS:
        g = x2[(x2.dataset == ds) & (x2.attacker_query == "score")]
        e = eq[(eq.dataset == ds) & (eq.attacker_query == "score")].iloc[0]
        L += [f"### {ds}", "", "| model | AUROC | AUROC-tied with best | loss per seed (mean [95% CI]) | loss-tied share |",
              "|---|---|---|---|---|"]
        for r in g.itertuples(index=False):
            L.append(f"| {r.model} | {r.auc_mean:.4f} | {'yes' if r.auroc_tied_with_best else 'no'} | "
                     f"{r.loss_mean:,.1f} [{r.loss_ci_lo:,.1f}, {r.loss_ci_hi:,.1f}] | "
                     f"{r.share_seeds_in_loss_tied_set:.2f} |")
        L += ["", f"Kendall tau (AUROC rank vs loss rank, tie-aware) per seed: {e.kendall_tau_mean:.3f} "
              f"[{e.kendall_tau_ci_lo:.3f}, {e.kendall_tau_ci_hi:.3f}]. Modal equilibrium model {e.eq_model_mode} "
              f"({e.eq_model_counts}); optimum on a B-grid edge in {e.share_seeds_on_B_edge:.2f} of seeds, on an FPR edge "
              f"in {e.share_seeds_on_fpr_edge:.2f}.", ""]
    L += ["Label-query X2 tables: `x2.md`.", ""]
    L += ["## X3: sensitivity (fractions of the sample grid, bootstrap 95% CI over samples)", "",
          "Conclusions use the interval: 'holds' when the lower bound is above 0.5, 'does not hold' when the upper "
          "bound is below 0.5, otherwise inconclusive.", ""]
    for (ds, eff), f in fr.items():
        tag = f"{ds}, efficacy {'on' if eff else 'off'}"
        L += [f"- {tag} (n = {f['n']} sample-seeds):",
              f"  - (a) mutate/novel capable action with recall more than {A_GAP} below mean reuse recall: "
              f"{_verdict(f['a_mut_nov'])}, {_x3_ci(f['a_mut_nov'])}.",
              f"  - weak known family exploited (reuse, same gap): {_x3_ci(f['a_weak_reuse'])}.",
              f"  - (b) AUROC-tied and loss-tied sets disjoint: {_verdict(f['b_auroc_disjoint'])}, "
              f"{_x3_ci(f['b_auroc_disjoint'])}.",
              f"  - (c) regret > {REGRET_REL:.0%} from keeping the lam = 1 optimum at lam = {LAM_LOW:g}: "
              f"{_verdict(f['c_regret'])}, {_x3_ci(f['c_regret'])}.",
              f"  - (c_cfg) optimal (model, FPR, B) changes (old indicator): {_x3_ci(f['c_cfg'])}; "
              f"(c_act) capable action class changes: {_x3_ci(f['c_act'])}.",
              f"  - deterrence (capable attacker abstains): {f['deterrence']:.3f}; grid edges: B {f['edge_B']:.3f}, "
              f"FPR {f['edge_fpr']:.3f}."]
    L += ["", "Dataset note: the CSE-CIC-IDS2018 equilibrium is driven by the Infiltration family, whose recall is "
          "about 0.12 for xgb (reuse) and is known to be label-noisy; treat the 2018 conclusions as conditional on "
          "that family. The weak-family and mutate/novel fractions in the table above are not separated by family.",
          ""]
    L += ["## Sobol drivers (ST with 95% CI; S1 in x3.md)", ""]
    for (ds, eff) in fr:
        g = sob[(sob.dataset == ds) & (sob.efficacy == eff) & (sob.status == "kept")]
        L += [f"### {ds}, efficacy {'on' if eff else 'off'}", ""]
        for o in g.output.unique():
            h = g[g.output == o].sort_values("ST", ascending=False).head(3)
            L.append(f"- {o}: " + "; ".join(f"{r.parameter} ST {r.ST:.3f} ± {r.ST_conf:.3f}" for r in h.itertuples()))
        dropped = sob[(sob.dataset == ds) & (sob.efficacy == eff) & sob.status.str.startswith("dropped")]
        if len(dropped):
            L.append("- dropped (prevalence < 5% or > 95%): " + ", ".join(dropped.output.unique()))
        L.append("")
    L += ["## X4: AI uplift", ""]
    sw = switch_points(x4)
    for ds, g in x4[x4.row == "per-seed"].groupby("dataset"):
        pts = sw.get(ds, [])
        L.append(f"- {ds}: modal capable class switches: " +
                 ("; ".join(f"{a} -> {b} at lam = {m:.3g}" for m, a, b in pts) or "none"))
    L += ["- The cicids2017 novelty switch equals V/kN by construction when the worst unseen-family recall is about 0: "
          "novel is then undetected, its utility is V - lam kN, and the attacker switches when lam kN = V. "
          "With V = 1000 and kN = 3000 this is lam = 0.333.", ""]
    L += ["## Thesis claim 3 (not tested)", "",
          "Claim 3 of the design (defender investment moves from supervised accuracy towards novelty detection, label "
          "budget and analyst capacity as AI uplift grows) is NOT tested by this model set. The defender's "
          "choices here are over five detectors and FPR and B only; no novelty-detection investment, label budget "
          "or learning-with-labels option is in the action space. The lam sweep shows how the optimum changes, "
          "but not that a shift toward novelty detection is optimal.", ""]
    L += ["## Label-mode attacker", "",
          "The label-mode attacker (alert / no alert only, one random order per flow, its RNG keyed on the budget "
          "label and seed) is a weak, non-adaptive baseline. It is reported in `e4_headline_label.md` and in the "
          "X2 label tables, not in the game's primary tables.", ""]
    L += ["## Limitations", "",
          "- Feature space only: mutations change CICFlowMeter feature vectors, not packets. Problem-space "
          "realisability is not established (arXiv 2005.07519).",
          "- Lab datasets (CIC-IDS2017, CSE-CIC-IDS2018). The AI-uplift results are for these two captures only.",
          "- Reference parameters (V, P, L, w, cB, kM, kN, N_benign, N_attack) are illustrative. Conclusions rest on "
          "the X3 intervals over the sampled ranges, not on point values.",
          "- Identity rules hold on a share of rows (see `e4_feature_groups.md`); the rest keep their offset (delta "
          "update). Fwd Packet Length Std, Flow IAT Std and Flow IAT Min are approximations that cannot be checked "
          "on the cache.",
          "- Only increase-only timing and padding are modelled; the attacker cannot reduce any feature.",
          "- Efficacy is a stated assumption (timing mutation reduces the gain of DoS, DDoS, BruteForce and PortScan "
          "by 1/m). The defender's breach loss L is not scaled by efficacy.",
          "- The alert volume uses the realised benign-test FPR of each threshold, so A = fpr_real N_benign + N_attack.",
          "- Adversarial training (xgb_adv) uses one augmentation round at the full budget (multiplier 5) against "
          "the base xgb; it is evaluated against the greedy, strong and transfer attackers.",
          "- Seeds: 10 for E4 and leave-one-family-out. X2 and X4 use every seed; X3 uses "
          f"{SEEDS_PER_SAMPLE} random seeds per sample (compute). Bootstrap CIs resample seeds (X2, X4) or samples (X3).",
          "- Only the feature-space E4 measurement feeds the game; E3 transfer rows are not in the game.",
          "- Infiltration (CSE-CIC-IDS2018) is label-noisy and drives the 2018 equilibrium (recall about 0.12).", ""]
    L += ["## Runtime and deviations", ""] + [f"- {x}" for x in meta.get("notes", [])] + [""]
    path.write_text("\n".join(L) + "\n")
