"""Robustness study: E4 matrix, defenders, realism diagnostics, statistics, game (secondary) and SUMMARY.

    python -m idsbench.robust.run_all [--quick] [--out DIR] [--datasets ...] [--seeds N] [--flows N]
                                      [--lofo all|reduced] [--skip-game] [--game-base N] [--summary-only]

Writes into DIR (default results/robust): robust_thresholds.csv, robust_clean.csv, robust_e4.csv.gz,
robust_mutben.csv, robust_identity.csv, robust_fingerprint.csv, robust_rq2_matched.csv, robust_curves.csv/.md,
robust_linf.csv, robust_headline.csv, robust_stats.csv, robust_run.json and SUMMARY.md; the game goes to DIR/game/.

All tables and SUMMARY.md are built from the CSV files, so ``--summary-only`` rebuilds them without rerunning the
simulation. Hand-written text (research questions, limitations, deviations) is read from DIR/summary_text.md and
appended to SUMMARY.md when it exists.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

from idsbench.robust.defenders import E4_MODELS, MODELS
from idsbench.robust.evaluate import ATTACKER_MIN_TEST, FPRS, run_seed, wilson
from idsbench.robust.gen2 import BUDGETS

OUT = Path("results/robust")
DATASETS = ("cicids2017", "cicids2018")
INFILTRATION = "Infiltration"   # label-noisy family of CSE-CIC-IDS2018 (reported with and without)
FPR_REF = 1e-3
RNG_CI = 20261127
RUN_FILE = "robust_run.json"
TEXT_FILE = "summary_text.md"


@dataclass(frozen=True)
class Config:
    seeds: tuple = tuple(range(10))
    n_flows: int = 1000
    benign_cap: int = 600_000
    family_cap: int = 10_000
    n_aug: int = 2000
    lofo_models: tuple = MODELS
    datasets: tuple = DATASETS


QUICK = Config(seeds=(0,), n_flows=100, benign_cap=150_000, family_cap=2000, n_aug=300)


def boot_ci(v, n=2000):
    v = np.asarray(v, dtype=float)
    v = v[np.isfinite(v)]
    if len(v) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(RNG_CI)
    means = v[rng.integers(0, len(v), size=(n, len(v)))].mean(axis=1)
    return float(v.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def fmt_ci(t, digits=3):
    m, lo, hi = t
    if not math.isfinite(m):
        return "n/a"
    return f"{m:.{digits}f} [{lo:.{digits}f}, {hi:.{digits}f}]"


def fmt_sci_ci(t):
    m, lo, hi = t
    if not math.isfinite(m):
        return "n/a"
    return f"{m:.2e} [{lo:.2e}, {hi:.2e}]"


def holm(pvals):
    p = np.asarray(pvals, dtype=float)
    order = np.argsort(p)
    m = len(p)
    adj = np.empty(m)
    run = 0.0
    for rank, i in enumerate(order):
        run = max(run, (m - rank) * p[i])
        adj[i] = min(1.0, run)
    return adj


# ----------------------------------------------------------------------------- tables
def per_family_worst(e4: pd.DataFrame, fpr: float, exclude: str | None = None) -> pd.DataFrame:
    """Per (dataset, seed, model, generator, family): minimum recall over attackers and budgets."""
    d = e4[np.isclose(e4.fpr, fpr)]
    if exclude is not None:
        d = d[d.family != exclude]
    return d.groupby(["dataset", "seed", "model", "generator", "family"]).recall_after.min().reset_index(
        name="worst")


def headline_table(clean, e4, mutben, thr, dataset: str, fpr: float = FPR_REF) -> pd.DataFrame:
    """Per (seed, model) and variant ('all' families, or 'no_infiltration'): clean macro recall, worst-case recall per
    generator, mutated-benign FPR per generator, realised benign-test FPR. The mutated-benign FPR is computed on the
    benign test rows, which do not depend on the attack family, so it is identical in both variants."""
    out = []
    for variant, excl in (("all", None), ("no_infiltration", INFILTRATION)):
        c = clean[(clean.dataset == dataset) & np.isclose(clean.fpr, fpr) & (clean.kind == "known")]
        if excl is not None:
            c = c[c.family != excl]
        cm = c.groupby(["seed", "model"]).recall.mean().reset_index().rename(columns={"recall": "clean_recall"})
        w = per_family_worst(e4[e4.dataset == dataset], fpr, excl)
        for g in ("G1", "G2"):
            wg = w[w.generator == g].groupby(["seed", "model"]).worst.mean().reset_index(name=f"worst_{g}")
            cm = cm.merge(wg, on=["seed", "model"], how="left")
        mb = mutben[(mutben.dataset == dataset) & np.isclose(mutben.fpr, fpr) & (mutben["mode"] == "random")]
        for g in ("G1", "G2"):
            mg = mb[mb.generator == g][["seed", "model", "fpr_mut"]].rename(columns={"fpr_mut": f"mutben_fpr_{g}"})
            cm = cm.merge(mg, on=["seed", "model"], how="left")
        t = thr[(thr.dataset == dataset) & np.isclose(thr.fpr, fpr)][
            ["seed", "model", "k_test_alerts", "n_benign_test", "fpr_test_realised"]]
        cm = cm.merge(t, on=["seed", "model"], how="left")
        cm["variant"] = variant
        out.append(cm)
    h = pd.concat(out, ignore_index=True)
    h["dataset"] = dataset
    return h


def stats_table(head: pd.DataFrame) -> pd.DataFrame:
    """Wilcoxon signed-rank over seeds (paired), Holm within each dataset and metric family."""
    comps = [("adv_naive_G1", "adv_sym_G1"), ("adv_sym_G1", "adv_sym_G1G2"), ("adv_sym_G1G2", "xgb"),
             ("adv_naive_G1", "adv_sym_G1G2")]
    metrics = ["worst_G2", "mutben_fpr_G1", "mutben_fpr_G2", "worst_G1"]
    rows = []
    for ds, h in head[head.variant == "all"].groupby("dataset"):
        for met in metrics:
            if met not in h:
                continue
            tab = h.pivot(index="seed", columns="model", values=met)
            recs = []
            for a, b in comps:
                if a not in tab or b not in tab:
                    continue
                x = tab[a].to_numpy(float)
                y = tab[b].to_numpy(float)
                ok = np.isfinite(x) & np.isfinite(y)
                x, y = x[ok], y[ok]
                diff = x - y
                if len(diff) < 2 or np.all(diff == 0):
                    p = float("nan")
                else:
                    p = float(wilcoxon(x, y, zero_method="wilcox").pvalue)
                mu, lo, hi = boot_ci(diff)
                recs.append({"dataset": ds, "metric": met, "a": a, "b": b, "n_seeds": int(len(diff)),
                             "mean_diff_a_minus_b": mu, "ci_lo": lo, "ci_hi": hi, "p_wilcoxon": p})
            if recs:
                adj = holm([r["p_wilcoxon"] if np.isfinite(r["p_wilcoxon"]) else 1.0 for r in recs])
                for r, a_ in zip(recs, adj):
                    r["p_holm"] = float(a_)
                rows += recs
    return pd.DataFrame(rows)


def rq2_table(rq2: pd.DataFrame) -> pd.DataFrame:
    """Per (dataset, nominal FPR): xgb_robust against xgb at matched realised calibration FPR. Paired over seeds."""
    rows = []
    for ds, g0 in rq2.groupby("dataset"):
        recs = []
        for fpr, g in g0.groupby("fpr"):
            g = g.sort_values("seed")
            diff = (g.recall_xgb_matched - g.recall_ref).to_numpy(float)
            if len(g) > 1 and np.any(diff != 0):
                p = float(wilcoxon(g.recall_xgb_matched, g.recall_ref, zero_method="wilcox").pvalue)
            else:
                p = float("nan")
            mu, lo, hi = boot_ci(diff)
            ref, mat, nom = (boot_ci(g[c]) for c in ("recall_ref", "recall_xgb_matched", "recall_xgb_nominal"))
            recs.append({
                "dataset": ds, "fpr": fpr, "n_seeds": len(g), "exact_matches": int(g.matched_exact.sum()),
                "fpr_cal_ref": g.fpr_cal_ref.mean(), "fpr_cal_xgb": g.fpr_cal_xgb.mean(),
                "fpr_test_ref": g.fpr_test_ref.mean(), "fpr_test_xgb": g.fpr_test_xgb.mean(),
                "recall_ref": ref, "recall_xgb": mat, "recall_xgb_nominal": nom,
                "diff": (mu, lo, hi), "p": p})
        adj = holm([r["p"] if np.isfinite(r["p"]) else 1.0 for r in recs])
        for r, a_ in zip(recs, adj):
            r["p_holm"] = float(a_)
        rows += recs
    return pd.DataFrame(rows)


def curves_table(e4: pd.DataFrame, clean: pd.DataFrame, fpr: float = FPR_REF):
    """Recall versus budget: worst case over attackers and group subsets at each multiplier, mean over seeds."""
    d = e4[np.isclose(e4.fpr, fpr)]
    w = d.groupby(["dataset", "seed", "model", "generator", "family", "multiplier"]).recall_after.min().reset_index()
    cur = w.groupby(["dataset", "model", "generator", "family", "multiplier"]).recall_after.agg(
        ["mean", "std", "count"]).reset_index().rename(columns={"mean": "worst_recall", "std": "sd", "count": "n_seeds"})
    c = clean[np.isclose(clean.fpr, fpr) & (clean.kind == "known")]
    base = c.groupby(["dataset", "model", "family"]).recall.mean().reset_index(name="clean_recall")
    cur = cur.merge(base, on=["dataset", "model", "family"], how="left")
    # Smallest multiplier at which the family's worst-case recall is below 0.5.
    rows = []
    for key, g in cur.groupby(["dataset", "model", "generator", "family"]):
        below = g[g.worst_recall < 0.5].multiplier
        rows.append({"dataset": key[0], "model": key[1], "generator": key[2], "family": key[3],
                     "smallest_multiplier_below_0.5": float(below.min()) if len(below) else float("nan")})
    return cur, pd.DataFrame(rows)


def curves_md(cur: pd.DataFrame, first: pd.DataFrame) -> str:
    L = ["# Recall versus budget (FPR 1e-3)", "",
         "Worst case over attackers (greedy, strong, transfer) and group subsets at each multiplier; mean over seeds. "
         "Clean recall = known scenario, no attack. The last column is the smallest multiplier at which the worst-case "
         "recall drops below 0.5 (none: never below 0.5 in the grid).", ""]
    for ds, g in cur.groupby("dataset"):
        L += [f"## {ds}", ""]
        for gen in ("G1", "G2"):
            L += [f"### generator {gen}", "",
                  "| model | family | clean | x1.5 | x2 | x5 | smallest x below 0.5 |", "|---|---|---|---|---|---|---|"]
            for (m, f), h in g[g.generator == gen].groupby(["model", "family"]):
                vals = {r.multiplier: r.worst_recall for r in h.itertuples()}
                fb = first[(first.dataset == ds) & (first.model == m) & (first.generator == gen) & (first.family == f)]
                sm = fb["smallest_multiplier_below_0.5"].iloc[0] if len(fb) else float("nan")
                cl = h.clean_recall.iloc[0]
                L.append(f"| {m} | {f} | {cl:.3f} | {vals.get(1.5, float('nan')):.3f} | "
                         f"{vals.get(2.0, float('nan')):.3f} | {vals.get(5.0, float('nan')):.3f} | "
                         f"{'none' if not np.isfinite(sm) else f'{sm:g}'} |")
            L.append("")
    return "\n".join(L) + "\n"


def linf_table(dist: dict, dataset: str) -> pd.DataFrame:
    rows = []
    for (gname, mult, groups), arrs in dist.items():
        v = np.concatenate(arrs) if arrs else np.array([])
        if len(v) == 0:
            continue
        rows.append({"dataset": dataset, "generator": gname, "multiplier": mult, "groups": groups,
                     "n_flows": int(len(v)), "linf_median": float(np.median(v)),
                     "linf_p90": float(np.quantile(v, 0.9))})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- driver
def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m idsbench.robust.run_all")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--datasets", nargs="*", default=list(DATASETS))
    ap.add_argument("--seeds", type=int, default=None, help="number of seeds (0..n-1)")
    ap.add_argument("--flows", type=int, default=None)
    ap.add_argument("--lofo", choices=["all", "reduced"], default="all",
                    help="reduced: LOFO only for xgb, fusion, xgb_robust (adv models: adv_sym_G1G2 only)")
    ap.add_argument("--skip-game", action="store_true")
    ap.add_argument("--game-base", type=int, default=128)
    ap.add_argument("--summary-only", action="store_true",
                    help="rebuild the tables, the game and SUMMARY.md from the CSV files in --out")
    args = ap.parse_args(argv)
    if args.summary_only:
        out = Path(args.out) if args.out else OUT
        run = json.loads((out / RUN_FILE).read_text())
        summarise(out, run, game=not args.skip_game, n_base=(16 if run["quick"] else args.game_base))
        print(f"[robust] summary rebuilt in {out}", flush=True)
        return
    cfg = QUICK if args.quick else Config()
    seeds = tuple(range(args.seeds)) if args.seeds else cfg.seeds
    if args.flows:
        cfg = Config(**{**cfg.__dict__, "n_flows": args.flows})
    lofo = ("xgb", "fusion", "xgb_robust", "adv_sym_G1G2") if args.lofo == "reduced" else MODELS
    if args.lofo == "reduced":
        lofo = tuple(m for m in MODELS if m in ("xgb", "fusion", "iforest", "xgb_robust", "adv_sym_G1G2"))
    cfg = Config(**{**cfg.__dict__, "seeds": seeds, "lofo_models": lofo, "datasets": tuple(args.datasets)})
    out = Path(args.out) if args.out else (OUT / "quick" if args.quick else OUT)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    print(f"[robust] config {cfg}", flush=True)

    allrows = {k: [] for k in ("thr", "clean", "e4", "mutben", "ident", "rq2")}
    fp_rows, cross_rows, linf_parts = [], [], []
    for ds in cfg.datasets:
        dist_all: dict = {}
        for seed in cfg.seeds:
            res = run_seed(ds, seed, cfg, log=lambda s: print(s, flush=True))
            for k in allrows:
                allrows[k] += res["rows"][k]
            for key, arrs in res["dist"].items():
                dist_all.setdefault(key, []).extend(arrs)
            print(f"[robust] {ds} seed {seed} finished at {(time.time() - t0) / 60:.1f} min", flush=True)
        linf_parts.append(linf_table(dist_all, ds))
        _fingerprint_dataset(ds, cfg, out, fp_rows, cross_rows)
        _write_partial(out, allrows, fp_rows, cross_rows, linf_parts)

    _write_partial(out, allrows, fp_rows, cross_rows, linf_parts)
    run = {"seeds": list(cfg.seeds), "n_flows": cfg.n_flows, "benign_cap": cfg.benign_cap,
           "family_cap": cfg.family_cap, "n_aug": cfg.n_aug, "lofo_models": list(cfg.lofo_models),
           "datasets": list(cfg.datasets), "quick": bool(args.quick), "game_base": int(args.game_base),
           "minutes": (time.time() - t0) / 60}
    (out / RUN_FILE).write_text(json.dumps(run, indent=2) + "\n")
    summarise(out, run, game=not args.skip_game, n_base=(16 if args.quick else args.game_base))
    print(f"[robust] all done in {(time.time() - t0) / 60:.1f} min -> {out}", flush=True)


def summarise(out: Path, run: dict, game: bool, n_base: int) -> None:
    """Tables, game and SUMMARY.md from the CSV files in ``out``."""
    thr = pd.read_csv(out / "robust_thresholds.csv")
    clean = pd.read_csv(out / "robust_clean.csv")
    e4 = pd.read_csv(out / "robust_e4.csv.gz")
    mutben = pd.read_csv(out / "robust_mutben.csv")
    ident = pd.read_csv(out / "robust_identity.csv")
    fp_all = pd.read_csv(out / "robust_fingerprint.csv")
    linf = pd.read_csv(out / "robust_linf.csv")
    rq2 = pd.read_csv(out / "robust_rq2_matched.csv")
    datasets = tuple(run["datasets"])
    head = pd.concat([headline_table(clean, e4, mutben, thr, ds) for ds in datasets], ignore_index=True)
    head.to_csv(out / "robust_headline.csv", index=False)
    stats = stats_table(head)
    stats.to_csv(out / "robust_stats.csv", index=False)
    cur, first = curves_table(e4, clean)
    cur.to_csv(out / "robust_curves.csv", index=False)
    (out / "robust_curves.md").write_text(curves_md(cur, first))
    first.to_csv(out / "robust_curves_first_below_half.csv", index=False)
    print("[robust] tables written", flush=True)
    if game:
        from idsbench.econ.robust_game import run_game
        run_game(out, out / "game", datasets=datasets, n_base=n_base, quick=bool(run["quick"]))
        print("[robust] game written", flush=True)
    fp = fp_all[fp_all.fingerprint_auroc.notna()]
    cross = fp_all[fp_all.cross_auroc.notna()]
    r2 = rq2_table(rq2)
    write_summary(out, run, head, thr, stats, cur, first, fp, cross, linf, ident, rq2, r2)


def _fingerprint_dataset(ds, cfg, out, fp_rows, cross_rows):
    """Fingerprint diagnostics on the benign training rows of seed 0 (realism section 3.3)."""
    from idsbench.feasibility.common import BENIGN, load_binary
    from idsbench.feasibility.e3_crosspair import ALIASES
    from idsbench.econ.mutation import apply_group, build_group_index
    from idsbench.feasibility.e2_lofo import _split_sets
    from idsbench.robust.fingerprint import fingerprint_rows
    from idsbench.robust.gen2 import G2

    seed = cfg.seeds[0]
    X, y, fam_s, _ = load_binary(ds, cap_benign=cfg.benign_cap, cap_per_family=cfg.family_cap, seed=seed)
    sets, _ = _split_sets(fam_s.to_numpy(), seed, 500)
    Xv = X.to_numpy(dtype=float)
    al = ALIASES.get(ds)
    gi = build_group_index(X.columns, al)
    g2 = G2(X.columns, al)
    gens = {"G1": lambda Z, g, lv: apply_group(Z, gi, g, lv), "G2": g2.apply}
    rows, cross = fingerprint_rows(ds, Xv[sets[BENIGN]["train"]], list(X.columns), gens, seed)
    fp_rows += rows
    cross_rows += cross


def _write_partial(out, allrows, fp_rows, cross_rows, linf_parts):
    pd.DataFrame(allrows["thr"]).to_csv(out / "robust_thresholds.csv", index=False)
    pd.DataFrame(allrows["clean"]).to_csv(out / "robust_clean.csv", index=False)
    pd.DataFrame(allrows["e4"]).to_csv(out / "robust_e4.csv.gz", index=False, compression="gzip",
                                       float_format="%.6g")
    pd.DataFrame(allrows["mutben"]).to_csv(out / "robust_mutben.csv", index=False)
    pd.DataFrame(allrows["ident"]).to_csv(out / "robust_identity.csv", index=False)
    pd.DataFrame(allrows["rq2"]).to_csv(out / "robust_rq2_matched.csv", index=False)
    pd.concat([pd.DataFrame(fp_rows), pd.DataFrame(cross_rows)], ignore_index=True).to_csv(
        out / "robust_fingerprint.csv", index=False)
    pd.concat(linf_parts, ignore_index=True).to_csv(out / "robust_linf.csv", index=False)


def write_summary(out, run, head, thr, stats, cur, first, fp, cross, linf, ident, rq2, r2):
    datasets = run["datasets"]
    n_ben = thr.groupby("dataset").n_benign_test.agg(lambda s: int(s.iloc[0]))
    ben_txt = ", ".join(f"{ds} {n_ben[ds]:,}" for ds in datasets if ds in n_ben.index)
    L = ["# Robustness study: SUMMARY", "",
         f"Datasets: {', '.join(datasets)}. Seeds: {run['seeds']}. E4 attack flows per family: {run['n_flows']}. "
         f"Benign cap {run['benign_cap']:,}, family cap {run['family_cap']:,}; split train 60% / calibration 20% / test "
         f"20% (benign), 70/30 (families). Benign test rows per seed: {ben_txt}. Augmentation: n_aug = "
         f"{run['n_aug']} attack copies per family. FPR grid {', '.join(f'{f:g}' for f in FPRS)}. Budgets: 7 group "
         f"subsets x multipliers 1.5, 2, 5 (21) per generator. Attackers: greedy, strong, transfer (from xgb; not for "
         f"xgb). LOFO models: {', '.join(run['lofo_models'])}. Wall-clock time of the run: {run['minutes']:.1f} min. "
         f"Attack-excluded families: test rows < {ATTACKER_MIN_TEST}.", ""]
    L += ["## Realism diagnostics", "", "Fingerprint AUROC (XGBoost separating x from G(x) on benign training rows of "
          "seed 0, held-out half; 0.5 = indistinguishable). Cross-generator AUROC: G1(x) against G2(x) at matched "
          "budgets.", "",
          "| dataset | generator | group | fingerprint AUROC | top features (gain) |", "|---|---|---|---|---|"]
    for r in fp.itertuples():
        top = r.top_features if isinstance(r.top_features, str) else ""
        L.append(f"| {r.dataset} | {r.generator} | {r.group} | {r.fingerprint_auroc:.4f} | {top} |")
    L += ["", "| dataset | pair | cross-generator AUROC |", "|---|---|---|"]
    for r in cross.itertuples():
        L.append(f"| {r.dataset} | {r.pair} | {r.cross_auroc:.4f} |")
    idm = ident.groupby(["dataset", "sample", "rule"]).agg(rows=("rows", "mean"), holds=("holds", "mean")).reset_index()
    L += ["", "Identity hold rates (share of rows where the rule holds; mean over seeds; original flows and flows after "
          "all groups at x5):", "", "| dataset | sample | rule | rows | holds |", "|---|---|---|---|---|"]
    for r in idm.itertuples():
        h = "n/a" if not np.isfinite(r.holds) else f"{r.holds:.4f}"
        L.append(f"| {r.dataset} | {r.sample} | {r.rule} | {r.rows:.0f} | {h} |")

    L += ["", "## Headline table (FPR 1e-3; mean [95% bootstrap CI over seeds])", "",
          "Clean recall: macro over families (known scenario). Worst-case recall: per family the minimum over attackers "
          "and budgets, macro over families. Mutated-benign FPR: benign test flows with random budgets at the clean "
          "threshold. Realised benign-test FPR: the share of benign test flows above the threshold (mean over seeds with "
          "bootstrap CI; pooled over seeds with a Wilson 95% interval on the pooled counts).", "",
          "| dataset | defender | clean recall | worst-case recall G1 | worst-case recall G2 | mutated-benign FPR G1 | "
          "mutated-benign FPR G2 | realised test FPR | realised test FPR, pooled [Wilson 95%] |",
          "|---|---|---|---|---|---|---|---|---|"]
    h_all = head[head.variant == "all"]
    for (ds, m), g in h_all.groupby(["dataset", "model"], sort=False):
        cells = []
        for col in ("clean_recall", "worst_G1", "worst_G2", "mutben_fpr_G1", "mutben_fpr_G2"):
            vals = g.groupby("seed")[col].mean() if col in g else []
            cells.append(fmt_ci(boot_ci(vals), 4 if "fpr" in col else 3))
        cells.append(fmt_sci_ci(boot_ci(g.groupby("seed").fpr_test_realised.mean())))
        k, n = g.k_test_alerts.sum(), g.n_benign_test.sum()
        if np.isfinite(k) and n > 0:
            lo, hi = wilson(k, n)
            cells.append(f"{k / n:.2e} [{lo:.2e}, {hi:.2e}]")
        else:
            cells.append("n/a")
        L.append(f"| {ds} | {m} | " + " | ".join(cells) + " |")

    no_inf = head[(head.variant == "no_infiltration") & (head.dataset == "cicids2018")]
    if len(no_inf):
        L += ["", "## CSE-CIC-IDS2018 without Infiltration (label-noisy family excluded from the macro over families)", "",
              "Same definitions as the headline table, with the Infiltration family removed from the clean and worst-case "
              "macros. The mutated-benign FPR is computed on the benign test rows and the thresholds of the models, which "
              "the family choice does not change, so its values equal the headline values.", "",
              "| defender | clean recall | worst-case recall G1 | worst-case recall G2 | mutated-benign FPR G1 | "
              "mutated-benign FPR G2 |", "|---|---|---|---|---|---|"]
        for m, g in no_inf.groupby("model", sort=False):
            cells = [fmt_ci(boot_ci(g.groupby("seed")[c].mean()), 3 if "fpr" not in c else 4)
                     for c in ("clean_recall", "worst_G1", "worst_G2", "mutben_fpr_G1", "mutben_fpr_G2")]
            L.append(f"| {m} | " + " | ".join(cells) + " |")

    L += ["", "## Matched realised FPR: xgb against xgb_robust (RQ2)", "",
          "For each seed and nominal FPR, xgb's threshold is set on the calibration scores of cal_full so that it alerts on "
          "the same number of calibration flows as xgb_robust's plateau-aware threshold, as far as the distinct scores "
          "allow (`exact` counts seeds where the match is exact). Both are scored on the known-family test flows, macro "
          "over families, mean over seeds with bootstrap CI. The difference is xgb (matched) minus xgb_robust. p is the "
          "paired Wilcoxon p, Holm-adjusted within dataset. Per-seed rows: `robust_rq2_matched.csv`.", "",
          "| dataset | nominal FPR | exact | realised cal FPR (xgb_robust; xgb) | realised test FPR (xgb_robust; xgb) | "
          "clean recall xgb_robust | clean recall xgb matched | difference [CI] | p (Holm) | clean recall xgb at its "
          "nominal threshold |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in r2.itertuples():
        d = r.diff
        L.append(f"| {r.dataset} | {r.fpr:g} | {r.exact_matches}/{r.n_seeds} | "
                 f"{r.fpr_cal_ref:.2e}; {r.fpr_cal_xgb:.2e} | {r.fpr_test_ref:.2e}; {r.fpr_test_xgb:.2e} | "
                 f"{fmt_ci(r.recall_ref)} | {fmt_ci(r.recall_xgb)} | {d[0]:.3f} [{d[1]:.3f}, {d[2]:.3f}] | "
                 f"{r.p_holm:.3f} | {fmt_ci(r.recall_xgb_nominal)} |")

    L += ["", "## Cross-generator gaps (worst-case recall G1 minus G2; mean [CI] over seeds)", "",
          "| dataset | defender | gap G1 - G2 | training generator |", "|---|---|---|---|"]
    trained = {"adv_naive_G1": "G1", "adv_sym_G1": "G1", "adv_sym_G1G2": "G1+G2", "xgb": "none", "xgb_robust": "none",
               "fusion": "none"}
    for (ds, m), g in h_all.groupby(["dataset", "model"], sort=False):
        gap = (g.assign(gap=g.worst_G1 - g.worst_G2)).groupby("seed").gap.mean()
        L.append(f"| {ds} | {m} | {fmt_ci(boot_ci(gap))} | {trained.get(m, '')} |")
    L += ["", "## Statistics (paired over seeds, Wilcoxon signed-rank; Holm within dataset and metric)", "",
          "| dataset | metric | a | b | n seeds | mean diff a - b [CI] | p | p (Holm) |", "|---|---|---|---|---|---|---|---|"]
    for r in stats.itertuples():
        L.append(f"| {r.dataset} | {r.metric} | {r.a} | {r.b} | {r.n_seeds} | {r.mean_diff_a_minus_b:.4f} "
                 f"[{r.ci_lo:.4f}, {r.ci_hi:.4f}] | {r.p_wilcoxon:.4f} | {r.p_holm:.4f} |")
    L += ["", "Minimum two-sided Wilcoxon p with n seeds: 2/2^n (0.031 for 6 seeds, 0.002 for 10).", ""]
    L += ["## Recall versus budget and L-inf distances", "",
          "Full curves: `robust_curves.md` / `robust_curves.csv`. L-inf distance of every mutated attack flow (strong "
          "attacker against xgb) from its original, in signed-log standardised space: z(x) = sign(x) log1p(|x|), divided "
          "by the train-set standard deviation of z per feature (the train mean cancels in the difference). Quantiles "
          "pooled over families and seeds.", "",
          "| dataset | generator | multiplier | groups | flows | median | p90 |", "|---|---|---|---|---|---|---|"]
    for r in linf.sort_values(["dataset", "generator", "multiplier", "groups"]).itertuples():
        L.append(f"| {r.dataset} | {r.generator} | {r.multiplier:g} | {r.groups} | {r.n_flows} | "
                 f"{r.linf_median:.3f} | {r.linf_p90:.3f} |")
    L += ["", "Smallest multiplier at which the worst-case recall of a family drops below 0.5 is in "
          "`robust_curves_first_below_half.csv`.", ""]
    L += ["## Game (secondary, cost lens)", "", "See `game/SUMMARY_GAME.md`.", ""]
    text = out / TEXT_FILE
    if text.exists():
        L += [text.read_text().rstrip(), ""]
    (out / "SUMMARY.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
