"""Packet-level validation study, design v2: per-analysis evaluation, tables and SUMMARY.

    python -m idsbench.pcap.run_all [--quick] [--seeds N] [--flows N] [--summary-only] [--text FILE]
    python -m idsbench.pcap.run_all --robust-columns [--seeds N]     (xgb_robust column list, reads the cache)

Three analyses run in one process, each over the same caches (data/pcap/cache):
  primary          connection flows, primary label rule           -> results/pcap/
  all_flows        every flow, primary label rule (secondary)      -> results/pcap/all_flows/
  drop_ambiguous   connection flows, ambiguous sets dropped (sensitivity) -> results/pcap/drop_ambiguous/
Each analysis writes its CSV tables into its directory. SUMMARY.md in results/pcap is generated from those CSV files,
with the hand-written findings (``--text``) appended at the end.
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

from idsbench.econ.mutation import ROBUST_DROP_DEPENDENT, build_group_index
from idsbench.feasibility.common import BENIGN
from idsbench.feasibility.e2_lofo import _split_sets
from idsbench.robust.defenders import G2_COUPLED, robust_columns
from idsbench.robust.gen2 import TOUCHED
from idsbench.robust.run_all import boot_ci, fmt_ci, holm

from .build import load_cache
from .evaluate import FPR_REF, FPRS, GENERATORS, MIN_FAMILY_ROWS, MODELS, Config, p_changed_columns, run_seed, select_view
from .extract import FEATURES
from .label import LABELS
from .pgen import PGen

OUT = Path("results/pcap")
CACHE_DAYS = ("tuesday", "friday")
FAMILIES = tuple(x for x in LABELS if x != "BENIGN")
BRUTE = ("FTP-Patator", "SSH-Patator")
NO_BOT = tuple(f for f in FAMILIES if f != "Bot")
CONFIGS = {
    "primary": {"population": "connection", "rule": "primary", "dir": OUT},
    "all_flows": {"population": "all", "rule": "primary", "dir": OUT / "all_flows"},
    "drop_ambiguous": {"population": "connection", "rule": "drop", "dir": OUT / "drop_ambiguous"},
}
TABLES = {
    "thresholds": "pcap_thresholds.csv", "clean": "pcap_clean.csv", "e4": "pcap_e4.csv",
    "mutben": "pcap_mutben.csv", "realism": "pcap_realism.csv", "relerr": "pcap_relerr.csv",
    "resplit": "pcap_resplit.csv", "timing": "pcap_timing_check.csv", "population": "pcap_population.csv",
    "dedup": "pcap_dedup.csv",
}
PAIRS = (("xgb", "xgb_robust"), ("xgb", "adv_naive_G1"), ("adv_naive_G1", "adv_sym_G1"),
         ("adv_sym_G1", "adv_sym_G1G2"), ("adv_sym_G1G2", "adv_sym_P"), ("adv_naive_G1", "adv_sym_P"))
QUICK = Config(seed=0, n_flows=100, n_aug=300)
REDUCED_E4_FLOWS = 300
REDUCED_STRONG_LEVELS = 5
REDUCED_STRONG_RESTARTS = 1
TEXT_OVERRIDE = None


# ----------------------------------------------------------------------------- derived tables
def per_family_worst(e4: pd.DataFrame, fpr: float) -> pd.DataFrame:
    d = e4[np.isclose(e4.fpr, fpr)]
    return d.groupby(["seed", "model", "generator", "family"]).recall_after.min().reset_index(name="worst")


def headline(clean, e4, mutben, thr, fpr: float = FPR_REF) -> pd.DataFrame:
    """Per seed and model, for the variants 'all' (five families), 'no_bot' and 'bruteforce' (FTP and SSH)."""
    out = []
    w = per_family_worst(e4, fpr)
    c = clean[np.isclose(clean.fpr, fpr)]
    mb = mutben[(mutben["mode"] == "random") & mutben.generator.isin(GENERATORS)]
    t = thr[np.isclose(thr.fpr, fpr)]
    for variant, fams in (("all", FAMILIES), ("no_bot", NO_BOT), ("bruteforce", BRUTE)):
        cm = c[c.family.isin(fams)].groupby(["seed", "model"]).recall.mean().reset_index(name="clean_recall")
        for g in GENERATORS:
            wg = w[(w.generator == g) & w.family.isin(fams)].groupby(["seed", "model"]).worst.mean().reset_index(
                name=f"worst_{g}")
            cm = cm.merge(wg, on=["seed", "model"], how="left")
        for g in GENERATORS:
            vals = mb[mb.generator == g][["seed"] + [f"fpr_{m}_{fpr:g}" for m in MODELS]]
            long = vals.melt(id_vars="seed", var_name="k", value_name=f"mutben_fpr_{g}")
            long["model"] = long.k.str.replace("fpr_", "", regex=False).str.replace(f"_{fpr:g}", "", regex=False)
            cm = cm.merge(long[["seed", "model", f"mutben_fpr_{g}"]], on=["seed", "model"], how="left")
        cm = cm.merge(t[["seed", "model", "fpr_test_realised"]], on=["seed", "model"], how="left")
        cm["variant"] = variant
        out.append(cm)
    return pd.concat(out, ignore_index=True)


def mutben_seed_table(mutben: pd.DataFrame, fpr: float = FPR_REF) -> pd.DataFrame:
    """Mutated-benign FPR per model, from the per-seed values of the mutated-benign table.

    The benign test pools of the seeds overlap (about 300k pooled rows hold about 234k distinct flows), so pooled Wilson
    intervals are too narrow. The verdict is therefore over seeds: the mean of the per-seed FPR with a percentile
    bootstrap CI over seeds, and a paired comparison with xgb on the same seed (seeds above and below xgb, Wilcoxon
    signed-rank p). Pooled counts are kept as a descriptive column only.

    References: 'clean' (the benign pool, unmutated) and one per generator (random budgets).
    """
    blocks = [("clean", mutben[mutben["mode"] == "clean"])]
    for g in GENERATORS:
        blocks.append((f"mutated_{g}", mutben[(mutben["mode"] == "random") & (mutben["generator"] == g)]))
    rows = []
    for ref, blk in blocks:
        blk = blk.set_index("seed").sort_index()
        xgb_v = blk[f"fpr_xgb_{fpr:g}"].to_numpy(float)
        for m in MODELS:
            v = blk[f"fpr_{m}_{fpr:g}"].to_numpy(float)
            mu, lo, hi = boot_ci(v)
            r = {"reference": ref, "model": m, "n_seeds": int(len(v)), "seed_mean": mu, "boot_ci_lo": lo,
                 "boot_ci_hi": hi, "seeds_above_xgb": np.nan, "seeds_below_xgb": np.nan,
                 "p_wilcoxon_vs_xgb": np.nan, "pooled_k": int(blk[f"k_{m}_{fpr:g}"].sum()),
                 "pooled_n": int(blk["n"].sum())}
            r["pooled_fpr"] = r["pooled_k"] / r["pooled_n"]
            if m != "xgb":
                diff = v - xgb_v
                r["seeds_above_xgb"] = int(np.sum(diff > 0))
                r["seeds_below_xgb"] = int(np.sum(diff < 0))
                if np.any(diff != 0):
                    r["p_wilcoxon_vs_xgb"] = float(wilcoxon(v, xgb_v).pvalue)
            rows.append(r)
    return pd.DataFrame(rows)


def xgb_robust_table(thr: pd.DataFrame, clean: pd.DataFrame, fpr: float = FPR_REF) -> pd.DataFrame:
    """Per seed, the xgb_robust operating point at FPR fpr: threshold (inf when no score exceeds the plateau), realised
    test FPR, clean recall and AUROC per family."""
    t = thr[(thr["model"] == "xgb_robust") & np.isclose(thr["fpr"], fpr)].set_index("seed")
    c = clean[(clean["model"] == "xgb_robust") & np.isclose(clean["fpr"], fpr)]
    rec = c.pivot(index="seed", columns="family", values="recall")
    auc = clean[clean["model"] == "xgb_robust"].groupby(["seed", "family"])["auroc"].first().unstack()
    out = pd.DataFrame({"threshold": t["threshold"], "plateau_moved": t["plateau_moved"],
                        "fpr_test_realised": t["fpr_test_realised"]})
    for f in FAMILIES:
        out[f"recall {f}"] = rec[f]
    for f in FAMILIES:
        out[f"AUROC {f}"] = auc[f]
    return out.reset_index()


def robust_column_table(cache: dict, n_seeds: int, population: str = "connection", rule: str = "primary",
                        log=print) -> pd.DataFrame:
    """Columns of xgb_robust per seed and the reason each one is excluded (design section 5): the G1 mutated set, the
    G1 dependent list, the G2 touched and coupled columns, and the columns P changes on more than 1% of the training
    flows. The first steps of ``evaluate.run_seed`` are repeated here, so the list does not need a full rerun."""
    view, X, label, _ = select_view(cache, population, rule)
    fam = np.asarray([BENIGN] + list(LABELS[1:]))[label]
    gi = build_group_index(FEATURES)
    constant = X.max(axis=0) == X.min(axis=0)
    pool_rows = np.flatnonzero(view["pool_row"] >= 0)
    rows = []
    for seed in range(n_seeds):
        sets, _ = _split_sets(fam, seed, MIN_FAMILY_ROWS)
        pool_train = np.intersect1d(sets[BENIGN]["train"], pool_rows)
        pg = PGen(view, X, seed)
        changed = [c.lower() for c in p_changed_columns(X, sets, pool_train, pg, seed, log)]
        excluded = {
            "G1": set(gi.mutated_idx().tolist()),
            "G1 dependent": set(gi.idx(ROBUST_DROP_DEPENDENT).tolist()),
            "G2 touched": set(gi.idx(list(TOUCHED)).tolist()),
            "G2 coupled": set(gi.idx(list(G2_COUPLED)).tolist()),
            "P": set(gi.idx(changed).tolist()),
        }
        kept = set(robust_columns(gi, list(TOUCHED) + changed).tolist())
        for j, name in enumerate(FEATURES):
            why = "+".join(k for k, s in excluded.items() if j in s)
            if (j in kept) != (why == ""):
                raise RuntimeError(f"seed {seed}: column {name} exclusion reasons disagree with robust_columns")
            rows.append({"seed": seed, "feature": name, "kept": bool(j in kept), "excluded_by": why or "none",
                         "constant_in_population": bool(constant[j])})
    return pd.DataFrame(rows)


def curves(e4: pd.DataFrame, fpr: float = FPR_REF) -> pd.DataFrame:
    d = e4[np.isclose(e4.fpr, fpr)]
    w = d.groupby(["seed", "model", "generator", "family", "multiplier"]).recall_after.min().reset_index()
    cur = w.groupby(["model", "generator", "family", "multiplier"]).recall_after.agg(["mean", "std", "count"])
    return cur.reset_index().rename(columns={"mean": "worst_recall_mean", "std": "sd", "count": "n_seeds"})


def stats_table(head: pd.DataFrame) -> pd.DataFrame:
    """Wilcoxon signed-rank over seeds (paired); Holm across the pairs of each metric; variant 'all'."""
    h = head[head.variant == "all"]
    rows = []
    for met in ("worst_P", "worst_G1", "worst_G2", "mutben_fpr_P", "mutben_fpr_G1", "mutben_fpr_G2", "clean_recall"):
        tab = h.pivot(index="seed", columns="model", values=met)
        recs = []
        for a, b in PAIRS:
            if a not in tab or b not in tab:
                continue
            x, y = tab[a].to_numpy(float), tab[b].to_numpy(float)
            ok = np.isfinite(x) & np.isfinite(y)
            x, y = x[ok], y[ok]
            diff = x - y
            p = float(wilcoxon(x, y, zero_method="wilcox").pvalue) if len(diff) > 1 and np.any(diff != 0) else float("nan")
            mu, lo, hi = boot_ci(diff)
            recs.append({"metric": met, "a": a, "b": b, "n_seeds": int(len(diff)), "mean_diff_a_minus_b": mu,
                         "ci_lo": lo, "ci_hi": hi, "p_wilcoxon": p})
        if recs:
            adj = holm([r["p_wilcoxon"] if np.isfinite(r["p_wilcoxon"]) else 1.0 for r in recs])
            for r, q in zip(recs, adj):
                r["p_holm"] = float(q)
            rows += recs
    return pd.DataFrame(rows)


def per_family_table(e4, clean, fpr: float = FPR_REF) -> pd.DataFrame:
    """Per family and model: clean recall, worst case under G1, G2 and P (means over seeds)."""
    c = clean[np.isclose(clean.fpr, fpr)].groupby(["family", "model"]).recall.mean().reset_index(name="clean")
    w = per_family_worst(e4, fpr).groupby(["family", "model", "generator"]).worst.mean().reset_index()
    w = w.pivot_table(index=["family", "model"], columns="generator", values="worst").reset_index()
    w.columns = [str(x) for x in w.columns]
    out = c.merge(w, on=["family", "model"], how="left")
    out = out.rename(columns={"G1": "worst_G1", "G2": "worst_G2", "P": "worst_P"})
    return out


# ----------------------------------------------------------------------------- rendering
def md_table(df: pd.DataFrame, floatfmt: str = "{:.3f}") -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(str(c) for c in cols) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        cells = []
        for c in cols:
            v = r[c]
            if isinstance(v, (float, np.floating)):
                cells.append("n/a" if not math.isfinite(v) else floatfmt.format(v))
            else:
                cells.append(str(v))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def analyse(out: Path, tabs: dict) -> dict:
    """Derived tables for one analysis; writes them into its directory."""
    head = headline(tabs["clean"], tabs["e4"], tabs["mutben"], tabs["thresholds"])
    cur = curves(tabs["e4"])
    st = stats_table(head)
    ms = mutben_seed_table(tabs["mutben"])
    pf = per_family_table(tabs["e4"], tabs["clean"])
    xr = xgb_robust_table(tabs["thresholds"], tabs["clean"])
    head.to_csv(out / "pcap_headline.csv", index=False)
    cur.to_csv(out / "pcap_curves.csv", index=False)
    st.to_csv(out / "pcap_stats.csv", index=False)
    ms.to_csv(out / "pcap_mutben_seeds.csv", index=False)
    pf.to_csv(out / "pcap_per_family.csv", index=False)
    xr.to_csv(out / "pcap_xgb_robust.csv", index=False)
    return dict(tabs, headline=head, curves=cur, stats=st, mutben_seeds=ms, per_family=pf, xgb_robust=xr)


def build_summary(out: Path, primary: dict, extra: dict, text: str | None, run: dict) -> str:
    L = []
    add = L.append
    add("# Packet-level validation of the client-side robustness results (design v2)")
    add("")
    add("Generated by `python -m idsbench.pcap.run_all` from the CSV files in this directory and its subdirectories. "
        "The hand-written findings are appended at the end.")
    add("")
    add(f"Run: {run.get('seeds')} seeds, {run.get('n_flows')} E4 test flows per family, {run.get('n_aug')} augmentation "
        f"copies per family, runtime {run.get('runtime_s', 'n/a')} s (all analyses).")
    add("")
    add("Bootstrap intervals over seeds are approximate with few seeds. With 10 seeds the smallest two-sided Wilcoxon "
        "p-value is 0.002; p-values are Holm-adjusted within each metric.")
    add("")
    add("## 1. Provenance, labels and population")
    add("")
    prov, labs, sel = [], [], []
    for day in CACHE_DAYS:
        p = OUT / f"build_{day}.json"
        if not p.exists():
            continue
        b = json.loads(p.read_text())
        prov.append({"capture": day, "file": b["pcap"], "size_bytes": b["size_bytes"], "sha256": b["sha256"],
                     "frames": b["frames_total"], "ipv4_tcp_udp_packets": b["packets_kept_ipv4_tcp_udp"],
                     "flows": b["flows_extracted"], "trailing_packets_absorbed": b.get("trailing_packets_absorbed"),
                     "shift_h": round(b["shift"]["shift_hours"], 2)})
        for name, v in b["labels_by_name"].items():
            if v["cic_rows"] == 0:
                continue
            labs.append({"capture": day, "label": name, "cic_rows": v["cic_rows"],
                         "cic_rows_matched": v["cic_rows_matched"],
                         "flows_primary_rule": v["flows_labelled"],
                         "flows_drop_rule": v["flows_labelled_drop_rule"]})
        sel.append({"capture": day, "flows_matched": b["flows_matched"],
                    "drop_rule_ambiguous": b.get("drop_rule_flows_ambiguous"), "unmatched": b["flows_unmatched"],
                    "primary_by_pattern": b.get("primary_rule_flows_by_how", {}).get("pattern"),
                    "primary_by_majority": b.get("primary_rule_flows_by_how", {}).get("majority"),
                    "benign_kept": b["benign_flows_kept"], "attack_kept": b["attack_flows_kept"],
                    "packet_pool_flows": b["packet_pool_flows"]})
    if prov:
        add(md_table(pd.DataFrame(prov), "{:.2f}"))
        add("")
    if labs:
        add("Label counts per capture (CIC rows, CIC rows matched, flows under the primary rule and the drop rule):")
        add("")
        add(md_table(pd.DataFrame(labs), "{:.0f}"))
        add("")
    if sel:
        add("Flows per capture:")
        add("")
        add(md_table(pd.DataFrame(sel), "{:.0f}"))
        add("")
    pop = primary.get("population")
    if pop is not None and len(pop):
        add("Analysis populations after dedup, per family (rows entering the split):")
        add("")
        add(md_table(pop, "{:.0f}"))
        add("")
    dd = primary.get("dedup")
    if dd is not None and len(dd):
        add("Duplicates before dedup, per family (memorisation check; dedup runs before the split):")
        add("")
        add(md_table(dd, "{:.3f}"))
        add("")
    add("## 2. Extractor validation against the CIC flow table")
    add("")
    add("`one_to_one`: pairs with exactly one candidate on each side; `any_candidate`: share of flows agreeing with at "
        "least one candidate CIC row (upper bound); `ks`: two-sample Kolmogorov-Smirnov distance on the whole day's "
        "features. Mean over the two captures.")
    add("")
    vals = []
    for day in CACHE_DAYS:
        p = OUT / f"extractor_validation_{day}.csv"
        if p.exists():
            vals.append(pd.read_csv(p))
    if vals:
        v = pd.concat(vals)
        agg = v.groupby("feature", sort=False).agg(one_to_one=("one_to_one_agree", "mean"),
                                                   any_candidate=("any_candidate_agree", "mean"),
                                                   ks=("ks_our_vs_cic", "mean")).reset_index()
        add(f"Features agreeing within 1% on at least 90% of one-to-one pairs: {int((agg.one_to_one >= 0.9).sum())} "
            f"of {len(agg)}.")
        add("")
        add(md_table(agg, "{:.3f}"))
        add("")
    add("## 3. Q1: realism of the feature-space generators (primary analysis)")
    add("")
    real = primary.get("realism")
    if real is not None and len(real):
        ra = []
        for m, g in real.groupby("measure"):
            mu, lo, hi = boot_ci(g.auroc.to_numpy(float))
            ra.append({"measure": m, "auroc_mean": mu, "ci_lo": lo, "ci_hi": hi, "seeds": int(len(g))})
        add("Fingerprint AUROC (0.5 means indistinguishable):")
        add("")
        add(md_table(pd.DataFrame(ra), "{:.3f}"))
        add("")
    rel = primary.get("relerr")
    if rel is not None and len(rel):
        rs = rel.groupby(["generator", "group_of_feature", "feature", "seed"]).median_rel_err.median().reset_index()
        rs = rs.groupby(["generator", "group_of_feature", "seed"]).median_rel_err.mean().reset_index()
        rg = rs.groupby(["generator", "group_of_feature"]).median_rel_err.agg(["mean", "min", "max"]).reset_index()
        rg = rg[rg.group_of_feature != "none"]
        add("Relative error |G(x) - P(x)| / |P(x)| per feature group at matched budgets: for each feature the median over "
            "the 21 budgets; group value = mean over the group's features; mean, min, max over seeds. Features outside "
            "the three groups are not shown.")
        add("")
        add(md_table(rg.rename(columns={"group_of_feature": "group"}), "{:.3f}"))
        add("")
    tc = primary.get("timing")
    if tc is not None and len(tc):
        tg = tc.groupby("multiplier")[["median_ratio_duration", "median_ratio_fwd_iat_mean",
                                       "mean_added_over_expected"]].mean().reset_index()
        add("Timing budget check (timing group alone, benign test pool; realised values vs nominal m):")
        add("")
        add(md_table(tg, "{:.3f}"))
        add("")
    rs_ = primary.get("resplit")
    if rs_ is not None and len(rs_):
        ts_, rr = rs_.p_timing_states.sum(), rs_.p_resplit_states.sum()
        add(f"Timeout re-split under P, over timing-active P states: {rr:,} of {ts_:,} "
            f"({100 * rr / max(ts_, 1):.2f}%) lost packets beyond the 120 s flow timeout.")
        add("")
    add("## 4. Headline (FPR 1e-3, primary analysis)")
    add("")
    hd = primary.get("headline")
    if hd is not None and len(hd):
        rows = []
        for (variant, model), g in hd.groupby(["variant", "model"], sort=False):
            r = {"variant": variant, "model": model}
            for c in ("clean_recall", "worst_G1", "worst_G2", "worst_P", "mutben_fpr_G1", "mutben_fpr_G2",
                      "mutben_fpr_P", "fpr_test_realised"):
                if c in g:
                    r[c] = fmt_ci(boot_ci(g[c].to_numpy(float)), 3)
            rows.append(r)
        add("Mean [approximate bootstrap CI over seeds]. Variants: all five families; no_bot (Bot removed, because Bot "
            "behaves as an outlier); bruteforce (FTP and SSH pooled).")
        add("")
        add(md_table(pd.DataFrame(rows), "{}"))
        add("")
    ms = primary.get("mutben_seeds")
    if ms is not None and len(ms):
        add("Mutated-benign FPR at FPR 1e-3 (30,000 benign test rows per seed). The verdict is over seeds: mean of the "
            "per-seed FPR with a percentile bootstrap CI over the 10 seeds, and a paired comparison with xgb on the same "
            "seed (seeds above and below xgb; Wilcoxon signed-rank p, Holm not applied). The clean row is the clean FPR on "
            "the same pool. Pooled counts are descriptive only: the seeds' pools overlap, so pooled intervals would be "
            "too narrow.")
        add("")
        disp = []
        for r in ms.itertuples():
            is_ref = r.model == "xgb"
            disp.append({
                "reference": r.reference, "model": r.model,
                "per-seed mean [bootstrap CI]": f"{r.seed_mean:.5f} [{r.boot_ci_lo:.5f}, {r.boot_ci_hi:.5f}]",
                "seeds vs xgb": "reference" if is_ref else
                f"{int(r.seeds_above_xgb)} of {r.n_seeds} above, {int(r.seeds_below_xgb)} below",
                "Wilcoxon p vs xgb": "reference" if is_ref else
                ("n/a" if not math.isfinite(r.p_wilcoxon_vs_xgb) else f"{r.p_wilcoxon_vs_xgb:.4f}"),
                "pooled k/n (descriptive)": f"{r.pooled_k}/{r.pooled_n} = {r.pooled_fpr:.5f}"})
        add(md_table(pd.DataFrame(disp), "{}"))
        add("")
    st = primary.get("stats")
    if st is not None and len(st):
        s2 = st.copy()
        s2["diff [CI]"] = [f"{r.mean_diff_a_minus_b:.3f} [{r.ci_lo:.3f}, {r.ci_hi:.3f}]" for r in s2.itertuples()]
        add("Paired comparisons over seeds (Wilcoxon, Holm within metric):")
        add("")
        add(md_table(s2[["metric", "a", "b", "n_seeds", "diff [CI]", "p_wilcoxon", "p_holm"]], "{:.4f}"))
        add("")
    pf = primary.get("per_family")
    if pf is not None and len(pf):
        add("## 5. Per-family results, primary analysis (FPR 1e-3, mean over seeds)")
        add("")
        add(md_table(pf, "{:.3f}"))
        add("")
    xr = primary.get("xgb_robust")
    if xr is not None and len(xr):
        add("### xgb_robust diagnostic (primary, FPR 1e-3, one row per seed)")
        add("")
        add("A threshold of 'inf' means no benign calibration score lies above the plateau, so no test row is alarmed and "
            "the realised FPR is 0; recall at that seed is 0 by construction. Recall and AUROC are on clean flows, per family.")
        add("")
        d = xr.copy()
        d["threshold"] = ["inf" if not math.isfinite(t) else f"{t:.4f}" for t in d["threshold"]]
        d["fpr_test_realised"] = [f"{x:.5f}" for x in d["fpr_test_realised"]]
        add(md_table(d, "{:.3f}"))
        add("")
        rc = primary.get("robust_columns")
        add("Columns of xgb_robust: a feature is excluded if G1 can change or recompute it, if it is on the G1 dependent "
            "list, if G2 touches or couples it, or if P changes it on more than 1% of the training flows.")
        add("")
        if rc is None or not len(rc):
            add("Remaining columns: not available (run `python -m idsbench.pcap.run_all --robust-columns`).")
            add("")
        else:
            per, kept_sets = [], {}
            for s, b in rc.groupby("seed"):
                kept = b[b["kept"]]
                kept_sets[s] = list(kept["feature"])
                per.append({"seed": s, "columns": len(b),
                            "touched by P": int(sum("P" in str(x).split("+") for x in b["excluded_by"])),
                            "excluded (any reason)": int((~b["kept"]).sum()), "remaining": len(kept),
                            "remaining and constant": int(kept["constant_in_population"].sum())})
            add(md_table(pd.DataFrame(per), "{:.0f}"))
            add("")
            order = list(dict.fromkeys(rc["feature"]))
            const = set(rc.loc[rc["constant_in_population"], "feature"])
            always = set.intersection(*(set(v) for v in kept_sets.values()))
            some = set.union(*(set(v) for v in kept_sets.values())) - always
            fmt = lambda names: ", ".join(f"{n} (constant)" if n in const else n
                                          for n in order if n in names) or "none"
            add(f"Remaining in every seed ({len(always)}): {fmt(always)}.")
            add("")
            if some:
                add(f"Remaining in some seeds only ({len(some)}): {fmt(some)}.")
                add("")
    for name, title in (("all_flows", "Secondary: all flows (scan probes and appendix flows included)"),
                        ("drop_ambiguous", "Sensitivity: connection flows, ambiguous label sets dropped")):
        t = extra.get(name)
        if not t:
            continue
        add(f"## {title}")
        add("")
        hd2 = t.get("headline")
        if hd2 is not None:
            rows = []
            for (variant, model), g in hd2[hd2.variant.isin(["all", "no_bot"])].groupby(["variant", "model"], sort=False):
                r = {"variant": variant, "model": model}
                for c in ("clean_recall", "worst_P", "worst_G1", "worst_G2", "mutben_fpr_P"):
                    r[c] = fmt_ci(boot_ci(g[c].to_numpy(float)), 3)
                rows.append(r)
            add(md_table(pd.DataFrame(rows), "{}"))
            add("")
        if t.get("population") is not None:
            add("Population per family:")
            add("")
            add(md_table(t["population"], "{:.0f}"))
            add("")
        if t.get("per_family") is not None:
            add("Per family:")
            add("")
            add(md_table(t["per_family"], "{:.3f}"))
            add("")
    if text:
        add("## 6. Findings, answers and deviations")
        add("")
        add(text.rstrip())
        add("")
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------- driver
def run_config(name: str, cfg_def: dict, cache: dict, n_seeds: int, n_flows: int, n_aug: int, run: dict,
               log) -> dict:
    out = cfg_def["dir"]
    out.mkdir(parents=True, exist_ok=True)
    view, X, label, dedup = select_view(cache, cfg_def["population"], cfg_def["rule"])
    fam = np.asarray(["Benign"] + list(LABELS[1:]))[label]
    pop = pd.DataFrame([{"family": f, "rows_after_dedup": int(np.sum(fam == f))} for f in pd.unique(fam)])
    dd = pd.DataFrame([{"family": f, **v} for f, v in dedup.items()])
    dd["duplicate_share"] = (dd.exact_duplicates + dd.label_conflicts + dd.feature_duplicates) / dd.rows.clip(lower=1)
    pop.to_csv(out / TABLES["population"], index=False)
    dd.to_csv(out / TABLES["dedup"], index=False)
    log(f"[pcap:{name}] population {cfg_def['population']}/{cfg_def['rule']}: rows after dedup {len(X):,}, "
        f"with packets {int(np.sum(view['pool_row'] >= 0)):,}")
    acc: dict = {k: [] for k in ("thr", "clean", "e4", "mutben", "realism", "relerr", "stats", "timing")}
    t0 = time.time()
    for seed in range(n_seeds):
        rows = run_seed(view, X, label, Config(seed=seed, n_flows=n_flows, n_aug=n_aug), log=log)
        for k, v in rows.items():
            acc[k].extend(v)
        pd.DataFrame(acc["thr"]).to_csv(out / TABLES["thresholds"], index=False)
    tabs = {k: pd.DataFrame(acc[k]) for k in acc}
    tabs["resplit"] = tabs.pop("stats")
    tabs["thresholds"] = tabs.pop("thr")
    for k, fname in TABLES.items():
        if k in tabs:
            tabs[k].to_csv(out / fname, index=False)
    tabs["population"] = pop
    tabs["dedup"] = dd
    run[name] = {"seconds": round(time.time() - t0, 1), "rows_after_dedup": int(len(X))}
    return analyse(out, tabs)


def main(argv=None):
    global TEXT_OVERRIDE
    ap = argparse.ArgumentParser(prog="python -m idsbench.pcap.run_all")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seeds", type=int, default=None)
    ap.add_argument("--flows", type=int, default=None)
    ap.add_argument("--n-aug", type=int, default=None)
    ap.add_argument("--configs", nargs="*", default=list(CONFIGS))
    ap.add_argument("--text", default=None, help="file with hand-written findings appended to SUMMARY.md")
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--robust-columns", action="store_true",
                    help="write results/pcap/pcap_xgb_robust_columns.csv (reads the cache, no defenders trained)")
    args = ap.parse_args(argv)
    TEXT_OVERRIDE = args.text
    base = QUICK if args.quick else Config()
    n_seeds = args.seeds if args.seeds is not None else (1 if args.quick else 10)
    if args.robust_columns:
        cache = load_cache(CACHE_DAYS)
        cols = robust_column_table(cache, n_seeds, log=lambda m: print(m, flush=True))
        cols.to_csv(OUT / "pcap_xgb_robust_columns.csv", index=False)
        print(f"[pcap] xgb_robust columns for {n_seeds} seeds written to {OUT / 'pcap_xgb_robust_columns.csv'}")
        return None
    # runtime reductions (design section 6 order): E4 flows per family 500 -> 300; strong attacker 5 levels, 1 restart
    n_flows = args.flows if args.flows is not None else (base.n_flows if args.quick else REDUCED_E4_FLOWS)
    if not args.quick:
        import idsbench.econ.mutation as _mutation
        _mutation.STRONG_LEVELS = REDUCED_STRONG_LEVELS
        _mutation.STRONG_RESTARTS = REDUCED_STRONG_RESTARTS
    n_aug = args.n_aug if args.n_aug is not None else base.n_aug
    run = {"seeds": n_seeds, "n_flows": n_flows, "n_aug": n_aug, "quick": bool(args.quick),
           "strong_levels": 10 if args.quick else REDUCED_STRONG_LEVELS,
           "strong_restarts": 2 if args.quick else REDUCED_STRONG_RESTARTS}
    log = lambda m: print(m, flush=True)
    t0 = time.time()
    results = {}
    if not args.summary_only:
        cache = load_cache(CACHE_DAYS)
        for name in args.configs:
            results[name] = run_config(name, CONFIGS[name], cache, n_seeds, n_flows, n_aug, run, log)
            run["runtime_s"] = round(time.time() - t0, 1)
            (OUT / "pcap_run.json").write_text(json.dumps(run, indent=2, default=float))
    else:
        for name, cfg_def in CONFIGS.items():
            d = cfg_def["dir"]
            if not (d / TABLES["thresholds"]).exists():
                continue
            tabs = {k: pd.read_csv(d / f) for k, f in TABLES.items() if (d / f).exists()}
            tabs["resplit"] = tabs.get("resplit", pd.DataFrame())
            results[name] = analyse(d, tabs)
        prev = OUT / "pcap_run.json"
        if prev.exists():
            run.update({k: v for k, v in json.loads(prev.read_text()).items() if k not in ("seeds",)})
    text = Path(TEXT_OVERRIDE).read_text() if TEXT_OVERRIDE and Path(TEXT_OVERRIDE).exists() else None
    primary = results.get("primary", {})
    rc_path = OUT / "pcap_xgb_robust_columns.csv"
    if rc_path.exists():
        primary["robust_columns"] = pd.read_csv(rc_path)
    extra ={k: results[k] for k in ("all_flows", "drop_ambiguous") if k in results}
    (OUT / "SUMMARY.md").write_text(build_summary(OUT, primary, extra, text, run))
    (OUT / "pcap_run.json").write_text(json.dumps(run, indent=2, default=float))
    log(f"[pcap] SUMMARY.md written to {OUT} ({time.time() - t0:.0f}s)")
    return results


if __name__ == "__main__":
    main()
