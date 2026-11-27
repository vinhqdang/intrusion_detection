"""Run E4 and the defender measurements, then X2, X3, X4, the E4 headline and the summary.

    python -m idsbench.econ.run_all [--quick] [--out DIR] [--workers N]

--quick: one seed and 300 flows per family, written to results/econ/quick/ (smoke test).
Writes: e4_mutation.csv, e4_reference.csv, detection_tables.csv, detection_tables_summary.csv,
e4_feature_groups.md, x2.md/.csv, x3.md/x3.csv.gz/x3_sobol.csv, x4.md/.csv, e4_headline.md, e4_headline_label.md,
SUMMARY.md.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import pandas as pd

from idsbench.econ import sweep
from idsbench.econ.detection_tables import excluded_families, summarise
from idsbench.econ.game import GameParams
from idsbench.econ.measure import CAPS_FULL, CAPS_QUICK, DATASETS, N_FLOWS_FULL, SEEDS_FULL, run_e4

OUT = Path("results/econ")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m idsbench.econ.run_all")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--sobol-n", type=int, default=sweep.N_BASE)
    ap.add_argument("--summary-only", action="store_true", help="rebuild SUMMARY.md from the saved CSVs")
    args = ap.parse_args(argv)
    out = Path(args.out) if args.out else (OUT / "quick" if args.quick else OUT)
    out.mkdir(parents=True, exist_ok=True)
    if args.summary_only:
        _summary_only(out, args.quick)
        return
    seeds = [0] if args.quick else list(SEEDS_FULL)
    n_flows = 300 if args.quick else N_FLOWS_FULL
    caps = CAPS_QUICK if args.quick else CAPS_FULL
    params = GameParams()
    n_base = 64 if args.quick else args.sobol_n
    t0 = time.time()

    t = time.time()
    print("[econ] E4 and defender measurements", flush=True)
    mutation, long = run_e4(out, seeds=seeds, n_flows=n_flows, caps=caps, datasets=DATASETS)
    summarise(long).to_csv(out / "detection_tables_summary.csv", index=False)
    excluded = {ds: excluded_families(long, ds) for ds in DATASETS}
    print(f"[econ] measurements done in {(time.time() - t) / 60:.1f} min; excluded families: {excluded}",
          flush=True)

    e4_ref = pd.read_csv(out / "e4_reference.csv")
    t = time.time()
    notes, x2_parts, eq_parts = [], [], []
    for q in ("score", "label"):
        df, eq, nt = sweep.run_x2(long, mutation, e4_ref, params, q)
        x2_parts.append(df)
        eq_parts.append(eq)
        notes += nt
    x2 = pd.concat(x2_parts, ignore_index=True)
    eq = pd.concat(eq_parts, ignore_index=True)
    sweep.write_x2(x2, eq, notes, out / "x2.md", params)
    print(f"[econ] X2 done in {time.time() - t:.0f}s", flush=True)

    t = time.time()
    samples, sobols = [], []
    for eff in (False, True):
        s, so = sweep.run_x3(long, mutation, e4_ref, params, efficacy=eff, n_base=n_base, workers=args.workers)
        samples.append(s)
        sobols.append(so)
        print(f"[econ] X3 efficacy={eff} done in {time.time() - t:.0f}s", flush=True)
    x3 = pd.concat(samples, ignore_index=True)
    sob = pd.concat(sobols, ignore_index=True)
    fr = sweep.write_x3(x3, sob, params, out / "x3.md", n_base)

    t = time.time()
    x4 = sweep.run_x4(long, mutation, params)
    sweep.write_x4(x4, sweep.switch_points(x4), out / "x4.md", params)
    print(f"[econ] X4 done in {time.time() - t:.0f}s", flush=True)

    h_score = sweep.e4_headline(mutation, "score")
    sweep.write_headline(h_score, out / "e4_headline.md", "score")
    sweep.write_headline(sweep.e4_headline(mutation, "label"), out / "e4_headline_label.md", "label")
    meta = _meta(seeds, n_flows, caps, n_base, excluded, args.quick, time.time() - t0)
    sweep.write_summary(fr, sob, x2, eq, x4, h_score, out / "SUMMARY.md", meta)
    print(f"[econ] all done in {(time.time() - t0) / 60:.1f} min -> {out}", flush=True)


def _meta(seeds, n_flows, caps, n_base, excluded, quick, secs) -> dict:
    return {"profile": "quick (smoke test)" if quick else "full", "seeds": seeds, "n_flows": n_flows,
            "caps": caps, "n_base": n_base, "excluded": excluded,
            "notes": [f"Wall-clock time of this run: {secs / 60:.1f} min (4 worker processes for X3)."]}


def _summary_only(out: Path, quick: bool) -> None:
    x3 = pd.read_csv(out / "x3.csv.gz")
    sob = pd.read_csv(out / "x3_sobol.csv")
    x2_all = pd.read_csv(out / "x2.csv")
    x2 = x2_all[x2_all.model != "EQUILIBRIUM"]
    eq = x2_all[x2_all.model == "EQUILIBRIUM"].drop(columns=["model"])
    x4 = pd.read_csv(out / "x4.csv")
    h = pd.read_csv(out / "e4_headline.csv")
    det = pd.read_csv(out / "detection_tables.csv", usecols=["dataset", "seed", "family", "action", "n_test"])
    long = det.assign(model="")
    fr = sweep.x3_fractions(x3)
    excluded = {ds: excluded_families(long, ds) for ds in DATASETS}
    meta = _meta(sorted(int(s) for s in det.seed.unique()), 300 if quick else N_FLOWS_FULL,
                 CAPS_QUICK if quick else CAPS_FULL, 64 if quick else sweep.N_BASE, excluded, quick, 0.0)
    meta["notes"] = ["SUMMARY rebuilt from the saved CSVs (run_all --summary-only); the run time is in the full run log."]
    sweep.write_summary(fr, sob, x2, eq, x4, h, out / "SUMMARY.md", meta)


if __name__ == "__main__":
    main()
