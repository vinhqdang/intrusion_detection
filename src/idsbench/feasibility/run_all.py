"""Run E1, E2, E3 (cross-network) and E3 (cross-pair) sequentially and write results/feasibility/SUMMARY.md.

    python -m idsbench.feasibility.run_all [--quick]

--quick: one seed and smaller caps (20k benign / 5k per family), written to results/feasibility/quick/.
"""

from __future__ import annotations

import argparse
import time
import traceback
from pathlib import Path

from idsbench.feasibility import e1_shortcut, e2_lofo, e3_crosspair, e3_crossnet
from idsbench.feasibility.common import DATASET_LOADERS, demote_headings, pool_meta

EXPERIMENTS = [
    ("E1 shortcut index", "e1_shortcut", e1_shortcut.main),
    ("E2 leave-one-family-out", "e2_lofo", e2_lofo.main),
    ("E3 cross-network", "e3_crossnet", e3_crossnet.main),
    ("E3 cross-pair transfer", "e3_crosspair", e3_crosspair.main),
]


def _section_body(md: str) -> str:
    """Drop the document's own H1 and demote the remaining headings under the section title."""
    lines = md.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return demote_headings("\n".join(lines), 1).rstrip()


def _cleaning_table() -> list[str]:
    lines = ["| dataset | rows loaded | exact duplicates removed | label-conflict rows removed "
             "(vectors) | feature-only duplicates removed | dedup+conflict % | pool rows | features | "
             "constant columns dropped | source / note |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for name in DATASET_LOADERS:
        try:
            m = pool_meta(name)
        except Exception:  # dataset could not be built: skipped and reported elsewhere
            continue  # not loadable: listed under "Datasets skipped"
        removed = m["n_exact_duplicates"] + m["n_conflict"] + m["n_feature_duplicates"]
        pct = 100 * removed / max(m["n_rows_loaded"], 1)
        note = m.get("mirror_note") or m.get("source") or ""
        lines.append(
            f"| {name} | {m['n_rows_loaded']:,} | {m['n_exact_duplicates']:,} | "
            f"{m['n_conflict']:,} ({m['n_conflict_vectors']:,}) | {m['n_feature_duplicates']:,} | "
            f"{pct:.2f} | {m['n_rows_pool']:,} | {m['n_features']} | {m['n_constant_dropped']} | "
            f"{note} |")
    return lines


def _partial_notes(netflow_skipped: dict, cross_pair_skipped: dict) -> list[str]:
    def files(name):
        try:
            return len(pool_meta(name).get("files") or [])
        except Exception:
            return None
    n2018, nmt = files("cicids2018"), files("ciciomt2024")
    nf_missing = ", ".join(sorted(netflow_skipped)) or "none"
    lines = [
        f"- CSE-CIC-IDS2018: partial download. {n2018} day-CSV files of the "
        "pcy12345BSU/CSE-CIC-IDS-2018 mirror were loaded; the full TrafficForML release is not used.",
        f"- CICIoMT2024: partial download. {nmt} per-attack CSV files of the somnath0100/CICIoMT2024Small "
        "mirror (train-named files) were loaded, not the full dataset.",
        "- CICIoT2023: the MaheshBaja mirror provides 39 features; the feature set is the mirror's, not the "
        "full CICIoT2023 release.",
        "- NetFlow: keys-i/netFlow-v3 has no data files on the HF hub. Only the NF-ToN-IoT-v2 test CSV "
        "(NetFlow v2 schema) is loaded, reported as NF-ToN-IoT-v2. Not loaded: " + nf_missing + ".",
    ]
    for pair, reason in cross_pair_skipped.items():
        lines.append(f"- Cross-pair {pair}: not run ({reason}).")
    if not cross_pair_skipped:
        lines.append("- Cross-pair: every configured pair was run.")
    return lines


def _protocol_notes(netflow_skipped: dict, cross_pair_skipped: dict) -> list[str]:
    e1, e2, e3c = e1_shortcut, e2_lofo, e3_crossnet
    lines = ["## Protocol notes", "",
             "Cleaning (common.clean_pool), applied to every pool before any split: (1) exact duplicates "
             "(features + family) are removed; (2) every row whose exact feature vector occurs with both "
             "benign and attack labels is removed, because no label can be trusted for that vector; "
             "(3) remaining feature-only duplicates (same vector, different attack family) are removed. "
             "After this no feature vector occurs twice, so the post-split overlap count is a guard that "
             "must be 0 (it is recorded per run as n_test_overlap).", ""]
    lines += _cleaning_table()
    lines += ["", "Caps (benign / per attack family) and seeds:", "",
              f"- E1 shortcut index: seeds {', '.join(map(str, e1.SEEDS_FULL))}; caps "
              f"{e1.CAPS_FULL[0]:,} / {e1.CAPS_FULL[1]:,} (quick: {e1.CAPS_QUICK[0]:,} / {e1.CAPS_QUICK[1]:,}).",
              f"- E2 leave-one-family-out: seeds {', '.join(map(str, e2.SEEDS_FULL))}; caps "
              f"{e2.CAPS_FULL[0]:,} / {e2.CAPS_FULL[1]:,} (quick: {e2.CAPS_QUICK[0]:,} / {e2.CAPS_QUICK[1]:,}); "
              "families need >= 500 rows (70/30 train/test); benign 60/20/20 train/calibration/test; "
              "the benign calibration set is split into two halves (reference for conformal p-values, "
              "threshold set for the fusion).",
              f"- E3 cross-network: seeds {', '.join(map(str, e3c.SEEDS_FULL))}; caps "
              f"{e3c.CAPS_FULL[0]:,} / {e3c.CAPS_FULL[1]:,} (quick: {e3c.CAPS_QUICK[0]:,} / {e3c.CAPS_QUICK[1]:,}); "
              f"domain classifiers fitted on at most {e3c.FIT_CAP:,} rows each, drawn from the B train split.",
              f"- E3 cross-pair: seeds {', '.join(map(str, e3_crosspair.SEEDS))}; caps "
              f"{e3_crosspair.CAPS_FULL[0]:,} / {e3_crosspair.CAPS_FULL[1]:,} (quick: "
              f"{e3_crosspair.CAPS_QUICK[0]:,} / {e3_crosspair.CAPS_QUICK[1]:,}).",
              "- Scores: XGBoost raw margin (log-odds, float64) everywhere a score is thresholded or turned "
              "into a p-value; IsolationForest -score_samples (float64).",
              "- Splits: stratified 70/30 for E1 and E3 (E3 additionally holds out 20% of train for "
              "calibration); every subsample and split uses the run seed.",
              "", "Partial downloads and feature notes:", ""]
    lines += _partial_notes(netflow_skipped, cross_pair_skipped)
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m idsbench.feasibility.run_all")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args(argv)
    out = Path("results/feasibility") / ("quick" if args.quick else "")
    out.mkdir(parents=True, exist_ok=True)
    flag = ["--quick"] if args.quick else []
    timings, skipped_all, failures, tables = {}, {}, {}, {}
    for title, stem, fn in EXPERIMENTS:
        t0 = time.time()
        try:
            _, skipped = fn(flag + ["--out", str(out)])
            skipped_all[stem] = skipped
        except Exception:
            failures[stem] = traceback.format_exc()
            print(failures[stem], flush=True)
        timings[title] = time.time() - t0
        md_path = out / f"{stem}.md"
        tables[title] = md_path.read_text() if md_path.exists() else "(not produced)\n"
    lines = ["# Feasibility summary", "",
             "Produced by `python -m idsbench.feasibility.run_all`"
             + (" --quick" if args.quick else "") + ".", "", "## Runtime", "",
             "| experiment | wall-clock minutes |", "|---|---|"]
    lines += [f"| {t} | {s / 60:.1f} |" for t, s in timings.items()]
    lines += [""] + _protocol_notes(skipped_all.get("e3_crossnet", {}),
                                    skipped_all.get("e3_crosspair", {}))
    lines += ["", "## Datasets skipped", ""]
    for stem, sk in skipped_all.items():
        lines.append(f"- {stem}: " + ("; ".join(f"{k}: {v}" for k, v in sk.items()) or "none"))
    if failures:
        lines += ["", "## Failures", ""] + [f"- {k}: see log" for k in failures]
    for title, body in tables.items():
        lines += ["", f"## {title}", "", _section_body(body), ""]
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines), flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
