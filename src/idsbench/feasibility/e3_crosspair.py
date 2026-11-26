"""E3 cross-pair transfer: dataset pairs that are meant to share a feature extractor (binary labels).

Each pair is canonicalised by column name (lowercase, whitespace-normalised, explicit alias map for
known abbreviations), then intersected. Port, Protocol, timestamp, IP and flow-id columns are excluded.
For each seed in {0, 1, 2} and each ordered pair A -> B (plus the in-domain A -> A reference):
  * XGBoost on 80% of A's train split, thresholds calibrated on A's held-out benign rows;
  * evaluation on B's test split (AUROC, AUPRC, realised FPR and recall at the A-thresholds);
  * conformal + BH at alpha = 0.1, unweighted and weighted (domain-classifier density ratio).
The per-pair analysis is the same run_pair used by E3 (e3_crossnet); only the feature set and the
dataset pairs differ. Cached pools come from data/feasibility_cache via common.get_pool.
"""

from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd

from idsbench.feasibility.common import (
    BENIGN, clean_pool, demote_headings, e3_tables_md, get_pool,
)
from idsbench.feasibility.e3_crossnet import run_pair

OUT = Path("results/feasibility")
SEEDS = (0, 1, 2)
CAPS_FULL = (100_000, 20_000)   # (benign, per attack family)
CAPS_QUICK = (20_000, 5_000)

# CICFlowMeter abbreviations used by CIC-IDS2018 mapped onto the CIC-IDS2017 names (lowercase keys).
CIC_2018_TO_2017 = {
    "ack flag cnt": "ack flag count",
    "ece flag cnt": "ece flag count",
    "fin flag cnt": "fin flag count",
    "psh flag cnt": "psh flag count",
    "rst flag cnt": "rst flag count",
    "syn flag cnt": "syn flag count",
    "urg flag cnt": "urg flag count",
    "bwd header len": "bwd header length",
    "fwd header len": "fwd header length",
    "bwd iat tot": "bwd iat total",
    "fwd iat tot": "fwd iat total",
    "bwd pkt len max": "bwd packet length max",
    "bwd pkt len mean": "bwd packet length mean",
    "bwd pkt len min": "bwd packet length min",
    "bwd pkt len std": "bwd packet length std",
    "fwd pkt len max": "fwd packet length max",
    "fwd pkt len mean": "fwd packet length mean",
    "fwd pkt len min": "fwd packet length min",
    "fwd pkt len std": "fwd packet length std",
    "bwd pkts/s": "bwd packets/s",
    "fwd pkts/s": "fwd packets/s",
    "flow pkts/s": "flow packets/s",
    "flow byts/s": "flow bytes/s",
    "bwd seg size avg": "avg bwd segment size",
    "fwd seg size avg": "avg fwd segment size",
    "fwd seg size min": "min_seg_size_forward",
    "fwd act data pkts": "act_data_pkt_fwd",
    "init bwd win byts": "init_win_bytes_backward",
    "init fwd win byts": "init_win_bytes_forward",
    "pkt len max": "max packet length",
    "pkt len min": "min packet length",
    "pkt len mean": "packet length mean",
    "pkt len std": "packet length std",
    "pkt len var": "packet length variance",
    "pkt size avg": "average packet size",
    "subflow bwd byts": "subflow bwd bytes",
    "subflow fwd byts": "subflow fwd bytes",
    "subflow fwd pkts": "subflow fwd packets",
    "subflow bwd pkts": "subflow bwd packets",
    "tot bwd pkts": "total backward packets",
    "tot fwd pkts": "total fwd packets",
    "totlen bwd pkts": "total length of bwd packets",
    "totlen fwd pkts": "total length of fwd packets",
}

ALIASES: dict[str, dict[str, str]] = {"cicids2018": CIC_2018_TO_2017}
PAIRS: tuple[tuple[str, str], ...] = (("cicids2017", "cicids2018"), ("ciciot2023", "ciciomt2024"))

_EXCLUDE_TOKENS = {"port", "ports", "sport", "dport", "ip", "ips", "timestamp", "id"}


def canonical_name(col: str, aliases: dict[str, str] | None = None) -> str:
    """Lowercase, collapse whitespace, then apply the explicit alias map."""
    key = re.sub(r"\s+", " ", str(col).strip().lower())
    return (aliases or {}).get(key, key)


def is_excluded(key: str) -> bool:
    """Ports, Protocol fields, timestamps, IP addresses and flow identifiers are not features here."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", key) if t]
    if not tokens:
        return True
    return tokens[0] == "protocol" or bool(set(tokens) & _EXCLUDE_TOKENS)


def match_columns(cols_a, cols_b, aliases_a=None, aliases_b=None) -> dict:
    """Intersect two column lists after canonicalisation. Returns matched keys and the original names."""
    map_a: dict[str, str] = {}
    for c in cols_a:
        k = canonical_name(c, aliases_a)
        if k in map_a:
            raise ValueError(f"canonical name collision in first dataset: {c!r} and {map_a[k]!r}")
        map_a[k] = c
    map_b: dict[str, str] = {}
    for c in cols_b:
        k = canonical_name(c, aliases_b)
        if k in map_b:
            raise ValueError(f"canonical name collision in second dataset: {c!r} and {map_b[k]!r}")
        map_b[k] = c
    excluded = sorted(k for k in set(map_a) | set(map_b) if is_excluded(k))
    shared = sorted((set(map_a) & set(map_b)) - set(excluded))
    unmatched_a = sorted(k for k in map_a if k not in shared and k not in excluded)
    unmatched_b = sorted(k for k in map_b if k not in shared and k not in excluded)
    applied = {
        f"{orig!r} -> {canonical_name(orig, al)!r}"
        for orig, al in [(c, aliases_a) for c in cols_a] + [(c, aliases_b) for c in cols_b]
        if canonical_name(orig, al) != re.sub(r"\s+", " ", str(orig).strip().lower())
    }
    return {
        "matched": shared, "orig_a": {k: map_a[k] for k in shared}, "orig_b": {k: map_b[k] for k in shared},
        "unmatched_a": unmatched_a, "unmatched_b": unmatched_b, "excluded": excluded,
        "aliases_applied": sorted(applied),
    }


def _dedup_pool(name: str, rename: dict[str, str], shared: list[str]) -> tuple[pd.DataFrame, np.ndarray, dict]:
    """Restrict a cached pool to the shared canonical features and clean it again (same rules as
    common.clean_pool: exact duplicates, label conflicts, feature-only duplicates)."""
    pool, _ = get_pool(name)
    family = pool["family"].to_numpy()
    X = pool.drop(columns="family")[list(rename)].rename(columns=rename)[shared]
    X, fam, counts = clean_pool(X, family)
    return X, fam, counts


def _capped_view(X: pd.DataFrame, family: np.ndarray, name: str, seed: int, caps: tuple[int, int]
                 ) -> tuple[pd.DataFrame, np.ndarray, pd.Series, dict]:
    """Per-family caps with the run seed, as in common.load_binary."""
    cap_benign, cap_family = caps
    rng = np.random.default_rng(seed)
    keep = []
    for fam in pd.unique(family):
        idx = np.flatnonzero(family == fam)
        cap = cap_benign if fam == BENIGN else cap_family
        if len(idx) > cap:
            idx = rng.choice(idx, size=cap, replace=False)
        keep.append(np.sort(idx))
    keep = np.concatenate(keep)
    Xc = X.iloc[keep].reset_index(drop=True)
    fam_out = pd.Series(family[keep], name="family")
    y = (fam_out != BENIGN).to_numpy().astype(int)
    meta = {"dataset": name, "n_rows_after_caps": int(len(Xc)),
            "family_counts_after_caps": {str(k): int(v) for k, v in fam_out.value_counts().items()}}
    return Xc, y, fam_out, meta


def _feature_report(A: str, B: str) -> dict:
    cols_a = [c for c in get_pool(A)[0].columns if c != "family"]
    cols_b = [c for c in get_pool(B)[0].columns if c != "family"]
    return match_columns(cols_a, cols_b, ALIASES.get(A), ALIASES.get(B))


def _report_lines(A: str, B: str, rep: dict) -> list[str]:
    fmt = lambda xs: ", ".join(xs) if xs else "none"  # noqa: E731
    return [
        f"### {A} <-> {B}", "",
        f"- matched features: {len(rep['matched'])}",
        f"- excluded (port / protocol / timestamp / IP / flow id): {fmt(rep['excluded'])}",
        f"- unmatched in {A}: {fmt(rep['unmatched_a'])}",
        f"- unmatched in {B}: {fmt(rep['unmatched_b'])}",
        f"- aliases applied: {fmt(rep['aliases_applied'])}",
        f"- matched: {fmt(rep['matched'])}", "",
    ]


def main(argv: list[str] | None = None) -> tuple[pd.DataFrame, dict]:
    ap = argparse.ArgumentParser(prog="python -m idsbench.feasibility.e3_crosspair")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--seeds", default=None)
    args = ap.parse_args(argv)
    if args.seeds:
        seeds = [int(s) for s in args.seeds.split(",")]
    else:
        seeds = [0] if args.quick else list(SEEDS)
    caps = CAPS_QUICK if args.quick else CAPS_FULL
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t_start = time.time()

    rows: list[dict] = []
    skipped: dict[str, str] = {}
    feature_md = ["## Feature canonicalisation", ""]
    result_md = ["## Results per pair", ""]
    pool_md = ["## Shared-feature pool cleaning (rows removed after restricting to shared features)", "",
               "| pair | dataset | rows before | exact duplicates | label conflicts | feature-only duplicates | rows kept |",
               "|---|---|---|---|---|---|---|"]
    for A, B in PAIRS:
        pair = f"{A} <-> {B}"
        rep = _feature_report(A, B)
        print(f"[E3-pair] {pair}: matched={len(rep['matched'])}", flush=True)
        print(f"  matched:      {rep['matched']}", flush=True)
        print(f"  unmatched {A}: {rep['unmatched_a']}", flush=True)
        print(f"  unmatched {B}: {rep['unmatched_b']}", flush=True)
        print(f"  excluded:     {rep['excluded']}", flush=True)
        feature_md += _report_lines(A, B, rep)
        if not rep["matched"]:
            reason = "no feature names shared after canonicalisation; the pair cannot be analysed"
            print(f"[E3-pair] {pair} not run: {reason}", flush=True)
            skipped[pair] = reason
            result_md += [f"### {pair}", "", f"Not run: {reason}.", ""]
            continue

        shared = rep["matched"]
        rename = {A: {v: k for k, v in rep["orig_a"].items()},
                  B: {v: k for k, v in rep["orig_b"].items()}}
        dedup = {}
        for name in (A, B):
            X, fam, counts = _dedup_pool(name, rename[name], shared)
            dedup[name] = (X, fam)
            n_before = counts["n_rows_clean"] + counts["n_exact_duplicates"] + counts["n_conflict"] + counts["n_feature_duplicates"]
            pool_md.append(f"| {pair} | {name} | {n_before:,} | {counts['n_exact_duplicates']:,} | "
                           f"{counts['n_conflict']:,} | {counts['n_feature_duplicates']:,} | "
                           f"{counts['n_rows_clean']:,} |")
            print(f"[E3-pair] {name}: shared pool rows after cleaning={len(X)} {counts}", flush=True)

        pair_rows = []
        for seed in seeds:
            data = {}
            for name in (A, B):
                X, fam = dedup[name]
                data[name] = _capped_view(X, fam, name, seed, caps)
            for X_name in (A, B):
                for Y_name in (A, B):
                    t0 = time.time()
                    row = run_pair(X_name, Y_name, data, shared, seed)
                    row["pair"] = pair
                    pair_rows.append(row)
                    print(f"[E3-pair] {X_name} -> {Y_name} seed={seed} auroc={row['auroc']:.4f} "
                          f"secs={time.time() - t0:.0f}", flush=True)
        rows.extend(pair_rows)
        pair_df = pd.DataFrame(pair_rows)
        body = e3_tables_md(pair_df, [A, B], len(shared), {})
        result_md += [f"### {pair}", "", demote_headings(body, 1), ""]

    if not rows:
        raise RuntimeError("no dataset pair had shared features; nothing was run")
    df = pd.DataFrame(rows)
    cols_front = ["pair", "A", "B", "seed"]
    df = df[cols_front + [c for c in df.columns if c not in cols_front]]
    df.to_csv(out / "e3_crosspair.csv", index=False)
    elapsed = (time.time() - t_start) / 60
    header = [
        "# E3 cross-pair transfer", "",
        "Dataset pairs that share a feature extractor. Features canonicalised by name, then intersected.",
        f"Caps: {caps[0]:,} benign, {caps[1]:,} per attack family per dataset. "
        f"Seeds: {', '.join(map(str, seeds))}. Wall-clock: {elapsed:.1f} min.", "",
    ]
    md = "\n".join(header + feature_md + pool_md + [""] + result_md)
    (out / "e3_crosspair.md").write_text(md)
    print(md, flush=True)
    return df, skipped


if __name__ == "__main__":
    main()
