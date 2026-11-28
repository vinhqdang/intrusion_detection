"""Build step: one pass per capture, writing the flow cache (design/design_pcap.md sections 2 and 3).

    python -m idsbench.pcap.build --day tuesday --pcap data/pcap/Tuesday-WorkingHours.pcap

For each capture the step
  1. hashes the file (SHA-256) and parses every IPv4 TCP/UDP packet;
  2. sorts packets by 5-tuple and time, assigns flows (CICFlowMeter rules with trailing-packet absorption) and
     extracts features;
  3. measures the CIC timezone shift on the busiest hour, labels flows from candidate CIC rows and drops unmatched
     and ambiguous flows;
  4. keeps every attack flow and up to ``--benign-cap`` benign flows (sampled after extraction); stores the packets
     of every attack flow and of ``--benign-pkt`` benign flows for the packet-level generator;
  5. writes data/pcap/cache/<day>.npz and the provenance and validation statistics to results/pcap/.

Caches are git-ignored (data/). Statistics go to results/pcap/build_<day>.json and extractor_validation_<day>.csv.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from . import extract as E
from . import label as L

CACHE = Path("data/pcap/cache")
RESULTS = Path("results/pcap")
PKT_DTYPES = {"ts": np.int64, "dir": np.int8, "pay": np.int32, "ipl": np.int32, "hdr": np.int16, "tph": np.int16,
              "flg": np.int16, "win": np.int32, "proto": np.int16}
PKT_COLS = tuple(PKT_DTYPES)


def sha256_file(path: str, chunk: int = 1 << 24) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def read_packets(path: str, log=print) -> tuple[dict, dict]:
    """All IPv4 TCP/UDP packets of a capture as one sorted column table (k1, k2 added)."""
    t0 = time.time()
    parts = {k: [] for k in ("ts", "src", "dst", "sport", "dport", "proto", "pay", "ipl", "hdr", "tph", "flg", "win")}
    skips: dict = {}
    n_chunks = 0
    for bufs, tss in E.iter_chunks(path):
        cols, sk = E.parse_frames(bufs, tss)
        for k in parts:
            parts[k].append(cols[k])
        for k, v in sk.items():
            skips[k] = skips.get(k, 0) + v
        n_chunks += 1
        if n_chunks % 10 == 0:
            log(f"  parsed {sum(len(x) for x in parts['ts']):,} packets, {time.time() - t0:.0f}s")
    pk = {k: np.concatenate(v) for k, v in parts.items()}
    del parts
    log(f"  parsing done: {len(pk['ts']):,} packets in {time.time() - t0:.0f}s")
    return pk, skips


def extractor_validation(day: str, first_ts, k1, k2, X, row_labels, shift_us, pair_flow, pair_row,
                         cic: pd.DataFrame, Xc: np.ndarray, sample: int = 60_000, seed: int = 7) -> pd.DataFrame:
    """Per-feature agreement with the CIC table (share within 1% relative error) and distribution distances.

    Three views, because CIC rows and our flows are not one-to-one for every connection (see SUMMARY.md):
      one_to_one   pairs with exactly one candidate on each side;
      any_candidate  a flow agrees with at least one candidate CIC row (upper bound);
      ks           two-sample Kolmogorov-Smirnov statistic of the whole day's features, our flows versus CIC rows.
    """
    from scipy.stats import ks_2samp

    rng = np.random.default_rng(seed)
    n_cand_flow = np.bincount(pair_flow, minlength=len(first_ts))
    n_cand_row = np.bincount(pair_row, minlength=len(cic))
    one = (n_cand_flow[pair_flow] == 1) & (n_cand_row[pair_row] == 1)
    pf1, pr1 = pair_flow[one], pair_row[one]
    rows = []
    # one-to-one
    if len(pf1):
        A = X[pf1]
        C = Xc[pr1]
        ok = np.abs(A - C) <= 0.01 * np.abs(C) + 1e-9
    else:
        ok = np.zeros((0, E.N_FEAT), bool)
    # any candidate on a sample of matched flows
    flows_m = np.unique(pair_flow)
    samp = rng.choice(flows_m, size=min(sample, len(flows_m)), replace=False)
    sset = np.zeros(len(first_ts), bool)
    sset[samp] = True
    sel = sset[pair_flow]
    pf, pr = pair_flow[sel], pair_row[sel]
    anyok = np.zeros((len(samp), E.N_FEAT), bool)
    pos = {f: i for i, f in enumerate(samp)}
    if len(pf):
        Ac = X[pf]
        Cc = Xc[pr]
        okc = np.abs(Ac - Cc) <= 0.01 * np.abs(Cc) + 1e-9
        for j, f in enumerate(pf):
            anyok[pos[f]] |= okc[j]
    # distributions
    ks_stat = {}
    cic_idx = rng.choice(len(Xc), size=min(200_000, len(Xc)), replace=False)
    our_idx = rng.choice(len(X), size=min(200_000, len(X)), replace=False)
    for j, name in enumerate(E.FEATURES):
        try:
            ks_stat[name] = float(ks_2samp(X[our_idx, j], Xc[cic_idx, j]).statistic)
        except ValueError:
            ks_stat[name] = float("nan")
    for j, name in enumerate(E.FEATURES):
        rows.append({
            "day": day, "feature": name,
            "one_to_one_pairs": int(len(pf1)),
            "one_to_one_agree": float(ok[:, j].mean()) if len(pf1) else float("nan"),
            "any_candidate_flows": int(len(samp)),
            "any_candidate_agree": float(anyok[:, j].mean()) if len(samp) else float("nan"),
            "ks_our_vs_cic": ks_stat[name],
        })
    return pd.DataFrame(rows)


def consistency_check(X, pk, starts, n_pkt, idx_flows, d_all) -> float:
    """Re-extracting a flow from the stored packets must reproduce the cached features."""
    sub = []
    segs = []
    for k, f in enumerate(idx_flows):
        a, b = starts[f], starts[f] + n_pkt[f]
        sub.append(np.arange(a, b))
        segs.append(np.full(b - a, k))
    ii = np.concatenate(sub)
    seg = np.concatenate(segs)
    Y = E.features(seg, pk["ts"][ii], d_all[ii], pk["pay"][ii], pk["ipl"][ii], pk["hdr"][ii], pk["tph"][ii],
                   pk["flg"][ii], pk["win"][ii], pk["proto"][ii], len(idx_flows))
    return float(np.max(np.abs(Y - X[idx_flows]) / (np.abs(X[idx_flows]) + 1.0)))


def build_day(day: str, pcap: str, pcap_name: str, cic_path: str, benign_cap: int, benign_pkt: int,
              seed: int, log=print) -> dict:
    t_start = time.time()
    stats: dict = {"day": day, "pcap": pcap_name}
    digest, size = sha256_file(pcap)
    stats.update({"sha256": digest, "size_bytes": size})
    log(f"[{day}] sha256 {digest} size {size:,}")

    pk, skips = read_packets(pcap, log)
    stats.update({"frames_total": skips.get("frames_total", 0), "packets_kept_ipv4_tcp_udp": int(len(pk["ts"])),
                  "skipped": {k: v for k, v in skips.items() if k.startswith("skipped")}})
    pk = E.sort_packets(pk)
    sfs: dict = {"absorbed": 0}
    fid, F = E.split_flows(pk["k1"], pk["k2"], pk["ts"], pk["src"], pk["proto"], pk["flg"], stats=sfs)
    stats["trailing_packets_absorbed"] = int(sfs["absorbed"])
    log(f"[{day}] flows {F:,} ({time.time() - t_start:.0f}s)")
    X, meta, d_all = E.extract_flows(pk, fid, F)
    starts = meta["starts"]
    n_pkt = meta["n_packets"]
    stats["flows_extracted"] = int(F)
    stats["tcp_flows"] = int(np.count_nonzero(meta["proto"] == E.TCP))
    stats["flows_single_packet"] = int(np.count_nonzero(n_pkt == 1))
    stats["max_flow_duration_us"] = float(X[:, E.FEATURES.index("Flow Duration")].max())

    cic, Xc = L.load_cic(day, cic_path, with_features=True)
    stats["cic_rows_day"] = int(len(cic))
    stats["cic_rows_by_label"] = cic["label"].value_counts().to_dict()
    shift = L.estimate_shift(meta["first_ts"], meta["k1"], meta["k2"], cic)
    stats["shift"] = shift
    log(f"[{day}] shift {shift['shift_hours']:+.2f} h, matched flows {shift['flows_matched_at_best']:,}")
    shift_us = shift["shift_us"]
    pair_flow, pair_row = L.candidate_pairs(meta["first_ts"], meta["k1"], meta["k2"], cic, shift_us)
    lab = L.assign_labels(F, pair_flow, pair_row, cic)
    label_drop = lab["label"]                     # sensitivity rule: ambiguous sets dropped (-2)
    prim = L.primary_labels(F, pair_flow, pair_row, cic, meta["init_src"], meta["init_dst"],
                            meta["init_sport"], meta["init_dport"])
    label = prim["label"]                         # primary rule (pattern, then majority)
    how = prim["how"]
    stats["primary_rule_flows_by_how"] = {"pattern": int(np.count_nonzero(how == 1)),
                                          "majority": int(np.count_nonzero(how == 2))}
    stats["drop_rule_flows_ambiguous"] = int(np.count_nonzero(label_drop == -2))
    stats["connection_flows_by_label"] = {
        name: int(np.count_nonzero((label == c) & meta["connection"])) for c, name in enumerate(L.LABELS)}
    stats["drop_rule_flows_by_label"] = {name: int(np.count_nonzero(label_drop == c))
                                         for c, name in enumerate(L.LABELS)}
    # CIC side: a CIC row is matched when at least one flow falls in its window
    cic_hits = np.bincount(pair_row, minlength=len(cic))
    is_attack_row = cic["label"].to_numpy() != "BENIGN"
    stats["cic_attack_rows"] = int(is_attack_row.sum())
    stats["cic_attack_rows_matched"] = int(np.count_nonzero((cic_hits > 0) & is_attack_row))
    stats["cic_attack_match_rate"] = stats["cic_attack_rows_matched"] / max(stats["cic_attack_rows"], 1)
    stats["cic_benign_rows_matched_share"] = float(np.count_nonzero((cic_hits > 0) & ~is_attack_row)
                                                 / max((~is_attack_row).sum(), 1))
    per_label = {}
    for c, name in enumerate(L.LABELS):
        per_label[name] = {"cic_rows": int(np.count_nonzero(cic["label"].to_numpy() == name)),
                           "cic_rows_matched": int(np.count_nonzero((cic_hits > 0)
                                                                    & (cic["label"].to_numpy() == name))),
                           "flows_labelled": int(np.count_nonzero(label == c)),
                           "flows_labelled_drop_rule": int(np.count_nonzero(label_drop == c))}
    stats["labels_by_name"] = per_label
    stats["flows_unmatched"] = int(np.count_nonzero(label == -1))
    stats["flows_ambiguous_dropped"] = int(np.count_nonzero(label_drop == -2))   # drop rule (sensitivity)
    stats["flows_matched"] = int(np.count_nonzero(label >= 0))
    stats["attack_flows_matched"] = int(np.count_nonzero(label > 0))
    stats["attack_flow_match_rate_vs_cic"] = stats["cic_attack_match_rate"]
    log(f"[{day}] CIC attack rows matched {stats['cic_attack_rows_matched']}/{stats['cic_attack_rows']} "
        f"({stats['cic_attack_match_rate']:.3f}); flows matched {stats['flows_matched']:,}, "
        f"ambiguous {stats['flows_ambiguous_dropped']:,}, unmatched {stats['flows_unmatched']:,}")

    # validation before selection (uses all matched pairs)
    val = extractor_validation(day, meta["first_ts"], meta["k1"], meta["k2"], X, label, shift_us, pair_flow,
                               pair_row, cic, Xc)
    RESULTS.mkdir(parents=True, exist_ok=True)
    val.to_csv(RESULTS / f"extractor_validation_{day}.csv", index=False)

    # selection: all attack flows, benign sampled after extraction
    rng = np.random.default_rng([seed, 2017])
    matched = np.flatnonzero(label >= 0)
    ben = matched[label[matched] == 0]
    att = matched[label[matched] > 0]
    ben_keep = rng.permutation(ben)[: min(benign_cap, len(ben))]
    ben_keep = np.sort(ben_keep)
    pool_ben = ben_keep[rng.permutation(len(ben_keep))[: min(benign_pkt, len(ben_keep))]]
    keep = np.sort(np.concatenate([att, ben_keep]))
    pool = np.sort(np.concatenate([att, pool_ben]))
    stats["benign_flows_matched"] = int(len(ben))
    stats["benign_flows_kept"] = int(len(ben_keep))
    stats["attack_flows_kept"] = int(len(att))
    stats["packet_pool_flows"] = int(len(pool))

    # consistency: re-extract stored packets of 2000 pool flows
    chk = rng.choice(pool, size=min(2000, len(pool)), replace=False)
    stats["reextraction_max_rel_diff"] = consistency_check(X, pk, starts, n_pkt, chk, d_all)

    # packets of the pool flows
    lens = n_pkt[pool]
    off = np.zeros(len(pool) + 1, dtype=np.int64)
    off[1:] = np.cumsum(lens)
    gather = np.repeat(starts[pool] - off[:-1], lens) + np.arange(off[-1], dtype=np.int64)
    arrays = {
        "pkt_ts": pk["ts"][gather].astype(np.int64),
        "pkt_dir": d_all[gather].astype(np.int8),
        "pkt_pay": pk["pay"][gather].astype(np.int32),
        "pkt_ipl": pk["ipl"][gather].astype(np.int32),
        "pkt_hdr": pk["hdr"][gather].astype(np.int16),
        "pkt_tph": pk["tph"][gather].astype(np.int16),
        "pkt_flg": pk["flg"][gather].astype(np.int16),
        "pkt_win": pk["win"][gather].astype(np.int32),
        "pkt_proto": pk["proto"][gather].astype(np.int16),
    }
    pool_row = np.full(F, -1, dtype=np.int64)
    pool_row[pool] = np.arange(len(pool))
    pool_row_keep = pool_row[keep]
    CACHE.mkdir(parents=True, exist_ok=True)
    np.savez(
        CACHE / f"{day}.npz",
        X=X[keep], label=label[keep], label_drop=label_drop[keep], connection=meta["connection"][keep],
        k1=meta["k1"][keep], k2=meta["k2"][keep],
        first_ts=meta["first_ts"][keep], n_packets=n_pkt[keep], pool_row=pool_row_keep,
        pkt_off=off, **arrays,
    )
    stats["cache_file"] = str(CACHE / f"{day}.npz")
    stats["shift_us"] = int(shift_us)
    stats["runtime_s"] = round(time.time() - t_start, 1)
    (RESULTS / f"build_{day}.json").write_text(json.dumps(stats, indent=2, default=float))
    log(f"[{day}] cache written, {stats['runtime_s']}s total")
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m idsbench.pcap.build")
    ap.add_argument("--day", choices=sorted(L.DAY_PREFIX), required=True)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--cic", default=L.CIC_PATH)
    ap.add_argument("--benign-cap", type=int, default=300_000)
    ap.add_argument("--benign-pkt", type=int, default=300_000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    build_day(args.day, args.pcap, Path(args.pcap).name, args.cic, args.benign_cap, args.benign_pkt, args.seed,
              log=lambda m: print(m, flush=True))


def load_cache(days=("tuesday", "friday"), root: Path = CACHE) -> dict:
    """Concatenated cache of the given days. ``pool_row`` indexes into the concatenated packet offsets."""
    parts = []
    xs, labels, k1s, k2s, firsts, npk, day_id, pool_rows = [], [], [], [], [], [], [], []
    labels_drop, conns = [], []
    pkt = {c: [] for c in PKT_COLS}
    off_all = [np.zeros(1, dtype=np.int64)]
    pool_off = 0
    for di, day in enumerate(days):
        z = np.load(root / f"{day}.npz")
        xs.append(z["X"])
        labels.append(z["label"])
        labels_drop.append(z["label_drop"])
        conns.append(z["connection"])
        k1s.append(z["k1"])
        k2s.append(z["k2"])
        firsts.append(z["first_ts"])
        npk.append(z["n_packets"])
        day_id.append(np.full(len(z["X"]), di, dtype=np.int8))
        pr = z["pool_row"].copy()
        pr[pr >= 0] += pool_off
        pool_rows.append(pr)
        off = z["pkt_off"]
        off_all.append(off[1:] + off_all[-1][-1])
        pool_off += len(off) - 1
        for c in PKT_COLS:
            pkt[c].append(z[f"pkt_{c}"])
    out = {
        "X": np.vstack(xs), "label": np.concatenate(labels), "label_drop": np.concatenate(labels_drop),
        "connection": np.concatenate(conns), "k1": np.concatenate(k1s), "k2": np.concatenate(k2s),
        "first_ts": np.concatenate(firsts), "n_packets": np.concatenate(npk), "day": np.concatenate(day_id),
        "pool_row": np.concatenate(pool_rows), "pkt_off": np.concatenate(off_all),
    }
    for c in PKT_COLS:
        out[f"pkt_{c}"] = np.concatenate(pkt[c])
    out["features"] = E.FEATURES
    out["families"] = L.LABELS
    return out


if __name__ == "__main__":
    main()
