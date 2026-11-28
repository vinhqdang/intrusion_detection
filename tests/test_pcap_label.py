"""Label join: CIC time parsing, candidate pairs, label rule, measured shift (design section 2)."""

import numpy as np
import pandas as pd

from idsbench.pcap import label as L
from idsbench.pcap.extract import canonical_keys

HOUR = 3600 * 1_000_000
MIN = 60 * 1_000_000


def cic_frame(rows):
    """rows: (src, sport, dst, dport, proto, lo_local_us, window_us, label)."""
    df = pd.DataFrame(rows, columns=["src", "sport", "dst", "dport", "proto", "lo_local", "window", "label"])
    df["src"] = df["src"].astype(np.uint64)
    df["dst"] = df["dst"].astype(np.uint64)
    k1, k2 = canonical_keys(df["src"], df["dst"], df["sport"], df["dport"], df["proto"])
    df["k1"], df["k2"] = k1, k2
    df["row"] = np.arange(len(df))
    return df


def test_cic_twelve_hour_clock_is_read_as_afternoon():
    us, sec = L.parse_cic_local(pd.Series(["4/7/2017 1:05", "4/7/2017 10:30", "4/7/2017 12:00", "4/7/2017 8:54"]))
    hours = pd.to_datetime(us, unit="us").hour.tolist()
    assert hours == [13, 10, 12, 8]
    assert not sec.any()


def test_monday_seconds_format_is_24_hour_and_precise():
    us, sec = L.parse_cic_local(pd.Series(["03/07/2017 08:55:58"]))
    assert pd.to_datetime(us, unit="us")[0] == pd.Timestamp("2017-07-03 08:55:58")
    assert sec.all()


def test_candidate_pairs_match_brute_force():
    rng = np.random.default_rng(3)
    n_cic, n_flow = 300, 400
    rows = []
    for _ in range(n_cic):
        ip = int(rng.integers(1, 4))
        rows.append((ip, int(rng.integers(1000, 1004)), 9, 80, 6, int(rng.integers(0, 6)) * MIN, MIN, "BENIGN"))
    cic = cic_frame(rows)
    fk1, fk2 = canonical_keys(np.array(rng.integers(1, 4, n_flow), np.uint64), np.full(n_flow, 9, np.uint64),
                              rng.integers(1000, 1004, n_flow), np.full(n_flow, 80), np.full(n_flow, 6))
    t = rng.integers(0, 6 * MIN + MIN, n_flow).astype(np.int64)
    shift = 0
    pf, pr = L.candidate_pairs(t, fk1, fk2, cic, shift)
    got = set(zip(pf.tolist(), pr.tolist()))
    lo = cic["lo_local"].to_numpy() + shift
    want = set()
    for i in range(n_flow):
        for r in range(n_cic):
            if (cic.k1.values[r] == fk1[i] and cic.k2.values[r] == fk2[i]
                    and lo[r] <= t[i] < lo[r] + cic.window.values[r]):
                want.add((i, int(cic.row.values[r])))
    assert got == want


def test_composite_searchsorted_matches_numpy_on_sorted_keys():
    rng = np.random.default_rng(5)
    n = 500
    k1 = np.sort(rng.integers(0, 4, n)).astype(np.uint64)
    k2 = np.zeros(n, np.uint64)
    t = np.zeros(n, np.int64)
    for v in np.unique(k1):
        m = np.flatnonzero(k1 == v)
        tt = np.sort(rng.integers(0, 100, len(m)))
        t[m] = tt
    q1 = rng.integers(0, 4, 200).astype(np.uint64)
    qt = rng.integers(-5, 105, 200).astype(np.int64)
    got = L._composite_searchsorted(k1, k2, t, q1, np.zeros(200, np.uint64), qt)
    keys = list(zip(k1.tolist(), t.tolist()))
    want = [sum(1 for kk in keys if kk <= (int(a), int(b))) for a, b in zip(q1, qt)]
    assert got.tolist() == want


def test_label_rule_unmatched_ambiguous_and_single():
    cic = cic_frame([
        (1, 1000, 9, 80, 6, 0, MIN, "PortScan"),
        (1, 2000, 9, 80, 6, 0, MIN, "BENIGN"),
        (1, 2000, 9, 80, 6, 0, MIN, "PortScan"),
        (1, 3000, 9, 80, 6, 0, MIN, "BENIGN"),
    ])
    fk1, fk2 = canonical_keys(np.array([1, 1, 1, 7], np.uint64), np.array([9, 9, 9, 9], np.uint64),
                              np.array([1000, 2000, 3000, 4000]), np.array([80, 80, 80, 80]),
                              np.array([6, 6, 6, 6]))
    t = np.array([10, 10, 10, 10], np.int64)
    pf, pr = L.candidate_pairs(t, fk1, fk2, cic, 0)
    res = L.assign_labels(4, pf, pr, cic)
    lab = res["label"]
    assert lab[0] == 4            # PortScan (index in LABELS)
    assert lab[1] == -2           # BENIGN and PortScan candidates: ambiguous
    assert lab[2] == 0            # BENIGN
    assert lab[3] == -1           # no CIC row with this 5-tuple
    assert res["n_candidates"].tolist() == [1, 2, 1, 0]


def test_shift_is_recovered_from_flows_and_cic_rows():
    rng = np.random.default_rng(11)
    true_shift = 3 * HOUR
    n = 400
    rows, flow_src = [], []
    for i in range(n):
        ip = int(rng.integers(1, 200))
        sp = int(rng.integers(1024, 60000))
        lo_local = 8 * HOUR + int(rng.integers(0, 50)) * MIN
        rows.append((ip, sp, 9, 80, 6, lo_local, MIN, "BENIGN"))
        flow_src.append(lo_local + true_shift + int(rng.integers(0, MIN)))
    cic = cic_frame(rows)
    k1, k2 = canonical_keys(cic["src"].to_numpy(), cic["dst"].to_numpy(), cic["sport"].to_numpy(),
                            cic["dport"].to_numpy(), cic["proto"].to_numpy())
    info = L.estimate_shift(np.array(flow_src, np.int64), k1, k2, cic, coarse_hours=range(0, 7))
    assert info["shift_us"] == true_shift
    assert info["flows_matched_at_best"] == n


def test_primary_rule_uses_the_attack_pattern_then_the_majority():
    cic = cic_frame([
        (L._ip("172.16.0.1"), 1000, L._ip("192.168.10.50"), 80, 6, 0, MIN, "DDoS"),
        (L._ip("172.16.0.1"), 1000, L._ip("192.168.10.50"), 80, 6, 0, MIN, "BENIGN"),
        (L._ip("10.0.0.9"), 2000, L._ip("192.168.10.50"), 80, 6, 0, MIN, "DDoS"),
        (L._ip("10.0.0.9"), 2000, L._ip("192.168.10.50"), 80, 6, 0, MIN, "BENIGN"),
        (L._ip("10.0.0.9"), 2000, L._ip("192.168.10.50"), 80, 6, 0, MIN, "BENIGN"),
    ])
    # flow 0: attacker pattern and a DDoS candidate -> DDoS; flow 1: wrong source -> majority BENIGN (2 vs 1)
    src = np.array([L._ip("172.16.0.1"), L._ip("10.0.0.9")], np.int64)
    dst = np.array([L._ip("192.168.10.50"), L._ip("192.168.10.50")], np.int64)
    sport = np.array([1000, 2000]); dport = np.array([80, 80])
    k1, k2 = canonical_keys(src, dst, sport, dport, np.array([6, 6]))
    pf, pr = L.candidate_pairs(np.array([10, 10], np.int64), k1, k2, cic, 0)
    res = L.primary_labels(2, pf, pr, cic, src, dst, sport, dport)
    assert res["label"][0] == 5          # DDoS
    assert res["label"][1] == 0          # BENIGN
    assert res["how"].tolist() == [1, 2]
