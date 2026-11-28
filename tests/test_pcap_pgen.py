"""Packet-level generator P: invariants and the adapter round trip (design/design_pcap.md sections 4 and 8)."""

import numpy as np

from idsbench.pcap import extract as E
from idsbench.pcap import pgen as P

A, B = 0x0A000001, 0x0A000002
SEC = 1_000_000


def _flow_rows(t0, cport, n_client=4, extra_gap=0):
    """A TCP exchange with data in both directions; client data separated by ``extra_gap`` microseconds."""
    rows = [(t0, A, B, cport, 80, E.TCP, 0, 0x02, 29200),
            (t0 + 1000, B, A, 80, cport, E.TCP, 0, 0x12, 28960),
            (t0 + 2000, A, B, cport, 80, E.TCP, 0, 0x10, 229)]
    t = t0 + 3000
    for i in range(n_client):
        rows.append((t, A, B, cport, 80, E.TCP, 100 + 10 * i, 0x18, 229))
        rows.append((t + 500, B, A, 80, cport, E.TCP, 40 + i, 0x18, 227))
        t += 500 + extra_gap
    rows.append((t + 300, B, A, 80, cport, E.TCP, 0, 0x11, 227))
    return rows


def _make_cache(flows):
    """Build a cache-like dict from several flows: features, packet arrays and pool offsets."""
    rows = [r for f in flows for r in f]
    cols = {k: [] for k in ("ts", "src", "dst", "sport", "dport", "proto", "pay", "flg", "win", "tph", "ipl", "hdr")}
    for ts, s, d, sp, dp, pr, pay, fl, w in rows:
        tph = 20 if pr == E.TCP else 8
        cols["ts"].append(ts); cols["src"].append(s); cols["dst"].append(d); cols["sport"].append(sp)
        cols["dport"].append(dp); cols["proto"].append(pr); cols["pay"].append(pay)
        cols["flg"].append(fl if pr == E.TCP else 0); cols["win"].append(w if pr == E.TCP else 0)
        cols["tph"].append(tph); cols["hdr"].append(20 + tph); cols["ipl"].append(20 + tph + pay)
    pk = E.sort_packets({k: np.asarray(v, dtype=np.int64) for k, v in cols.items()})
    fid, F = E.split_flows(pk["k1"], pk["k2"], pk["ts"], pk["src"], pk["proto"], pk["flg"])
    X, meta, d_all = E.extract_flows(pk, fid, F)
    starts = meta["starts"]
    n_pkt = meta["n_packets"]
    G = {"pkt_ts": pk["ts"], "pkt_dir": d_all, "pkt_pay": pk["pay"].astype(np.int64),
         "pkt_ipl": pk["ipl"].astype(np.int64), "pkt_hdr": pk["hdr"].astype(np.int64),
         "pkt_tph": pk["tph"].astype(np.int64), "pkt_flg": pk["flg"].astype(np.int64),
         "pkt_win": pk["win"].astype(np.int64), "pkt_proto": pk["proto"].astype(np.int64)}
    off = np.zeros(F + 1, dtype=np.int64)
    off[1:] = np.cumsum(n_pkt)
    idx = np.concatenate([np.arange(s, s + n) for s, n in zip(starts, n_pkt)])
    cache = {k: v[idx] for k, v in G.items()}
    cache["pkt_off"] = off
    cache["pool_row"] = np.arange(F, dtype=np.int64)
    return cache, X, starts, n_pkt, pk, d_all


def _packets_of(pg, rows_idx):
    bases = np.asarray(rows_idx, dtype=np.int64)
    M, seg = pg._packets(bases)
    return M, seg


def test_level_one_returns_the_flow_unchanged_and_bit_identical():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000), _flow_rows(10 * SEC, 40001, extra_gap=SEC)])
    pg = P.PGen(cache, X, seed=1)
    for g in P.GROUPS:
        assert np.array_equal(pg(X, g, 1.0), X)


def test_cache_features_are_reproduced_from_the_stored_packets():
    cache, X, starts, n_pkt, pk, d_all = _make_cache([_flow_rows(0, 40000), _flow_rows(10 * SEC, 40001)])
    pg = P.PGen(cache, X, seed=1)
    M, seg = _packets_of(pg, np.arange(len(X)))
    Y = E.features(seg, M[:, P.TS], M[:, P.DIR], M[:, P.PAY], M[:, P.IPL], M[:, P.HDR], M[:, P.TPH], M[:, P.FLG],
                   M[:, P.WIN], M[:, P.PRO], len(X))
    assert np.allclose(Y, X, rtol=1e-12, atol=1e-9)


def test_server_packets_keep_size_and_flags_and_order_is_causal():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000, extra_gap=2 * SEC)])
    pg = P.PGen(cache, X, seed=3)
    M0, seg0 = _packets_of(pg, [0])
    # apply count and length then timing with the canonical composition
    M1, seg1 = P._op_count(M0, seg0, np.array([0]), np.array([2.0]), 1, 3)
    M1, seg1 = P._op_length(M1, seg1, np.array([0]), np.array([2.0]), 1, 3)
    M2, seg2, _ = P._op_timing(M1, seg1, np.array([0]), np.array([3.0]), 1, 3)
    server0 = M0[M0[:, P.DIR] == 1]
    server2 = M2[M2[:, P.DIR] == 1]
    assert len(server0) == len(server2)
    for col in (P.PAY, P.IPL, P.HDR, P.TPH, P.FLG, P.WIN):
        assert np.array_equal(server0[:, col], server2[:, col])
    assert np.all(np.diff(M2[:, P.TS]) >= 0)
    assert M2[0, P.TS] == M0[0, P.TS]                    # the flow start does not move
    assert np.all(M1[:, P.PAY][M1[:, P.DIR] == 0] >= M0[M0[:, P.DIR] == 0][:, P.PAY].min())


def test_no_client_quantity_is_reduced_and_totals_are_monotone():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000, extra_gap=SEC // 2), _flow_rows(20 * SEC, 40001)])
    pg = P.PGen(cache, X, seed=7)
    idx = np.arange(len(X))
    cols = {"Total Fwd Packets": 1, "Total Length of Fwd Packets": 1, "Fwd Header Length": 1,
            "Flow Duration": 1, "Fwd Packet Length Max": 1, "Total Backward Packets": 1}
    for g in P.GROUPS:
        for m in (1.5, 5.0):
            Y = pg(X[idx], g, m)
            for name in cols:
                j = E.FEATURES.index(name)
                assert np.all(Y[:, j] >= X[idx][:, j] - 1e-9), (g, m, name)
            bwd = E.FEATURES.index("Total Backward Packets")
            assert np.all(Y[:, bwd] == X[idx][:, bwd])     # no group adds or removes server packets


def test_count_adds_the_expected_number_of_client_packets():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000)])
    pg = P.PGen(cache, X, seed=2)
    nf = X[0, E.FEATURES.index("Total Fwd Packets")]
    Y = pg(X, "count", 2.0)
    assert Y[0, E.FEATURES.index("Total Fwd Packets")] == nf + np.ceil(1.0 * nf - 1e-9)
    # the inserted packets are pure ACKs: payload bytes unchanged
    assert Y[0, E.FEATURES.index("Total Length of Fwd Packets")] == X[0, E.FEATURES.index("Total Length of Fwd Packets")]


def test_timing_cuts_the_flow_at_120_seconds():
    rows = [(0, A, B, 40000, 80, E.TCP, 0, 0x02, 29200),
            (1000, B, A, 80, 40000, E.TCP, 0, 0x12, 28960),
            (2000, A, B, 40000, 80, E.TCP, 0, 0x10, 229),
            (3000, A, B, 40000, 80, E.TCP, 100, 0x18, 229),
            (60 * SEC, A, B, 40000, 80, E.TCP, 100, 0x18, 229),
            (110 * SEC, A, B, 40000, 80, E.TCP, 100, 0x18, 229)]
    cache, X, *_ = _make_cache([rows])
    pg = P.PGen(cache, X, seed=4)
    Y = pg(X, "timing", 5.0)
    assert Y[0, E.FEATURES.index("Flow Duration")] <= 120 * SEC   # the first sub-flow is what is scored
    assert pg.stats["states"] == 1


def test_composition_does_not_depend_on_the_order_of_groups():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000, extra_gap=SEC // 4), _flow_rows(30 * SEC, 40001)])
    pg = P.PGen(cache, X, seed=9)
    a = pg(pg(X, "length", 2.0), "timing", 2.0)
    pg.reset()
    b = pg(pg(X, "timing", 2.0), "length", 2.0)
    assert np.array_equal(a, b)


def test_same_seed_same_result_and_other_seed_differs():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000, extra_gap=SEC // 4)])
    a = P.PGen(cache, X, seed=5)(X, "timing", 2.0)
    b = P.PGen(cache, X, seed=5)(X, "timing", 2.0)
    c = P.PGen(cache, X, seed=6)(X, "timing", 2.0)
    assert np.array_equal(a, b)
    assert not np.array_equal(a, c)                          # the delay draws depend on the seed


def test_adapter_accepts_its_own_output_and_rejects_unknown_rows():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000)])
    pg = P.PGen(cache, X, seed=1)
    Y1 = pg(X, "length", 2.0)
    Y2 = pg(Y1, "timing", 2.0)            # chained call on a mutated row
    assert Y2.shape == X.shape
    try:
        pg(X + 1.0, "count", 2.0)
    except KeyError:
        pass
    else:
        raise AssertionError("unknown rows must not be silently accepted")


def _no_handshake_rows(t0, cport):
    """Client data and server ACKs with no SYN: a mid-stream flow."""
    return [(t0, A, B, cport, 80, E.TCP, 100, 0x18, 229), (t0 + 2 * SEC, B, A, 80, cport, E.TCP, 40, 0x18, 227),
            (t0 + 4 * SEC, A, B, cport, 80, E.TCP, 60, 0x18, 229), (t0 + 6 * SEC, B, A, 80, cport, E.TCP, 0, 0x10, 227)]


def test_count_is_a_no_op_without_a_handshake():
    cache, X, *_ = _make_cache([_no_handshake_rows(0, 41000)])
    pg = P.PGen(cache, X, seed=1)
    Y = pg(X, "count", 3.0)
    assert np.array_equal(Y, X)


def test_count_inserts_acks_strictly_inside_the_span_after_the_handshake():
    cache, X, starts, n_pkt, pk, d_all = _make_cache([_flow_rows(0, 40000, extra_gap=SEC // 2)])
    pg = P.PGen(cache, X, seed=3)
    M0, seg0 = _packets_of(pg, [0])
    M1, seg1 = P._op_count(M0, seg0, np.array([0]), np.array([2.0]), 1, 3)
    ins = M1[(M1[:, P.PAY] == 0) & (M1[:, P.DIR] == 0) & (M1[:, P.FLG] == 0x10)]
    third_ts = M0[2, P.TS]
    last_ts = M0[-1, P.TS]
    new = [t for t in M1[:, P.TS] if t not in set(M0[:, P.TS].tolist())]
    assert len(new) >= 1
    assert all(third_ts < t < last_ts for t in new)


def test_expected_added_delay_equals_m_minus_one_times_forward_iat_total():
    cache, X, *_ = _make_cache([_flow_rows(0, 40000, extra_gap=SEC)])
    fwd_total = None
    base_dur = X[0, E.FEATURES.index("Flow Duration")]
    fwd_iat_total = X[0, E.FEATURES.index("Fwd IAT Total")]
    m = 2.0
    added = []
    for seed in range(200):
        pg = P.PGen(cache, X, seed=seed)
        Y = pg(X, "timing", m)
        added.append(Y[0, E.FEATURES.index("Flow Duration")] - base_dur)
    assert abs(np.mean(added) - (m - 1) * fwd_iat_total) < 0.15 * (m - 1) * fwd_iat_total
