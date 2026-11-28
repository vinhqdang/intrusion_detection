"""Flow extractor on small hand-computed packet lists (design/design_pcap.md section 8)."""

import struct

import numpy as np

from idsbench.pcap import extract as E

A, B = 0x0A000001, 0x0A000002          # client, server
SEC = 1_000_000                        # microseconds per second


def table(rows):
    """rows: (ts_us, src, dst, sport, dport, proto, payload, tcp_flags, window)."""
    cols = {k: [] for k in ("ts", "src", "dst", "sport", "dport", "proto", "pay", "flg", "win", "tph", "ipl", "hdr")}
    for ts, s, d, sp, dp, pr, pay, fl, w in rows:
        tph = 20 if pr == E.TCP else 8
        cols["ts"].append(ts)
        cols["src"].append(s)
        cols["dst"].append(d)
        cols["sport"].append(sp)
        cols["dport"].append(dp)
        cols["proto"].append(pr)
        cols["pay"].append(pay)
        cols["flg"].append(fl if pr == E.TCP else 0)
        cols["win"].append(w if pr == E.TCP else 0)
        cols["tph"].append(tph)
        cols["hdr"].append(20 + tph)
        cols["ipl"].append(20 + tph + pay)
    return {k: np.asarray(v, dtype=np.int64) for k, v in cols.items()}


def extract(rows):
    pk = E.sort_packets(table(rows))
    fid, F = E.split_flows(pk["k1"], pk["k2"], pk["ts"], pk["src"], pk["proto"], pk["flg"])
    X, meta, _ = E.extract_flows(pk, fid, F)
    return X, meta, pk


def col(X, name):
    return X[:, E.FEATURES.index(name)]


SYN, SYNACK, ACK, PSH, FIN, RST = 0x02, 0x12, 0x10, 0x18, 0x01, 0x04
FINACK = 0x11


def handshake_and_close(t0=0):
    return [
        (t0 + 0, A, B, 50000, 80, E.TCP, 0, SYN, 29200),
        (t0 + 1000, B, A, 80, 50000, E.TCP, 0, SYNACK, 28960),
        (t0 + 2000, A, B, 50000, 80, E.TCP, 0, ACK, 229),
        (t0 + 3000, A, B, 50000, 80, E.TCP, 100, PSH, 229),
        (t0 + 4000, B, A, 80, 50000, E.TCP, 50, PSH, 227),
        (t0 + 5000, A, B, 50000, 80, E.TCP, 0, FINACK, 229),
        (t0 + 5100, B, A, 80, 50000, E.TCP, 0, ACK, 227),
        (t0 + 5200, B, A, 80, 50000, E.TCP, 0, FINACK, 227),
    ]


def test_handshake_data_and_fin_close_one_flow():
    X, meta, _ = extract(handshake_and_close())
    assert len(X) == 1
    assert col(X, "Flow Duration")[0] == 5200
    assert col(X, "Total Fwd Packets")[0] == 4          # SYN, ACK, data, FIN
    assert col(X, "Total Backward Packets")[0] == 4     # SYN-ACK, data, ACK, FIN
    assert col(X, "Total Length of Fwd Packets")[0] == 100
    assert col(X, "Total Length of Bwd Packets")[0] == 50
    assert col(X, "Fwd Packet Length Max")[0] == 100
    assert col(X, "Bwd Packet Length Min")[0] == 0
    assert col(X, "FIN Flag Count")[0] == 2
    assert col(X, "SYN Flag Count")[0] == 2
    assert col(X, "Init_Win_bytes_forward")[0] == 29200
    assert col(X, "Init_Win_bytes_backward")[0] == 28960
    assert col(X, "act_data_pkt_fwd")[0] == 1
    assert col(X, "Fwd Header Length")[0] == 4 * 40
    assert col(X, "Down/Up Ratio")[0] == 1


def test_trailing_ack_within_two_seconds_is_absorbed_into_the_closed_flow():
    rows = handshake_and_close() + [(5300, A, B, 50000, 80, E.TCP, 0, ACK, 229)]
    X, meta, _ = extract(rows)
    assert len(X) == 1
    assert col(X, "Total Fwd Packets")[0] == 5
    assert col(X, "Flow Duration")[0] == 5300          # the absorbed ACK is part of the flow


def test_packet_after_two_seconds_opens_a_new_flow():
    rows = handshake_and_close() + [(5200 + 3 * SEC, A, B, 50000, 80, E.TCP, 0, ACK, 229)]
    X, meta, _ = extract(rows)
    assert len(X) == 2
    assert sorted(col(X, "Total Fwd Packets").tolist()) == [1, 4]


def test_syn_after_close_always_opens_a_new_flow():
    rows = handshake_and_close() + [(5300, A, B, 50000, 80, E.TCP, 0, SYN, 29200)]
    X, meta, _ = extract(rows)
    assert len(X) == 2


def test_connection_flag_needs_syn_synack_and_three_packets():
    full = handshake_and_close()
    half = [(0, A, B, 40001, 80, E.TCP, 0, SYN, 29200), (1000, A, B, 40001, 80, E.TCP, 5, PSH, 229),
            (2000, A, B, 40001, 80, E.TCP, 5, PSH, 229)]
    udp1 = [(0, A, B, 53, 53, E.UDP, 10, 0, 0)]
    udp2 = [(0, A, B, 5353, 5353, E.UDP, 10, 0, 0), (1000, B, A, 5353, 5353, E.UDP, 10, 0, 0)]
    pk = E.sort_packets(table(full + half + udp1 + udp2))
    fid, F = E.split_flows(pk["k1"], pk["k2"], pk["ts"], pk["src"], pk["proto"], pk["flg"])
    X, meta, _ = E.extract_flows(pk, fid, F)
    by_sport = {int(p): bool(c) for p, c in zip(meta["init_sport"], meta["connection"])}
    assert by_sport[50000] is True       # full handshake, 8 packets
    assert by_sport[40001] is False      # no SYN-ACK
    assert by_sport[53] is False         # UDP with one packet
    assert by_sport[5353] is True        # UDP with two packets


def test_single_fin_does_not_close_the_flow():
    rows = handshake_and_close()[:5] + [(5000, A, B, 50000, 80, E.TCP, 0, FIN, 229),
                                        (5100, B, A, 80, 50000, E.TCP, 0, ACK, 227)]
    X, _, _ = extract(rows)
    assert len(X) == 1
    assert col(X, "Total Backward Packets")[0] == 3


def test_rst_closes_the_flow_and_a_trailing_ack_is_absorbed():
    rows = [(0, A, B, 1000, 22, E.TCP, 0, SYN, 1000),
            (500, B, A, 22, 1000, E.TCP, 0, RST, 0),
            (600, A, B, 1000, 22, E.TCP, 0, ACK, 1000)]
    X, _, _ = extract(rows)
    assert len(X) == 1
    assert col(X, "RST Flag Count")[0] == 1
    assert col(X, "Total Fwd Packets")[0] == 2


def test_rst_then_syn_opens_a_new_flow():
    rows = [(0, A, B, 1000, 22, E.TCP, 0, SYN, 1000),
            (500, B, A, 22, 1000, E.TCP, 0, RST, 0),
            (600, A, B, 1000, 22, E.TCP, 0, SYN, 1000)]
    X, _, _ = extract(rows)
    assert len(X) == 2


def test_flow_timeout_splits_at_120_seconds_from_the_start():
    inside = [(0, A, B, 53, 53, E.UDP, 10, 0, 0), (119 * SEC, A, B, 53, 53, E.UDP, 10, 0, 0)]
    X, _, _ = extract(inside)
    assert len(X) == 1
    split = [(0, A, B, 53, 53, E.UDP, 10, 0, 0), (121 * SEC, A, B, 53, 53, E.UDP, 10, 0, 0)]
    X, _, _ = extract(split)
    assert len(X) == 2
    assert np.all(col(X, "Flow Duration") == 0)


def test_active_and_idle_periods_use_the_5_second_threshold():
    t = [0, 1 * SEC, 2 * SEC, 10 * SEC, 11 * SEC]          # gap of 8 s between 2 s and 10 s is idle
    rows = [(x, A, B, 53, 53, E.UDP, 10, 0, 0) for x in t]
    X, _, _ = extract(rows)
    # only the first burst (0 to 2 s) is closed by the idle gap; the last burst (10 to 11 s) is not recorded
    assert col(X, "Active Mean")[0] == 2 * SEC
    assert col(X, "Active Max")[0] == 2 * SEC
    assert col(X, "Idle Mean")[0] == 8 * SEC
    assert col(X, "Idle Max")[0] == 8 * SEC


def test_no_idle_gap_means_zero_idle_and_active_features():
    rows = [(x * SEC, A, B, 53, 53, E.UDP, 10, 0, 0) for x in range(4)]
    X, _, _ = extract(rows)
    assert col(X, "Idle Mean")[0] == 0
    assert col(X, "Active Mean")[0] == 0                      # the only active period is never closed


def test_standard_deviations_are_sample_deviations_as_in_cicflowmeter():
    rows = [(0, A, B, 53, 53, E.UDP, 10, 0, 0), (1 * SEC, A, B, 53, 53, E.UDP, 20, 0, 0),
            (3 * SEC, A, B, 53, 53, E.UDP, 30, 0, 0)]
    X, _, _ = extract(rows)
    gaps = np.array([1.0, 2.0]) * SEC
    assert np.isclose(col(X, "Flow IAT Std")[0], np.std(gaps, ddof=1))
    assert np.isclose(col(X, "Packet Length Std")[0], np.std([10.0, 20.0, 30.0], ddof=1))


def test_rates_and_iat_on_a_simple_udp_exchange():
    rows = [(0, A, B, 5000, 9, E.UDP, 100, 0, 0), (2 * SEC, B, A, 9, 5000, E.UDP, 300, 0, 0)]
    X, _, _ = extract(rows)
    assert col(X, "Flow Duration")[0] == 2 * SEC
    assert col(X, "Flow Bytes/s")[0] == 400 / 2
    assert col(X, "Flow Packets/s")[0] == 1.0
    assert col(X, "Flow IAT Mean")[0] == 2 * SEC
    assert col(X, "Fwd IAT Total")[0] == 0                   # one forward packet
    assert col(X, "Average Packet Size")[0] == 200


def test_parse_frames_reads_ethernet_ipv4_tcp_and_skips_other_frames():
    def frame(src, dst, sport, dport, flags, payload=b"x" * 10, win=1000):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 2, 5 << 4, flags, win, 0, 0)
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                         struct.pack("!I", src), struct.pack("!I", dst))
        return eth + ip + tcp + payload

    cdp = b"\x01\x00\x0c\xcc\xcc\xcc" + b"\x70\x6e\x6d\x1d\xbb\x04" + b"\x01\xbb" + b"\xaa\xaa\x03\x00\x00\x0c"
    bufs = [frame(A, B, 1234, 80, 0x18), cdp, frame(B, A, 80, 1234, 0x10, payload=b"")]
    cols, skip = E.parse_frames(bufs, np.array([1.0, 2.0, 3.0]))
    assert len(cols["ts"]) == 2
    assert cols["ts"].tolist() == [1_000_000, 3_000_000]
    assert cols["pay"].tolist() == [10, 0]
    assert cols["flg"].tolist() == [0x18, 0x10]
    assert cols["win"].tolist() == [1000, 1000]
    assert cols["dport"].tolist() == [80, 1234]
    assert skip["skipped_non_ipv4"] == 1
