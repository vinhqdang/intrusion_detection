"""Packet-level flow extractor shared by every condition (design/design_pcap.md section 3).

Pipeline for one capture:
  1. ``iter_chunks`` streams the pcap(ng) file (dpkt) and ``parse_frames`` turns each chunk of raw Ethernet frames
     into numpy columns (IPv4 TCP and UDP only).
  2. ``canonical_keys`` gives every packet a direction-free 5-tuple key; ``sort_packets`` orders packets by
     (key, time).
  3. ``split_flows`` assigns flow ids with CICFlowMeter rules and trailing-packet absorption (120 s flow timeout, TCP
     termination on RST or on FIN from both sides, trailing packets within 2 s absorbed). This is the only sequential
     step; it loops over packets in Python, chunk by chunk.
  4. ``features`` computes the CICFlowMeter feature vector of every flow from its packets with segment operations.

``features`` is the single feature definition. The cache build and the packet-level generator P both call it, so
clean and mutated flows are extracted by the same code. Each flow is a contiguous segment of packets sorted by time.
"""

from __future__ import annotations

import numpy as np

FLOW_TIMEOUT_US = 120_000_000        # flow timeout: a packet more than 120 s after the flow start opens a new flow
ACTIVITY_TIMEOUT_US = 5_000_000      # active/idle threshold (CICFlowMeter activity timeout)
ABSORB_US = 2_000_000                # trailing packets of a closed TCP flow attach to it within 2 s
TCP, UDP = 6, 17
MIN_PACKETS_CONNECTION = {6: 3, 17: 2}      # connection flows: TCP with a handshake and 3 packets, UDP with 2
F_FIN, F_SYN, F_RST, F_PSH, F_ACK, F_URG, F_ECE, F_CWE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
MSS = {TCP: 1460.0, UDP: 1472.0}     # maximum payload per packet used by the packet-level generator
MTU_PAYLOAD_CAP = 1500.0

# CICFlowMeter feature names as they appear in the CIC-IDS2017 flow table (same order).
FEATURES = (
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
)
N_FEAT = len(FEATURES)
_FI = {n: i for i, n in enumerate(FEATURES)}

# Packet columns kept for a flow (order used by the packet store and by pgen).
PKT_COLS = ("ts", "dir", "pay", "ipl", "hdr", "tph", "flg", "win", "proto")


# ----------------------------------------------------------------------------- reading
def iter_chunks(path: str, size: int = 1_000_000):
    """Yield (frames, ts_seconds) lists of at most ``size`` packets from a pcap or pcapng file."""
    import dpkt

    with open(path, "rb") as fh:
        magic = fh.read(4)
        fh.seek(0)
        reader = dpkt.pcapng.Reader(fh) if magic == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(fh)
        bufs, tss = [], []
        for ts, buf in reader:
            bufs.append(buf)
            tss.append(ts)
            if len(bufs) >= size:
                yield bufs, np.asarray(tss, dtype=np.float64)
                bufs, tss = [], []
        if bufs:
            yield bufs, np.asarray(tss, dtype=np.float64)


def parse_frames(bufs, ts_sec) -> tuple[dict, dict]:
    """Vectorised parse of Ethernet II frames. Returns (columns of the IPv4 TCP/UDP packets, skip counts).

    Columns: ts (int64 microseconds), src, dst (uint32), sport, dport (uint16), proto (uint8), pay (uint16 payload
    bytes), ipl (uint16 IP total length), hdr (uint8 IP + transport header bytes), tph (uint8 transport header
    bytes), flg (uint8 TCP flags, 0 for UDP), win (uint16 TCP window, 0 for UDP).
    """
    n = len(bufs)
    lens = np.fromiter((len(b) for b in bufs), dtype=np.int64, count=n)
    blob = np.frombuffer(b"".join(bufs) + b"\0" * 128, dtype=np.uint8)
    last = len(blob) - 1
    off = np.zeros(n, dtype=np.int64)
    if n > 1:
        off[1:] = np.cumsum(lens)[:-1]

    def at(idx):
        return blob[np.minimum(off + idx, last)].astype(np.int64)

    def at16(idx):
        return (at(idx) << 8) | at(idx + 1)

    ethertype = at16(np.full(n, 12))
    is_ip4 = (lens >= 34) & (ethertype == 0x0800)
    vihl = at(np.full(n, 14))
    ihl = (vihl & 15) * 4
    frag = at16(np.full(n, 20)) & 0x1FFF
    proto = at(np.full(n, 23))
    ipl = at16(np.full(n, 16))
    tp = 14 + ihl
    is_l4 = (proto == TCP) | (proto == UDP)
    ok = is_ip4 & ((vihl >> 4) == 4) & (ihl >= 20) & is_l4 & (frag == 0)
    ok &= lens >= tp + np.where(proto == TCP, 20, 8)
    skip = {
        "frames_total": int(n),
        "skipped_non_ipv4": int(np.count_nonzero(~is_ip4)),
        "skipped_ip_other_proto_or_fragment": int(np.count_nonzero(is_ip4 & ~(is_l4 & (frag == 0)))),
        "skipped_truncated": int(np.count_nonzero(is_ip4 & is_l4 & (frag == 0) & ~ok)),
    }

    src = (at16(np.full(n, 26)) << 16) | at16(np.full(n, 28))
    dst = (at16(np.full(n, 30)) << 16) | at16(np.full(n, 32))
    sport = at16(tp)
    dport = at16(tp + 2)
    doff = (at(tp + 12) >> 4) * 4
    is_tcp = proto == TCP
    tph = np.where(is_tcp, doff, 8)
    flg = np.where(is_tcp, at(tp + 13), 0)
    win = np.where(is_tcp, at16(tp + 14), 0)
    hdr = ihl + tph
    pay = np.maximum(ipl - hdr, 0)
    ts = np.round(np.asarray(ts_sec, dtype=np.float64) * 1e6).astype(np.int64)
    cols = {
        "ts": ts[ok], "src": src[ok].astype(np.uint32), "dst": dst[ok].astype(np.uint32),
        "sport": sport[ok].astype(np.uint16), "dport": dport[ok].astype(np.uint16),
        "proto": proto[ok].astype(np.uint8), "pay": pay[ok].astype(np.uint16),
        "ipl": ipl[ok].astype(np.uint16), "hdr": hdr[ok].astype(np.uint8), "tph": tph[ok].astype(np.uint8),
        "flg": flg[ok].astype(np.uint8), "win": win[ok].astype(np.uint16),
    }
    skip["packets_kept"] = int(ok.sum())
    return cols, skip


def canonical_keys(src, dst, sport, dport, proto) -> tuple[np.ndarray, np.ndarray]:
    """Direction-free 5-tuple as two uint64 keys. The smaller endpoint (ip, port) is written first."""
    src = np.asarray(src, np.int64)
    dst = np.asarray(dst, np.int64)
    sport = np.asarray(sport, np.int64)
    dport = np.asarray(dport, np.int64)
    swap = (src > dst) | ((src == dst) & (sport > dport))
    a_ip = np.where(swap, dst, src).astype(np.uint64)
    b_ip = np.where(swap, src, dst).astype(np.uint64)
    a_p = np.where(swap, dport, sport).astype(np.uint64)
    b_p = np.where(swap, sport, dport).astype(np.uint64)
    k1 = (a_ip << np.uint64(32)) | b_ip
    k2 = (a_p << np.uint64(32)) | (b_p << np.uint64(16)) | np.asarray(proto, np.uint64)
    return k1, k2


def sort_packets(p: dict) -> dict:
    """Sort packet columns by (key, time, arrival). Adds k1 and k2."""
    k1, k2 = canonical_keys(p["src"], p["dst"], p["sport"], p["dport"], p["proto"])
    order = np.lexsort((np.arange(len(k1)), p["ts"], k2, k1))
    out = {name: arr[order] for name, arr in p.items()}
    out["k1"], out["k2"] = k1[order], k2[order]
    return out


# ----------------------------------------------------------------------------- flow assignment
def split_flows(k1, k2, ts, src, proto, flg, chunk: int = 2_000_000, stats: dict | None = None):
    """Flow id of every packet (sorted input). Sequential over packets, in chunks to bound memory.

    CICFlowMeter-style with trailing-packet absorption (not the corrected semantics of Engelen et al.):
    - a packet opens a new flow when its key differs from the previous packet's key, or when it arrives more than
      FLOW_TIMEOUT_US after the flow's first packet;
    - a TCP flow closes on a RST, or on the second FIN (one from each side); the closing packet is included;
    - after a close, packets of the same 5-tuple that carry no SYN and arrive within ABSORB_US of the closing packet
      stay in the closed flow (trailing ACKs and retransmitted FINs); a SYN, or a later packet, opens a new flow.
    """
    n = len(ts)
    fid = np.empty(n, dtype=np.int64)
    cur = -1
    pk1 = pk2 = -1
    start = 0
    init = 0
    term = False
    closed_t = 0
    fin0 = fin1 = False
    absorbed = 0
    for c0 in range(0, n, chunk):
        sl = slice(c0, min(n, c0 + chunk))
        A = k1[sl].tolist()
        B = k2[sl].tolist()
        T = ts[sl].tolist()
        S = src[sl].tolist()
        P = proto[sl].tolist()
        G = flg[sl].tolist()
        out = [0] * len(A)
        for i in range(len(A)):
            a = A[i]
            b = B[i]
            t = T[i]
            s = S[i]
            g = G[i]
            if a != pk1 or b != pk2:
                cur += 1
                pk1, pk2 = a, b
                start, init, term, fin0, fin1 = t, s, False, False, False
            elif term:
                if P[i] == TCP and (g & F_SYN):
                    cur += 1
                    start, init, term, fin0, fin1 = t, s, False, False, False
                elif t - closed_t > ABSORB_US or t - start > FLOW_TIMEOUT_US:
                    cur += 1
                    start, init, term, fin0, fin1 = t, s, False, False, False
                else:
                    absorbed += 1
            elif t - start > FLOW_TIMEOUT_US:
                cur += 1
                start, init, term, fin0, fin1 = t, s, False, False, False
            out[i] = cur
            if P[i] == TCP and not term:
                if g & F_RST:
                    term = True
                    closed_t = t
                elif g & F_FIN:
                    if s == init:
                        fin0 = True
                    else:
                        fin1 = True
                    if fin0 and fin1:
                        term = True
                        closed_t = t
        fid[sl] = out
    if stats is not None:
        stats["absorbed"] = absorbed
    return fid, cur + 1


def flow_starts(fid: np.ndarray) -> np.ndarray:
    """Index of the first packet of every flow (fid is non-decreasing and dense)."""
    if len(fid) == 0:
        return np.zeros(0, dtype=np.int64)
    return np.concatenate(([0], np.flatnonzero(np.diff(fid)) + 1)).astype(np.int64)


# ----------------------------------------------------------------------------- segment helpers
def _sum(v, seg, F):
    return np.bincount(seg, weights=np.asarray(v, dtype=np.float64), minlength=F)


def _reduce(ufunc, v, seg, F, default=0.0):
    """Per-segment reduction of a sorted segment array; empty segments get ``default``."""
    out = np.full(F, default, dtype=np.float64)
    if len(v) == 0:
        return out
    change = np.flatnonzero(np.diff(seg)) + 1
    starts = np.concatenate(([0], change))
    out[seg[starts]] = ufunc.reduceat(np.asarray(v, dtype=np.float64), starts)
    return out


def _first(v, seg, F, default=0.0):
    out = np.full(F, default, dtype=np.float64)
    if len(v) == 0:
        return out
    change = np.flatnonzero(np.diff(seg)) + 1
    starts = np.concatenate(([0], change))
    out[seg[starts]] = np.asarray(v, dtype=np.float64)[starts]
    return out


def _stats(v, seg, F, cnt):
    """Mean, sample std (n - 1 denominator, as CICFlowMeter), max, min per segment; 0 where fewer than the needed
    values exist."""
    safe = np.maximum(cnt, 1.0)
    mean = _sum(v, seg, F) / safe
    dev = np.asarray(v, dtype=np.float64) - mean[seg]
    std = np.sqrt(_sum(dev * dev, seg, F) / np.maximum(cnt - 1.0, 1.0))
    mx = _reduce(np.maximum, v, seg, F)
    mn = _reduce(np.minimum, v, seg, F)
    empty = cnt == 0
    mean[empty] = 0.0
    std[empty | (cnt < 2)] = 0.0
    return mean, std, mx, mn


def _gap_stats(ts, seg, F):
    """Sum, mean, std, max, min of consecutive gaps within each segment (0 where there is no gap)."""
    if len(ts) < 2:
        z = np.zeros(F)
        return z, z, z, z, z
    same = seg[1:] == seg[:-1]
    g = (ts[1:] - ts[:-1]).astype(np.float64)[same]
    gs = seg[1:][same]
    cnt = np.bincount(gs, minlength=F).astype(np.float64)
    mean_, std_, mx, mn = _stats(g, gs, F, cnt)
    total = _sum(g, gs, F)
    return total, mean_, std_, mx, mn


# ----------------------------------------------------------------------------- features
def features(seg, ts, d, pay, ipl, hdr, tph, flg, win, proto, F: int) -> np.ndarray:
    """CICFlowMeter feature matrix (F x N_FEAT) from packets sorted by (segment, time).

    seg: flow index per packet (non-decreasing, values in [0, F)); ts: microseconds; d: 0 forward (flow initiator),
    1 backward; pay: payload bytes; ipl: IP total length; hdr: IP plus transport header bytes; tph: transport header
    bytes; flg: TCP flags; win: TCP window; proto: 6 or 17.
    """
    seg = np.asarray(seg, dtype=np.int64)
    out = np.zeros((F, N_FEAT), dtype=np.float64)
    if F == 0 or len(seg) == 0:
        return out
    ts = np.asarray(ts, dtype=np.int64)
    fwd = np.asarray(d) == 0
    bwd = ~fwd
    pay = np.asarray(pay, dtype=np.float64)
    hdr = np.asarray(hdr, dtype=np.float64)
    tph = np.asarray(tph, dtype=np.float64)
    flg = np.asarray(flg, dtype=np.int64)
    win = np.asarray(win, dtype=np.float64)
    proto = np.asarray(proto, dtype=np.int64)
    ids = np.arange(F)
    first_idx = np.searchsorted(seg, ids, side="left")
    last_idx = np.searchsorted(seg, ids, side="right") - 1
    cnt = np.bincount(seg, minlength=F).astype(np.float64)
    nf = np.bincount(seg[fwd], minlength=F).astype(np.float64)
    nb = cnt - nf
    dur = (ts[last_idx] - ts[first_idx]).astype(np.float64)
    dur_s = dur / 1e6
    pos = dur > 0
    bf = _sum(pay * fwd, seg, F)
    bb = _sum(pay * bwd, seg, F)
    btot = bf + bb
    safe_dur = np.where(pos, dur_s, 1.0)

    def put(name, val):
        out[:, _FI[name]] = val

    put("Flow Duration", dur)
    put("Total Fwd Packets", nf)
    put("Total Backward Packets", nb)
    put("Total Length of Fwd Packets", bf)
    put("Total Length of Bwd Packets", bb)

    # packet length statistics per direction and overall
    m_f, s_f, x_f, n_f = _stats(pay[fwd], seg[fwd], F, nf)
    m_b, s_b, x_b, n_b = _stats(pay[bwd], seg[bwd], F, nb)
    put("Fwd Packet Length Max", x_f)
    put("Fwd Packet Length Min", n_f)
    put("Fwd Packet Length Mean", m_f)
    put("Fwd Packet Length Std", s_f)
    put("Bwd Packet Length Max", x_b)
    put("Bwd Packet Length Min", n_b)
    put("Bwd Packet Length Mean", m_b)
    put("Bwd Packet Length Std", s_b)
    m_a, s_a, x_a, n_a = _stats(pay, seg, F, cnt)
    put("Min Packet Length", n_a)
    put("Max Packet Length", x_a)
    put("Packet Length Mean", m_a)
    put("Packet Length Std", s_a)
    put("Packet Length Variance", s_a * s_a)                 # sample variance, consistent with the sample std

    put("Flow Bytes/s", np.where(pos, btot / safe_dur, 0.0))
    put("Flow Packets/s", np.where(pos, cnt / safe_dur, 0.0))
    put("Fwd Packets/s", np.where(pos, nf / safe_dur, 0.0))
    put("Bwd Packets/s", np.where(pos, nb / safe_dur, 0.0))

    # inter-arrival statistics: all packets, forward packets, backward packets
    tot, mu, sd, mx, mn = _gap_stats(ts, seg, F)
    put("Flow IAT Mean", mu)
    put("Flow IAT Std", sd)
    put("Flow IAT Max", mx)
    put("Flow IAT Min", mn)
    tot_f, mu_f, sd_f, mx_f, mn_f = _gap_stats(ts[fwd], seg[fwd], F)
    put("Fwd IAT Total", tot_f)
    put("Fwd IAT Mean", mu_f)
    put("Fwd IAT Std", sd_f)
    put("Fwd IAT Max", mx_f)
    put("Fwd IAT Min", mn_f)
    tot_b, mu_b, sd_b, mx_b, mn_b = _gap_stats(ts[bwd], seg[bwd], F)
    put("Bwd IAT Total", tot_b)
    put("Bwd IAT Mean", mu_b)
    put("Bwd IAT Std", sd_b)
    put("Bwd IAT Max", mx_b)
    put("Bwd IAT Min", mn_b)

    # flags
    is_tcp = proto == 6
    put("Fwd PSH Flags", _sum(((flg & F_PSH) > 0) & fwd, seg, F))
    put("Bwd PSH Flags", _sum(((flg & F_PSH) > 0) & bwd, seg, F))
    put("Fwd URG Flags", _sum(((flg & F_URG) > 0) & fwd, seg, F))
    put("Bwd URG Flags", _sum(((flg & F_URG) > 0) & bwd, seg, F))
    put("FIN Flag Count", _sum((flg & F_FIN) > 0, seg, F))
    put("SYN Flag Count", _sum((flg & F_SYN) > 0, seg, F))
    put("RST Flag Count", _sum((flg & F_RST) > 0, seg, F))
    put("PSH Flag Count", _sum((flg & F_PSH) > 0, seg, F))
    put("ACK Flag Count", _sum((flg & F_ACK) > 0, seg, F))
    put("URG Flag Count", _sum((flg & F_URG) > 0, seg, F))
    put("CWE Flag Count", _sum((flg & F_CWE) > 0, seg, F))
    put("ECE Flag Count", _sum((flg & F_ECE) > 0, seg, F))

    put("Fwd Header Length", _sum(hdr * fwd, seg, F))
    put("Bwd Header Length", _sum(hdr * bwd, seg, F))
    put("Down/Up Ratio", np.where(nf > 0, np.floor(nb / np.maximum(nf, 1.0)), 0.0))
    put("Average Packet Size", np.where(cnt > 0, btot / np.maximum(cnt, 1.0), 0.0))
    put("Avg Fwd Segment Size", np.where(nf > 0, bf / np.maximum(nf, 1.0), 0.0))
    put("Avg Bwd Segment Size", np.where(nb > 0, bb / np.maximum(nb, 1.0), 0.0))
    # bulk features: CICFlowMeter reports zero for every flow of CIC-IDS2017 (checked against the flow table)
    put("Subflow Fwd Packets", nf)
    put("Subflow Fwd Bytes", bf)
    put("Subflow Bwd Packets", nb)
    put("Subflow Bwd Bytes", bb)

    # first window per direction (-1 when the first packet of that direction is not TCP)
    fi = np.flatnonzero(fwd)
    bi = np.flatnonzero(bwd)
    fwd_first = _first(win[fi], seg[fi], F, 0.0)
    bwd_first = _first(win[bi], seg[bi], F, 0.0)
    fwd_tcp = _first(is_tcp[fi].astype(np.float64), seg[fi], F, 0.0)
    bwd_tcp = _first(is_tcp[bi].astype(np.float64), seg[bi], F, 0.0)
    put("Init_Win_bytes_forward", np.where((nf > 0) & (fwd_tcp > 0), fwd_first, -1.0))
    put("Init_Win_bytes_backward", np.where((nb > 0) & (bwd_tcp > 0), bwd_first, -1.0))
    put("act_data_pkt_fwd", _sum((pay > 0) & fwd, seg, F))
    tcp_fwd_min = _reduce(np.minimum, tph[fwd & is_tcp], seg[fwd & is_tcp], F, default=0.0)
    put("min_seg_size_forward", tcp_fwd_min)

    # active and idle periods (CICFlowMeter activity timeout)
    _active_idle(ts, seg, F, out, cnt)
    return out


def _active_idle(ts, seg, F, out, cnt):
    N = len(ts)
    if N == 0:
        return
    new_seg = np.ones(N, dtype=bool)
    new_seg[1:] = seg[1:] != seg[:-1]
    gap = np.zeros(N, dtype=np.int64)
    gap[1:] = ts[1:] - ts[:-1]
    idle_gap = (~new_seg) & (gap > ACTIVITY_TIMEOUT_US)
    burst_start = new_seg | idle_gap
    bidx = np.flatnonzero(burst_start)
    bend = np.concatenate((bidx[1:] - 1, [N - 1]))
    dur_b = (ts[bend] - ts[bidx]).astype(np.float64)
    seg_b = seg[bidx]
    # CICFlowMeter records an active period only when an idle period follows it; the last active period of a flow
    # is never recorded. Periods of zero length are not recorded either.
    followed_by_idle = np.concatenate([idle_gap[1:], [False]])[bend]
    keep = followed_by_idle & (dur_b > 0)
    cnt_b = np.bincount(seg_b[keep], minlength=F).astype(np.float64)
    m, s, x, n = _stats(dur_b[keep], seg_b[keep], F, cnt_b)
    out[:, _FI["Active Mean"]] = m
    out[:, _FI["Active Std"]] = s
    out[:, _FI["Active Max"]] = x
    out[:, _FI["Active Min"]] = n
    ig = gap[idle_gap].astype(np.float64)
    gseg = seg[idle_gap]
    cnt_i = np.bincount(gseg, minlength=F).astype(np.float64)
    m, s, x, n = _stats(ig, gseg, F, cnt_i)
    out[:, _FI["Idle Mean"]] = m
    out[:, _FI["Idle Std"]] = s
    out[:, _FI["Idle Max"]] = x
    out[:, _FI["Idle Min"]] = n


def extract_flows(pk: dict, fid: np.ndarray, F: int, block_packets: int = 5_000_000):
    """Features for every flow of a sorted packet table. Works in blocks of whole flows to bound memory.

    pk: columns sorted by (key, time) with ``fid`` the flow of each packet. Returns (X, meta) where meta holds
    per-flow k1, k2, first timestamp, protocol, and the number of packets.
    """
    starts = flow_starts(fid)
    src = pk["src"]
    init_src = src[starts]
    d_all = (src != init_src[fid]).astype(np.int8)
    X = np.zeros((F, N_FEAT), dtype=np.float64)
    f0 = 0
    while f0 < F:
        # largest flow index f1 such that packets of flows [f0, f1) stay within the block size
        p0 = starts[f0]
        f1 = int(np.searchsorted(starts, p0 + block_packets, side="right"))
        f1 = min(max(f1, f0 + 1), F)
        p1 = starts[f1] if f1 < F else len(fid)
        sl = slice(p0, p1)
        X[f0:f1] = features(
            fid[sl] - f0, pk["ts"][sl], d_all[sl], pk["pay"][sl], pk["ipl"][sl], pk["hdr"][sl], pk["tph"][sl],
            pk["flg"][sl], pk["win"][sl], pk["proto"][sl], f1 - f0,
        )
        f0 = f1
    proto_f = pk["proto"][starts].astype(np.int64)
    syn_f = np.bincount(fid[((pk["flg"] & F_SYN) > 0) & (d_all == 0)], minlength=F) > 0
    synack_b = np.bincount(fid[((pk["flg"] & (F_SYN | F_ACK)) == (F_SYN | F_ACK)) & (d_all == 1)], minlength=F) > 0
    npk = np.bincount(fid, minlength=F).astype(np.int64)
    connection = np.where(proto_f == TCP, syn_f & synack_b & (npk >= MIN_PACKETS_CONNECTION[TCP]),
                          npk >= MIN_PACKETS_CONNECTION[UDP])
    meta = {
        "connection": connection,
        "init_src": pk["src"][starts], "init_dst": pk["dst"][starts],
        "init_sport": pk["sport"][starts].astype(np.int64), "init_dport": pk["dport"][starts].astype(np.int64),
        "k1": pk["k1"][starts], "k2": pk["k2"][starts], "first_ts": pk["ts"][starts],
        "proto": pk["proto"][starts].astype(np.int64), "n_packets": np.bincount(fid, minlength=F).astype(np.int64),
        "starts": starts,
    }
    return X, meta, d_all
