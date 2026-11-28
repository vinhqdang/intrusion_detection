"""Packet-level client-side generator P (design/design_pcap.md section 4).

P rewrites the packets of a flow it can control (the client side) and re-extracts the flow with the same extractor
as the clean data. It cannot change server packets, except that they move later in time when the client packets
before them are delayed.

Canonical composition. A mutated flow is the base flow (packets from the cache) with a level per group. Every call
recomputes the flow from the base packets in the fixed order count -> length -> timing, so inserted packets are
delayed by the timing group too, and the result does not depend on the order in which an attacker applies groups.
Randomness is a function of (seed, base flow, group, packet index): the per-packet draws are common to every budget
and level of a flow, so levels are comparable (common random numbers) and an attacker never sees the draws.

The adapter is generator-agnostic like G1 and G2: ``PGen(X)(rows, group, level)`` returns feature rows. A registry
maps the bit pattern of each returned feature row to (base flow, levels), so the attackers of
``idsbench.econ.mutation`` can call it with rows they got from an earlier call.

Groups:
  count   k = ceil((m - 1) n_fwd) pure client ACKs (TCP) or zero-payload datagrams (UDP), at uniform random times
          strictly inside the flow (between the third packet and the last packet), with the header of the last
          client packet.
  length  each client packet with payload > 0 is padded to a uniform size between its size and min(MSS, m * size);
          the IP total length grows with it.
  timing  before each client data packet after the first, an Exp(mean delta) delay is added, with delta =
          max((m - 1) * forward IAT mean, 1 ms). Every later packet moves by the total delay so far (causal shift).
          Packets beyond 120 s from the flow start are cut: the first sub-flow is scored (handshake included).
"""

from __future__ import annotations

import numpy as np

from ..pcap.extract import FLOW_TIMEOUT_US, MSS, TCP, features, N_FEAT
F_SYN, F_ACK = 0x02, 0x10

GROUPS = ("count", "length", "timing")          # canonical order of composition
PKT_COLS = ("ts", "dir", "pay", "ipl", "hdr", "tph", "flg", "win", "proto")
TS, DIR, PAY, IPL, HDR, TPH, FLG, WIN, PRO = range(9)
SALT_COUNT, SALT_LEN, SALT_TIME = 0x11, 0x22, 0x33
FWD_IAT_FLOOR_US = 1000.0
F_ACK = 0x10
_C1 = np.uint64(0x9E3779B97F4A7C15)
_C2 = np.uint64(0xC2B2AE3D27D4EB4F)
_C3 = np.uint64(0x165667B19E3779F9)
_C4 = np.uint64(0x27D4EB2F165667C5)
_C5 = np.uint64(0xBF58476D1CE4E5B9)
_C6 = np.uint64(0x94D049BB133111EB)


def _mix(x: np.ndarray) -> np.ndarray:
    with np.errstate(over="ignore"):
        x = x ^ (x >> np.uint64(30))
        x = x * _C5
        x = x ^ (x >> np.uint64(27))
        x = x * _C6
        x = x ^ (x >> np.uint64(31))
    return x


def _u01(seed: int, base: np.ndarray, salt: int, idx: np.ndarray) -> np.ndarray:
    """Uniform in (0, 1), a deterministic function of (seed, base flow, salt, index)."""
    with np.errstate(over="ignore"):
        x = np.uint64(seed & 0xFFFF_FFFF_FFFF) * _C1
        x = x ^ (np.asarray(base, dtype=np.int64).astype(np.uint64) * _C2)
        x = x ^ (np.uint64(salt) * _C3)
        x = x ^ (np.asarray(idx, dtype=np.int64).astype(np.uint64) * _C4)
        x = _mix(x)
    return ((x >> np.uint64(11)).astype(np.float64) + 0.5) / 9007199254740992.0


def row_keys(X: np.ndarray) -> np.ndarray:
    """64-bit keys of feature rows (bit patterns of the float64 values)."""
    bits = np.ascontiguousarray(X, dtype=np.float64).view(np.uint64)
    h = np.full(len(bits), np.uint64(0x5EED_2026), dtype=np.uint64)
    with np.errstate(over="ignore"):
        for j in range(bits.shape[1]):
            h = _mix(h * _C1 ^ bits[:, j])
    return h


def _seg_starts(seg: np.ndarray, S: int) -> np.ndarray:
    return np.searchsorted(seg, np.arange(S), side="left")


# ----------------------------------------------------------------------------- group operations
def _op_count(M, seg, base, lv, S, seed):
    N = len(M)
    d = M[:, DIR]
    starts = _seg_starts(seg, S)
    lens = np.bincount(seg, minlength=S)
    ends = starts + lens
    fwd = d == 0
    fidx = np.flatnonzero(fwd)
    nf = np.bincount(seg[fidx], minlength=S)
    k = np.where(nf > 0, np.ceil((lv - 1.0) * nf - 1e-9), 0).astype(np.int64)
    k = np.maximum(k, 0)
    if k.sum() == 0:
        return M, seg
    # handshake: first packet is the client SYN and a server SYN-ACK follows. Without it, count is a no-op.
    first_syn = (M[starts, PRO] == TCP) & (M[starts, DIR] == 0) & ((M[starts, FLG] & F_SYN) > 0)
    synack = np.bincount(seg[((M[:, FLG] & (F_SYN | F_ACK)) == (F_SYN | F_ACK)) & (d == 1)], minlength=S) > 0
    hs = first_syn & synack & (lens >= 3)
    k = np.where(hs, k, 0)
    if k.sum() == 0:
        return M, seg
    # insertion window: strictly after the handshake ACK (third packet) and strictly before the last packet
    first_ts = M[starts, TS]
    last_ts = M[ends - 1, TS]
    third = np.minimum(starts + 2, ends - 1)
    t_lo = M[third, TS]
    span = (last_ts - t_lo).astype(np.float64)
    k = np.where(span >= 2.0, k, 0)
    if k.sum() == 0:
        return M, seg
    # template: header of the last client packet of each flow
    last_f_pos = np.searchsorted(seg[fidx], np.arange(S), side="right") - 1
    has_f = nf > 0
    lastf = fidx[np.clip(last_f_pos, 0, max(len(fidx) - 1, 0))]
    new_seg = np.repeat(np.arange(S), k)
    K = len(new_seg)
    j = np.arange(K) - np.repeat(np.cumsum(k) - k, k)
    u = _u01(seed, base[new_seg], SALT_COUNT, j)
    # strictly inside (t_lo, last): t_lo + 1 + floor(u * (span - 1)) lies in [t_lo + 1, last - 1]
    ts_new = (t_lo[new_seg] + 1 + np.floor(u * (span[new_seg] - 1.0))).astype(np.int64)
    tpl = lastf[new_seg]
    pro = M[starts[new_seg], PRO]
    new = np.zeros((K, len(PKT_COLS)), dtype=np.int64)
    new[:, TS] = ts_new
    new[:, DIR] = 0
    new[:, PAY] = 0
    new[:, HDR] = M[tpl, HDR]
    new[:, IPL] = M[tpl, HDR]
    new[:, TPH] = M[tpl, TPH]
    new[:, FLG] = np.where(pro == TCP, F_ACK, 0)
    new[:, WIN] = M[tpl, WIN]
    new[:, PRO] = pro
    M2 = np.vstack([M, new])
    seg2 = np.concatenate([seg, new_seg])
    is_new = np.concatenate([np.zeros(N, dtype=np.int64), np.ones(K, dtype=np.int64)])
    order = np.lexsort((is_new, M2[:, TS], seg2))
    return M2[order], seg2[order]


def _op_length(M, seg, base, lv, S, seed):
    starts = _seg_starts(seg, S)
    pos = np.arange(len(M)) - starts[seg]
    pay = M[:, PAY].astype(np.float64)
    cand = (M[:, DIR] == 0) & (pay > 0)
    if not cand.any():
        return M, seg
    mss = np.where(M[:, PRO] == TCP, MSS[TCP], MSS[17])
    upper = np.minimum(mss, lv[seg] * pay)
    add = np.maximum(upper - pay, 0.0)
    u = _u01(seed, base[seg], SALT_LEN, pos)
    newpay = np.where(cand, pay + np.floor(u * add), pay)
    M = M.copy()
    delta = (newpay - pay).astype(np.int64)
    M[:, PAY] = newpay.astype(np.int64)
    M[:, IPL] = M[:, IPL] + delta
    return M, seg


def timing_delta(M, seg, lt, S):
    """Mean delay per delayed client packet, computed from the ORIGINAL packets of each state.

    The expected added delay of a state equals (m - 1) times its original forward IAT total, spread over the
    client data packets after the first: delta = (m - 1) * FwdIATTotal_orig / n_delayed. States with no delayed
    packets get delta 0.
    """
    starts = _seg_starts(seg, S)
    lens = np.bincount(seg, minlength=S)
    pos = np.arange(len(M)) - starts[seg]
    fwd = M[:, DIR] == 0
    fidx = np.flatnonzero(fwd)
    nf = np.bincount(seg[fidx], minlength=S)
    fs = np.searchsorted(seg[fidx], np.arange(S), side="left")
    fe = fs + nf
    t_f0 = M[fidx[np.clip(fs, 0, max(len(fidx) - 1, 0))], TS].astype(np.float64)
    t_f1 = M[fidx[np.clip(fe - 1, 0, max(len(fidx) - 1, 0))], TS].astype(np.float64)
    total = np.where(nf >= 2, t_f1 - t_f0, 0.0)
    delayed = fwd & (M[:, PAY] > 0) & (pos > 0)
    n_delayed = np.bincount(seg[delayed], minlength=S).astype(np.float64)
    ok = (lt > 1.0) & (n_delayed > 0)
    return np.where(ok, (lt - 1.0) * total / np.maximum(n_delayed, 1.0), 0.0)


def _op_timing(M, seg, base, delta, S, seed):
    N = len(M)
    starts = _seg_starts(seg, S)
    lens = np.bincount(seg, minlength=S)
    ends = starts + lens
    d = M[:, DIR]
    fwd = d == 0
    pos = np.arange(N) - starts[seg]
    pay = M[:, PAY]
    client_data = fwd & (pay > 0) & (pos > 0)     # inserted ACKs carry no payload and are not delayed themselves
    if not client_data.any():
        return M, seg, 0
    u = _u01(seed, base[seg], SALT_TIME, pos)
    dd = np.where(client_data, delta[seg] * (-np.log(u)), 0.0)
    cs = np.cumsum(dd)
    before = cs[starts] - dd[starts]
    shift = cs - before[seg]
    M = M.copy()
    M[:, TS] = M[:, TS] + np.rint(shift).astype(np.int64)
    rel = M[:, TS] - M[starts[seg], TS]
    keep = rel <= FLOW_TIMEOUT_US
    cut_states = np.bincount(seg[~keep], minlength=S) > 0
    M = M[keep]
    seg = seg[keep]
    return M, seg, int(cut_states.sum())


# ----------------------------------------------------------------------------- the adapter
class PGen:
    """Generator P as ``apply(X, group, level)`` over the feature rows of the cache.

    base_rows: indices of cache rows that have packets (the packet pool); X: the cache feature matrix; cache: the
    dict returned by ``idsbench.pcap.build.load_cache`` (packets and pool offsets).
    """

    def __init__(self, cache: dict, X: np.ndarray, seed: int):
        self.seed = int(seed)
        self.G = np.column_stack([cache[f"pkt_{c}"] for c in ("ts", "dir", "pay", "ipl", "hdr", "tph", "flg",
                                                              "win", "proto")]).astype(np.int64)
        off = cache["pkt_off"]
        pool_row = cache["pool_row"]
        n = len(X)
        self.base_a = np.full(n, -1, dtype=np.int64)
        self.base_b = np.full(n, -1, dtype=np.int64)
        rows = np.flatnonzero(pool_row >= 0)
        p = pool_row[rows]
        self.base_a[rows] = off[p]
        self.base_b[rows] = off[p + 1]
        self.rows = rows
        self.base_reg = {int(k): (int(r), 1.0, 1.0, 1.0) for k, r in zip(row_keys(X[rows]), rows)}
        self.mut_reg: dict = {}
        self.stats = {"calls": 0, "states": 0, "resplit_states": 0, "timing_states": 0}

    def reset(self):
        """Forget the mutated states of the previous attack (base flows stay registered)."""
        self.mut_reg.clear()

    def _lookup(self, key: int):
        e = self.mut_reg.get(key)
        if e is None:
            e = self.base_reg.get(key)
        if e is None:
            raise KeyError("feature row unknown to the packet-level generator (no packets)")
        return e

    def _packets(self, bases: np.ndarray):
        a = self.base_a[bases]
        b = self.base_b[bases]
        lens = b - a
        seg = np.repeat(np.arange(len(bases)), lens)
        idx = np.repeat(a - (np.cumsum(lens) - lens), lens) + np.arange(int(lens.sum()))
        return self.G[idx], seg

    def __call__(self, X, group: str, level) -> np.ndarray:
        if group not in GROUPS:
            raise ValueError(f"unknown group {group!r}")
        X = np.asarray(X, dtype=np.float64)
        lev = np.asarray(level, dtype=np.float64)
        lev = np.full(len(X), float(lev)) if lev.ndim == 0 else lev.reshape(len(X))
        if not np.all(np.isfinite(lev)) or np.any(lev < 1.0):
            raise ValueError("level must be >= 1 (attacker changes are increase-only)")
        out = X.copy()
        act = np.flatnonzero(lev > 1.0)
        if len(act) == 0:
            return out
        keys = row_keys(X[act])
        entries = [self._lookup(int(k)) for k in keys]
        bases = np.array([e[0] for e in entries], dtype=np.int64)
        lv = np.stack([np.array([e[1] for e in entries]), np.array([e[2] for e in entries]),
                       np.array([e[3] for e in entries])])
        gi = GROUPS.index(group)
        lv[gi] = lev[act]
        S = len(act)
        M, seg = self._packets(bases)
        lc, ll, lt = lv[0], lv[1], lv[2]
        delta = timing_delta(M, seg, lt, S)          # from the original packets, before any insertion
        if lc.max() > 1.0:
            M, seg = _op_count(M, seg, bases, lc, S, self.seed)
        if ll.max() > 1.0:
            M, seg = _op_length(M, seg, bases, ll, S, self.seed)
        cut = 0
        if lt.max() > 1.0:
            M, seg, cut = _op_timing(M, seg, bases, delta, S, self.seed)
            self.stats["timing_states"] += int(np.count_nonzero(lt > 1.0))
        feats = features(seg, M[:, TS], M[:, DIR], M[:, PAY], M[:, IPL], M[:, HDR], M[:, TPH], M[:, FLG],
                         M[:, WIN], M[:, PRO], S)
        fk = row_keys(feats)
        for s in range(S):
            self.mut_reg[int(fk[s])] = (int(bases[s]), float(lv[0, s]), float(lv[1, s]), float(lv[2, s]))
        out[act] = feats
        self.stats["calls"] += 1
        self.stats["states"] += S
        self.stats["resplit_states"] += cut
        return out
