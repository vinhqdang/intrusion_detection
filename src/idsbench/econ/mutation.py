"""E4 mutation machinery: forward-direction, attacker-controllable features (design section 4.1).

Controllable features (CICFlowMeter names after canonicalisation; forward direction only):
  timing (increase-only, level >= 1): Flow Duration, Fwd IAT Total, Fwd IAT Max, Fwd IAT Min, Fwd IAT Std
      (scaled by the level; negative sentinels are not scaled) and Flow IAT Max (>= new Fwd IAT Max).
      Fwd IAT Mean is not scaled directly: it is recomputed from the identity below.
  length (padding to at most 1500 bytes): Fwd Packet Length Max/Min/Mean and Avg Fwd Segment Size.
      v -> max(v, min(1500, v * level)): never decreases, never pushes a value that was at most 1500
      above 1500. The forward byte totals (Total Length of Fwd Packets, Subflow Fwd Bytes) grow by
      Total Fwd Packets * (change of the forward mean).
  count (dummy forward packets): Total Fwd Packets, Subflow Fwd Packets and Fwd Act Data Pkts become
      ceil(v * level); Total Length of Fwd Packets and Subflow Fwd Bytes become v * level; Fwd Header
      Length += added packets * (orig Fwd Header Length / max(orig Total Fwd Packets, 1)).
  Min_seg_size_forward is a TCP header minimum, not a payload size: it is in no group and never changes.

Derived features (changed by a mutation; design section 4.1, consistency). Every rule is a delta update
    Y = X + f(Y_inputs) - f(X_inputs)
so that a feature keeps the offset it had on the cache when its identity does not hold exactly.
  Rates: Flow / Fwd / Bwd Packets/s and Flow Bytes/s from the totals and the duration (exact).
  Max/Min Packet Length (length group): max / min of the forward and backward extremes (exact).
  Packet Length Mean and Average Packet Size: bytes / packets, delta form (identity holds on ~20% of rows).
  Flow IAT Mean = Flow Duration / (Total packets - 1) (identity, delta form; see the report).
  Fwd IAT Mean = Fwd IAT Total / (Total Fwd Packets - 1) (identity, delta form; see the report).
  Down/Up Ratio = floor(Total Bwd Packets / Total Fwd Packets) (identity holds on every cached row).
  Packet Length Variance: pooled variance of the forward and backward directions from their means and
      standard deviations (delta form; the pooled identity holds on ~19% of rows); Packet Length Std is
      the square root of the updated variance.
  Approximation, Fwd Packet Length Std (length group): min(orig std * level, Bhatia-Davis bound
      sqrt((M - mu') (mu' - m')) with the new forward mean mu', new minimum m' and M = max(1500, orig max)).
      The bound is the largest standard deviation a sample in [m', M] with mean mu' can have.
  Approximation, Flow IAT Std (timing): scaled by the duration ratio (exact when every gap scales).
  Approximation, Flow IAT Min (timing): scaled by the level when it equals Fwd IAT Min (the minimum gap is
      forward); otherwise it is a backward gap and is unchanged. Count changes leave it unchanged.

Not controllable and never changed: every backward (server-side) feature, flags, Init_Win bytes, Active and
Idle, Bwd IAT, Bwd Header Length, Destination Port, Protocol, min_seg_size_forward.

Budget b = (groups G, multiplier m). Per flow the attacker may apply each group of G at most once,
at a level in (1, m]. Attacker types (all use the same budgets):
  greedy (score): greedy over (group, level) candidates, picking the lowest score at each step and accepting
      it only if it lowers the score (score query access, two levels per group);
  strong (score): per-group continuous level search over STRONG_LEVELS levels in [1, m], one coordinate sweep
      over the groups from two starts (all levels at m, and random levels). A single group is searched
      exhaustively, so one start suffices. The attacker keeps the lowest score of every state it queried;
  transfer (score of another model): the states found by the strong attacker against xgb, submitted to the
      defender's model (the attacker never queries that model);
  label: the groups of G in a random per-flow order at level m, seeing only alert / no alert (weak baseline).
A flow is evaded at threshold tau iff min over the attacker's queried states of score <= tau.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from idsbench.feasibility.e3_crosspair import canonical_name

GROUPS = ("timing", "length", "count")
FPRS = (5e-4, 1e-3, 3e-3, 1e-2)
MULTIPLIERS = (1.5, 2.0, 5.0)
PAD_MAX = 1500.0
STRONG_LEVELS = 10
STRONG_RESTARTS = 2
IDENT_RTOL = 1e-2          # identity 'holds' tolerance used in the report only

TIMING_SCALED = ("flow duration", "fwd iat total", "fwd iat max", "fwd iat min", "fwd iat std")
FWD_IAT_MEAN = "fwd iat mean"
TIMING_FEATURES = TIMING_SCALED + (FWD_IAT_MEAN,)
FLOW_IAT_MAX = "flow iat max"
FLOW_IAT_MEAN = "flow iat mean"
FLOW_IAT_STD = "flow iat std"
FLOW_IAT_MIN = "flow iat min"
LENGTH_FEATURES = ("fwd packet length max", "fwd packet length min", "fwd packet length mean",
                   "avg fwd segment size")
FWD_LEN_MAX, FWD_LEN_MIN, FWD_LEN_MEAN = "fwd packet length max", "fwd packet length min", "fwd packet length mean"
FWD_LEN_STD = "fwd packet length std"
BWD_LEN_MEAN, BWD_LEN_STD = "bwd packet length mean", "bwd packet length std"
PKT_LEN_STD = "packet length std"
PKT_LEN_VAR = "packet length variance"
COUNT_PACKET_FEATURES = ("total fwd packets", "subflow fwd packets", "act_data_pkt_fwd")
COUNT_BYTE_FEATURES = ("total length of fwd packets", "subflow fwd bytes")
FWD_HEADER = "fwd header length"
FWD_TOTAL_PKTS, BWD_TOTAL_PKTS = "total fwd packets", "total backward packets"
FWD_BYTES, BWD_BYTES = "total length of fwd packets", "total length of bwd packets"
DOWN_UP = "down/up ratio"
RATE_FEATURES = ("flow packets/s", "fwd packets/s", "bwd packets/s", "flow bytes/s")
AGG_FEATURES = ("max packet length", "min packet length", "packet length mean", "average packet size")
# Recomputed by a rule above (delta or exact); together with the controllable features these are the
# columns a mutation can change.
DERIVED = (FLOW_IAT_MEAN, FLOW_IAT_STD, FLOW_IAT_MIN, FWD_LEN_STD, PKT_LEN_STD, PKT_LEN_VAR, DOWN_UP)
DERIVED_ALL = DERIVED + RATE_FEATURES + AGG_FEATURES
# Robust model (design 4.1, item 2): every feature that depends on forward timing or size and is not
# already controllable or derived. Listed explicitly so that the feature-group log can show them.
ROBUST_DROP_DEPENDENT = (
    "flow iat mean", "flow iat std", "flow iat min", "flow iat max",
    "fwd iat total", "fwd iat max", "fwd iat min", "fwd iat mean", "fwd iat std",
    "packet length std", "packet length variance", "fwd packet length std", "down/up ratio",
    "init_win_bytes_forward", "fwd psh flags", "fwd urg flags",
    "active mean", "active max", "active min", "active std",
    "idle mean", "idle max", "idle min", "idle std",
)


@dataclass(frozen=True)
class GroupIndex:
    """Column positions of the canonical features of one pool."""

    columns: tuple[str, ...]
    canonical: tuple[str, ...]
    pos: dict

    def col(self, name: str) -> int | None:
        return self.pos.get(name)

    def idx(self, names) -> np.ndarray:
        return np.array([self.pos[n] for n in names if n in self.pos], dtype=int)

    @property
    def timing(self) -> np.ndarray:
        return self.idx(TIMING_FEATURES)

    @property
    def length(self) -> np.ndarray:
        return self.idx(LENGTH_FEATURES)

    @property
    def packets(self) -> np.ndarray:
        return self.idx(COUNT_PACKET_FEATURES)

    @property
    def bytes_(self) -> np.ndarray:
        return self.idx(COUNT_BYTE_FEATURES)

    def controllable_idx(self) -> np.ndarray:
        return np.unique(np.concatenate([self.timing, self.idx([FLOW_IAT_MAX]), self.length,
                                         self.packets, self.bytes_, self.idx([FWD_HEADER])]))

    def derived_idx(self) -> np.ndarray:
        return self.idx(DERIVED_ALL)

    def mutated_idx(self) -> np.ndarray:
        """Columns a mutation can change (controllable or derived)."""
        return np.unique(np.concatenate([self.controllable_idx(), self.derived_idx()]))

    def robust_idx(self) -> np.ndarray:
        """Columns no mutation can change and that do not depend on forward timing or size."""
        drop = set(self.mutated_idx().tolist()) | set(self.idx(ROBUST_DROP_DEPENDENT).tolist())
        return np.array([i for i in range(len(self.columns)) if i not in drop], dtype=int)

    def dropped_robust_columns(self) -> list[str]:
        """Columns excluded from the robust model, with the reason in the feature log."""
        keep = set(self.robust_idx().tolist())
        return [c for i, c in enumerate(self.columns) if i not in keep]

    def group_columns(self, group: str) -> list[str]:
        names = {
            "timing": TIMING_FEATURES + (FLOW_IAT_MAX,),
            "length": LENGTH_FEATURES,
            "count": COUNT_PACKET_FEATURES + COUNT_BYTE_FEATURES + (FWD_HEADER,),
        }[group]
        return [self.columns[i] for i in sorted(self.idx(names))]

    def columns_of(self, idx: np.ndarray) -> list[str]:
        return [self.columns[i] for i in sorted(idx)]

    def uncontrollable_columns(self) -> list[str]:
        used = set(self.mutated_idx().tolist())
        return [c for i, c in enumerate(self.columns) if i not in used]


def build_group_index(columns, aliases: dict | None = None) -> GroupIndex:
    """Map feature columns to canonical names. Raises on duplicate canonical names."""
    cols = tuple(str(c) for c in columns)
    canon = tuple(canonical_name(c, aliases) for c in cols)
    pos: dict[str, int] = {}
    for i, k in enumerate(canon):
        if k in pos:
            raise ValueError(f"canonical name collision: {cols[i]!r} and {cols[pos[k]]!r}")
        pos[k] = i
    return GroupIndex(columns=cols, canonical=canon, pos=pos)


def _levels(level, n: int) -> np.ndarray:
    """Level per row as an (n, 1) array; scalars broadcast. Every level must be at least 1."""
    lv = np.asarray(level, dtype=float)
    lv = np.full(n, float(lv)) if lv.ndim == 0 else lv.reshape(n)
    if not np.all(np.isfinite(lv)) or np.any(lv < 1.0):
        raise ValueError("level must be >= 1 (attacker changes are increase-only)")
    return lv[:, None]


def _scale(v: np.ndarray, lev: np.ndarray) -> np.ndarray:
    """Multiply non-negative values by the level; negative sentinel values are left unchanged."""
    return np.where(v >= 0, v * lev, v)


def _timing(Y: np.ndarray, X: np.ndarray, gi: GroupIndex, lev: np.ndarray) -> None:
    t = gi.idx(TIMING_SCALED)
    Y[:, t] = _scale(X[:, t], lev)
    fi, fw = gi.col(FLOW_IAT_MAX), gi.col("fwd iat max")
    if fi is not None and fw is not None:
        orig = X[:, fi]
        Y[:, fi] = np.where(orig >= 0, np.maximum(orig, Y[:, fw]), orig)


def _length(Y: np.ndarray, X: np.ndarray, gi: GroupIndex, lev: np.ndarray) -> None:
    c = gi.length
    v = X[:, c]
    Y[:, c] = np.maximum(v, np.minimum(PAD_MAX, v * lev))
    fm, tf = gi.col(FWD_LEN_MEAN), gi.col(FWD_TOTAL_PKTS)
    if fm is not None and tf is not None:
        delta = Y[:, fm] - X[:, fm]
        add = np.where(delta > 0, X[:, tf] * delta, 0.0)
        for b in gi.bytes_:
            Y[:, b] = X[:, b] + add
    fs, fmn, fmx = gi.col(FWD_LEN_STD), gi.col(FWD_LEN_MIN), gi.col(FWD_LEN_MAX)
    if None not in (fs, fm, fmn, fmx):
        mu, lo = Y[:, fm], Y[:, fmn]
        hi = np.maximum(PAD_MAX, X[:, fmx])
        bound = np.sqrt(np.maximum((hi - mu) * (mu - lo), 0.0))
        Y[:, fs] = np.minimum(X[:, fs] * lev[:, 0], bound)


def _count(Y: np.ndarray, X: np.ndarray, gi: GroupIndex, lev: np.ndarray) -> None:
    p = gi.packets
    x = X[:, p]
    Y[:, p] = np.where(x >= 0, np.ceil(x * lev), x)
    b = gi.bytes_
    Y[:, b] = _scale(X[:, b], lev)
    tf, fh = gi.col(FWD_TOTAL_PKTS), gi.col(FWD_HEADER)
    if tf is not None and fh is not None:
        n0 = X[:, tf]
        added = np.maximum(Y[:, tf] - n0, 0.0)
        per_pkt = X[:, fh] / np.maximum(n0, 1.0)
        Y[:, fh] = np.where(X[:, fh] >= 0, X[:, fh] + added * per_pkt, X[:, fh])


def _set_rate(Y, gi: GroupIndex, name: str, num: np.ndarray, dur: np.ndarray, pos: np.ndarray):
    c = gi.col(name)
    if c is not None:
        Y[pos, c] = num[pos] / dur[pos]


def _pooled_var(nf, mf, sf, nb, mb, sb):
    """Variance of the union of a forward and a backward sample from their means and std (population)."""
    N = nf + nb
    ok = N > 0
    Nd = np.where(ok, N, 1.0)
    mu = (nf * mf + nb * mb) / Nd
    var = (nf * (sf ** 2 + (mf - mu) ** 2) + nb * (sb ** 2 + (mb - mu) ** 2)) / Nd
    return np.where(ok, var, 0.0)


def _id_iat(dur, n):
    """Duration / (n - 1) for n >= 2 packets, else 0 (the identity of the mean inter-arrival time)."""
    return np.where(n >= 2, dur / np.maximum(n - 1, 1.0), 0.0)


def _recompute(Y: np.ndarray, X: np.ndarray, gi: GroupIndex, group: str, lev: np.ndarray) -> None:
    dc = gi.col("flow duration")
    tf, tb = gi.col(FWD_TOTAL_PKTS), gi.col(BWD_TOTAL_PKTS)
    bf, bb = gi.col(FWD_BYTES), gi.col(BWD_BYTES)
    dur = None
    if dc is not None:
        dur = Y[:, dc] / 1e6
        pos = dur > 0
        if tf is not None and tb is not None:
            _set_rate(Y, gi, "flow packets/s", Y[:, tf] + Y[:, tb], dur, pos)
            _set_rate(Y, gi, "fwd packets/s", Y[:, tf], dur, pos)
            _set_rate(Y, gi, "bwd packets/s", Y[:, tb], dur, pos)
        if bf is not None and bb is not None:
            _set_rate(Y, gi, "flow bytes/s", Y[:, bf] + Y[:, bb], dur, pos)
    if group == "length":
        fmx, bmx = gi.col(FWD_LEN_MAX), gi.col("bwd packet length max")
        fmn, bmn = gi.col(FWD_LEN_MIN), gi.col("bwd packet length min")
        cmx, cmn = gi.col("max packet length"), gi.col("min packet length")
        if fmx is not None and bmx is not None and cmx is not None:
            Y[:, cmx] = np.maximum(Y[:, fmx], X[:, bmx])
        if fmn is not None and bmn is not None and cmn is not None:
            Y[:, cmn] = np.minimum(Y[:, fmn], X[:, bmn])
    # Delta-form identities: packet length mean and average packet size (bytes over packets).
    if None not in (tf, tb, bf, bb):
        n_old = X[:, tf] + X[:, tb]
        n_new = Y[:, tf] + Y[:, tb]
        b_old = X[:, bf] + X[:, bb]
        b_new = Y[:, bf] + Y[:, bb]
        ok = (n_old > 0) & (n_new > 0)
        d = np.zeros(len(Y))
        d[ok] = b_new[ok] / n_new[ok] - b_old[ok] / n_old[ok]
        for name in ("packet length mean", "average packet size"):
            c = gi.col(name)
            if c is not None:
                Y[:, c] = X[:, c] + d
    if dur is not None and tf is not None and tb is not None:
        dur0 = X[:, dc] / 1e6
        fim = gi.col(FLOW_IAT_MEAN)
        if fim is not None:
            # Flow IAT Mean is in microseconds, like Flow Duration (not in seconds).
            n0, n1 = X[:, tf] + X[:, tb], Y[:, tf] + Y[:, tb]
            Y[:, fim] = X[:, fim] + _id_iat(Y[:, dc], n1) - _id_iat(X[:, dc], n0)
        ratio = np.where(dur0 > 0, dur / np.where(dur0 > 0, dur0, 1.0), 1.0)
        fis = gi.col(FLOW_IAT_STD)
        if fis is not None:
            Y[:, fis] = np.where(X[:, fis] >= 0, X[:, fis] * ratio, X[:, fis])
        fimin, fwmin = gi.col(FLOW_IAT_MIN), gi.col("fwd iat min")
        if fimin is not None and fwmin is not None and group == "timing":
            x, f = X[:, fimin], X[:, fwmin]
            fwd_min = (x >= 0) & (f >= 0) & (np.abs(x - f) <= 1e-6 * np.maximum(np.abs(f), 1.0))
            Y[:, fimin] = np.where(fwd_min, x * ratio, x)
    if tf is not None and gi.col(FWD_IAT_MEAN) is not None:
        fwt, fwm = gi.col("fwd iat total"), gi.col(FWD_IAT_MEAN)
        if fwt is not None:
            n0, n1 = X[:, tf], Y[:, tf]
            id0 = np.where(n0 >= 2, X[:, fwt] / np.maximum(n0 - 1, 1.0), 0.0)
            id1 = np.where(n1 >= 2, Y[:, fwt] / np.maximum(n1 - 1, 1.0), 0.0)
            Y[:, fwm] = X[:, fwm] + id1 - id0
    du = gi.col(DOWN_UP)
    if du is not None and tf is not None and tb is not None:
        f0, f1 = X[:, tf], Y[:, tf]
        d0 = np.where(f0 > 0, np.floor(X[:, tb] / np.maximum(f0, 1.0)), 0.0)
        d1 = np.where(f1 > 0, np.floor(Y[:, tb] / np.maximum(f1, 1.0)), 0.0)
        Y[:, du] = X[:, du] + d1 - d0
    vc, sc = gi.col(PKT_LEN_VAR), gi.col(PKT_LEN_STD)
    fm, fs = gi.col(FWD_LEN_MEAN), gi.col(FWD_LEN_STD)
    bm, bs = gi.col(BWD_LEN_MEAN), gi.col(BWD_LEN_STD)
    if None not in (vc, sc, fm, fs, bm, bs, tf, tb):
        v0 = _pooled_var(X[:, tf], X[:, fm], X[:, fs], X[:, tb], X[:, bm], X[:, bs])
        v1 = _pooled_var(Y[:, tf], Y[:, fm], Y[:, fs], Y[:, tb], X[:, bm], X[:, bs])
        delta = v1 - v0
        Y[:, vc] = X[:, vc] + delta
        Y[:, sc] = np.sqrt(np.maximum(X[:, sc] ** 2 + delta, 0.0))


def apply_group(X: np.ndarray, gi: GroupIndex, group: str, level) -> np.ndarray:
    """Return a mutated copy of X (n x d) with one group changed at the given level (>= 1).

    ``level`` is a scalar or one level per row (rows at level 1 are returned unchanged by the group).
    """
    if group not in GROUPS:
        raise ValueError(f"unknown group {group!r}")
    X = np.asarray(X, dtype=float)
    lev = _levels(level, len(X))
    Y = np.array(X, dtype=float, copy=True)
    if group == "timing":
        _timing(Y, X, gi, lev)
    elif group == "length":
        _length(Y, X, gi, lev)
    else:
        _count(Y, X, gi, lev)
    _recompute(Y, X, gi, group, lev)
    rows = lev[:, 0] == 1.0
    if rows.any():
        Y[rows] = X[rows]
    return Y


def budgets() -> list[tuple[tuple[str, ...], float]]:
    """All (non-empty group subset, multiplier) budgets: 7 subsets x 3 multipliers = 21."""
    subsets = [c for r in range(1, len(GROUPS) + 1) for c in itertools.combinations(GROUPS, r)]
    return [(g, m) for g in subsets for m in MULTIPLIERS]


def budget_label(groups: tuple[str, ...], mult: float) -> str:
    return "+".join(groups) + f",x{mult:g}"


def budget_units(groups: tuple[str, ...], mult: float) -> float:
    """|groups| * log2(2 * multiplier): the cost unit of a budget (design section 3.1)."""
    return len(groups) * math.log2(2.0 * mult)


def _g1(gi: GroupIndex):
    """Default generator (G1, proportional scaling) for a column index."""
    return lambda X, g, lv: apply_group(X, gi, g, lv)


def _score_mode(score_fn, X0: np.ndarray, gi: GroupIndex, groups, mult: float, apply=None):
    ap = apply if apply is not None else _g1(gi)
    n, d = X0.shape
    G = len(groups)
    levels = (math.sqrt(mult), mult) if mult > 1.0 else (1.0,)
    X = np.array(X0, dtype=float, copy=True)
    s = np.asarray(score_fn(X), dtype=float).copy()
    path = [s.copy()]
    applied = np.zeros((n, G), dtype=bool)
    rows = np.arange(n)
    meta = np.array([j for j in range(G) for _ in levels])
    for _ in range(G):
        cands = np.stack([ap(X, groups[j], lv) for j in range(G) for lv in levels])
        C = cands.shape[0]
        sc = np.asarray(score_fn(cands.reshape(C * n, d)), dtype=float).reshape(C, n)
        sc = np.where(applied[:, meta].T, np.inf, sc)
        best = np.argmin(sc, axis=0)
        best_s = sc[best, rows]
        improve = best_s < s
        X = np.where(improve[:, None], cands[best, rows], X)
        jb = meta[best]
        applied[rows[improve], jb[improve]] = True
        s = np.where(improve, best_s, s)
        path.append(s.copy())
    return np.column_stack(path), X


def _label_mode(score_fn, X0: np.ndarray, gi: GroupIndex, groups, mult: float,
                rng: np.random.Generator, apply=None):
    ap = apply if apply is not None else _g1(gi)
    n, G = len(X0), len(groups)
    path = [np.asarray(score_fn(X0), dtype=float)]
    order = np.argsort(rng.random((n, G)), axis=1)
    X = np.asarray(X0, dtype=float)
    for k in range(G):
        cands = np.stack([ap(X, g, mult) for g in groups])
        X = cands[order[:, k], np.arange(n)]
        path.append(np.asarray(score_fn(X), dtype=float))
    return np.column_stack(path), X


def attack_path(score_fn, X0: np.ndarray, gi: GroupIndex | None, groups: tuple[str, ...], mult: float,
                query_mode: str, rng: np.random.Generator | None = None, apply=None):
    """Scores along the attack path of every flow (array (n, K + 1), column 0 unmutated) and the
    final mutated flows. The evaded status at threshold tau is ``path.min(axis=1) <= tau``."""
    if query_mode == "score":
        return _score_mode(score_fn, np.asarray(X0, dtype=float), gi, groups, mult, apply)
    if query_mode == "label":
        if rng is None:
            raise ValueError("label mode needs an rng")
        return _label_mode(score_fn, np.asarray(X0, dtype=float), gi, groups, mult, rng, apply)
    raise ValueError(query_mode)


def score_path(score_fn, X0, gi, groups, mult, query_mode, rng=None, apply=None) -> np.ndarray:
    return attack_path(score_fn, X0, gi, groups, mult, query_mode, rng, apply)[0]


def _build(X0: np.ndarray, gi: GroupIndex | None, groups, idx: np.ndarray, grid: np.ndarray,
           apply=None) -> np.ndarray:
    """Flows with group j at level grid[idx[:, j]] (level index 0 = unchanged); groups in fixed order."""
    ap = apply if apply is not None else _g1(gi)
    Y = np.array(X0, dtype=float, copy=True)
    for j, g in enumerate(groups):
        lv = grid[idx[:, j]]
        rows = lv > 1.0
        if rows.any():
            Y[rows] = ap(Y[rows], g, lv[rows])
    return Y


def strong_attack(score_fn, X0: np.ndarray, gi: GroupIndex | None, groups: tuple[str, ...], mult: float,
                  rng: np.random.Generator, apply=None):
    """Strong score-query attacker: per-group level search over STRONG_LEVELS levels in [1, mult].

    Coordinate sweep over the groups from two starts (every group at the top level; random levels).
    A single group is searched exhaustively by one sweep, so it gets one start. Returns the lowest score
    of every queried state (per flow) and the state that reached it. The unmutated flow is a queried state.
    """
    X0 = np.asarray(X0, dtype=float)
    n, d = X0.shape
    G = len(groups)
    K = STRONG_LEVELS
    grid = np.linspace(1.0, mult, K)
    s0 = np.asarray(score_fn(X0), dtype=float)
    best_s = s0.copy()
    best_X = X0.copy()
    starts = 1 if G == 1 else STRONG_RESTARTS
    rows = np.arange(n)
    for r in range(starts):
        if r == 0:
            idx = np.full((n, G), K - 1, dtype=int)
        else:
            idx = rng.integers(0, K, size=(n, G))
        for j in range(G):
            cand = np.empty((K, n, d))
            for k in range(K):
                ik = idx.copy()
                ik[:, j] = k
                cand[k] = _build(X0, gi, groups, ik, grid, apply)
            sc = np.asarray(score_fn(cand.reshape(K * n, d)), dtype=float).reshape(K, n)
            kmin = np.argmin(sc, axis=0)
            m = sc[kmin, rows]
            better = m < best_s
            if better.any():
                best_s = np.where(better, m, best_s)
                best_X[better] = cand[kmin[better], rows[better]]
            idx[:, j] = kmin
    return best_s, best_X


def recall_from_scores(scores: np.ndarray, thr: float, ok: bool) -> float:
    """Recall when the attacker's submitted flows have these scores (fraction not evaded)."""
    if not ok:
        return float("nan")
    return float(np.mean(np.asarray(scores) > thr))


def recall_at(path: np.ndarray, thr: float, ok: bool) -> float:
    """Recall after the attack: fraction of flows never evaded (NaN when the level is unattainable)."""
    if not ok:
        return float("nan")
    return float(1.0 - np.mean(path.min(axis=1) <= thr))


def identity_hold_rates(X: np.ndarray, gi: GroupIndex, rtol: float = IDENT_RTOL) -> dict[str, dict]:
    """Share of rows on which each identity behind a recomputed feature holds (within rtol)."""
    X = np.asarray(X, dtype=float)
    c = gi.col
    n = len(X)
    out: dict[str, dict] = {}

    def rate(name, rule, mask, lhs, rhs, tol_abs=1e-6):
        mask = np.asarray(mask, dtype=bool)
        if mask.sum() == 0:
            out[name] = {"rule": rule, "rows": 0, "holds": float("nan")}
            return
        ok = np.abs(lhs[mask] - rhs[mask]) <= rtol * np.maximum(np.abs(rhs[mask]), 1.0) + tol_abs
        out[name] = {"rule": rule, "rows": int(mask.sum()), "holds": float(ok.mean())}

    tf, tb = c(FWD_TOTAL_PKTS), c(BWD_TOTAL_PKTS)
    dur = c("flow duration")
    if None not in (tf, tb, dur, c(FLOW_IAT_MEAN)):
        nt = X[:, tf] + X[:, tb]
        rate(FLOW_IAT_MEAN, "Flow Duration / (Total packets - 1)", nt >= 2,
             X[:, c(FLOW_IAT_MEAN)], X[:, dur] / np.maximum(nt - 1, 1.0))
    if None not in (tf, c("fwd iat total"), c(FWD_IAT_MEAN)):
        rate(FWD_IAT_MEAN, "Fwd IAT Total / (Total Fwd Packets - 1)", X[:, tf] >= 2,
             X[:, c(FWD_IAT_MEAN)], X[:, c("fwd iat total")] / np.maximum(X[:, tf] - 1, 1.0))
    if None not in (tf, tb, c(DOWN_UP)):
        ok = X[:, tf] > 0
        lhs = X[:, c(DOWN_UP)]
        rhs = np.floor(X[:, tb] / np.maximum(X[:, tf], 1.0))
        holds = np.where(ok, lhs == rhs, False)
        out[DOWN_UP] = {"rule": "floor(Total Bwd Packets / Total Fwd Packets)", "rows": int(ok.sum()),
                        "holds": float(holds[ok].mean()) if ok.any() else float("nan")}
    if None not in (c(PKT_LEN_VAR), c(PKT_LEN_STD)):
        v, s = X[:, c(PKT_LEN_VAR)], X[:, c(PKT_LEN_STD)]
        rate(PKT_LEN_VAR, "Packet Length Std ** 2 (identity used only to define the variance rule)",
             np.ones(n, dtype=bool), v, s ** 2)
    if None not in (tf, tb, c(FWD_LEN_MEAN), c(FWD_LEN_STD), c(BWD_LEN_MEAN), c(BWD_LEN_STD), c(PKT_LEN_VAR)):
        v1 = _pooled_var(X[:, tf], X[:, c(FWD_LEN_MEAN)], X[:, c(FWD_LEN_STD)], X[:, tb],
                         X[:, c(BWD_LEN_MEAN)], X[:, c(BWD_LEN_STD)])
        rate("packet length variance (pooled)", "pooled variance of fwd and bwd directions", tf >= 0,
             X[:, c(PKT_LEN_VAR)], v1)
    if None not in (tf, tb, c(FWD_BYTES), c(BWD_BYTES), c("packet length mean")):
        npk = X[:, tf] + X[:, tb]
        byt = X[:, c(FWD_BYTES)] + X[:, c(BWD_BYTES)]
        rate("packet length mean", "(fwd bytes + bwd bytes) / (fwd packets + bwd packets)", npk > 0,
             X[:, c("packet length mean")], byt / np.maximum(npk, 1.0))
    fimin, fwmin = c(FLOW_IAT_MIN), c("fwd iat min")
    if None not in (fimin, fwmin):
        ok = (X[:, fwmin] >= 0) & (X[:, fimin] >= 0)
        same = np.abs(X[:, fimin] - X[:, fwmin]) <= 1e-6 * np.maximum(np.abs(X[:, fwmin]), 1.0)
        out["flow iat min = fwd iat min"] = {"rule": "rule applies when the minimum gap is forward",
                                             "rows": int(ok.sum()),
                                             "holds": float((same & ok).sum() / max(ok.sum(), 1))}
    mx, mn = c("max packet length"), c("min packet length")
    fmx, bmx, fmn, bmn = c(FWD_LEN_MAX), c("bwd packet length max"), c(FWD_LEN_MIN), c("bwd packet length min")
    if None not in (mx, fmx, bmx):
        rate("max packet length", "max(fwd max, bwd max)", np.ones(n, dtype=bool), X[:, mx],
             np.maximum(X[:, fmx], X[:, bmx]))
    if None not in (mn, fmn, bmn):
        rate("min packet length", "min(fwd min, bwd min)", np.ones(n, dtype=bool), X[:, mn],
             np.minimum(X[:, fmn], X[:, bmn]))
    if None not in (dur, tf, tb, c("flow packets/s"), c("fwd packets/s"), c("bwd packets/s")):
        d = X[:, dur] / 1e6
        pos = d > 0
        rate("flow packets/s", "(fwd + bwd packets) / duration", pos, X[:, c("flow packets/s")],
             (X[:, tf] + X[:, tb]) / np.where(pos, d, 1.0))
        rate("fwd packets/s", "fwd packets / duration", pos, X[:, c("fwd packets/s")],
             X[:, tf] / np.where(pos, d, 1.0))
        rate("bwd packets/s", "bwd packets / duration", pos, X[:, c("bwd packets/s")],
             X[:, tb] / np.where(pos, d, 1.0))
    if None not in (tf, tb, c(FWD_BYTES), c(BWD_BYTES)) and c("average packet size") is not None:
        npk = X[:, tf] + X[:, tb]
        byt = X[:, c(FWD_BYTES)] + X[:, c(BWD_BYTES)]
        rate("average packet size", "(fwd bytes + bwd bytes) / (fwd packets + bwd packets)", npk > 0,
             X[:, c("average packet size")], byt / np.maximum(npk, 1.0))
    rr = c("flow bytes/s")
    if None not in (rr, dur, tf, tb, c(FWD_BYTES), c(BWD_BYTES)):
        d = X[:, dur] / 1e6
        pos = d > 0
        rate("flow bytes/s", "(fwd bytes + bwd bytes) / duration", pos,
             X[:, rr], (X[:, c(FWD_BYTES)] + X[:, c(BWD_BYTES)]) / np.where(pos, d, 1.0))
    return out


def feature_log_lines(name: str, gi: GroupIndex, rates: dict | None = None) -> list[str]:
    lines = [f"## {name}", ""]
    for g in GROUPS:
        cols = gi.group_columns(g)
        lines.append(f"- {g} group, controllable ({len(cols)}): " + (", ".join(cols) if cols else "none"))
    lines.append(f"- derived, recomputed by a rule ({len(DERIVED)}): " + ", ".join(DERIVED))
    lines.append(f"- all columns a mutation can change ({len(gi.columns_of(gi.mutated_idx()))}): "
                 + ", ".join(gi.columns_of(gi.mutated_idx())))
    lines.append(f"- uncontrollable, never changed ({len(gi.uncontrollable_columns())}): "
                 + ", ".join(gi.uncontrollable_columns()))
    lines.append(f"- robust model input ({len(gi.robust_idx())}): " + ", ".join(gi.columns_of(gi.robust_idx())))
    lines.append(f"- robust model excluded ({len(gi.dropped_robust_columns())}): "
                 + ", ".join(gi.dropped_robust_columns()))
    if rates:
        lines += ["", f"Identity hold rates on the cached pool (sample of {name}; relative tolerance "
                  f"{IDENT_RTOL:g} unless the rule is exact):", "",
                  "| feature | rule | rows checked | share of rows where the rule holds |",
                  "|---|---|---|---|"]
        for k, v in rates.items():
            h = "n/a" if v["holds"] != v["holds"] else f"{v['holds']:.4f}"
            lines.append(f"| {k} | {v['rule']} | {v['rows']} | {h} |")
    lines.append("")
    return lines


def write_feature_log(path: Path, indexes: dict[str, GroupIndex], rates: dict[str, dict] | None = None) -> None:
    lines = ["# E4 feature groups (mapping used by mutation.py)", "",
             "Columns are matched by canonical name (lowercase; CIC-IDS2018 abbreviations mapped to "
             "CIC-IDS2017 names). Only forward-direction features are controllable; every backward "
             "(server-side) feature is uncontrollable.", "",
             "Derived features are recomputed by delta updates (Y = X + f(Y) - f(X)), so a value keeps its "
             "offset from the identity where the identity does not hold exactly. Approximations (not "
             "checkable on the cache, since per-packet lengths and gaps are not stored): Fwd Packet Length "
             "Std (Bhatia-Davis bound on the level-scaled std), Flow IAT Std (duration ratio), Flow IAT Min "
             "(fwd-minimum rule).", "",
             "Robust model (xgb_robustfeat): input = every column outside the mutated set and outside "
             "ROBUST_DROP_DEPENDENT; the explicit lists are below for each dataset.", ""]
    for name, gi in indexes.items():
        lines += feature_log_lines(name, gi, (rates or {}).get(name))
    path.write_text("\n".join(lines) + "\n")
