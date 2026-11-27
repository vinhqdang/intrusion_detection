"""G2: additive, coupled client-side generator (design/design_robustness.md section 3.2).

Independent code path: no helper is imported from ``idsbench.econ.mutation``. The column layout, the
per-flow random draws and every recomputation rule are defined here. The only shared piece is the
canonical feature naming of ``feasibility.e3_crosspair``.

Groups and levels follow the attacker interface ``apply(X, group, level)``: ``level`` is the budget
multiplier m >= 1 (scalar or one value per row); rows at level 1 are returned unchanged.

Timing (additive, coupled): per-packet delay delta = (m - 1) * Fwd IAT Mean (1 ms = 1000 us when the mean is 0).
Length (random target): per-flow target T in (mean, min(MTU, m mean)), drawn deterministically from the flow.
Count (dummy packets): k = ceil((m - 1) n_fwd) zero-payload forward packets.

Recomputation is in delta form. A derived value (packet-length mean, average packet size, variance, Flow IAT
Mean, Down/Up Ratio, rates) moves by the change that the group implies, so an original flow that does not satisfy
the textbook identity keeps its offset. Rows whose inputs did not change are returned bit-identical. Timing
therefore leaves every length column unchanged. ``MAY_DECREASE`` lists the only columns a group may reduce, with
the physical reason; the tests check that no other column decreases.

Fwd Packet Length Max = max(original max, T / (1 - a)), where T / (1 - a) is the padded data-packet size (a is the
zero-payload share). Fwd IAT Min, Fwd IAT Max and Fwd IAT Std are left unchanged by the count group.
"""

from __future__ import annotations

import itertools

import numpy as np

from idsbench.feasibility.e3_crosspair import canonical_name

GROUPS = ("timing", "length", "count")
MTU = 1500.0
FALLBACK_GAP_US = 1000.0   # timing budget floor: 1 ms in CICFlowMeter microseconds
SALT = 0x5EED_2026

# Every column G2 can change (controllable, recomputed or coupled). Used to build the robust column list.
TOUCHED = (
    "flow duration", "fwd iat total", "fwd iat mean", "fwd iat max", "fwd iat min", "fwd iat std",
    "bwd iat total", "bwd iat mean", "bwd iat max", "active mean", "active max",
    "flow iat max", "flow iat mean", "flow iat std", "flow iat min",
    "fwd packet length max", "fwd packet length min", "fwd packet length mean", "fwd packet length std",
    "avg fwd segment size", "total length of fwd packets", "subflow fwd bytes",
    "total fwd packets", "subflow fwd packets", "fwd header length",
    "packet length mean", "packet length std", "packet length variance", "average packet size",
    "max packet length", "min packet length", "flow packets/s", "fwd packets/s", "bwd packets/s",
    "flow bytes/s", "down/up ratio",
)

# Columns a group may reduce, with the physical reason (canonical names). Anything else must not decrease.
MAY_DECREASE = {
    # Longer duration over the same packets: rates fall.
    "timing": frozenset({"flow bytes/s", "flow packets/s", "fwd packets/s", "bwd packets/s"}),
    # Pooled variance is not monotone in the forward length: moving the forward mean towards the backward mean
    # can shrink the between-direction spread.
    "length": frozenset({"packet length variance", "packet length std"}),
    # Zero-payload packets: forward mean length, the segment size and the overall averages fall, the minimum
    # becomes 0, more packets in the same duration give smaller mean gaps, and the down/up ratio falls.
    "count": frozenset({
        "fwd packet length mean", "fwd packet length std", "avg fwd segment size", "fwd packet length min",
        "min packet length", "packet length mean", "average packet size", "packet length variance",
        "packet length std", "flow iat mean", "fwd iat mean", "down/up ratio",
    }),
}

# The budget grid of the design (7 non-empty group subsets x 3 multipliers), same labels as G1.
SUBSETS = tuple(c for r in range(1, len(GROUPS) + 1) for c in itertools.combinations(GROUPS, r))
MULTIPLIERS = (1.5, 2.0, 5.0)
BUDGETS = tuple((g, m) for g in SUBSETS for m in MULTIPLIERS)


class Layout:
    """Column positions by canonical name (own implementation)."""

    def __init__(self, columns, aliases: dict | None = None):
        self.columns = tuple(str(c) for c in columns)
        self.pos: dict[str, int] = {}
        for i, c in enumerate(self.columns):
            k = canonical_name(c, aliases)
            if k in self.pos:
                raise ValueError(f"canonical name collision: {c!r}")
            self.pos[k] = i

    def c(self, name: str) -> int | None:
        return self.pos.get(name)

    def has(self, *names) -> bool:
        return all(n in self.pos for n in names)


def _mix(bits: np.ndarray, salt: int) -> np.ndarray:
    """splitmix-style hash of each row's float64 bit patterns, mapped to [0, 1)."""
    with np.errstate(over="ignore"):
        h = np.full(len(bits), np.uint64(salt), dtype=np.uint64)
        for j in range(bits.shape[1]):
            h = (h ^ bits[:, j]) * np.uint64(0xBF58476D1CE4E5B9)
            h ^= h >> np.uint64(31)
        h = (h ^ (h >> np.uint64(30))) * np.uint64(0x94D049BB133111EB)
        h ^= h >> np.uint64(27)
    return (h >> np.uint64(11)).astype(np.float64) / 2.0 ** 53


def flow_uniform(X: np.ndarray, salt: int = SALT) -> np.ndarray:
    """One deterministic uniform draw per flow (a function of the flow's own values, not of its position)."""
    bits = np.ascontiguousarray(X, dtype=np.float64).view(np.uint64)
    return _mix(bits, salt)


def _gap_mean(duration: np.ndarray, n: np.ndarray) -> np.ndarray:
    """duration / (n - 1) for n >= 2 packets, else 0 (the mean inter-arrival time of n packets)."""
    return np.where(n >= 2, duration / np.maximum(n - 1.0, 1.0), 0.0)


def _pooled_var(nf, mf, sf, nb, mb, sb) -> np.ndarray:
    """Population variance of the union of a forward and a backward sample, from their counts, means and stds."""
    N = nf + nb
    ok = N > 0
    Nd = np.where(ok, N, 1.0)
    mu = (nf * mf + nb * mb) / Nd
    var = (nf * (sf ** 2 + (mf - mu) ** 2) + nb * (sb ** 2 + (mb - mu) ** 2)) / Nd
    return np.where(ok, var, 0.0)


class G2:
    """Additive, coupled generator on one column layout."""

    def __init__(self, columns, aliases: dict | None = None):
        self.lay = Layout(columns, aliases)
        self.touched = np.array(sorted({self.lay.c(n) for n in TOUCHED if self.lay.c(n) is not None}), dtype=int)

    # ------------------------------------------------------------------ public
    def apply(self, X, group: str, level) -> np.ndarray:
        if group not in GROUPS:
            raise ValueError(f"unknown group {group!r}")
        X = np.asarray(X, dtype=np.float64)
        lev = np.asarray(level, dtype=np.float64)
        lev = np.full(len(X), float(lev)) if lev.ndim == 0 else lev.reshape(len(X))
        if not np.all(np.isfinite(lev)) or np.any(lev < 1.0):
            raise ValueError("level must be >= 1 (attacker changes are increase-only)")
        Y = X.copy()
        if group == "timing":
            self._timing(Y, X, lev)
        elif group == "length":
            self._length(Y, X, lev)
        else:
            self._count(Y, X, lev)
        self._recompute(Y, X)
        keep = lev == 1.0
        if keep.any():
            Y[keep] = X[keep]
        return Y

    # ------------------------------------------------------------------ timing
    def _timing(self, Y, X, lev):
        L = self.lay
        tf, mean = L.c("total fwd packets"), L.c("fwd iat mean")
        if tf is None or mean is None:
            return
        nf = X[:, tf]
        m = nf >= 2
        if not m.any():
            return
        base = np.where(X[:, mean] > 0, X[:, mean], FALLBACK_GAP_US)
        delta = np.where(m, (lev - 1.0) * base, 0.0)
        gaps = np.maximum(nf - 1.0, 0.0)
        k = np.maximum(nf - 1.0, 1.0)
        c_max = 1.0 + np.log(k)
        c_min = 1.0 / k
        dur = L.c("flow duration")
        ft, fx, fn, fs = L.c("fwd iat total"), L.c("fwd iat max"), L.c("fwd iat min"), L.c("fwd iat std")
        if ft is not None:
            Y[:, ft] = np.where(m, X[:, ft] + gaps * delta, X[:, ft])
        Y[:, mean] = np.where(m, X[:, mean] + delta, X[:, mean])
        if fx is not None:
            Y[:, fx] = np.where(m, X[:, fx] + delta * c_max, X[:, fx])
        if fn is not None:
            Y[:, fn] = np.where(m & (X[:, fn] >= 0), X[:, fn] + delta * c_min, X[:, fn])
        if fs is not None:
            Y[:, fs] = np.where(m & (X[:, fs] >= 0), np.sqrt(X[:, fs] ** 2 + delta ** 2), X[:, fs])
        added = gaps * delta
        if dur is not None:
            Y[:, dur] = X[:, dur] + added
        # Request-response coupling: the server answers later in the share of the delay between its packets.
        nb = X[:, L.c("total backward packets")] if L.c("total backward packets") is not None else None
        if nb is not None:
            coupled = m & (nb > 1)
            share_gap = np.where(coupled, delta * np.minimum(nf - 1.0, nb - 1.0) / np.maximum(nb - 1.0, 1.0), 0.0)
            bt, bm, bx = L.c("bwd iat total"), L.c("bwd iat mean"), L.c("bwd iat max")
            if bt is not None:
                Y[:, bt] = X[:, bt] + share_gap * np.maximum(nb - 1.0, 0.0)
            if bm is not None:
                Y[:, bm] = X[:, bm] + share_gap
            if bx is not None:
                Y[:, bx] = X[:, bx] + share_gap
            for name in ("active mean", "active max"):
                c = L.c(name)
                if c is not None:
                    Y[:, c] = X[:, c] + share_gap
        # Flow-level gaps follow the forward gaps (max / min identities; std by the duration ratio).
        fimax, fis, fimin = L.c("flow iat max"), L.c("flow iat std"), L.c("flow iat min")
        if fimax is not None and fx is not None:
            cand = [Y[:, fx]]
            if L.c("bwd iat max") is not None:
                cand.append(Y[:, L.c("bwd iat max")])
            Y[:, fimax] = np.maximum(X[:, fimax], np.max(np.stack(cand), axis=0))
        if fis is not None and dur is not None:
            ratio = np.where(X[:, dur] > 0, Y[:, dur] / np.where(X[:, dur] > 0, X[:, dur], 1.0), 1.0)
            Y[:, fis] = np.where(X[:, fis] >= 0, X[:, fis] * ratio, X[:, fis])
        if fimin is not None and fn is not None:
            same = m & (X[:, fimin] >= 0) & (np.abs(X[:, fimin] - X[:, fn]) <= 1e-6 * np.maximum(np.abs(X[:, fn]), 1.0))
            Y[:, fimin] = np.where(same, Y[:, fn], X[:, fimin])

    # ------------------------------------------------------------------ length
    def _length(self, Y, X, lev):
        L = self.lay
        need = ("total fwd packets", "fwd packet length mean", "fwd packet length std", "fwd packet length max")
        if not L.has(*need):
            return
        nf = X[:, L.c("total fwd packets")]
        mu0 = X[:, L.c("fwd packet length mean")]
        s0 = X[:, L.c("fwd packet length std")]
        mx0 = X[:, L.c("fwd packet length max")]
        data = (nf >= 1) & (mu0 > 0)
        den = np.where(data, s0 ** 2 + mu0 ** 2, 1.0)
        # Zero-payload (ACK) share of the flow from a two-point mixture: s^2 / mu^2 = a / (1 - a).
        a = np.where(data, s0 ** 2 / den, 0.0)
        # The implied data-packet size mu0 / (1 - a) must not exceed the MTU: cap the ACK share accordingly.
        a = np.clip(a, 0.0, np.minimum(0.999, np.maximum(0.0, 1.0 - mu0 / MTU)))
        mu_safe = np.where(data, mu0, 1.0)
        upper = np.maximum(mu0, np.minimum(MTU * (1.0 - a), lev * mu0))
        T = mu0 + flow_uniform(X) * (upper - mu0)          # one target per flow
        d = T / (1.0 - a)                                  # padded data-packet size (<= MTU)
        new_std = T * s0 / mu_safe                         # = d sqrt(a (1 - a))
        fb = L.c("total length of fwd packets")
        sb = L.c("subflow fwd bytes")
        dbytes = np.where(data, nf * (T - mu0), 0.0)
        Y[:, L.c("fwd packet length mean")] = np.where(data, T, mu0)
        Y[:, L.c("fwd packet length max")] = np.where(data, np.maximum(mx0, d), mx0)
        Y[:, L.c("fwd packet length std")] = np.where(data, new_std, s0)
        asg = L.c("avg fwd segment size")
        if asg is not None:
            Y[:, asg] = np.where(data, X[:, asg] + (T - mu0), X[:, asg])
        if fb is not None:
            Y[:, fb] = X[:, fb] + dbytes
        if sb is not None:
            Y[:, sb] = X[:, sb] + dbytes

    # ------------------------------------------------------------------ count
    def _count(self, Y, X, lev):
        L = self.lay
        need = ("total fwd packets", "fwd packet length mean", "fwd packet length std")
        if not L.has(*need):
            return
        nf = X[:, L.c("total fwd packets")]
        k = np.where(nf >= 1, np.ceil((lev - 1.0) * nf), 0.0)
        k = np.maximum(k, 0.0)
        N1 = nf + k
        ok = N1 > 0
        mu0 = X[:, L.c("fwd packet length mean")]
        s0 = X[:, L.c("fwd packet length std")]
        Nd = np.where(ok, N1, 1.0)
        mu1 = nf * mu0 / Nd                                  # the bytes stay, the count grows
        e2 = nf * (s0 ** 2 + mu0 ** 2) / Nd
        s1 = np.sqrt(np.maximum(e2 - mu1 ** 2, 0.0))
        grow = k > 0
        Y[:, L.c("total fwd packets")] = N1
        sp = L.c("subflow fwd packets")
        if sp is not None:
            Y[:, sp] = X[:, sp] + k
        fh = L.c("fwd header length")
        if fh is not None:
            per = X[:, fh] / np.maximum(nf, 1.0)
            Y[:, fh] = np.where(grow, X[:, fh] + k * per, X[:, fh])
        fmn = L.c("fwd packet length min")
        if fmn is not None:
            Y[:, fmn] = np.where(grow, 0.0, X[:, fmn])
        Y[:, L.c("fwd packet length mean")] = np.where(grow, mu1, mu0)
        Y[:, L.c("fwd packet length std")] = np.where(grow, s1, s0)
        asg = L.c("avg fwd segment size")
        if asg is not None:
            Y[:, asg] = np.where(grow, X[:, asg] + (mu1 - mu0), X[:, asg])
        # Fwd IAT Total is unchanged (the dummies sit inside the existing duration), so the mean gap moves to
        # Fwd IAT Total / (n_fwd_new - 1). Delta form: the original offset of the mean is kept.
        fwt, fim = L.c("fwd iat total"), L.c("fwd iat mean")
        if fwt is not None and fim is not None:
            tot = X[:, fwt]
            Y[:, fim] = np.where(grow, X[:, fim] + _gap_mean(tot, N1) - _gap_mean(tot, nf), X[:, fim])

    # ------------------------------------------------------------------ recomputation after any group
    def _recompute(self, Y, X):
        """Delta-form recomputation from the changed counts, bytes and durations. Unchanged inputs give exactly
        the original values."""
        L = self.lay
        tf, tb = L.c("total fwd packets"), L.c("total backward packets")
        if tf is None or tb is None:
            return
        bf, bb = L.c("total length of fwd packets"), L.c("total length of bwd packets")
        dur = L.c("flow duration")
        zero = np.zeros(len(X))
        nf0, nb0 = X[:, tf], X[:, tb]
        nf1, nb1 = Y[:, tf], Y[:, tb]
        n0, n1 = nf0 + nb0, nf1 + nb1
        B0 = (X[:, bf] if bf is not None else zero) + (X[:, bb] if bb is not None else zero)
        B1 = (Y[:, bf] if bf is not None else zero) + (Y[:, bb] if bb is not None else zero)

        # Rates: the original rate times the ratio of the new to the old numerator, and of the old to the new
        # duration. A rate falls only when the duration grows (or a count or byte total falls, which G2 never does).
        if dur is not None:
            D0, D1 = X[:, dur], Y[:, dur]
            dok = (D0 > 0) & (D1 > 0)
            for name, N0, Nn in (("flow packets/s", n0, n1), ("fwd packets/s", nf0, nf1),
                                 ("bwd packets/s", nb0, nb1), ("flow bytes/s", B0, B1)):
                c = L.c(name)
                if c is None:
                    continue
                ok = dok & (N0 > 0)
                ratio = np.where(ok, (Nn / np.where(N0 > 0, N0, 1.0)) * (D0 / np.where(D1 > 0, D1, 1.0)), 1.0)
                Y[:, c] = X[:, c] * ratio
            # Flow IAT Mean (microseconds, like Flow Duration): duration / (n - 1), moved by its change.
            fim = L.c("flow iat mean")
            if fim is not None:
                Y[:, fim] = X[:, fim] + _gap_mean(D1, n1) - _gap_mean(D0, n0)

        # Down/Up Ratio = floor(bwd / fwd packets), moved by its change.
        du = L.c("down/up ratio")
        if du is not None:
            d0 = np.where(nf0 > 0, np.floor(nb0 / np.maximum(nf0, 1.0)), 0.0)
            d1 = np.where(nf1 > 0, np.floor(nb1 / np.maximum(nf1, 1.0)), 0.0)
            Y[:, du] = X[:, du] + (d1 - d0)

        # Packet length mean and average packet size = bytes / packets, moved by the change in the average.
        changed = (n1 != n0) | (B1 != B0)
        both = changed & (n0 > 0) & (n1 > 0)
        dmean = np.where(both, B1 / np.maximum(n1, 1.0) - B0 / np.maximum(n0, 1.0), 0.0)
        for name in ("packet length mean", "average packet size"):
            c = L.c(name)
            if c is not None:
                Y[:, c] = X[:, c] + dmean

        # Packet length variance (pooled forward and backward sample) and std, moved by the change in the pooled
        # variance. The backward sample is unchanged by G2.
        fm, fs = L.c("fwd packet length mean"), L.c("fwd packet length std")
        bm, bs = L.c("bwd packet length mean"), L.c("bwd packet length std")
        vc, sc = L.c("packet length variance"), L.c("packet length std")
        if None not in (fm, fs, bm, bs) and vc is not None:
            mb, sb = X[:, bm], X[:, bs]
            dv = (_pooled_var(nf1, Y[:, fm], Y[:, fs], nb1, mb, sb)
                  - _pooled_var(nf0, X[:, fm], X[:, fs], nb0, mb, sb))
            Y[:, vc] = X[:, vc] + dv
            if sc is not None:
                Y[:, sc] = np.where(dv != 0.0, np.sqrt(np.maximum(X[:, sc] ** 2 + dv, 0.0)), X[:, sc])

        # Max packet length rises with the forward maximum; min packet length falls with the forward minimum.
        mx, fmx = L.c("max packet length"), L.c("fwd packet length max")
        if mx is not None and fmx is not None:
            up = Y[:, fmx] > X[:, fmx]
            Y[:, mx] = np.where(up, np.maximum(X[:, mx], Y[:, fmx]), X[:, mx])
        mn, fmn = L.c("min packet length"), L.c("fwd packet length min")
        if mn is not None and fmn is not None:
            dn = Y[:, fmn] < X[:, fmn]
            Y[:, mn] = np.where(dn, np.minimum(X[:, mn], Y[:, fmn]), X[:, mn])


def apply_budget(gen: G2, X, groups, mult: float) -> np.ndarray:
    """Apply the groups of a budget, in group order, each at level ``mult``."""
    Y = np.asarray(X, dtype=np.float64)
    for g in GROUPS:
        if g in groups:
            Y = gen.apply(Y, g, mult)
    return Y


def apply_random_budget(gen: G2, X, rng: np.random.Generator) -> np.ndarray:
    """Each row gets its own budget drawn uniformly from BUDGETS."""
    X = np.asarray(X, dtype=np.float64)
    bid = rng.integers(0, len(BUDGETS), size=len(X))
    Y = X.copy()
    for b, (groups, mult) in enumerate(BUDGETS):
        rows = bid == b
        if rows.any():
            Y[rows] = apply_budget(gen, X[rows], groups, mult)
    return Y
