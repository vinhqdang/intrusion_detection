"""Defender-attacker game of design section 3: payoffs, attacker best responses, defender enumeration.

Notation (per day):
  N_benign benign flows, N_attack attack attempts if every attacker type attacks;
  r(a) recall of action a at the operating threshold (measured; see detection_tables.py);
  A(fpr) = fpr * N_benign + N_attack: alert volume, a conservative upper bound on attack alerts (the
           same A is used in the attacker's detection probability and in the defender's alert cost);
  p(a) = r(a) * min(1, B / A): probability that an attempt is detected and investigated;
  attacker payoff U(a) = (1 - p) * e(a) * V - p * P - c(a), where e(a) is the efficacy of the action
           (1 when GameParams.efficacy is False); commodity attackers only choose reuse or abstain;
  c(reuse) = 0, c(mutate(G, m)) = lam * kM * |G| * log2(2 m), c(novel) = lam * kN;
  defender loss (per day) = N_attack * sum_t w_t * attacked_t * (1 - p_t) * L + w * A + cB * B.

Efficacy e(family, G, m) (attacker gain when undetected): timing mutation of DoS, DDoS, BruteForce or
PortScan flows multiplies the gain by 1 / m (slowing the attack costs effectiveness); every other
action has e = 1. The defender's breach loss L is not scaled by efficacy (a stated choice).

Attacker types: commodity with weight pi (actions reuse, abstain); capable with weight 1 - pi (reuse,
mutate for every measured budget, novel, abstain). Novel: 'worst' uses the unseen family with the
lowest recall (the attacker picks it), 'average' uses the mean recall over unseen families.
Ties: the attacker breaks ties in the defender's favour (strong Stackelberg): abstain if tied with an
attack, otherwise the attack with the smallest defender cost.
The defender enumerates configurations d = (model, fpr, B) and minimises the expected loss.
Model comparisons treat losses within LOSS_TIE_REL (relative) as tied.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np

ABSTAIN = "abstain"
NO_ACTION = "none"
LOSS_TIE_REL = 0.01
EFFICACY_TIMING_FAMILIES = ("DoS", "DDoS", "BruteForce", "PortScan")
ATTACKER_QUERIES = ("score", "label")


@dataclass(frozen=True)
class GameParams:
    """Reference parameter values.

    ILLUSTRATIVE: none of these values is estimated from data or taken from a source that fixes the
    scale. The conclusions rest on the sensitivity analysis (X3) over log-grids around these values,
    not on the point values. Units are arbitrary currency per day (V, P, L, w, cB) and flows per day
    (N_benign, N_attack).
    """

    V: float = 1000.0          # attacker gain per undetected attempt
    P: float = 2000.0          # attacker loss per detected attempt
    lam: float = 1.0           # AI uplift factor (scales mutation and novelty costs)
    kM: float = 100.0          # mutation cost scale per (group x log2(2 m))
    kN: float = 3000.0         # novelty cost scale
    pi: float = 0.5            # commodity attacker fraction
    N_benign: float = 1.0e6    # benign flows per day
    N_attack: float = 50.0     # attack attempts per day when every type attacks
    L: float = 1000.0          # defender loss per undetected attempt
    w: float = 0.5             # analyst cost per alert
    cB: float = 2.0            # cost per unit of analyst capacity per day
    novel_mode: str = "worst"  # 'worst' (lowest-recall unseen family) or 'average'
    efficacy: bool = True      # attacker efficacy of mutation (see module doc)
    attacker_query: str = "score"   # 'score' or 'label': which E4 query mode the capable attacker has

    def __post_init__(self):
        if self.attacker_query not in ATTACKER_QUERIES:
            raise ValueError(f"attacker_query must be one of {ATTACKER_QUERIES}")
        if self.novel_mode not in ("worst", "average"):
            raise ValueError(f"unknown novel_mode {self.novel_mode!r}")


def efficacy_factor(family: str, groups: Sequence[str], mult: float) -> float:
    """Efficacy e(family, groups, m) of a mutation budget (module doc)."""
    if "timing" in groups and family in EFFICACY_TIMING_FAMILIES:
        return 1.0 / float(mult)
    return 1.0


@dataclass(frozen=True)
class RecallTable:
    """Measured recall of every action for one (dataset, model, FPR) cell.

    families: family names (the same list for reuse, novel and mutate);
    reuse[i]: recall of reuse(family i); novel[i]: recall of novel(family i);
    mutate[i, k]: recall of mutate(family i, budget k), shape (F, K) with K = 0 when not measured;
    budget_units[k] = |G| * log2(2 m) of budget k; budget_labels[k] names it;
    budget_groups[k], budget_mults[k]: groups and multiplier of budget k (efficacy). When empty,
    every mutation has efficacy 1.
    fpr_real: realised FPR on benign test rows at the threshold (NaN: use the nominal FPR). The alert
    volume A = fpr_real N_benign + N_attack uses it (design section 3.2).
    """

    families: tuple[str, ...]
    reuse: np.ndarray
    novel: np.ndarray
    mutate: np.ndarray
    budget_units: np.ndarray
    budget_labels: tuple[str, ...]
    budget_groups: tuple = ()
    budget_mults: tuple = ()
    fpr_real: float = float("nan")

    def __post_init__(self):
        F = len(self.families)
        object.__setattr__(self, "reuse", np.asarray(self.reuse, dtype=float))
        object.__setattr__(self, "novel", np.asarray(self.novel, dtype=float))
        object.__setattr__(self, "mutate", np.asarray(self.mutate, dtype=float).reshape(F, -1))
        object.__setattr__(self, "budget_units", np.asarray(self.budget_units, dtype=float))
        if self.reuse.shape != (F,) or self.novel.shape != (F,):
            raise ValueError("reuse and novel must have one entry per family")
        K = self.mutate.shape[1]
        if self.budget_units.shape != (K,) or len(self.budget_labels) != K:
            raise ValueError("budget arrays must match the mutate columns")
        if self.budget_groups and len(self.budget_groups) != K:
            raise ValueError("budget_groups must match the mutate columns")
        if self.budget_mults and len(self.budget_mults) != K:
            raise ValueError("budget_mults must match the mutate columns")

    @property
    def has_mutation(self) -> bool:
        return self.mutate.shape[1] > 0


@dataclass(frozen=True)
class ActionSet:
    """Actions of one attacker type with recall, cost units, labels and efficacy (NaN recall removed)."""

    labels: tuple[str, ...]
    recall: np.ndarray
    mut_units: np.ndarray   # budget units for mutation actions, 0 otherwise
    is_novel: np.ndarray    # bool
    eff: np.ndarray         # efficacy of each action (1 for reuse and novel)

    def cost(self, params: GameParams) -> np.ndarray:
        return params.lam * (params.kM * self.mut_units + params.kN * self.is_novel)


def action_set(table: RecallTable, novel_mode: str, capable: bool, efficacy: bool = True) -> ActionSet:
    labels, rec, units, novel, eff = [], [], [], [], []
    for i, f in enumerate(table.families):
        labels.append(f"reuse({f})")
        rec.append(table.reuse[i])
        units.append(0.0)
        novel.append(False)
        eff.append(1.0)
    if capable:
        for i, f in enumerate(table.families):
            for k, b in enumerate(table.budget_labels):
                labels.append(f"mutate({f},{b})")
                rec.append(table.mutate[i, k])
                units.append(table.budget_units[k])
                novel.append(False)
                e = 1.0
                if efficacy and table.budget_groups:
                    e = efficacy_factor(f, table.budget_groups[k], table.budget_mults[k])
                eff.append(e)
        nov = table.novel[~np.isnan(table.novel)]
        if len(nov):
            if novel_mode == "worst":
                i = int(np.nanargmin(table.novel))
                labels.append(f"novel({table.families[i]})")
                rec.append(table.novel[i])
            elif novel_mode == "average":
                labels.append("novel(average)")
                rec.append(float(nov.mean()))
            else:
                raise ValueError(f"unknown novel_mode {novel_mode!r}")
            units.append(0.0)
            novel.append(True)
            eff.append(1.0)
    rec = np.asarray(rec, dtype=float)
    keep = ~np.isnan(rec)
    return ActionSet(
        labels=tuple(l for l, k in zip(labels, keep) if k),
        recall=rec[keep],
        mut_units=np.asarray(units, dtype=float)[keep],
        is_novel=np.asarray(novel, dtype=bool)[keep],
        eff=np.asarray(eff, dtype=float)[keep],
    )


@dataclass(frozen=True)
class Response:
    """Best response of one attacker type."""

    label: str
    attacked: bool
    recall: float
    p: float
    utility: float


def alert_volume(fpr: float, params: GameParams) -> float:
    """Alert volume A = fpr * N_benign + N_attack (conservative: every attempt alerts)."""
    return float(fpr) * params.N_benign + params.N_attack


def effective_fpr(table: "RecallTable", fpr: float) -> float:
    """Realised benign FPR of the table when measured, else the nominal FPR."""
    return float(table.fpr_real) if math.isfinite(table.fpr_real) else float(fpr)


def best_response(actions: ActionSet, B: float, fpr: float, params: GameParams) -> Response:
    if len(actions.recall) == 0:
        return Response(NO_ACTION, False, 0.0, 0.0, 0.0)
    r = actions.recall
    A = alert_volume(fpr, params)
    share = min(1.0, B / A) if A > 0 else 1.0
    p = r * share
    U = (1.0 - p) * params.V * actions.eff - p * params.P - actions.cost(params)
    best = float(U.max())
    tol = 1e-9 * max(1.0, abs(best))
    if best < -tol:
        return Response(ABSTAIN, False, 0.0, 0.0, 0.0)
    if abs(best) <= tol:
        # Tied with abstaining (utility 0): the defender's loss is lowest when the attacker abstains.
        return Response(ABSTAIN, False, 0.0, 0.0, 0.0)
    defender_cost = (1.0 - p) * params.L
    tied = np.flatnonzero(U >= best - tol)
    j = int(tied[np.argmin(defender_cost[tied])])
    return Response(actions.labels[j], True, float(r[j]), float(p[j]), float(U[j]))


@dataclass(frozen=True)
class Outcome:
    model: str
    fpr: float
    B: float
    loss: float
    p_eq: float
    alerts: float
    capable: Response
    commodity: Response
    attack_loss: float
    alert_cost: float
    capacity_cost: float


def capacity_cost(B: float, cB: float) -> float:
    """Analyst capacity cost. Zero when cB = 0 (even for B = inf); inf for B = inf otherwise."""
    return 0.0 if cB == 0.0 else cB * B


def evaluate(table: RecallTable, model: str, fpr: float, B: float, params: GameParams,
             capable_set: ActionSet | None = None, commodity_set: ActionSet | None = None) -> Outcome:
    """Equilibrium of the follower stage for one defender configuration d = (model, fpr, B)."""
    cap = capable_set if capable_set is not None else action_set(table, params.novel_mode, True,
                                                                 params.efficacy)
    com = commodity_set if commodity_set is not None else action_set(table, params.novel_mode, False,
                                                                     params.efficacy)
    f_eff = effective_fpr(table, fpr)
    rk = best_response(cap, B, f_eff, params)
    rc = best_response(com, B, f_eff, params)
    pi = params.pi
    ac = pi * (1.0 if rc.attacked else 0.0)
    ak = (1.0 - pi) * (1.0 if rk.attacked else 0.0)
    A = alert_volume(f_eff, params)
    attack_loss = params.N_attack * (ac * (1.0 - rc.p) + ak * (1.0 - rk.p)) * params.L
    alert_cost = params.w * A
    cap_cost = capacity_cost(B, params.cB)
    loss = attack_loss + alert_cost + cap_cost
    denom = ac + ak
    p_eq = (ac * rc.p + ak * rk.p) / denom if denom > 0 else float("nan")
    return Outcome(model=model, fpr=float(fpr), B=float(B), loss=float(loss), p_eq=float(p_eq),
                   alerts=float(A), capable=rk, commodity=rc, attack_loss=float(attack_loss),
                   alert_cost=float(alert_cost), capacity_cost=float(cap_cost))


def feasible(table: RecallTable) -> bool:
    """A configuration is available to the defender only if its threshold is attainable."""
    if not (np.isfinite(table.reuse).all() and np.isfinite(table.novel).all()):
        return False
    return not (table.has_mutation and not np.isfinite(table.mutate).all())


def enumerate_configs(tables: Mapping[str, Mapping[float, RecallTable]], params: GameParams,
                      B_grid: Sequence[float], cache: dict | None = None) -> list[Outcome]:
    """Outcome of every feasible defender configuration (model, fpr, B).

    ``cache`` (optional, keyed by (model, fpr)) holds the action sets; they depend on the table and
    on efficacy and novel_mode only, so a sweep that varies other parameters can reuse them.
    """
    out = []
    for model, by_fpr in tables.items():
        for fpr, table in by_fpr.items():
            if not feasible(table):
                continue
            key = (model, fpr)
            if cache is not None and key in cache:
                cap, com = cache[key]
            else:
                cap = action_set(table, params.novel_mode, True, params.efficacy)
                com = action_set(table, params.novel_mode, False, params.efficacy)
                if cache is not None:
                    cache[key] = (cap, com)
            for B in B_grid:
                out.append(evaluate(table, model, fpr, B, params, cap, com))
    return out


def solve(tables: Mapping[str, Mapping[float, RecallTable]], params: GameParams,
          B_grid: Sequence[float]) -> tuple[Outcome, list[Outcome]]:
    """Strong Stackelberg equilibrium by enumeration (scalar reference; the sweeps use ``solve_stack``).

    Exact ties in loss are not broken by enumeration order. Among them the representative is the one with
    the least analyst capacity, then the lowest FPR, then the model name (a fixed key, not the position in
    ``tables``). Use ``tied_models`` for the whole set of models whose loss is within LOSS_TIE_REL.
    """
    outs = enumerate_configs(tables, params, B_grid)
    if not outs:
        raise ValueError("no feasible defender configuration")
    finite = [o for o in outs if math.isfinite(o.loss)]
    if not finite:
        raise ValueError("no finite defender loss")
    best_loss = min(o.loss for o in finite)
    ties = [o for o in finite if o.loss <= best_loss + 1e-9 * max(1.0, abs(best_loss))]
    best = min(ties, key=lambda o: (o.B, o.fpr, o.model))
    return best, outs


def tied_models(outs: Sequence[Outcome], rel: float = LOSS_TIE_REL) -> frozenset[str]:
    """Models whose best (lowest-loss) configuration is within ``rel`` of the overall lowest loss."""
    per = {}
    for o in outs:
        if math.isfinite(o.loss):
            per[o.model] = min(per.get(o.model, math.inf), o.loss)
    return frozenset(tied_best(per, rel))


def tied_best(losses: Mapping[str, float], rel: float = LOSS_TIE_REL) -> set[str]:
    """Models whose loss is within ``rel`` (relative) of the lowest loss."""
    finite = {m: v for m, v in losses.items() if math.isfinite(v)}
    if not finite:
        return set()
    best = min(finite.values())
    tol = rel * abs(best)
    return {m for m, v in finite.items() if v <= best + tol}


def tied_ranks(values: Sequence[float], rel: float = LOSS_TIE_REL) -> np.ndarray:
    """Competition ranks (1 = lowest) where values within ``rel`` of their group's lowest member tie."""
    v = np.asarray(values, dtype=float)
    order = np.argsort(v, kind="stable")
    ranks = np.empty(len(v))
    start_val, start_pos = None, 0
    for pos, i in enumerate(order):
        if start_val is None or v[i] > start_val + rel * abs(start_val):
            start_val, start_pos = v[i], pos
        ranks[i] = start_pos + 1
    return ranks


def min_recall_capable(table: RecallTable, novel_mode: str = "worst") -> float:
    """Minimum recall over all capable attacker actions (reuse, mutate, novel). Test helper."""
    acts = action_set(table, novel_mode, True)
    return float(acts.recall.min())


# ---------------------------------------------------------------------------------------------------------
# Vectorised solver (the sweeps). Same model as the scalar reference above; tested against it.
# ---------------------------------------------------------------------------------------------------------

KIND_REUSE, KIND_MUTATE, KIND_NOVEL = "reuse", "mutate", "novel"


@dataclass(frozen=True)
class Stack:
    """T measured tables (model, nominal FPR, [seed]) on one shared action layout.

    Layout of the capable actions (nA = F + F*K + 1): reuse(f) for each family, then mutate(f, b) family-major,
    then the novel action (lowest-recall unseen family, or the mean). Commodity attackers use the reuse
    entries only. ``avail`` is False for actions a table does not have (mutation of a model without E4 rows).
    """

    models: tuple[str, ...]
    fprs: np.ndarray          # (T,) nominal FPR
    fpr_real: np.ndarray      # (T,) realised benign FPR (nominal when not measured)
    feasible: np.ndarray      # (T,) bool
    rc: np.ndarray            # (T, nA) recall of every capable action
    avail: np.ndarray         # (T, nA) bool
    mean_reuse: np.ndarray    # (T,) mean reuse recall over families (indicator a)
    units: np.ndarray         # (nA,) mutation cost units
    nov: np.ndarray           # (nA,) novel flag
    is_reuse: np.ndarray      # (nA,) reuse flag
    kind: np.ndarray          # (nA,) 'reuse' / 'mutate' / 'novel'
    eff_base: np.ndarray      # (nA,) efficacy factor (1 when efficacy is off)
    families: tuple[str, ...]
    budget_labels: tuple[str, ...]
    B: np.ndarray             # (nB,) analyst capacity grid (ascending; inf last)


def stack_tables(tables: Mapping[str, Mapping[float, RecallTable]], params: GameParams,
                 B_grid: Sequence[float]) -> Stack:
    """Stack RecallTables of one dataset (all models and FPRs, one seed or the seed mean)."""
    rows = [(m, f, t) for m, by in tables.items() for f, t in by.items()]
    if not rows:
        raise ValueError("no tables")
    fams = rows[0][2].families
    labels = rows[0][2].budget_labels
    F = len(fams)
    K = len(labels)
    nA = F + F * K + 1
    T = len(rows)
    rc = np.zeros((T, nA))
    avail = np.ones((T, nA), dtype=bool)
    feas = np.zeros(T, dtype=bool)
    fprs = np.zeros(T)
    fpr_real = np.zeros(T)
    mean_reuse = np.zeros(T)
    units = np.zeros(nA)
    nov = np.zeros(nA, dtype=bool)
    is_reuse = np.zeros(nA, dtype=bool)
    kind = np.array([KIND_REUSE] * F + [KIND_MUTATE] * (F * K) + [KIND_NOVEL], dtype=object)
    eff_base = np.ones(nA)
    is_reuse[:F] = True
    for i in range(F * K):
        units[F + i] = rows[0][2].budget_units[i % K] if K else 0.0
    nov[-1] = True
    if rows[0][2].budget_groups and params.efficacy:
        for i in range(F * K):
            fam, k = fams[i // K], i % K
            eff_base[F + i] = efficacy_factor(fam, rows[0][2].budget_groups[k], rows[0][2].budget_mults[k])
    for t, (m, f, tb) in enumerate(rows):
        if tb.families != fams or tb.budget_labels != labels:
            raise ValueError("tables must share families and budgets")
        fprs[t] = f
        fpr_real[t] = effective_fpr(tb, f)
        mean_reuse[t] = float(np.nanmean(tb.reuse)) if np.isfinite(tb.reuse).any() else float("nan")
        novel_recall = float(np.nanmin(tb.novel)) if np.isfinite(tb.novel).any() else float("nan")
        mut = tb.mutate.reshape(F, K)
        finite_mut = np.isfinite(mut).all() if K else True
        feas[t] = bool(np.isfinite(tb.reuse).all() and np.isfinite(tb.novel).all() and finite_mut)
        rc[t, :F] = tb.reuse
        if K:
            rc[t, F:F + F * K] = mut.reshape(-1)
            avail[t, F:F + F * K] = tb.has_mutation
        rc[t, -1] = novel_recall
    # Novel action: 'worst' (lowest unseen family) or 'average' (mean over unseen families).
    if params.novel_mode == "average":
        for t, (m, f, tb) in enumerate(rows):
            nv = tb.novel[np.isfinite(tb.novel)]
            rc[t, -1] = float(nv.mean()) if len(nv) else float("nan")
    rc = np.where(np.isfinite(rc), rc, 0.0)
    B = np.array(list(B_grid), dtype=float)
    return Stack(models=tuple(m for m, _, _ in rows), fprs=fprs, fpr_real=fpr_real, feasible=feas,
                 rc=rc, avail=avail, mean_reuse=mean_reuse, units=units, nov=nov, is_reuse=is_reuse,
                 kind=kind, eff_base=eff_base, families=tuple(fams), budget_labels=tuple(labels), B=B)


def share_tensor(S: Stack, p: GameParams) -> np.ndarray:
    """Detection of every capable action at every table and B: pm[t, g, j] = r[t, j] * min(1, B_g / A_t).

    Independent of lam and of the costs, so the two lam values of one sample share it (see solve_stack).
    """
    A = S.fpr_real * p.N_benign + p.N_attack                       # (T,)
    with np.errstate(divide="ignore", invalid="ignore"):
        share = np.minimum(1.0, S.B[None, :] / A[:, None])        # (T, nB); B = inf gives 1
    return S.rc[:, None, :] * share[:, :, None]


def solve_stack(S: Stack, p: GameParams, pm: np.ndarray | None = None) -> dict:
    """Follower best responses and defender loss for every table and every B of the grid.

    Returns arrays of shape (T, nB): loss, p_eq (NaN when nobody attacks), cap_att, com_att (bool),
    cap_p, com_p (detection of the chosen action), cap_j (index of the capable action).
    Ties: an attacker abstains when its best utility is at most 0 (tolerance 1e-9); among attacker-tied
    actions it chooses the one with the least defender loss, which is the highest detection because the
    defender's loss from an action, (1 - p) L, falls in p when L > 0 (strong Stackelberg).
    """
    if pm is None:
        pm = share_tensor(S, p)
    c = p.lam * (p.kM * S.units + p.kN * S.nov)                   # (nA,)
    a = p.V * S.eff_base - c                                      # U = a - pm * b
    b = p.V * S.eff_base + p.P
    U = a - pm * b
    full = bool(S.avail.all())
    nF = int(S.is_reuse.sum())                                    # reuse actions come first in the layout
    out = {}
    for name, idx in (("cap", None), ("com", nF)):
        Uc = U if idx is None else U[:, :, :idx]
        pc = pm if idx is None else pm[:, :, :idx]
        if idx is None and not full:
            Uc = np.where(S.avail[:, None, :], Uc, -np.inf)
        best = Uc.max(axis=2)
        tol = 1e-9 * np.maximum(1.0, np.abs(best))
        attacked = best > tol
        tied = Uc >= (best - tol)[:, :, None]
        j = np.where(tied, pc, -np.inf).argmax(axis=2)
        p_sel = np.take_along_axis(pc, j[:, :, None], axis=2)[:, :, 0]
        out[name + "_att"] = attacked
        out[name + "_p"] = np.where(attacked, p_sel, 0.0)
        if name == "cap":
            out["cap_j"] = np.where(attacked, j, -1)
    ac = p.pi * out["com_att"]
    ak = (1.0 - p.pi) * out["cap_att"]
    A = S.fpr_real * p.N_benign + p.N_attack
    attack_loss = p.N_attack * p.L * (ac * (1.0 - out["com_p"]) + ak * (1.0 - out["cap_p"]))
    with np.errstate(invalid="ignore"):
        capc = np.where(p.cB == 0.0, 0.0, p.cB * S.B)[None, :]
    loss = attack_loss + p.w * A[:, None] + capc
    loss = np.where(S.feasible[:, None], loss, np.inf)
    denom = ac + ak
    out["p_eq"] = np.where(denom > 0, (ac * out["com_p"] + ak * out["cap_p"]) / np.where(denom > 0, denom, 1.0),
                           np.nan)
    out["loss"] = loss
    return out


def kind_of(S: Stack, j: int) -> str:
    """Class of a capable action index: reuse, mutate, novel, or abstain for -1."""
    return ABSTAIN if j < 0 else str(S.kind[j])


def equilibrium(S: Stack, p: GameParams, out: dict | None = None, rel: float = LOSS_TIE_REL) -> dict:
    """Strong Stackelberg equilibrium of one stack: the defender's (table, B) with least loss.

    Returns the representative configuration, the loss-tied model set (within ``rel`` of the lowest loss),
    per-model optima, and whether the optimum sits on an edge of the FPR or B grid.
    """
    if out is None:
        out = solve_stack(S, p)
    loss = out["loss"]
    Bi = np.argmin(loss, axis=1)                     # least capacity among exact ties (B ascending)
    tl = loss[np.arange(len(loss)), Bi]
    per_model: dict[str, dict] = {}
    for t, m in enumerate(S.models):
        if not np.isfinite(tl[t]):
            continue
        cur = per_model.get(m)
        key = (tl[t], S.fprs[t])
        if cur is None or key < (cur["loss"], cur["fpr"]):
            per_model[m] = {"loss": float(tl[t]), "fpr": float(S.fprs[t]), "t": t, "g": int(Bi[t])}
    if not per_model:
        return {"loss": float("nan"), "model": None}
    eq_loss = min(v["loss"] for v in per_model.values())
    tied = frozenset(m for m, v in per_model.items() if v["loss"] <= eq_loss + rel * abs(eq_loss))
    rep_model = min((m for m in per_model if per_model[m]["loss"] == eq_loss))
    r = per_model[rep_model]
    t, g = r["t"], r["g"]
    n_tied_cfg = int(np.sum(loss <= eq_loss * (1.0 + 1e-9) + 1e-12))
    B_val = float(S.B[g])
    B = S.B
    edge_B = bool(g == 0 or g == len(B) - 1 or math.isinf(B_val))
    edge_fpr = bool(S.fprs[t] in (min(S.fprs), max(S.fprs)))
    cap_j = int(out["cap_j"][t, g])
    class_cap = kind_of(S, cap_j)
    cap_rc = S.rc[t, cap_j] if cap_j >= 0 else float("nan")
    return {
        "loss": eq_loss, "model": rep_model, "fpr": r["fpr"], "B": B_val, "t": int(t), "g": int(g),
        "p_eq": float(out["p_eq"][t, g]), "capable_class": class_cap,
        "capable_recall": float(cap_rc), "mean_reuse": float(S.mean_reuse[t]),
        "attacked": bool(out["cap_att"][t, g]),
        "capable_j": cap_j, "tied_models": tied, "model_loss": {m: v["loss"] for m, v in per_model.items()},
        "model_fpr": {m: v["fpr"] for m, v in per_model.items()},
        "model_t": {m: v["t"] for m, v in per_model.items()}, "model_g": {m: v["g"] for m, v in per_model.items()},
        "n_tied_configs": n_tied_cfg, "edge_B": edge_B, "edge_fpr": edge_fpr,
        "loss_matrix": loss,
    }


def model_detail(S: Stack, out: dict, eq: dict, m: str) -> dict:
    """Per-model optimum: loss, detection, chosen class and the minimum capable recall of its table."""
    t, g = eq["model_t"][m], eq["model_g"][m]
    j = int(out["cap_j"][t, g])
    avail = S.avail[t]
    return {"loss": float(out["loss"][t, g]), "fpr": float(S.fprs[t]), "B": float(S.B[g]),
            "p_eq": float(out["p_eq"][t, g]), "class": kind_of(S, j),
            "min_capable_recall": float(S.rc[t][avail].min()) if avail.any() else float("nan"),
            "mean_reuse": float(S.mean_reuse[t])}
