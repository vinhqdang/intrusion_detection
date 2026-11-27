"""Game as a cost lens on the robustness results (design/design_robustness.md, section 6).

Changes relative to idsbench.econ.game / sweep (the round-3 solver is unchanged):
  * Analyst capacity B is parametrised by the detection share x = min(1, B / A) (so p = r x). Per table the
    candidates are (a) a geometric grid in x with step 0.5% from 1 down to 0.01 (B = x A) and (b) the closed-form
    deterrence point x* = max over actions of max(0, alpha_a) / beta_a, where alpha_a = V e_a - c_a and
    beta_a = r_a (V e_a + P). At x >= x* every attacker type abstains, so x* is the smallest deterring capacity.
    Unit-tested against a dense grid (tests/test_robust_game.py).
  * Recall tables: the detection input of a mutate action is the worst case over generators (G1, G2) and attackers.
  * Mutated benign traffic enters the alert volume: A = fpr_real (1 - rho) N + fpr_mut rho N + N_attack, with
    fpr_mut the random-budget mutated-benign FPR of the threshold (worst generator). rho in [0, 0.2] is swept.
  * FPR grid {1e-4, 5e-4, 1e-3, 1e-2}; optima on the lower edge (1e-4) and the upper edge (1e-2) are reported
    separately; likewise the B edges (x = 0.01 and x = 1).
  * Sobol: the same fixed seed pair for every Saltelli row (plus a second pair), reported separately. Outputs whose
    first-order indices sum to less than 0.1 are labelled noise-floor. Indicator (d): the equilibrium defender model
    changes when rho goes from 0 to 0.1.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np
import pandas as pd
from SALib.analyze import sobol as sobol_analyze
from SALib.sample import sobol as sobol_sample

from idsbench.econ.game import efficacy_factor
from idsbench.econ.sweep import X3_RANGES, auroc_tie_table, bootstrap_ci, kendall, rank_with_ties, loss_tie_fn
from idsbench.robust.defenders import E4_MODELS, MODELS
from idsbench.robust.evaluate import FPRS, ATTACKER_MIN_TEST, budget_label
from idsbench.robust.gen2 import BUDGETS

LOSS_TIE_REL = 0.01
X_STEP = 1.005
X_MIN = 0.01
XG = np.array([X_STEP ** -k for k in range(int(math.ceil(math.log(1 / X_MIN) / math.log(X_STEP))) + 1)])
LAM_LOW = 0.05
RHO_RANGE = (0.0, 0.2)
SOBOL_SEED = 20261127
PAIR_SEED = 20261128
EFFICACY_FAMILIES = ("DoS", "DDoS", "BruteForce", "PortScan")
A_GAP = 0.2
REGRET_REL = 0.01
REUSE, MUTATE, NOVEL, ABSTAIN = "reuse", "mutate", "novel", "abstain"


@dataclass(frozen=True)
class RParams:
    """Reference parameters (illustrative, as in econ.game.GameParams) plus the mutated-benign share rho."""

    V: float = 1000.0
    P: float = 2000.0
    lam: float = 1.0
    kM: float = 100.0
    kN: float = 3000.0
    pi: float = 0.5
    N_benign: float = 1.0e6
    N_attack: float = 50.0
    L: float = 1000.0
    w: float = 0.5
    cB: float = 2.0
    efficacy: bool = True
    rho: float = 0.0


@dataclass
class Stack:
    """Measured tables of one (dataset, seed) over (model, FPR) rows, on one action layout.

    Layout of the capable actions (nA = F + F K + 1): reuse(f) per family, mutate(f, b) family-major, then the
    novel action (the unseen family with the lowest recall). Commodity attackers use the reuse entries only.
    """

    rows: list                # (model, fpr) per table
    fams: tuple
    labels: tuple
    fpr_real: np.ndarray      # (T,)
    fpr_mut: np.ndarray       # (T,)
    feasible: np.ndarray      # (T,) bool
    rc: np.ndarray            # (T, nA) recall of every capable action
    avail: np.ndarray         # (T, nA) bool
    mean_reuse: np.ndarray    # (T,)
    units: np.ndarray         # (nA,)
    nov: np.ndarray           # (nA,) bool
    kind: np.ndarray          # (nA,) object
    eff: np.ndarray           # (nA,) efficacy factor (1 when efficacy is off)
    F: int


def build_stack(clean: pd.DataFrame, e4: pd.DataFrame, thr: pd.DataFrame, mutben: pd.DataFrame,
                fams: tuple, efficacy: bool, models=MODELS) -> Stack:
    """One seed of one dataset. clean/e4/thr/mutben are the rows of that dataset and seed."""
    F, K = len(fams), len(BUDGETS)
    nA = F + F * K + 1
    units = np.zeros(nA)
    nov = np.zeros(nA, dtype=bool)
    kind = np.array([REUSE] * F + [MUTATE] * (F * K) + [NOVEL], dtype=object)
    eff = np.ones(nA)
    for k, (groups, mult) in enumerate(BUDGETS):
        u = len(groups) * math.log2(2.0 * mult)
        for i in range(F):
            units[F + i * K + k] = u
            if efficacy and "timing" in groups and fams[i] in EFFICACY_FAMILIES:
                eff[F + i * K + k] = efficacy_factor(fams[i], groups, mult)
    nov[-1] = True
    T = len(models) * len(FPRS)
    rc = np.zeros((T, nA))
    avail = np.zeros((T, nA), dtype=bool)
    feas = np.zeros(T, dtype=bool)
    fr = np.zeros(T)
    fm = np.zeros(T)
    mr = np.zeros(T)
    rows = []
    cl_known = clean[clean.kind == "known"]
    cl_novel = clean[clean.kind == "novel"]
    for t, (m, fpr) in enumerate(((m, f) for m in models for f in FPRS)):
        rows.append((m, fpr))
        reuse = np.array([_pick(cl_known, m, fpr, f) for f in fams])
        novel = np.array([_pick(cl_novel, m, fpr, f) for f in fams])
        if m in ("adv_naive_G1", "adv_sym_G1") and np.isnan(novel).all():
            novel = np.array([_pick(cl_novel, "adv_sym_G1G2", fpr, f) for f in fams])   # reduced LOFO protocol
        mut = np.full((F, K), np.nan)
        if m in E4_MODELS:
            e = e4[(e4.model == m) & np.isclose(e4.fpr, fpr)]
            w = e.groupby(["family", "generator", "budget", "attacker"]).recall_after.min().reset_index()
            w = w.groupby(["family", "budget"]).recall_after.min()
            for i, f in enumerate(fams):
                for k, (groups, mult) in enumerate(BUDGETS):
                    mut[i, k] = w.get((f, budget_label(groups, mult)), np.nan)
        novel_worst = np.nanmin(novel) if np.isfinite(novel).any() else np.nan
        rc[t, :F] = reuse
        rc[t, F:F + F * K] = mut.reshape(-1)
        rc[t, -1] = novel_worst
        if m in E4_MODELS:
            avail[t, F:F + F * K] = True
        avail[t, :F] = True
        avail[t, -1] = True
        ok = np.isfinite(reuse).all() and np.isfinite(novel_worst)
        if m in E4_MODELS:
            ok = ok and np.isfinite(mut).all()
        feas[t] = bool(ok)
        th = thr[(thr.model == m) & np.isclose(thr.fpr, fpr)]
        fr[t] = float(th.fpr_test_realised.iloc[0]) if len(th) else fpr
        mb = mutben[(mutben.model == m) & np.isclose(mutben.fpr, fpr) & (mutben["mode"] == "random")]
        fm[t] = float(mb.groupby("generator").fpr_mut.first().max()) if len(mb) else fr[t]
        mr[t] = float(np.nanmean(reuse)) if np.isfinite(reuse).any() else float("nan")
    rc = np.where(np.isfinite(rc), rc, 0.0)
    return Stack(rows=rows, fams=tuple(fams), labels=tuple(budget_label(g, m) for g, m in BUDGETS),
                 fpr_real=fr, fpr_mut=fm, feasible=feas, rc=rc, avail=avail, mean_reuse=mr, units=units,
                 nov=nov, kind=kind, eff=eff, F=F)


def _pick(df: pd.DataFrame, m: str, fpr: float, f: str) -> float:
    s = df[(df.model == m) & np.isclose(df.fpr, fpr) & (df.family == f)].recall
    return float(s.iloc[0]) if len(s) else float("nan")


# ----------------------------------------------------------------------------- solver
def _alpha_beta(S: Stack, p: RParams):
    ev = p.V * S.eff
    c = p.lam * (p.kM * S.units + p.kN * S.nov)
    alpha = ev - c
    beta = S.rc * (ev + p.P)[None, :]
    return alpha, beta


def deterrence_x(S: Stack, p: RParams) -> np.ndarray:
    """Closed-form smallest detection share x* that deters every attacker action (per table); inf when none."""
    alpha, beta = _alpha_beta(S, p)
    a = np.maximum(alpha, 0.0)[None, :]
    with np.errstate(divide="ignore", invalid="ignore"):
        req = np.where(beta > 0, a / np.where(beta > 0, beta, 1.0), np.where(a > 0, np.inf, 0.0))
    req = np.where(S.avail, req, 0.0)
    xs = req.max(axis=1)
    return np.where(xs <= 1.0, xs, np.inf)


def responses(S: Stack, p: RParams, XC: np.ndarray, closed_last: bool = True) -> dict:
    """Follower best responses at candidate detection shares XC (T, nC). rho does not enter (p = r x)."""
    alpha, beta = _alpha_beta(S, p)
    F = S.F
    U = alpha[None, None, :] - beta[:, None, :] * XC[:, :, None]
    U = np.where(S.avail[:, None, :], U, -np.inf)
    best = U.max(axis=2)
    tol = 1e-9 * np.maximum(1.0, np.abs(best))
    att_cap = best > tol
    rcT = S.rc[:, None, :]
    tied = U >= (best - tol)[:, :, None]
    cand = np.where(tied, rcT, -np.inf)
    p_cap = np.where(att_cap, cand.max(axis=2) * XC, 0.0)
    cap_j = np.where(att_cap, cand.argmax(axis=2), -1)
    Uc = U[:, :, :F]
    bc = Uc.max(axis=2)
    att_com = bc > (1e-9 * np.maximum(1.0, np.abs(bc)))
    tiedc = Uc >= (bc - 1e-9 * np.maximum(1.0, np.abs(bc)))[:, :, None]
    p_com = np.where(att_com, np.where(tiedc, rcT[:, :, :F], -np.inf).max(axis=2) * XC, 0.0)
    valid = np.ones(XC.shape, dtype=bool)
    if closed_last:
        valid[:, -1] = np.isfinite(deterrence_x(S, p))
    return {"att_cap": att_cap, "att_com": att_com, "p_cap": p_cap, "p_com": p_com, "cap_j": cap_j,
            "XC": XC, "valid": valid}


def attack_part(R: dict, p: RParams) -> np.ndarray:
    ac = p.pi * R["att_com"]
    ak = (1.0 - p.pi) * R["att_cap"]
    return p.N_attack * p.L * (ac * (1.0 - R["p_com"]) + ak * (1.0 - R["p_cap"]))


def alert_volume(S: Stack, p: RParams) -> np.ndarray:
    N = p.N_benign
    return S.fpr_real * (1.0 - p.rho) * N + S.fpr_mut * p.rho * N + p.N_attack


def losses(S: Stack, p: RParams, R: dict, part: np.ndarray) -> np.ndarray:
    A = alert_volume(S, p)
    XC = R["XC"]
    loss = part + (p.w + p.cB * XC) * A[:, None]
    ok = S.feasible[:, None] & R.get("valid", np.ones(XC.shape, bool))
    return np.where(ok, loss, np.inf)


def candidates(S: Stack, p: RParams):
    """Candidate shares per table: the geometric grid plus the closed-form deterrence point (last column).
    A table that cannot be deterred has an infinite x*: its last column is set to 1 here and masked to infinite
    loss in losses()."""
    xs = deterrence_x(S, p)
    xs = np.where(np.isfinite(xs), xs, 1.0)
    XC = np.concatenate([np.broadcast_to(XG, (len(S.rows), len(XG))), xs[:, None]], axis=1)
    return XC


def equilibrium(S: Stack, p: RParams, R: dict | None = None, part: np.ndarray | None = None) -> dict:
    """Strong Stackelberg equilibrium over (model, FPR, capacity) of one stack."""
    if R is None:
        R = responses(S, p, candidates(S, p))
        part = attack_part(R, p)
    L = losses(S, p, R, part)
    T = L.shape[0]
    tl = L.min(axis=1)
    ci = L.argmin(axis=1)
    if not np.isfinite(tl).any():
        return {"loss": float("nan"), "model": None}
    per_model = {}
    for t, (m, f) in enumerate(S.rows):
        if not np.isfinite(tl[t]):
            continue
        key = (tl[t], f)
        if m not in per_model or key < (per_model[m]["loss"], per_model[m]["fpr"]):
            per_model[m] = {"loss": float(tl[t]), "fpr": f, "t": t, "c": int(ci[t])}
    eq = min(v["loss"] for v in per_model.values())
    tied = frozenset(m for m, v in per_model.items() if v["loss"] <= eq + LOSS_TIE_REL * abs(eq))
    rep = min(per_model, key=lambda m: (per_model[m]["loss"], per_model[m]["fpr"], m))
    r = per_model[rep]
    t, c = r["t"], r["c"]
    x = float(R["XC"][t, c])
    A = float(alert_volume(S, p)[t])
    j = int(R["cap_j"][t, c])
    ac = p.pi * R["att_com"][t, c]
    ak = (1 - p.pi) * R["att_cap"][t, c]
    p_eq = float((ac * R["p_com"][t, c] + ak * R["p_cap"][t, c]) / (ac + ak)) if (ac + ak) > 0 else float("nan")
    return {"loss": eq, "model": rep, "fpr": r["fpr"], "x": x, "B": x * A, "A": A,
            "t": int(t), "c": int(c), "closed_form": bool(c == R["XC"].shape[1] - 1),
            "class": ABSTAIN if j < 0 else str(S.kind[j]), "attacked": bool(R["att_cap"][t, c]),
            "capable_recall": float(S.rc[t, j]) if j >= 0 else float("nan"),
            "mean_reuse": float(S.mean_reuse[t]), "p_eq": p_eq,
            "upper_B_edge": bool(x >= 1.0), "lower_B_edge": bool(x <= XG[-1] + 1e-12),
            "lower_fpr_edge": bool(r["fpr"] == min(FPRS)), "upper_fpr_edge": bool(r["fpr"] == max(FPRS)),
            "tied_models": tied, "model_loss": {m: v["loss"] for m, v in per_model.items()}}


def solve(S: Stack, p: RParams) -> dict:
    return equilibrium(S, p)


# ----------------------------------------------------------------------------- reporting
def equilibrium_rows(dataset: str, seed: int, S: Stack, p: RParams, tag: str) -> dict:
    eq = equilibrium(S, p)
    return {"dataset": dataset, "seed": seed, "setting": tag, "eq_model": eq["model"], "eq_fpr": eq["fpr"],
            "eq_x": eq["x"], "eq_B": eq["B"], "eq_A": eq["A"], "eq_loss": eq["loss"], "eq_detection": eq["p_eq"],
            "capable_class": eq["class"], "capable_recall": eq["capable_recall"], "mean_reuse": eq["mean_reuse"],
            "closed_form_optimum": eq["closed_form"], "upper_B_edge": eq["upper_B_edge"],
            "lower_B_edge": eq["lower_B_edge"], "lower_fpr_edge": eq["lower_fpr_edge"],
            "upper_fpr_edge": eq["upper_fpr_edge"], "tied_models": "+".join(sorted(eq["tied_models"])),
            **{f"loss_{m}": eq["model_loss"].get(m, float("nan")) for m in MODELS}}


def sample_indicators(S1: Stack, SL: Stack, p1: RParams, pL: RParams, auc_tied: frozenset) -> dict:
    """Per (sample, seed) indicators (a), (b), (c), (d) at the lam = 1 optimum and the lam = LAM_LOW check."""
    R1 = responses(S1, p1, candidates(S1, p1))
    part1 = attack_part(R1, p1)
    e1 = equilibrium(S1, p1, R1, part1)
    RL = responses(SL, pL, candidates(SL, pL))
    partL = attack_part(RL, pL)
    eL = equilibrium(SL, pL, RL, partL)
    if e1["model"] is None or eL["model"] is None:
        return {"eq_loss": float("nan"), "eq_model": None, "eq_fpr": float("nan"), "eq_x": float("nan"),
                "closed_form": float("nan"), "attacked": float("nan"), "a_mut_nov": float("nan"),
                "a_weak_reuse": float("nan"), "b_auroc_disjoint": float("nan"), "c_regret": float("nan"),
                "d_model_change": float("nan"), "upper_B_edge": float("nan"), "lower_fpr_edge": float("nan"),
                "upper_fpr_edge": float("nan"), "lower_B_edge": float("nan"), "log10_loss": float("nan")}
    t1, c1 = e1["t"], e1["c"]
    loss_low_d1 = float(losses(SL, pL, RL, partL)[t1, c1])
    weak = e1["attacked"] and math.isfinite(e1["mean_reuse"]) and e1["capable_recall"] < e1["mean_reuse"] - A_GAP
    p0 = replace(p1, rho=0.0)
    p01 = replace(p1, rho=0.1)
    e0 = equilibrium(S1, p0, R1, part1)
    e01 = equilibrium(S1, p01, R1, part1)
    return {"eq_loss": e1["loss"], "eq_model": e1["model"], "eq_fpr": e1["fpr"], "eq_x": e1["x"],
            "closed_form": float(e1["closed_form"]), "attacked": float(e1["attacked"]),
            "a_mut_nov": float(weak and e1["class"] in (MUTATE, NOVEL)),
            "a_weak_reuse": float(weak and e1["class"] == REUSE),
            "b_auroc_disjoint": float(len(auc_tied & e1["tied_models"]) == 0),
            "c_regret": float(loss_low_d1 > eL["loss"] * (1.0 + REGRET_REL)),
            "d_model_change": float(e0["model"] != e01["model"]),
            "upper_B_edge": float(e1["upper_B_edge"]), "lower_fpr_edge": float(e1["lower_fpr_edge"]),
            "upper_fpr_edge": float(e1["upper_fpr_edge"]), "lower_B_edge": float(e1["lower_B_edge"]),
            "log10_loss": math.log10(e1["loss"]) if e1["loss"] > 0 else float("nan")}


# ----------------------------------------------------------------------------- Sobol
PARAM_NAMES = list(X3_RANGES) + ["rho"]
OUTPUTS = ("a_mut_nov", "a_weak_reuse", "b_auroc_disjoint", "c_regret", "d_model_change", "log10_loss")


def _problem():
    b = [[math.log10(a), math.log10(c)] for a, c in X3_RANGES.values()] + [list(RHO_RANGE)]
    return {"num_vars": len(PARAM_NAMES), "names": PARAM_NAMES, "bounds": b}


def _sample_params(theta, efficacy: bool) -> tuple[RParams, RParams, RParams]:
    kw = dict(zip(PARAM_NAMES, theta))
    base = dict(V=1000.0, P=1000.0 / kw["V/P"], L=kw["L"], w=kw["w"], kM=kw["kM"], kN=kw["kN"], pi=kw["pi"],
                N_attack=kw["N_attack"], cB=kw["cB"], N_benign=kw["N_benign"], efficacy=efficacy, rho=kw["rho"])
    return RParams(**{**base, "lam": 1.0}), RParams(**{**base, "lam": LAM_LOW}), kw


def seed_pairs(seeds: list[int]) -> tuple[tuple, tuple]:
    rng = np.random.default_rng(PAIR_SEED)
    perm = [int(s) for s in rng.permutation(seeds)]
    p1 = tuple(sorted(perm[:2]))
    p2 = tuple(sorted(perm[2:4])) if len(perm) >= 4 else p1
    return p1, p2


def run_sobol(stacks: dict, pair: tuple, efficacy: bool, n_base: int, auc_tied: frozenset, dataset: str):
    """Sobol design with the same seed pair on every row. Returns (indicator means per output, Sobol table)."""
    problem = _problem()
    theta = sobol_sample.sample(problem, n_base, calc_second_order=False, seed=SOBOL_SEED)
    theta = np.asarray(theta, dtype=float).copy()
    theta[:, :-1] = 10 ** theta[:, :-1]          # log-uniform parameters; rho stays linear
    rows = []
    for i, th in enumerate(theta):
        p1, pL, _ = _sample_params(th, efficacy)
        for s in pair:
            ind = sample_indicators(stacks[s], stacks[s], p1, pL, auc_tied)
            rows.append({"sample": i, "seed": s, **{k: float(v) for k, v in zip(PARAM_NAMES, th)}, **ind})
    df = pd.DataFrame(rows)
    per_sample = df.groupby("sample")
    out = {k: per_sample[k].mean().to_numpy(float) for k in OUTPUTS}
    sob = []
    for name, Y in out.items():
        if np.nanstd(Y) == 0 or not np.isfinite(Y).all():
            sob += [{"dataset": dataset, "efficacy": efficacy, "pair": str(pair), "output": name, "parameter": q,
                     "S1": float("nan"), "ST": float("nan"), "S1_conf": float("nan"), "ST_conf": float("nan"),
                     "status": "constant"} for q in PARAM_NAMES]
            continue
        r = sobol_analyze.analyze(problem, Y, calc_second_order=False, num_resamples=100, conf_level=0.95,
                                  print_to_console=False, seed=SOBOL_SEED)
        s1sum = float(np.sum(r["S1"]))
        status = "noise-floor" if s1sum < 0.1 else "kept"
        for j, q in enumerate(PARAM_NAMES):
            sob.append({"dataset": dataset, "efficacy": efficacy, "pair": str(pair), "output": name,
                        "parameter": q, "S1": float(r["S1"][j]), "S1_conf": float(r["S1_conf"][j]),
                        "ST": float(r["ST"][j]), "ST_conf": float(r["ST_conf"][j]), "S1_sum": s1sum,
                        "status": status})
    return df, pd.DataFrame(sob)


# ----------------------------------------------------------------------------- driver
def run_game(robust_dir: Path, out: Path, datasets=("cicids2017", "cicids2018"), n_base: int = 128,
             quick: bool = False) -> None:
    out.mkdir(parents=True, exist_ok=True)
    clean = pd.read_csv(robust_dir / "robust_clean.csv")
    thr = pd.read_csv(robust_dir / "robust_thresholds.csv")
    mutben = pd.read_csv(robust_dir / "robust_mutben.csv")
    e4 = pd.read_csv(robust_dir / "robust_e4.csv.gz")
    eq_rows, rho_rows, sob_all, df_all, meta = [], [], [], [], {}
    for ds in datasets:
        c_ds = clean[clean.dataset == ds]
        seeds = sorted(int(s) for s in c_ds.seed.unique())
        fam_ok = c_ds[(c_ds.kind == "known") & (c_ds.model == "xgb") & np.isclose(c_ds.fpr, 1e-3)]
        fams = tuple(sorted(f for f, g in fam_ok.groupby("family") if g.n_family_test.iloc[0] >= ATTACKER_MIN_TEST))
        # AUROC of each model (mean over families), tie set and rank data.
        auc = (c_ds[c_ds.kind == "known"].groupby(["seed", "model", "family"]).auroc.first().reset_index()
               .groupby(["seed", "model"]).auroc.mean().unstack("model")[list(MODELS)])
        tt = auroc_tie_table(auc)["tie"]
        best = str(auc.mean().idxmax())
        auc_tied = frozenset(m for m in MODELS if tt[(m, best)])
        for eff in (True, False):
            stacks = {s: build_stack(c_ds[c_ds.seed == s], e4[(e4.dataset == ds) & (e4.seed == s)],
                                     thr[(thr.dataset == ds) & (thr.seed == s)],
                                     mutben[(mutben.dataset == ds) & (mutben.seed == s)], fams, eff)
                      for s in seeds}
            if eff:
                for s in seeds:
                    eq_rows.append(equilibrium_rows(ds, s, stacks[s], RParams(), "lam=1,rho=0"))
                    for rho in (0.0, 0.1, 0.2):
                        r = equilibrium_rows(ds, s, stacks[s], RParams(rho=rho), f"lam=1,rho={rho:g}")
                        rho_rows.append(r)
                    eq_rows.append(equilibrium_rows(ds, s, stacks[s], RParams(lam=LAM_LOW), f"lam={LAM_LOW:g},rho=0"))
            p1, p2 = seed_pairs(seeds) if seeds else ((), ())
            for k, pair in enumerate((p1, p2), start=1):
                if not pair:
                    continue
                df, sob = run_sobol(stacks, pair, eff, n_base, auc_tied, ds)
                sob["pair_index"] = k
                sob_all.append(sob)
                df["dataset"], df["efficacy"], df["pair_index"] = ds, eff, k
                df_all.append(df)
        meta[ds] = {"seeds": seeds, "families": list(fams), "pair1": list(p1), "pair2": list(p2),
                    "auroc_best": best, "auroc_tied": sorted(auc_tied)}
        print(f"[game] {ds} done", flush=True)
    eqdf = pd.DataFrame(eq_rows)
    eqdf.to_csv(out / "game_equilibrium.csv", index=False)
    pd.DataFrame(rho_rows).to_csv(out / "game_rho_sensitivity.csv", index=False)
    sob = pd.concat(sob_all, ignore_index=True) if sob_all else pd.DataFrame()
    sob.to_csv(out / "game_x3_sobol.csv", index=False)
    df = pd.concat(df_all, ignore_index=True) if df_all else pd.DataFrame()
    df.to_csv(out / "game_x3_samples.csv.gz", index=False, compression="gzip", float_format="%.6g")
    write_game_summary(out, eqdf, pd.DataFrame(rho_rows), sob, df, meta, n_base, quick)


def write_game_summary(out: Path, eqdf, rhodf, sob, df, meta, n_base, quick) -> None:
    L = ["# Game (cost lens) on the robustness results", "",
         "Parameters: reference values of econ.game (V = 1000, P = 2000, L = 1000, w = 0.5, cB = 2, kM = 100, kN = 3000, "
         "pi = 0.5, N_benign = 1e6, N_attack = 50), lam = 1 unless stated, rho = 0 unless stated. Illustrative, see the "
         "sensitivity (Sobol) rows. Detection input: worst case over generators (G1, G2) and attackers. Capacity: "
         "closed form at the deterrence point, plus a geometric grid in x = B/A with step 0.5%.",
         "", f"Profile: {'quick' if quick else 'full'}; Sobol base N = {n_base} ({n_base * (len(PARAM_NAMES) + 2)} "
         f"samples per dataset, efficacy setting and seed pair). Seed pairs (recorded): {meta}.", "",
         "## Equilibrium per seed (lam = 1, rho = 0, efficacy on)", ""]
    e = eqdf[eqdf.setting == "lam=1,rho=0"]
    for ds, g in e.groupby("dataset"):
        L.append(f"### {ds}")
        L.append("")
        L.append(f"- modal equilibrium model: {g.eq_model.mode().iloc[0]} "
                 f"(counts: {g.eq_model.value_counts().to_dict()})")
        m, lo, hi = bootstrap_ci(g.eq_loss)
        L.append(f"- loss mean [95% CI over seeds]: {m:,.1f} [{lo:,.1f}, {hi:,.1f}]")
        L.append(f"- lower FPR edge (1e-4) share of seeds: {g.lower_fpr_edge.mean():.2f}; upper FPR edge (1e-2): "
                 f"{g.upper_fpr_edge.mean():.2f}; upper B edge (x = 1): {g.upper_B_edge.mean():.2f}; lower B edge "
                 f"(x = 0.01): {g.lower_B_edge.mean():.2f}; closed-form optimum: {g.closed_form_optimum.mean():.2f}")
        L.append(f"- modal capable class: {g.capable_class.mode().iloc[0]}")
        L.append("")
        L.append("| model | loss mean (per seed) | share of seeds in loss-tied set |")
        L.append("|---|---|---|")
        for mm in MODELS:
            col = f"loss_{mm}"
            v = g[col].astype(float)
            tied = g.tied_models.fillna("").str.split("+").apply(lambda s: mm in s).mean()
            L.append(f"| {mm} | {v.mean():,.1f} | {tied:.2f} |")
        L.append("")
    L += ["## Sensitivity to the mutated-benign share rho (lam = 1)", "",
          "| dataset | rho | mean loss [95% CI] | modal equilibrium model | share upper FPR edge |", "|---|---|---|---|---|"]
    for (ds, rho), g in rhodf.assign(rho=rhodf.setting.str.extract(r"rho=([\d.]+)")[0].astype(float)).groupby(
            ["dataset", "rho"]):
        m, lo, hi = bootstrap_ci(g.eq_loss)
        L.append(f"| {ds} | {rho:g} | {m:,.1f} [{lo:,.1f}, {hi:,.1f}] | {g.eq_model.mode().iloc[0]} | "
                 f"{g.upper_fpr_edge.mean():.2f} |")
    L += ["", "## Sobol indicators (fixed seed pair; mean over samples; bootstrap 95% CI over samples)", ""]
    if len(df):
        L += ["| dataset | efficacy | pair | (a) mut/novel weak | (a_weak) reuse weak | (b) AUROC-tied and loss-tied disjoint | "
              "(c) regret at lam = 0.05 | (d) model changes, rho 0 -> 0.1 | closed-form optimum |",
              "|---|---|---|---|---|---|---|---|---|"]
        for (ds, eff, pi), g in df.groupby(["dataset", "efficacy", "pair_index"]):
            cells = []
            for k in ("a_mut_nov", "a_weak_reuse", "b_auroc_disjoint", "c_regret", "d_model_change", "closed_form"):
                mu, lo, hi = bootstrap_ci(g.groupby("sample")[k].mean().to_numpy(float))
                cells.append(f"{mu:.3f} [{lo:.3f}, {hi:.3f}]")
            L.append(f"| {ds} | {'on' if eff else 'off'} | {pi} | " + " | ".join(cells) + " |")
    L += ["", "## Sobol first-order and total indices (rows with S1 sum < 0.1 are labelled noise-floor)", ""]
    if len(sob):
        for (ds, eff, pi, o), g in sob.groupby(["dataset", "efficacy", "pair_index", "output"]):
            st = g.status.iloc[0]
            top = g.sort_values("ST", ascending=False).head(3)
            txt = "; ".join(f"{r.parameter} S1 {r.S1:.3f}, ST {r.ST:.3f}" for r in top.itertuples())
            L.append(f"- {ds}, efficacy {'on' if eff else 'off'}, pair {pi}, {o} [{st}]: {txt}")
    L += ["", "Indicator (d) asks whether the equilibrium defender changes when rho goes from 0 to 0.1; (c) compares the "
          "lam = 1 optimum with the lam = 0.05 loss, as in the round-3 game.", ""]
    (out / "SUMMARY_GAME.md").write_text("\n".join(L) + "\n")
