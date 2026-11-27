# Design: data-driven game-theoretic evaluation of ML intrusion detectors

Status: design v2, 2026-11-27 (v2 changes are marked in the text; see `results/econ/SUMMARY.md`). This replaces the conformal direction as the main project (see
[`lit_review_conformal_ids.md`](lit_review_conformal_ids.md) for why conformal-for-IDS is too crowded).

## 1. Thesis

ML intrusion detectors are ranked by AUC/F1 on a fixed test set, as if attackers drew attacks at
random from that test set. Real attackers pick the cheapest action that goes undetected. Our
feasibility data shows the detection a defender actually gets is shaped by that choice:
- recall collapses on unseen families (E2);
- detectors lean on cheap shortcut features (E1);
- calibration breaks on a new network (E3).

**Claim to test.** If detection is evaluated at the Stackelberg equilibrium of a defender–attacker
game whose detection probabilities are *measured* on real detectors and datasets:
1. equilibrium detection is set by the detector's weakest affordable attacker option, not by its
   average;
2. the ranking of detectors by equilibrium expected loss differs from their ranking by AUC;
3. as AI tools cut the attacker's cost of mutation and novelty, the defender's optimal investment
   moves from supervised accuracy towards novelty detection, label budget and analyst capacity.

   v2 status of claim 3: **not tested** by the current model set. The defender's action space is five detectors,
   FPR and analyst capacity; it has no novelty-detection investment or label budget. The λ sweep reports how the
   optimum moves, not whether a shift toward novelty detection is optimal (`results/econ/SUMMARY.md`).

## 2. Positioning (quick novelty check, 2026-11-27; not a systematic review)

| Line of work | What it does | What it lacks for our question |
|---|---|---|
| Alert-allocation / alert-prioritization games (Schlenker et al., IJCAI 2017; Laszka et al., AAAI-17 workshop; adversarial-RL prioritization, arXiv 1810.05921) | Stackelberg allocation of alerts to analysts | Detection probabilities are assumed parameters, not measured ML detectors |
| Stackelberg prediction games / adversarial classification (Brückner & Scheffer, KDD 2011; Neyman–Pearson detection game, arXiv 2206.05276; Stackelberg flow classifier, ICC 2020) | Train a robust classifier against a feature-manipulating attacker | Optimise a model, not an evaluation; no novelty option; no economics of AI uplift |
| Game-theoretic IDS surveys (ACM CSUR 10.1145/3232848) and Nash IDS on UNSW-NB15 (ACM 10.1145/3474198.3478267) | Equilibrium attack and scan rates | Still report standard metrics; payoffs not tied to measured per-strategy detection |
| Economics of AI-era attacks (*The Adversarial Discount*, arXiv 2605.04336; *Uplifted attackers*, arXiv 2508.15808; *Defensive sufficiency*, arXiv 2610.09892; Ebel & Mitra, arXiv 2207.09497) | AI lowers attacker cost; defender investment models | Abstract effectiveness functions; no data from real detectors |
| Zero-day development and stockpiling games (Wang, Welburn & Hausken 2020; Hausken & Welburn) | Attacker R&D vs immediate use | No detection model; no ML |
| Empirical game-theoretic analysis (EGTA, Wellman line) | Payoffs estimated by simulation | Not applied to ML-IDS evaluation as far as found; **check before claiming** |

**Gap.** No work was found that measures per-strategy detection functions of real ML-IDS (known
reuse, cheap feature mutation, unseen family, cross-network deployment), plugs them into a
defender–attacker game, and uses the equilibrium as the evaluation criterion. It is EGTA for
ML-IDS, with an AI-cost parameter.

## 3. Model

### 3.1 Players and actions

**Defender (leader)** commits to a configuration `d = (m, τ, B)`:
- `m` ∈ {xgb (supervised GBDT), fusion (hybrid gate: GBDT + one-class at a split FPR budget), iforest (benign-only
  one-class), xgb_robustfeat (GBDT on the explicit robust column list of §4.1: no column a mutation can change and
  no column that depends on forward timing or size), xgb_adv (GBDT retrained once on mutated copies of its own
  training attacks; evaluated against the three attackers of §4.1)}.
- `τ`: operating threshold, set by a target benign FPR ∈ {5e-4, 1e-3, 3e-3, 1e-2} (v2 adds 5e-4; it is attainable
  because the fusion threshold set has 20,000 rows, so k = ceil((n+1)(1-fpr)) ≤ n). The alert volume uses the
  realised benign-test FPR of the threshold (v2), not the nominal value.
- `B`: analyst capacity (alerts per day that can be investigated). Alerts beyond `B` are dropped
  uninvestigated (triage loss). v2: B on a geometric grid of 200 points in [10, 1e5] plus infinity; the
  defender's optimum is exact on this grid. An optional extension is a label budget for learning new families.

**Attacker (follower)** observes `d` (worst case; a partial-information variant is in §3.4) and
chooses one action `a`:
- `reuse(f)`: run known family `f` as is. Cost `c_R` ≈ 0 (commodity tooling).
- `mutate(f, b)`: modify attacker-controllable flow features of family `f` within budget `b`. Cost
  `c_M(b) = λ · κ_M · b`. v2: the recall of the action is the worst case over the score-query attackers
  (greedy, strong per-group level search, transfer from xgb), see §4.1.
- `novel`: launch a family the defender has never seen. Cost `c_N = λ · κ_N`, with `κ_N ≫ κ_M`.
- `abstain`: payoff 0.

`λ ∈ (0, 1]` is the **AI uplift factor**: it scales the cost of mutation and novelty (λ = 1 means no
AI). It is a parameter we sweep. We do not estimate it.

### 3.2 Payoffs

Let `p_d(a)` be the probability that action `a` is **detected and investigated** under `d`:

    p_d(a) = r_d(a) · min(1, B / A_d)

Here `r_d(a)` is the measured recall at threshold `τ`. `A_d = FPR_realised(τ)·N_benign + N_attack` is the alert
volume (a conservative upper bound: every attempt alerts; the same A is used in the attacker's detection
probability and in the defender's alert cost). v2: `FPR_realised` is the benign-test FPR of the threshold
(the benign test rows are disjoint from calibration, asserted), recorded per (model, nominal FPR, seed). The `min` term is the probability that a given alert is investigated, assuming
uniform triage (prioritised triage is an extension).

- Attacker: `U_A(a, d) = (1 − p_d(a)) · e(a) · V − p_d(a) · P − c(a)`, where `e(a)` is the efficacy of the
  action (timing mutation of DoS, DDoS, BruteForce and PortScan multiplies the gain by 1/m; `e = 1` otherwise;
  switched off by `GameParams.efficacy = False`). `V` is the gain if undetected; `P`
  is the loss when caught (burned infrastructure, attribution).
- Defender: `U_D(d) = − [ (1 − p_d(a*)) · L + w · A_d + K(m, B) ]`. Here `a*` is the attacker's best
  response, `L` is the breach loss, `w` is analyst cost per alert, and `K` is fixed cost (model
  operation, analyst salaries ∝ B).

**Attacker population (Bayesian Stackelberg).** A fraction `π` of attackers are commodity, with
action set {reuse, abstain}. The remaining `1 − π` are capable and have the full action set. This
avoids the degenerate "everyone is an APT" case.

### 3.3 Solution and metrics

The defender's configuration space is small and discrete (5 models × 4 thresholds × 201 values of B). We solve
by enumeration, vectorised over B and actions (`game.solve_stack`, tested against the scalar reference
`game.evaluate`). For each `d`, the attacker best response for each type, then `U_D`, then the minimum.
Attacker ties are broken in the defender's favour (strong Stackelberg).

v2 tie rules. Defender and model ties are **never broken by enumeration order**. The reference equilibrium
reports the whole loss-tied set of models: a model is tied with the lowest loss when its best loss is within
1% (relative). Exact ties between configurations are represented by the least analyst capacity (a fixed rule,
reported as a set in the tables). AUROC ties: two models are AUROC-tied when the paired difference of their
seed-mean AUROC has a 95% bootstrap interval over seeds that contains 0, or |mean difference| < 1e-4.

v2 solution per seed. The attacker knows the deployed detector, so the equilibrium is solved per seed on that
seed's recall tables, and outcomes are aggregated over seeds (distribution of the chosen model sets, detection
and loss with bootstrap intervals). The seed-mean tables are a secondary solve.

Reported metrics:
- **Equilibrium detection** `p_d*(a*)` against **average-case recall** (the test-set view).
- **Equilibrium expected loss** per detector (per-seed optimum, bootstrap interval over seeds), the loss-tied share
  of each model, and **Kendall τ** (tie-aware ranks, bootstrap interval over seeds) between the AUROC rank and the
  equilibrium-loss rank. A model's rank is 1 + the number of models significantly better than it.
- **Price of AI uplift**: defender loss at λ divided by loss at λ = 1 (same seed), and how the optimal `d*`
  changes with λ.
- **Grid edges**: the share of optima on the edge of the B grid (10, 1e5, inf) or of the FPR grid (5e-4, 1e-2).

### 3.4 Extensions (only if time allows)

- Partial observability: the attacker knows `m` but not `τ`, and holds a belief over `τ`.
- Repeated game with learning: once a novel family is caught and labelled, it becomes `reuse` for
  later attackers. The defender's label budget sets how fast this happens. This links to the active
  learning work (Dang, RIVF 2020).
- Cross-network deployment: `r_d(a)` comes from the E3 transfer measurements, and FPR drift raises `A_d`.

## 4. Measuring the detection functions (data side)

| Action | Source of `r_d(a)` | Status |
|---|---|---|
| reuse(f) | E2 "recall when known" per family, per model, per FPR | **have** (XGB, IForest, fusion) |
| novel | E2 "recall unseen" per held-out family. Attacker picks its best family (min recall); averaging is reported as a contrast | **have** |
| mutate(f, b) | **New experiment E4**: black-box evasion of the trained detector limited to attacker-controllable features | **to build** |
| new network | E3 cross-pair transfer recall and realised FPR | **have** (one pair) |

### 4.1 E4: constrained mutation (attacker-controllable features)

- **Feature classes on CICFlowMeter features** (CIC-IDS2017 / CSE-CIC-IDS2018), forward direction only:
  - *Timing (increase-only)*: Flow Duration, Fwd IAT Total/Max/Min/Std, scaled by the level; Flow IAT Max becomes at
    least the new Fwd IAT Max. Negative sentinel values are not scaled.
  - *Padding*: Fwd Packet Length Max/Min/Mean and Avg Fwd Segment Size, raised to at most 1500 bytes; the forward
    byte totals follow the change of the forward mean. v2: min_seg_size_forward (a TCP header minimum, not payload)
    is removed from the group and never changes.
  - *Dummy packets*: Total Fwd Packets, Subflow Fwd Packets, Fwd Act Data Pkts (ceil of the scaled count), forward
    bytes (scaled), and Fwd Header Length (per added packet).
  - *Not controllable*: every backward (server-side) feature, flags, Init_Win, Active and Idle, Bwd IAT, Bwd Header
    Length, Destination Port, Protocol, min_seg_size_forward.
- **Derived features (v2).** Each rule is a delta update `Y = X + f(Y inputs) − f(X inputs)`, so a value keeps its
  offset where the identity does not hold exactly on the cache. Identity hold rates are in
  `results/econ/e4_feature_groups.md`.
  - Exact: rates (packets/s, bytes/s); Max/Min Packet Length from the forward and backward extremes.
  - Identity, delta form: Packet Length Mean and Average Packet Size (bytes over packets; holds on ~25% of rows at
    1%); Flow IAT Mean = Flow Duration/(packets − 1); Fwd IAT Mean = Fwd IAT Total/(Fwd packets − 1); Down/Up Ratio =
    floor(bwd packets / fwd packets) (holds on every row of both datasets); Packet Length Variance from the pooled
    variance of the two directions (pooled identity holds on ~20% of rows; the delta is applied).
  - Approximations, not checkable on the cache (per-packet lengths and gaps are not stored): Packet Length Std =
    sqrt(variance); Fwd Packet Length Std = min(orig std × level, Bhatia–Davis bound sqrt((M − μ′)(μ′ − m′)), M =
    max(1500, orig max)); Flow IAT Std scaled by the duration ratio; Flow IAT Min scaled by the level when it equals
    Fwd IAT Min (its minimum gap is forward), otherwise unchanged (a backward gap).
- **Robust model (v2).** xgb_robustfeat uses only the columns that no mutation changes and that do not depend on
  forward timing or size: 25 of 68 columns on CIC-IDS2017. The explicit lists (kept and excluded, with the reason) are in
  `e4_feature_groups.md`. A test asserts that no mutated or derived column is in its input.
- **Consistency.** Problem-space realism is a known weakness of feature-space attacks (arXiv 2005.07519). We state it
  as a limitation and do not claim packet-level realisability.
- **Budget `b`**: non-empty subset of the three groups and a relative magnitude (×1.5, ×2, ×5): 21 budgets.
- **Attackers (v2).** All attackers query a score (or the label) and are applied to every defender:
  - *greedy* (score): the greedy over the groups and two levels per group, as in v1 (the E4 attack).
  - *strong* (score): per-group level search over 10 levels in [1, m]; one coordinate sweep over the groups from two
    starts (all at the top level; random). A single group is searched exhaustively, so one start suffices. The
    attacker keeps the lowest score of every state it queried.
  - *transfer* (score of another model): the states found by the strong attacker against xgb, submitted to the
    defender's model. Not run for xgb itself.
  - *label* (label query): the groups in a random per-flow order at level m. A weak, non-adaptive baseline. Its RNG
    is keyed on the budget label and seed.
  - The game uses the worst case over greedy, strong and transfer for the score query (`min` of recall, per budget and
    seed). For xgb_adv this is the only evaluation: the augmentation attacker (xgb-greedy) is not the evaluation attacker.
- **Output**: `r_d(mutate(f, b))` for every model, family, FPR, budget and attacker; `realised FPR` per model, FPR,
  seed.

## 5. Experiments

1. **X1: payoff tables.** Build `r_d(a)` from E2, E3 and E4 for CIC-IDS2017 and CSE-CIC-IDS2018 (main), plus
   CICIoT2023 and CICIoMT2024 (reuse/novel only, not in v2). Use 10 seeds.
2. **X2: equilibrium vs AUC.** For each dataset, query and model: per-seed AUROC, per-seed optimum, loss-tied share,
   and the per-seed equilibrium with bootstrap intervals over seeds; Kendall τ (tie-aware, bootstrap over seeds).
   The seed-mean solve is a secondary row.
3. **X3: sensitivity (v2).**
   - Sobol design (SALib sobol sampler, fixed seed) over log-uniform ranges of V/P, L, w, kM, kN, pi, N_attack, cB,
     N_benign. Base N = 4096 (45,056 samples per dataset and efficacy setting; N = 8192 did not fit the compute budget).
   - Each sample is solved per seed on 2 seeds drawn at random for that sample (compute; documented in `x3.md`).
   - Indicators, per sample-seed: (a) the capable attacker's chosen action is mutate or novel and its recall is more
     than 0.2 below the mean reuse recall of the chosen model and FPR; (a_weak) the same with reuse of a weak known
     family (reported separately); (b) the AUROC-tied set and the loss-tied set are disjoint; (c) regret: keeping the
     λ = 1 optimum costs more than 1% above the optimal loss at λ = 0.05; (c_cfg) the optimal (model, FPR, B)
     changes (the v1 indicator, kept for comparison); (c_act) the capable attacker's action class changes.
   - Sobol outputs: log10 of the mean loss over the sample's seeds, the indicators (mean over seeds), the membership
     of each model in the loss-tied set, and the capable action class. Outputs with prevalence < 5% or > 95% are
     dropped and listed. S1 and ST are reported with the SALib 95% intervals in `x3.md` and `x3_sobol.csv`.
   - A conclusion is claimed only when the bootstrap interval of its fraction lies on one side of 0.5.
4. **X4: AI uplift.** Sweep `λ` from 1 to 0.01 (20 log points), per seed and on the seed-mean tables. Track the
   modal `d*`, the loss and its price relative to λ = 1, and the λ at which the capable attacker's class switches.
5. **X5 (optional): repeated game** with label budget (not done).

Reference parameter values must come from cited sources where possible (e.g. breach cost and
analyst cost per alert from industry reports). Each reference value is labelled as illustrative,
and conclusions rest on the sensitivity analysis, not on these values.

## 6. Expected contributions

1. An evaluation method for ML-IDS based on measured detection functions and a Stackelberg
   attacker. A metric (equilibrium loss / equilibrium detection) that can replace or accompany AUC.
2. Empirical evidence, on modern flow datasets, that AUC-optimal detectors are not loss-optimal
   against strategic attackers, with the conditions under which this holds.
3. A quantified "price of AI uplift" for flow-based IDS, and the defender investments that reduce it.
4. Open code and payoff tables, so other detectors can be scored with the same game.

Target venues: WEIS 2027, GameSec 2027; journal version for IEEE TIFS / TDSC or Computers & Security.

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Reviewers dispute cost parameters | Conclusions only from the sensitivity analysis; reference values cited and labelled illustrative |
| Feature-space mutation is not realisable as packets | Restrict to controllable, monotone groups; state the limitation; optional packet-level check on a few flows later |
| Game too simple for GameSec | Bayesian attacker types plus the repeated game with learning (X5) add depth; keep proofs to small propositions |
| "Equilibrium detection = min recall" looks obvious | Make the contribution the measurement and the ranking reversals, not the proposition; show when it is *not* the min (costs, capacity) |
| Datasets are lab captures | Same limitation as all NIDS work; the method transfers to any dataset |

## 8. Implementation plan (code)

- `src/idsbench/econ/detection_tables.py`: build `r_d(a)` tables from E2/E3 CSVs (reuse, novel,
  transfer) at each FPR.
- `src/idsbench/econ/mutation.py`: E4 constrained black-box mutation (feature groups, consistency,
  greedy and label query paths).
- `src/idsbench/econ/measure.py`: defender models (xgb, fusion, iforest, xgb_robustfeat, xgb_adv), reuse,
  leave-one-family-out novel recall and the E4 runs, writing `results/econ/e4_mutation.csv`,
  `detection_tables.csv` and `e4_reference.csv`.
- `src/idsbench/econ/game.py`: payoffs, attacker best response per type, defender enumeration,
  strong Stackelberg solution, and metrics.
- `src/idsbench/econ/sweep.py`: X2–X4 sweeps, Kendall τ, bootstrap over seeds, Sobol indices (SALib Saltelli).
- Tests: best response on hand-built tables; equilibrium detection equals min affordable recall in
  the zero-cost limit; mutation keeps uncontrollable features unchanged and respects monotonicity.
