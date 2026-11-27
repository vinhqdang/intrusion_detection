# Design: data-driven game-theoretic evaluation of ML intrusion detectors

Status: design v1, 2026-11-27. This replaces the conformal direction as the main project (see
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
- `m` ∈ {supervised GBDT, benign-only one-class, hybrid gate (GBDT + one-class at a split FPR budget)}.
- `τ`: operating threshold, set by a target benign FPR ∈ {1e-4, 1e-3, 1e-2}. This determines alert
  volume.
- `B`: analyst capacity (alerts per day that can be investigated). Alerts beyond `B` are dropped
  uninvestigated (triage loss). An optional extension is a label budget for learning new families.

**Attacker (follower)** observes `d` (worst case; a partial-information variant is in §3.4) and
chooses one action `a`:
- `reuse(f)`: run known family `f` as is. Cost `c_R` ≈ 0 (commodity tooling).
- `mutate(f, b)`: modify attacker-controllable flow features of family `f` within budget `b`. Cost
  `c_M(b) = λ · κ_M · b`.
- `novel`: launch a family the defender has never seen. Cost `c_N = λ · κ_N`, with `κ_N ≫ κ_M`.
- `abstain`: payoff 0.

`λ ∈ (0, 1]` is the **AI uplift factor**: it scales the cost of mutation and novelty (λ = 1 means no
AI). It is a parameter we sweep. We do not estimate it.

### 3.2 Payoffs

Let `p_d(a)` be the probability that action `a` is **detected and investigated** under `d`:

    p_d(a) = r_d(a) · min(1, B / A_d)

Here `r_d(a)` is the measured recall at threshold `τ`. `A_d = FPR(τ)·N_benign + Σ attack alerts` is
the alert volume. The `min` term is the probability that a given alert is investigated, assuming
uniform triage (prioritised triage is an extension).

- Attacker: `U_A(a, d) = (1 − p_d(a)) · V − p_d(a) · P − c(a)`. `V` is the gain if undetected; `P`
  is the loss when caught (burned infrastructure, attribution).
- Defender: `U_D(d) = − [ (1 − p_d(a*)) · L + w · A_d + K(m, B) ]`. Here `a*` is the attacker's best
  response, `L` is the breach loss, `w` is analyst cost per alert, and `K` is fixed cost (model
  operation, analyst salaries ∝ B).

**Attacker population (Bayesian Stackelberg).** A fraction `π` of attackers are commodity, with
action set {reuse, abstain}. The remaining `1 − π` are capable and have the full action set. This
avoids the degenerate "everyone is an APT" case.

### 3.3 Solution and metrics

The defender's configuration space is small and discrete (3 models × 3 thresholds × a grid of B).
We solve by enumeration: for each `d`, compute the attacker best response for each type, then
`U_D`, then take argmax. Ties are broken in the defender's favour (strong Stackelberg).

Reported metrics:
- **Equilibrium detection** `p_d*(a*)` against **average-case recall** (the test-set view).
- **Equilibrium expected loss** per detector, and **Kendall τ** between the AUC ranking and the
  equilibrium-loss ranking.
- **Price of AI uplift**: defender loss at λ divided by loss at λ = 1, and how the optimal `d*`
  changes with λ.

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

- **Feature classes on CICFlowMeter features** (CIC-IDS2017 / CSE-CIC-IDS2018):
  - *Controllable, increase-only*: timing features (flow duration, inter-arrival times, idle and
    active times). The attacker can slow down or add jitter.
  - *Controllable by padding*: packet-length features (max/mean/min, fwd/bwd). The attacker can pad
    up to 1500 bytes, which shifts length statistics up.
  - *Controllable by adding packets*: packet counts and bytes (dummy packets). This also changes
    rates.
  - *Not controllable*: flags that the protocol semantics require, and server-side (bwd) responses
    beyond what padding can do.
- **Consistency.** Derived features must be recomputed from the base features when possible (rates
  = bytes/duration, means consistent with totals). If exact recomputation is impossible, apply only
  monotone transforms and document the approximation. Problem-space realism is a known weakness of
  feature-space attacks (arXiv 2005.07519). We state it as a limitation and do not claim
  packet-level realisability.
- **Budget `b`**: number of controllable feature groups changed (0–4) and relative magnitude
  (×1.5, ×2, ×5).
- **Search**: black-box greedy over the groups and magnitudes, maximising evasion rate at the
  defender's threshold. Query access to the score is the worst case. The threshold-only (label-only)
  case is a variant.
- **Output**: `r_d(mutate(f, b))` for every model, family, FPR and budget.

## 5. Experiments

1. **X1: payoff tables.** Build `r_d(a)` from E2, E3 and E4 for CIC-IDS2017 and CSE-CIC-IDS2018
   (main), plus CICIoT2023 and CICIoMT2024 (reuse/novel only). Use 10 seeds.
2. **X2: equilibrium vs AUC.** For each dataset and model, report AUC, average recall, equilibrium
   detection and equilibrium loss at a reference parameter point. Report Kendall τ between the
   rankings.
3. **X3: sensitivity.**
   - Sweep `V/P`, `L`, `w`, `κ_M`, `κ_N`, `π` over log-grids spanning ≥ 2 orders of magnitude.
   - Report the fraction of the grid in which each qualitative conclusion holds.
   - Use Sobol indices for the main outputs.
   - A conclusion is claimed only if it holds on most of the grid.
4. **X4: AI uplift.** Sweep `λ` from 1 to 0.01. Track the defender's optimal `d*`, the equilibrium
   loss, and the λ at which the capable attacker switches from reuse to mutate to novel.
5. **X5 (optional): repeated game** with label budget.

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
  greedy search), writing `results/econ/e4_mutation.csv`.
- `src/idsbench/econ/game.py`: payoffs, attacker best response per type, defender enumeration,
  strong Stackelberg solution, and metrics.
- `src/idsbench/econ/sweep.py`: X2–X4 sweeps, Kendall τ, Sobol (SALib if available, otherwise
  grid-based variance decomposition).
- Tests: best response on hand-built tables; equilibrium detection equals min affordable recall in
  the zero-cost limit; mutation keeps uncontrollable features unchanged and respects monotonicity.
