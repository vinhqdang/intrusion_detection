# Design: ML-IDS against a client-side-only attacker

Status: design v1, 2026-11-27. This design follows from the round-3 results of the game study
([`design_econ_game.md`](design_econ_game.md), [`../results/econ/OPEN_ISSUES.md`](../results/econ/OPEN_ISSUES.md)).
In that study, AUROC still picked the right detector at equilibrium, so the game framing alone is weak. Three
robustness findings were strong and open:
1. standard detectors collapse when an attacker changes only the client side of a flow;
2. removing every client-controllable feature costs a lot of clean recall;
3. naive adversarial training looks robust but has learned a *mutation fingerprint*.

The game stays in the paper as a cost lens for SOC operating points (§6). It is not the headline.

## 1. Research questions

- **RQ1 (attack surface).** How much recall at strict FPR do flow-feature detectors lose when an attacker can only
  delay client packets, pad client payload, or add client packets? Derived features are recomputed consistently.
- **RQ2 (price of robust features).** How much clean recall does a detector lose when it uses only features the
  client cannot influence?
- **RQ3 (fingerprint).** Does adversarial training on mutated attack flows give real robustness, or does it learn
  "looks mutated → attack"? Tests:
  - FPR on mutated benign flows;
  - robustness against a *different* mutation generator.
- **RQ4 (fix and protocol).** Does symmetric augmentation (mutated benign copies added as negatives), or training on
  two generators, give robustness that transfers across generators at an acceptable FPR? Which evaluation protocol
  exposes fingerprint robustness?

## 2. Threat model

- The attacker controls the client endpoint of a flow. It can:
  - add delay before client packets (timing);
  - pad client payload up to the MTU (length);
  - add client packets (count).
- It cannot change server responses, flags set by the server, or the server's TCP window. It cannot reduce any
  quantity.
- Mutation operates in feature space on CICFlowMeter vectors. Problem-space realisability is a stated limitation.
  §3 reduces the risk that results depend on one feature-space model by using two generators built on different
  physical assumptions.
- Query access:
  - score (margin) for the greedy and strong attackers;
  - none for the transfer attacker (it attacks xgb and replays the result);
  - label only for the weak baseline.
- Budget: a subset of groups and a multiplier m ∈ {1.5, 2, 5} (G1). G2 uses an equivalent budget (§3.2).

## 3. Two mutation generators

### 3.1 G1: proportional scaling (existing `idsbench.econ.mutation`)

- Timing multiplies forward IATs and the duration by the level.
- Length scales forward packet lengths up to a cap of 1500.
- Count scales the forward packet and byte totals.
- Derived features are updated by delta rules.
- Fwd Packet Length Std uses the Bhatia–Davis bound.
- Backward timing, Active and Idle are left unchanged.

### 3.2 G2: additive, coupled generator (new, independent code path)

G2 must not share helper functions with G1. A different set of physical assumptions is the point.

- **Timing (additive and coupled).**
  - Add a per-packet delay with mean δ to each client inter-arrival:
    - Fwd IAT Total += (n_fwd − 1)·δ;
    - Fwd IAT Mean += δ;
    - Fwd IAT Max += δ·c_max, where c_max = 1 + ln(max(n_fwd − 1, 1)) (expected maximum of exponential delays);
    - Fwd IAT Min += δ·c_min, with c_min = 1/max(n_fwd − 1, 1);
    - Fwd IAT Std = sqrt(old² + δ²);
    - Flow Duration += (n_fwd − 1)·δ.
  - Request–response coupling: when n_bwd > 1 and n_fwd > 1, the server answers later. Backward IAT Total, Mean
    and Max then grow by the share of delay that falls between server packets: δ·min(n_fwd − 1, n_bwd − 1)/(n_bwd − 1)
    per gap.
  - Active Mean/Max grow by the same share of the added duration. Idle is unchanged.
  - The budget δ is set so that the added duration equals what G1 adds at multiplier m:
    δ = (m − 1)·Fwd IAT Mean_orig, with a floor of 1 ms when the mean is 0.
- **Length (random target).**
  - Each flow draws a target mean payload T ~ Uniform(current mean, min(MTU, m·current mean)) per flow.
  - Only data-carrying packets are padded, and the padded size is drawn per flow.
  - Fwd Pkt Len Max = max(old max, T); Min stays unchanged (pure ACKs are not padded); Mean = T.
  - Std is recomputed from a two-point mixture (unpadded ACK share, padded data share).
  - Totals, Avg Fwd Segment Size, Packet Length Mean/Std/Var and Average Packet Size are recomputed from the
    totals.
- **Count (dummy packets, header-only).**
  - Add k = ⌈(m − 1)·n_fwd⌉ forward packets with zero payload.
  - Packet counts and Fwd Header Length grow.
  - Byte totals are unchanged, so the forward mean length drops and Fwd Pkt Len Min becomes 0.
  - Rates, Down/Up Ratio and the packet-length aggregates are recomputed.
- **After any group, recompute** Flow Bytes/s, Flow/Fwd/Bwd Packets/s, Flow IAT Mean (duration / (n − 1)) and
  Down/Up Ratio. When G2 timing coupling applies, Bwd Packets/s changes only through the duration.

### 3.3 Realism diagnostics (report for both generators)

1. **Fingerprint AUROC.** Train a small XGBoost to separate G(x) from x on benign flows, using random budgets and a
   held-out split.
   - AUROC near 1 means the generator leaves artefacts that a detector can learn.
   - Report per group and per generator, plus the top features.
2. **Cross-generator distance.** Fingerprint AUROC of G1(x) vs G2(x) at matched budgets.
3. **Identity hold rates** of every recomputed feature on mutated flows: rate identities and the packet-length mean
   identity.

## 4. Defenders

All are trained on the same splits per seed. The scenarios are known (every family in train) and leave-one-family-out
(LOFO, for the game's novel action only).

| id | Training data | Notes |
|---|---|---|
| `xgb` | clean | baseline |
| `fusion` | clean xgb + benign IsolationForest via conformal p-values | as before |
| `iforest` | benign only | lower bound; skip E4 attacks (recall ≈ 0) |
| `xgb_robust` | clean, robust columns only | robust list from G1 **and** G2. Any column that G1 or G2 mutates or recomputes is dropped, including backward timing and Active (G2 coupling) |
| `adv_naive_G1` | clean + G1-mutated attack copies (greedy, full budget) | the round-3 `xgb_adv` |
| `adv_sym_G1` | clean + G1-mutated attack copies + G1-mutated benign copies (random group subset and level, same count as attack copies) | fix A |
| `adv_sym_G1G2` | clean + attack and benign copies from G1 and G2, half each | fix B |

- **Augmentation rows** come only from training folds. The LOFO held-out family is never used.
- **Benign copies** have random budgets, not greedy ones, because benign clients do not optimise against the
  detector.
- **Attack copies** use greedy mutation against the base xgb. Train the base xgb first, then augment. This gives one
  round, as before.

## 5. Evaluation

**Seeds and splits.**
- 10 seeds.
- Benign cap 600,000 per dataset. The split is train 60% / calibration 20% / test 20%. This gives 60,000 rows in
  `cal_thr` and 120,000 benign test rows.
- Family cap 10,000. Use 1,000 attack test flows per family for E4.

**FPR grid.** {1e-4, 5e-4, 1e-3, 1e-2}.
- Assert attainability.
- Report the realised benign-test FPR with a Wilson 95% interval.
- **Plateau-aware thresholds:** if more than 0.5·fpr·n calibration scores tie at the threshold, move it to the next
  distinct score above. Record the realised calibration FPR.

**Metrics** per (dataset, seed, defender, FPR, family):
1. clean recall and clean AUROC (family vs benign);
2. adversarial recall under each (generator ∈ {G1, G2}) × (attacker ∈ {greedy, strong, transfer-from-xgb}) at each
   budget;
3. **worst-case recall per generator**: the minimum over attackers and budgets of the per-seed recall at matched
   budget units. Also give the same number at each fixed budget;
4. **mutated-benign FPR** (fingerprint test): benign test flows passed through G with random budgets (the same
   distribution as benign augmentation) and through each fixed budget, scored at the clean threshold. Report it per
   generator;
5. **cross-generator gap:** adversarial recall under the training generator minus recall under the other generator,
   for `adv_*` models.

**Headline table.** One row per (dataset, defender). Columns, at FPR 1e-3, all as mean [95% bootstrap CI over seeds]:
- clean recall (macro over families);
- worst-case recall under G1;
- worst-case recall under G2;
- mutated-benign FPR under G1;
- mutated-benign FPR under G2.

**Statistics.**
- Paired comparisons over seeds: Wilcoxon signed-rank with 10 seeds (the minimum two-sided p is 0.002) and Holm
  correction within each table.
- Effect sizes with bootstrap CIs.

**Families.** Report every family. Mark CSE-CIC-IDS2018 Infiltration as label-noisy, and give macro numbers both with
and without it.

## 6. Game as a cost lens (secondary)

Keep `idsbench.econ.game`, with the new defenders and the following changes:
- **Analyst capacity B.**
  - Solve it in closed form where the attacker is deterred, using the smallest B with p ≥ V/(V+P) for every
    attacker type.
  - Otherwise use a geometric grid with a step of 0.5% or less.
  - Unit-test the closed form against a dense grid.
- **FPR grid.** Use the §5 FPR grid. Report lower-edge and upper-edge hits separately.
- **Detection input.** Use the worst-case recall over generators, so the attacker picks the generator.
- **Mutated-benign FPR in alert volume.**
  - A = fpr_real·N_benign·(1 − ρ) + fpr_mutated·N_benign·ρ + N_attack, where ρ is the share of benign traffic that
    looks "mutated".
  - Add ρ ∈ [0, 0.2] to the sensitivity analysis. This is how fingerprint robustness shows up as cost.
- **Sobol.**
  - Use the same fixed set of 2 seeds for every Saltelli row, chosen once and recorded. This removes seed noise
    within the estimator.
  - Repeat with a second seed pair and report both.
  - Drop outputs whose S1 sum is below 0.1, or label them noise-floor.
- **Indicators.**
  - Report (a), (b) and (c) as before.
  - Add (d): the equilibrium defender changes when ρ goes from 0 to 0.1. This tests whether fingerprint models lose
    their equilibrium advantage.

## 7. Expected results and what would falsify them

- **RQ1.** A collapse similar to round 3 for xgb and fusion. If G2 does not reproduce the collapse, the RQ1 claim is
  limited to G1.
- **RQ3.**
  - `adv_naive_G1` should show mutated-benign FPR far above its nominal FPR, and recall under G2 far below recall
    under G1.
  - If its G2 recall stays high **and** its mutated-benign FPR stays low, the fingerprint claim is false and the
    paper reports real robustness.
- **RQ4.**
  - `adv_sym_*` should keep a low mutated-benign FPR.
  - Their cross-generator gap tells whether symmetric augmentation alone is enough, or whether a second generator is
    needed.

## 8. Implementation plan

- `src/idsbench/robust/`:
  - `gen2.py`: the G2 generator; it imports no private helpers from `econ.mutation`;
  - `fingerprint.py`: the realism diagnostics;
  - `defenders.py`: the training variants;
  - `evaluate.py`: the E4 matrix, mutated-benign FPR and headline tables;
  - `run_all.py`.
- G1 stays in `idsbench.econ.mutation`. Make the attackers generator-agnostic: they take an `apply(X, group,
  level)` callable.
- Outputs go to `results/robust/`. Any CSV larger than 50 MB is written as `.csv.gz` with only the needed columns.
- Tests must cover:
  - G2 invariants: no reduction, server-only fields unchanged except the coupled timing, recomputed identities;
  - augmentation reading training folds only;
  - plateau-aware thresholds;
  - the closed-form B against a dense grid;
  - the same-seed Sobol rows.
- Compute budget about 4 h on 4 CPUs. Run datasets sequentially; XGBoost uses all cores.
