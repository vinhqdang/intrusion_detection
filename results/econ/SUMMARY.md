# Summary: game-theoretic evaluation of ML-IDS


> **Read [`OPEN_ISSUES.md`](OPEN_ISSUES.md) first.** An independent review found that the xgb_adv robustness, the optimal FPR and several Sobol rankings below are not supported as stated.

Profile: full. E4 and defender seeds [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]; 1000 attack test flows per family; benign cap 200,000, family cap 10,000. Sobol base N = 4096 (45056 samples per dataset and efficacy setting), 2 random seeds per sample. FPR grid (0.0005, 0.001, 0.003, 0.01); B grid: 200 geometric points in [10, 1e5] plus infinity. Attacker-excluded families (fewer than 300 test flows in a seed): cicids2017: none; cicids2018: none.

## What changed in this round

- Derived features are recomputed by delta updates (Flow IAT Mean, Fwd IAT Mean, Down/Up Ratio, Packet Length Variance/Std) or approximated and labelled (Fwd Packet Length Std, Flow IAT Std/Min). min_seg_size_forward is removed from the length group. Identity hold rates: `e4_feature_groups.md`.
- xgb_robustfeat uses an explicit robust column list (no mutated, derived or timing/size-dependent column).
- The FPR grid has 5e-4 added; the capacity grid is 200 geometric points plus infinity; the defender optimum is exact on that grid; edge hits are reported.
- Exact ties are reported as sets (loss within 1%; AUROC within paired-seed noise), not broken by order.
- The realised benign-test FPR of each threshold enters the alert volume A.
- Attackers: greedy, strong (per-group level search, two starts) and transfer from xgb, for every model. The game uses the worst case over the score attackers. The label attacker is a weak, non-adaptive baseline.
- Equilibria are solved per seed on each seed's own recall tables; the seed-mean solve is a secondary row.
- Sobol outputs and indicators: see X3 below. Indicator (a) covers mutate and novel actions only; reuse of a weak known family is reported separately.

## Headline E4 (xgb and xgb_adv, FPR 1e-3, score query)

Recall of attack flows before and after the attack (mean ± sd over seeds). After = worst case over greedy, strong and transfer, at the budget that is worst on average.

| dataset | model | family | recall before | worst-case recall after | budget |
|---|---|---|---|---|---|
| cicids2017 | xgb | Bot | 0.950 ± 0.029 | 0.541 ± 0.196 | timing+length+count,x5 |
| cicids2017 | xgb | BruteForce | 0.999 ± 0.001 | 0.243 ± 0.201 | timing+length+count,x5 |
| cicids2017 | xgb | DDoS | 0.999 ± 0.001 | 0.654 ± 0.060 | timing+length+count,x5 |
| cicids2017 | xgb | DoS | 0.997 ± 0.002 | 0.923 ± 0.025 | timing+length+count,x5 |
| cicids2017 | xgb | PortScan | 0.997 ± 0.002 | 0.619 ± 0.027 | timing+length+count,x5 |
| cicids2017 | xgb | WebAttack | 0.985 ± 0.005 | 0.829 ± 0.168 | timing+length+count,x5 |
| cicids2017 | xgb_adv | Bot | 0.940 ± 0.040 | 0.890 ± 0.094 | timing+count,x2 |
| cicids2017 | xgb_adv | BruteForce | 0.999 ± 0.001 | 0.969 ± 0.071 | timing+length,x5 |
| cicids2017 | xgb_adv | DDoS | 0.999 ± 0.001 | 0.998 ± 0.001 | timing+length+count,x5 |
| cicids2017 | xgb_adv | DoS | 0.997 ± 0.003 | 0.981 ± 0.003 | timing+length+count,x1.5 |
| cicids2017 | xgb_adv | PortScan | 0.997 ± 0.002 | 0.990 ± 0.012 | timing+length,x5 |
| cicids2017 | xgb_adv | WebAttack | 0.986 ± 0.006 | 0.978 ± 0.006 | timing+length+count,x5 |
| cicids2018 | xgb | Bot | 0.996 ± 0.002 | 0.014 ± 0.006 | timing+length+count,x5 |
| cicids2018 | xgb | BruteForce | 1.000 ± 0.000 | 0.003 ± 0.002 | timing+length+count,x2 |
| cicids2018 | xgb | DDoS | 0.998 ± 0.001 | 0.615 ± 0.035 | timing+length+count,x5 |
| cicids2018 | xgb | DoS | 1.000 ± 0.000 | 0.832 ± 0.013 | timing+length+count,x5 |
| cicids2018 | xgb | Infiltration | 0.123 ± 0.015 | 0.034 ± 0.010 | timing+length+count,x5 |
| cicids2018 | xgb_adv | Bot | 0.995 ± 0.001 | 0.990 ± 0.004 | timing+length+count,x5 |
| cicids2018 | xgb_adv | BruteForce | 1.000 ± 0.001 | 0.999 ± 0.002 | timing+length+count,x5 |
| cicids2018 | xgb_adv | DDoS | 0.998 ± 0.001 | 0.991 ± 0.005 | timing+length+count,x5 |
| cicids2018 | xgb_adv | DoS | 1.000 ± 0.000 | 0.991 ± 0.004 | timing+length+count,x5 |
| cicids2018 | xgb_adv | Infiltration | 0.122 ± 0.016 | 0.093 ± 0.012 | timing+length,x5 |

Full table with per-attacker columns: `e4_headline.md`.

## X2: equilibrium loss versus AUROC (score query)

### cicids2017

| model | AUROC | AUROC-tied with best | loss per seed (mean [95% CI]) | loss-tied share |
|---|---|---|---|---|
| xgb | 0.9998 | yes | 786.2 [661.6, 919.9] | 0.30 |
| fusion | 0.9996 | no | 2,159.3 [1,557.2, 2,811.6] | 0.00 |
| iforest | 0.7118 | no | 50,300.0 [50,256.2, 50,342.5] | 0.00 |
| xgb_robustfeat | 0.9945 | no | 9,720.7 [9,390.3, 10,023.0] | 0.00 |
| xgb_adv | 0.9998 | yes | 633.7 [507.5, 784.0] | 0.70 |

Kendall tau (AUROC rank vs loss rank, tie-aware) per seed: 0.928 [0.885, 0.949]. Modal equilibrium model xgb_adv (xgb:3; xgb_adv:7); optimum on a B-grid edge in 0.00 of seeds, on an FPR edge in 1.00.

### cicids2018

| model | AUROC | AUROC-tied with best | loss per seed (mean [95% CI]) | loss-tied share |
|---|---|---|---|---|
| xgb | 0.9832 | yes | 47,723.4 [47,526.3, 47,917.4] | 0.00 |
| fusion | 0.9717 | no | 47,857.2 [47,718.3, 48,011.0] | 0.00 |
| iforest | 0.6318 | no | 50,272.5 [50,222.5, 50,322.5] | 0.00 |
| xgb_robustfeat | 0.9678 | no | 48,742.9 [48,484.9, 48,987.8] | 0.00 |
| xgb_adv | 0.9831 | yes | 46,363.5 [46,125.7, 46,600.9] | 1.00 |

Kendall tau (AUROC rank vs loss rank, tie-aware) per seed: 0.874 [0.834, 0.907]. Modal equilibrium model xgb_adv (xgb_adv:10); optimum on a B-grid edge in 0.00 of seeds, on an FPR edge in 0.90.

Label-query X2 tables: `x2.md`.

## X3: sensitivity (fractions of the sample grid, bootstrap 95% CI over samples)

Conclusions use the interval: 'holds' when the lower bound is above 0.5, 'does not hold' when the upper bound is below 0.5, otherwise inconclusive.

- cicids2017, efficacy off (n = 90112 sample-seeds):
  - (a) mutate/novel capable action with recall more than 0.2 below mean reuse recall: does not hold on most of the grid, 0.128 [0.125, 0.131].
  - weak known family exploited (reuse, same gap): 0.039 [0.038, 0.041].
  - (b) AUROC-tied and loss-tied sets disjoint: does not hold on most of the grid, 0.055 [0.053, 0.056].
  - (c) regret > 1% from keeping the lam = 1 optimum at lam = 0.05: holds on most of the grid, 0.641 [0.637, 0.645].
  - (c_cfg) optimal (model, FPR, B) changes (old indicator): 0.785 [0.782, 0.789]; (c_act) capable action class changes: 0.770 [0.766, 0.773].
  - deterrence (capable attacker abstains): 0.719; grid edges: B 0.039, FPR 0.886.
- cicids2017, efficacy on (n = 90112 sample-seeds):
  - (a) mutate/novel capable action with recall more than 0.2 below mean reuse recall: does not hold on most of the grid, 0.129 [0.126, 0.132].
  - weak known family exploited (reuse, same gap): 0.040 [0.039, 0.042].
  - (b) AUROC-tied and loss-tied sets disjoint: does not hold on most of the grid, 0.064 [0.062, 0.065].
  - (c) regret > 1% from keeping the lam = 1 optimum at lam = 0.05: holds on most of the grid, 0.622 [0.618, 0.627].
  - (c_cfg) optimal (model, FPR, B) changes (old indicator): 0.770 [0.767, 0.774]; (c_act) capable action class changes: 0.777 [0.774, 0.781].
  - deterrence (capable attacker abstains): 0.719; grid edges: B 0.038, FPR 0.889.
- cicids2018, efficacy off (n = 90112 sample-seeds):
  - (a) mutate/novel capable action with recall more than 0.2 below mean reuse recall: does not hold on most of the grid, 0.087 [0.085, 0.090].
  - weak known family exploited (reuse, same gap): 0.661 [0.657, 0.665].
  - (b) AUROC-tied and loss-tied sets disjoint: does not hold on most of the grid, 0.299 [0.295, 0.303].
  - (c) regret > 1% from keeping the lam = 1 optimum at lam = 0.05: does not hold on most of the grid, 0.480 [0.476, 0.484].
  - (c_cfg) optimal (model, FPR, B) changes (old indicator): 0.652 [0.648, 0.656]; (c_act) capable action class changes: 0.490 [0.486, 0.495].
  - deterrence (capable attacker abstains): 0.252; grid edges: B 0.137, FPR 0.832.
- cicids2018, efficacy on (n = 90112 sample-seeds):
  - (a) mutate/novel capable action with recall more than 0.2 below mean reuse recall: does not hold on most of the grid, 0.087 [0.085, 0.090].
  - weak known family exploited (reuse, same gap): 0.661 [0.657, 0.665].
  - (b) AUROC-tied and loss-tied sets disjoint: does not hold on most of the grid, 0.299 [0.295, 0.303].
  - (c) regret > 1% from keeping the lam = 1 optimum at lam = 0.05: does not hold on most of the grid, 0.481 [0.477, 0.485].
  - (c_cfg) optimal (model, FPR, B) changes (old indicator): 0.653 [0.649, 0.657]; (c_act) capable action class changes: 0.490 [0.486, 0.495].
  - deterrence (capable attacker abstains): 0.252; grid edges: B 0.137, FPR 0.832.

Dataset note: the CSE-CIC-IDS2018 equilibrium is driven by the Infiltration family, whose recall is about 0.12 for xgb (reuse) and is known to be label-noisy; treat the 2018 conclusions as conditional on that family. The weak-family and mutate/novel fractions in the table above are not separated by family.

## Sobol drivers (ST with 95% CI; S1 in x3.md)

### cicids2017, efficacy off

- log10_loss: kN ST 0.698 ± 0.036; N_benign ST 0.127 ± 0.008; N_attack ST 0.106 ± 0.006
- a_mut_nov: kN ST 0.864 ± 0.047; pi ST 0.446 ± 0.041; V/P ST 0.287 ± 0.030
- b_auroc_disjoint: N_benign ST 0.792 ± 0.074; L ST 0.790 ± 0.066; N_attack ST 0.771 ± 0.067
- c_regret: kN ST 0.650 ± 0.034; V/P ST 0.498 ± 0.027; pi ST 0.477 ± 0.024
- tied_xgb: kN ST 0.689 ± 0.032; kM ST 0.680 ± 0.031; N_benign ST 0.396 ± 0.022
- tied_fusion: kN ST 0.893 ± 0.048; kM ST 0.372 ± 0.032; V/P ST 0.306 ± 0.026
- tied_xgb_robustfeat: kN ST 0.730 ± 0.073; V/P ST 0.562 ± 0.063; N_benign ST 0.499 ± 0.052
- tied_xgb_adv: kM ST 0.878 ± 0.040; kN ST 0.676 ± 0.035; V/P ST 0.498 ± 0.030
- class_reuse: kN ST 0.790 ± 0.039; pi ST 0.384 ± 0.034; V/P ST 0.272 ± 0.027
- class_mutate: kN ST 0.844 ± 0.067; kM ST 0.658 ± 0.064; pi ST 0.352 ± 0.048
- class_novel: kN ST 0.842 ± 0.064; pi ST 0.539 ± 0.062; kM ST 0.345 ± 0.052
- class_abstain: kN ST 0.947 ± 0.031; L ST 0.059 ± 0.011; N_attack ST 0.054 ± 0.010
- dropped (prevalence < 5% or > 95%): tied_iforest

### cicids2017, efficacy on

- log10_loss: kN ST 0.698 ± 0.036; N_benign ST 0.127 ± 0.008; N_attack ST 0.106 ± 0.006
- a_mut_nov: kN ST 0.867 ± 0.047; pi ST 0.437 ± 0.041; V/P ST 0.281 ± 0.030
- b_auroc_disjoint: N_benign ST 0.767 ± 0.069; kN ST 0.763 ± 0.060; L ST 0.745 ± 0.062
- c_regret: kN ST 0.658 ± 0.032; pi ST 0.501 ± 0.026; V/P ST 0.488 ± 0.027
- tied_xgb: kM ST 0.718 ± 0.032; kN ST 0.716 ± 0.031; N_benign ST 0.482 ± 0.023
- tied_fusion: kN ST 0.881 ± 0.047; kM ST 0.341 ± 0.028; V/P ST 0.316 ± 0.025
- tied_xgb_robustfeat: kN ST 0.737 ± 0.071; V/P ST 0.554 ± 0.064; N_benign ST 0.492 ± 0.051
- tied_xgb_adv: kM ST 0.879 ± 0.037; kN ST 0.698 ± 0.034; V/P ST 0.539 ± 0.031
- class_reuse: kN ST 0.793 ± 0.039; pi ST 0.378 ± 0.034; V/P ST 0.271 ± 0.028
- class_mutate: kN ST 0.865 ± 0.075; kM ST 0.697 ± 0.071; pi ST 0.318 ± 0.045
- class_novel: kN ST 0.845 ± 0.062; pi ST 0.542 ± 0.061; V/P ST 0.315 ± 0.045
- class_abstain: kN ST 0.948 ± 0.031; L ST 0.058 ± 0.011; N_attack ST 0.054 ± 0.010
- dropped (prevalence < 5% or > 95%): tied_iforest

### cicids2018, efficacy off

- log10_loss: V/P ST 0.483 ± 0.031; N_attack ST 0.260 ± 0.012; L ST 0.251 ± 0.015
- a_mut_nov: kN ST 0.654 ± 0.060; V/P ST 0.630 ± 0.054; pi ST 0.432 ± 0.049
- b_auroc_disjoint: N_attack ST 0.526 ± 0.026; N_benign ST 0.506 ± 0.030; L ST 0.488 ± 0.032
- c_regret: V/P ST 0.626 ± 0.031; kN ST 0.526 ± 0.027; L ST 0.470 ± 0.025
- tied_xgb: kM ST 0.643 ± 0.033; V/P ST 0.434 ± 0.026; N_attack ST 0.398 ± 0.025
- tied_fusion: V/P ST 0.574 ± 0.043; L ST 0.570 ± 0.044; N_benign ST 0.547 ± 0.038
- tied_xgb_robustfeat: L ST 0.495 ± 0.028; N_attack ST 0.492 ± 0.027; N_benign ST 0.469 ± 0.027
- tied_xgb_adv: N_attack ST 0.562 ± 0.028; N_benign ST 0.552 ± 0.029; L ST 0.516 ± 0.029
- class_reuse: V/P ST 0.847 ± 0.032; N_attack ST 0.172 ± 0.016; N_benign ST 0.169 ± 0.018
- class_mutate: V/P ST 0.611 ± 0.062; kN ST 0.567 ± 0.065; kM ST 0.559 ± 0.059
- class_abstain: V/P ST 0.834 ± 0.037; kN ST 0.368 ± 0.028; N_attack ST 0.109 ± 0.015
- dropped (prevalence < 5% or > 95%): tied_iforest, class_novel

### cicids2018, efficacy on

- log10_loss: V/P ST 0.483 ± 0.031; N_attack ST 0.260 ± 0.012; L ST 0.251 ± 0.015
- a_mut_nov: kN ST 0.654 ± 0.060; V/P ST 0.630 ± 0.054; pi ST 0.432 ± 0.049
- b_auroc_disjoint: N_attack ST 0.526 ± 0.026; N_benign ST 0.506 ± 0.030; L ST 0.488 ± 0.032
- c_regret: V/P ST 0.625 ± 0.031; kN ST 0.525 ± 0.027; L ST 0.470 ± 0.025
- tied_xgb: kM ST 0.642 ± 0.033; V/P ST 0.434 ± 0.026; N_attack ST 0.398 ± 0.025
- tied_fusion: V/P ST 0.575 ± 0.043; L ST 0.570 ± 0.044; N_benign ST 0.547 ± 0.038
- tied_xgb_robustfeat: L ST 0.495 ± 0.028; N_attack ST 0.491 ± 0.027; N_benign ST 0.469 ± 0.027
- tied_xgb_adv: N_attack ST 0.562 ± 0.028; N_benign ST 0.553 ± 0.029; L ST 0.516 ± 0.029
- class_reuse: V/P ST 0.847 ± 0.032; N_attack ST 0.172 ± 0.016; N_benign ST 0.169 ± 0.018
- class_mutate: V/P ST 0.610 ± 0.062; kN ST 0.566 ± 0.065; kM ST 0.558 ± 0.059
- class_abstain: V/P ST 0.834 ± 0.037; kN ST 0.368 ± 0.028; N_attack ST 0.109 ± 0.015
- dropped (prevalence < 5% or > 95%): tied_iforest, class_novel

## X4: AI uplift

- cicids2017: modal capable class switches: abstain -> mutate at lam = 0.336; mutate -> novel at lam = 0.0234
- cicids2018: modal capable class switches: reuse -> mutate at lam = 0.207
- The cicids2017 novelty switch equals V/kN by construction when the worst unseen-family recall is about 0: novel is then undetected, its utility is V - lam kN, and the attacker switches when lam kN = V. With V = 1000 and kN = 3000 this is lam = 0.333.

## Thesis claim 3 (not tested)

Claim 3 of the design (defender investment moves from supervised accuracy towards novelty detection, label budget and analyst capacity as AI uplift grows) is NOT tested by this model set. The defender's choices here are over five detectors and FPR and B only; no novelty-detection investment, label budget or learning-with-labels option is in the action space. The lam sweep shows how the optimum changes, but not that a shift toward novelty detection is optimal.

## Label-mode attacker

The label-mode attacker (alert / no alert only, one random order per flow, its RNG keyed on the budget label and seed) is a weak, non-adaptive baseline. It is reported in `e4_headline_label.md` and in the X2 label tables, not in the game's primary tables.

## Limitations

- Feature space only: mutations change CICFlowMeter feature vectors, not packets. Problem-space realisability is not established (arXiv 2005.07519).
- Lab datasets (CIC-IDS2017, CSE-CIC-IDS2018). The AI-uplift results are for these two captures only.
- Reference parameters (V, P, L, w, cB, kM, kN, N_benign, N_attack) are illustrative. Conclusions rest on the X3 intervals over the sampled ranges, not on point values.
- Identity rules hold on a share of rows (see `e4_feature_groups.md`); the rest keep their offset (delta update). Fwd Packet Length Std, Flow IAT Std and Flow IAT Min are approximations that cannot be checked on the cache.
- Only increase-only timing and padding are modelled; the attacker cannot reduce any feature.
- Efficacy is a stated assumption (timing mutation reduces the gain of DoS, DDoS, BruteForce and PortScan by 1/m). The defender's breach loss L is not scaled by efficacy.
- The alert volume uses the realised benign-test FPR of each threshold, so A = fpr_real N_benign + N_attack.
- Adversarial training (xgb_adv) uses one augmentation round at the full budget (multiplier 5) against the base xgb; it is evaluated against the greedy, strong and transfer attackers.
- Seeds: 10 for E4 and leave-one-family-out. X2 and X4 use every seed; X3 uses 2 random seeds per sample (compute). Bootstrap CIs resample seeds (X2, X4) or samples (X3).
- Only the feature-space E4 measurement feeds the game; E3 transfer rows are not in the game.
- Infiltration (CSE-CIC-IDS2018) is label-noisy and drives the 2018 equilibrium (recall about 0.12).

## Runtime and deviations

- Wall-clock time of this run: 87.7 min (4 worker processes for X3).

