# Game (cost lens) on the robustness results

Parameters: reference values of econ.game (V = 1000, P = 2000, L = 1000, w = 0.5, cB = 2, kM = 100, kN = 3000, pi = 0.5, N_benign = 1e6, N_attack = 50), lam = 1 unless stated, rho = 0 unless stated. Illustrative, see the sensitivity (Sobol) rows. Detection input: worst case over generators (G1, G2) and attackers. Capacity: closed form at the deterrence point, plus a geometric grid in x = B/A with step 0.5%.

Profile: full; Sobol base N = 128 (1536 samples per dataset, efficacy setting and seed pair). Seed pairs (recorded): {'cicids2017': {'seeds': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'families': ['Bot', 'BruteForce', 'DDoS', 'DoS', 'PortScan', 'WebAttack'], 'pair1': [0, 9], 'pair2': [3, 7], 'auroc_best': 'xgb', 'auroc_tied': ['adv_naive_G1', 'adv_sym_G1', 'adv_sym_G1G2', 'xgb']}, 'cicids2018': {'seeds': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'families': ['Bot', 'BruteForce', 'DDoS', 'DoS', 'Infiltration'], 'pair1': [0, 9], 'pair2': [3, 7], 'auroc_best': 'adv_sym_G1G2', 'auroc_tied': ['adv_sym_G1', 'adv_sym_G1G2', 'xgb']}}.

## Equilibrium per seed (lam = 1, rho = 0, efficacy on)

### cicids2017

- modal equilibrium model: xgb_robust (counts: {'xgb_robust': 10})
- loss mean [95% CI over seeds]: 10,450.5 [10,157.9, 10,831.2]
- lower FPR edge (1e-4) share of seeds: 0.00; upper FPR edge (1e-2): 1.00; upper B edge (x = 1): 0.00; lower B edge (x = 0.01): 0.00; closed-form optimum: 1.00
- modal capable class: abstain

| model | loss mean (per seed) | share of seeds in loss-tied set |
|---|---|---|
| xgb | 23,019.9 | 0.00 |
| fusion | 23,350.7 | 0.00 |
| iforest | 50,075.8 | 0.00 |
| xgb_robust | 10,450.5 | 1.00 |
| adv_naive_G1 | 23,138.8 | 0.00 |
| adv_sym_G1 | 23,098.4 | 0.00 |
| adv_sym_G1G2 | 14,345.5 | 0.00 |

### cicids2018

- modal equilibrium model: adv_sym_G1 (counts: {'adv_sym_G1': 5, 'adv_sym_G1G2': 5})
- loss mean [95% CI over seeds]: 45,773.5 [45,557.4, 45,980.5]
- lower FPR edge (1e-4) share of seeds: 0.00; upper FPR edge (1e-2): 0.00; upper B edge (x = 1): 1.00; lower B edge (x = 0.01): 0.00; closed-form optimum: 0.00
- modal capable class: reuse

| model | loss mean (per seed) | share of seeds in loss-tied set |
|---|---|---|
| xgb | 47,175.5 | 0.20 |
| fusion | 47,562.7 | 0.00 |
| iforest | 50,063.0 | 0.00 |
| xgb_robust | 48,412.2 | 0.00 |
| adv_naive_G1 | 46,017.5 | 1.00 |
| adv_sym_G1 | 45,812.2 | 1.00 |
| adv_sym_G1G2 | 45,842.6 | 1.00 |

## Sensitivity to the mutated-benign share rho (lam = 1)

| dataset | rho | mean loss [95% CI] | modal equilibrium model | share upper FPR edge |
|---|---|---|---|---|
| cicids2017 | 0 | 10,450.5 [10,157.9, 10,831.2] | xgb_robust | 1.00 |
| cicids2017 | 0.1 | 10,450.5 [10,157.9, 10,831.2] | xgb_robust | 1.00 |
| cicids2017 | 0.2 | 10,450.5 [10,157.9, 10,831.2] | xgb_robust | 1.00 |
| cicids2018 | 0 | 45,773.5 [45,557.4, 45,980.5] | adv_sym_G1 | 0.00 |
| cicids2018 | 0.1 | 47,222.0 [46,848.4, 47,527.9] | xgb | 0.00 |
| cicids2018 | 0.2 | 47,299.7 [46,941.9, 47,587.6] | xgb | 0.00 |

## Sobol indicators (fixed seed pair; mean over samples; bootstrap 95% CI over samples)

| dataset | efficacy | pair | (a) mut/novel weak | (a_weak) reuse weak | (b) AUROC-tied and loss-tied disjoint | (c) regret at lam = 0.05 | (d) model changes, rho 0 -> 0.1 | closed-form optimum |
|---|---|---|---|---|---|---|---|---|
| cicids2017 | off | 1 | 0.282 [0.259, 0.305] | 0.126 [0.110, 0.142] | 0.261 [0.241, 0.282] | 0.729 [0.708, 0.751] | 0.068 [0.059, 0.077] | 0.571 [0.546, 0.595] |
| cicids2017 | off | 2 | 0.269 [0.247, 0.291] | 0.131 [0.114, 0.147] | 0.339 [0.317, 0.360] | 0.746 [0.725, 0.767] | 0.127 [0.114, 0.140] | 0.583 [0.559, 0.607] |
| cicids2017 | on | 1 | 0.282 [0.259, 0.305] | 0.126 [0.110, 0.142] | 0.261 [0.241, 0.282] | 0.729 [0.708, 0.751] | 0.068 [0.059, 0.077] | 0.571 [0.546, 0.595] |
| cicids2017 | on | 2 | 0.269 [0.247, 0.291] | 0.131 [0.114, 0.147] | 0.339 [0.317, 0.360] | 0.744 [0.723, 0.765] | 0.129 [0.116, 0.142] | 0.583 [0.559, 0.607] |
| cicids2018 | off | 1 | 0.062 [0.050, 0.074] | 0.638 [0.616, 0.661] | 0.290 [0.268, 0.311] | 0.639 [0.617, 0.661] | 0.462 [0.442, 0.482] | 0.249 [0.227, 0.271] |
| cicids2018 | off | 2 | 0.062 [0.052, 0.073] | 0.594 [0.572, 0.617] | 0.331 [0.309, 0.353] | 0.637 [0.614, 0.659] | 0.539 [0.516, 0.560] | 0.282 [0.259, 0.304] |
| cicids2018 | on | 1 | 0.062 [0.050, 0.074] | 0.638 [0.616, 0.661] | 0.290 [0.268, 0.311] | 0.639 [0.617, 0.661] | 0.462 [0.442, 0.482] | 0.249 [0.227, 0.271] |
| cicids2018 | on | 2 | 0.062 [0.052, 0.073] | 0.594 [0.572, 0.617] | 0.331 [0.309, 0.353] | 0.637 [0.614, 0.659] | 0.539 [0.516, 0.560] | 0.282 [0.259, 0.304] |

## Sobol first-order and total indices (rows with S1 sum < 0.1 are labelled noise-floor)

- cicids2017, efficacy off, pair 1, a_mut_nov [kept]: kN S1 0.116, ST 0.423; V/P S1 -0.075, ST 0.409; pi S1 0.119, ST 0.336
- cicids2017, efficacy off, pair 1, a_weak_reuse [noise-floor]: pi S1 0.037, ST 0.491; kN S1 0.005, ST 0.443; V/P S1 0.203, ST 0.406
- cicids2017, efficacy off, pair 1, b_auroc_disjoint [kept]: V/P S1 0.210, ST 0.744; kM S1 0.105, ST 0.395; kN S1 0.081, ST 0.395
- cicids2017, efficacy off, pair 1, c_regret [noise-floor]: kN S1 0.051, ST 0.540; V/P S1 -0.133, ST 0.405; kM S1 -0.089, ST 0.280
- cicids2017, efficacy off, pair 1, d_model_change [kept]: kM S1 0.143, ST 0.911; N_attack S1 -0.018, ST 0.869; V/P S1 0.049, ST 0.787
- cicids2017, efficacy off, pair 1, log10_loss [kept]: kN S1 0.153, ST 0.361; V/P S1 0.119, ST 0.269; N_attack S1 0.103, ST 0.137
- cicids2017, efficacy off, pair 2, a_mut_nov [kept]: kN S1 0.156, ST 0.426; V/P S1 -0.106, ST 0.397; pi S1 0.121, ST 0.358
- cicids2017, efficacy off, pair 2, a_weak_reuse [noise-floor]: pi S1 0.069, ST 0.487; kN S1 -0.022, ST 0.478; V/P S1 0.188, ST 0.469
- cicids2017, efficacy off, pair 2, b_auroc_disjoint [noise-floor]: V/P S1 0.015, ST 0.789; N_benign S1 -0.031, ST 0.389; kN S1 0.039, ST 0.378
- cicids2017, efficacy off, pair 2, c_regret [noise-floor]: kN S1 -0.015, ST 0.677; V/P S1 -0.146, ST 0.315; kM S1 -0.115, ST 0.273
- cicids2017, efficacy off, pair 2, d_model_change [noise-floor]: N_benign S1 -0.204, ST 0.859; kM S1 0.085, ST 0.592; V/P S1 -0.020, ST 0.578
- cicids2017, efficacy off, pair 2, log10_loss [kept]: kN S1 0.156, ST 0.365; V/P S1 0.111, ST 0.250; N_attack S1 0.092, ST 0.138
- cicids2017, efficacy on, pair 1, a_mut_nov [kept]: kN S1 0.116, ST 0.423; V/P S1 -0.075, ST 0.409; pi S1 0.119, ST 0.336
- cicids2017, efficacy on, pair 1, a_weak_reuse [noise-floor]: pi S1 0.037, ST 0.491; kN S1 0.005, ST 0.443; V/P S1 0.203, ST 0.406
- cicids2017, efficacy on, pair 1, b_auroc_disjoint [kept]: V/P S1 0.210, ST 0.744; kM S1 0.105, ST 0.395; kN S1 0.081, ST 0.395
- cicids2017, efficacy on, pair 1, c_regret [noise-floor]: kN S1 0.051, ST 0.540; V/P S1 -0.133, ST 0.405; kM S1 -0.089, ST 0.280
- cicids2017, efficacy on, pair 1, d_model_change [kept]: kM S1 0.143, ST 0.911; N_attack S1 -0.018, ST 0.869; V/P S1 0.049, ST 0.787
- cicids2017, efficacy on, pair 1, log10_loss [kept]: kN S1 0.153, ST 0.361; V/P S1 0.119, ST 0.269; N_attack S1 0.103, ST 0.137
- cicids2017, efficacy on, pair 2, a_mut_nov [kept]: kN S1 0.156, ST 0.426; V/P S1 -0.106, ST 0.397; pi S1 0.121, ST 0.358
- cicids2017, efficacy on, pair 2, a_weak_reuse [noise-floor]: pi S1 0.069, ST 0.487; kN S1 -0.022, ST 0.478; V/P S1 0.188, ST 0.469
- cicids2017, efficacy on, pair 2, b_auroc_disjoint [noise-floor]: V/P S1 0.015, ST 0.789; N_benign S1 -0.031, ST 0.389; kN S1 0.039, ST 0.378
- cicids2017, efficacy on, pair 2, c_regret [noise-floor]: kN S1 -0.020, ST 0.655; V/P S1 -0.119, ST 0.296; pi S1 -0.004, ST 0.296
- cicids2017, efficacy on, pair 2, d_model_change [noise-floor]: N_benign S1 -0.212, ST 0.873; kM S1 0.085, ST 0.592; V/P S1 -0.019, ST 0.578
- cicids2017, efficacy on, pair 2, log10_loss [kept]: kN S1 0.156, ST 0.365; V/P S1 0.111, ST 0.250; N_attack S1 0.092, ST 0.138
- cicids2018, efficacy off, pair 1, a_mut_nov [kept]: V/P S1 0.273, ST 0.796; pi S1 0.204, ST 0.741; kN S1 -0.009, ST 0.370
- cicids2018, efficacy off, pair 1, a_weak_reuse [kept]: V/P S1 0.555, ST 0.920; L S1 -0.054, ST 0.221; pi S1 0.036, ST 0.177
- cicids2018, efficacy off, pair 1, b_auroc_disjoint [noise-floor]: V/P S1 0.079, ST 0.484; N_attack S1 -0.141, ST 0.446; L S1 -0.101, ST 0.359
- cicids2018, efficacy off, pair 1, c_regret [kept]: N_attack S1 0.078, ST 0.429; V/P S1 -0.071, ST 0.410; L S1 0.118, ST 0.405
- cicids2018, efficacy off, pair 1, d_model_change [noise-floor]: V/P S1 -0.103, ST 0.648; N_attack S1 -0.126, ST 0.636; L S1 -0.229, ST 0.575
- cicids2018, efficacy off, pair 1, log10_loss [kept]: V/P S1 0.225, ST 0.474; L S1 0.238, ST 0.308; N_attack S1 0.213, ST 0.302
- cicids2018, efficacy off, pair 2, a_mut_nov [kept]: V/P S1 0.155, ST 0.840; pi S1 0.033, ST 0.840; kN S1 0.260, ST 0.508
- cicids2018, efficacy off, pair 2, a_weak_reuse [kept]: V/P S1 0.685, ST 1.006; L S1 0.017, ST 0.186; cB S1 -0.025, ST 0.161
- cicids2018, efficacy off, pair 2, b_auroc_disjoint [noise-floor]: N_attack S1 -0.116, ST 0.489; V/P S1 0.044, ST 0.432; cB S1 -0.078, ST 0.370
- cicids2018, efficacy off, pair 2, c_regret [kept]: L S1 0.131, ST 0.467; N_attack S1 0.060, ST 0.457; V/P S1 -0.042, ST 0.419
- cicids2018, efficacy off, pair 2, d_model_change [kept]: N_attack S1 0.011, ST 0.558; V/P S1 0.096, ST 0.527; L S1 0.033, ST 0.495
- cicids2018, efficacy off, pair 2, log10_loss [kept]: V/P S1 0.299, ST 0.518; N_attack S1 0.201, ST 0.289; L S1 0.197, ST 0.274
- cicids2018, efficacy on, pair 1, a_mut_nov [kept]: V/P S1 0.273, ST 0.796; pi S1 0.204, ST 0.741; kN S1 -0.009, ST 0.370
- cicids2018, efficacy on, pair 1, a_weak_reuse [kept]: V/P S1 0.555, ST 0.920; L S1 -0.054, ST 0.221; pi S1 0.036, ST 0.177
- cicids2018, efficacy on, pair 1, b_auroc_disjoint [noise-floor]: V/P S1 0.079, ST 0.484; N_attack S1 -0.141, ST 0.446; L S1 -0.101, ST 0.359
- cicids2018, efficacy on, pair 1, c_regret [kept]: N_attack S1 0.078, ST 0.429; V/P S1 -0.071, ST 0.410; L S1 0.118, ST 0.405
- cicids2018, efficacy on, pair 1, d_model_change [noise-floor]: V/P S1 -0.103, ST 0.648; N_attack S1 -0.126, ST 0.636; L S1 -0.229, ST 0.575
- cicids2018, efficacy on, pair 1, log10_loss [kept]: V/P S1 0.225, ST 0.474; L S1 0.238, ST 0.308; N_attack S1 0.213, ST 0.302
- cicids2018, efficacy on, pair 2, a_mut_nov [kept]: V/P S1 0.155, ST 0.840; pi S1 0.033, ST 0.840; kN S1 0.260, ST 0.508
- cicids2018, efficacy on, pair 2, a_weak_reuse [kept]: V/P S1 0.685, ST 1.006; L S1 0.017, ST 0.186; cB S1 -0.025, ST 0.161
- cicids2018, efficacy on, pair 2, b_auroc_disjoint [noise-floor]: N_attack S1 -0.116, ST 0.489; V/P S1 0.044, ST 0.432; cB S1 -0.078, ST 0.370
- cicids2018, efficacy on, pair 2, c_regret [kept]: L S1 0.131, ST 0.467; N_attack S1 0.060, ST 0.457; V/P S1 -0.042, ST 0.419
- cicids2018, efficacy on, pair 2, d_model_change [kept]: N_attack S1 0.011, ST 0.558; V/P S1 0.096, ST 0.527; L S1 0.033, ST 0.495
- cicids2018, efficacy on, pair 2, log10_loss [kept]: V/P S1 0.299, ST 0.518; N_attack S1 0.201, ST 0.289; L S1 0.197, ST 0.274

Indicator (d) asks whether the equilibrium defender changes when rho goes from 0 to 0.1; (c) compares the lam = 1 optimum with the lam = 0.05 loss, as in the round-3 game.

