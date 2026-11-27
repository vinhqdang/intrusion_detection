# Robustness study: SUMMARY

Datasets: cicids2017, cicids2018. Seeds: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]. E4 attack flows per family: 1000. Benign cap 600,000, family cap 10,000; split train 60% / calibration 20% / test 20% (benign), 70/30 (families). Benign test rows per seed: cicids2017 120,000, cicids2018 85,822. Augmentation: n_aug = 2000 attack copies per family. FPR grid 0.0001, 0.0005, 0.001, 0.01. Budgets: 7 group subsets x multipliers 1.5, 2, 5 (21) per generator. Attackers: greedy, strong, transfer (from xgb; not for xgb). LOFO models: xgb, fusion, iforest, xgb_robust, adv_naive_G1, adv_sym_G1, adv_sym_G1G2. Wall-clock time of the run: 199.1 min. Attack-excluded families: test rows < 300.

## Realism diagnostics

Fingerprint AUROC (XGBoost separating x from G(x) on benign training rows of seed 0, held-out half; 0.5 = indistinguishable). Cross-generator AUROC: G1(x) against G2(x) at matched budgets.

| dataset | generator | group | fingerprint AUROC | top features (gain) |
|---|---|---|---|---|
| cicids2017 | G1 | timing | 0.9940 |  |
| cicids2017 | G1 | length | 0.9772 |  |
| cicids2017 | G1 | count | 0.9997 |  |
| cicids2017 | G1 | all | 0.9841 | Down/Up Ratio, Fwd Packet Length Min, Fwd IAT Mean, Fwd IAT Total, Fwd IAT Min |
| cicids2017 | G2 | timing | 0.9689 |  |
| cicids2017 | G2 | length | 0.9658 |  |
| cicids2017 | G2 | count | 0.9998 |  |
| cicids2017 | G2 | all | 0.9776 | Down/Up Ratio, Active Max, Active Min, Idle Max, Fwd IAT Mean |
| cicids2018 | G1 | timing | 0.9946 |  |
| cicids2018 | G1 | length | 0.9822 |  |
| cicids2018 | G1 | count | 0.9999 |  |
| cicids2018 | G1 | all | 0.9904 | Bwd Pkt Len Min, Subflow Fwd Byts, Pkt Len Max, Down/Up Ratio, Subflow Fwd Pkts |
| cicids2018 | G2 | timing | 0.9860 |  |
| cicids2018 | G2 | length | 0.9775 |  |
| cicids2018 | G2 | count | 0.9999 |  |
| cicids2018 | G2 | all | 0.9885 | Active Max, Active Min, Down/Up Ratio, Pkt Len Mean, Subflow Fwd Pkts |

| dataset | pair | cross-generator AUROC |
|---|---|---|
| cicids2017 | G1 vs G2 | 0.9903 |
| cicids2018 | G1 vs G2 | 0.9925 |

Identity hold rates (share of rows where the rule holds; mean over seeds; original flows and flows after all groups at x5):

| dataset | sample | rule | rows | holds |
|---|---|---|---|---|
| cicids2017 | G1 all groups x5 | average packet size | 5000 | 0.3967 |
| cicids2017 | G1 all groups x5 | bwd packets/s | 4999 | 1.0000 |
| cicids2017 | G1 all groups x5 | down/up ratio | 5000 | 1.0000 |
| cicids2017 | G1 all groups x5 | flow bytes/s | 4999 | 1.0000 |
| cicids2017 | G1 all groups x5 | flow iat mean | 5000 | 1.0000 |
| cicids2017 | G1 all groups x5 | flow iat min = fwd iat min | 4993 | 0.4213 |
| cicids2017 | G1 all groups x5 | flow packets/s | 4999 | 1.0000 |
| cicids2017 | G1 all groups x5 | fwd iat mean | 5000 | 1.0000 |
| cicids2017 | G1 all groups x5 | fwd packets/s | 4999 | 1.0000 |
| cicids2017 | G1 all groups x5 | max packet length | 5000 | 1.0000 |
| cicids2017 | G1 all groups x5 | min packet length | 5000 | 1.0000 |
| cicids2017 | G1 all groups x5 | packet length mean | 5000 | 0.2656 |
| cicids2017 | G1 all groups x5 | packet length variance | 5000 | 0.9994 |
| cicids2017 | G1 all groups x5 | packet length variance (pooled) | 1 | 0.3797 |
| cicids2017 | G2 all groups x5 | average packet size | 5000 | 0.3929 |
| cicids2017 | G2 all groups x5 | bwd packets/s | 4999 | 1.0000 |
| cicids2017 | G2 all groups x5 | down/up ratio | 5000 | 1.0000 |
| cicids2017 | G2 all groups x5 | flow bytes/s | 4999 | 1.0000 |
| cicids2017 | G2 all groups x5 | flow iat mean | 5000 | 1.0000 |
| cicids2017 | G2 all groups x5 | flow iat min = fwd iat min | 4993 | 0.4213 |
| cicids2017 | G2 all groups x5 | flow packets/s | 4999 | 1.0000 |
| cicids2017 | G2 all groups x5 | fwd iat mean | 5000 | 1.0000 |
| cicids2017 | G2 all groups x5 | fwd packets/s | 4999 | 1.0000 |
| cicids2017 | G2 all groups x5 | max packet length | 5000 | 1.0000 |
| cicids2017 | G2 all groups x5 | min packet length | 5000 | 1.0000 |
| cicids2017 | G2 all groups x5 | packet length mean | 5000 | 0.1934 |
| cicids2017 | G2 all groups x5 | packet length variance | 5000 | 0.9993 |
| cicids2017 | G2 all groups x5 | packet length variance (pooled) | 1 | 0.2693 |
| cicids2017 | original | average packet size | 5000 | 0.3934 |
| cicids2017 | original | bwd packets/s | 4999 | 1.0000 |
| cicids2017 | original | down/up ratio | 5000 | 1.0000 |
| cicids2017 | original | flow bytes/s | 4999 | 1.0000 |
| cicids2017 | original | flow iat mean | 5000 | 1.0000 |
| cicids2017 | original | flow iat min = fwd iat min | 4993 | 0.4213 |
| cicids2017 | original | flow packets/s | 4999 | 1.0000 |
| cicids2017 | original | fwd iat mean | 3822 | 1.0000 |
| cicids2017 | original | fwd packets/s | 4999 | 1.0000 |
| cicids2017 | original | max packet length | 5000 | 1.0000 |
| cicids2017 | original | min packet length | 5000 | 0.9611 |
| cicids2017 | original | packet length mean | 5000 | 0.2040 |
| cicids2017 | original | packet length variance | 5000 | 1.0000 |
| cicids2017 | original | packet length variance (pooled) | 1 | 0.2175 |
| cicids2018 | G1 all groups x5 | average packet size | 5000 | 0.7611 |
| cicids2018 | G1 all groups x5 | bwd packets/s | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | down/up ratio | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | flow bytes/s | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | flow iat mean | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | flow iat min = fwd iat min | 5000 | 0.3532 |
| cicids2018 | G1 all groups x5 | flow packets/s | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | fwd iat mean | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | fwd packets/s | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | max packet length | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | min packet length | 5000 | 1.0000 |
| cicids2018 | G1 all groups x5 | packet length mean | 5000 | 0.1881 |
| cicids2018 | G1 all groups x5 | packet length variance | 5000 | 0.9999 |
| cicids2018 | G1 all groups x5 | packet length variance (pooled) | 1 | 0.2720 |
| cicids2018 | G2 all groups x5 | average packet size | 5000 | 0.7596 |
| cicids2018 | G2 all groups x5 | bwd packets/s | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | down/up ratio | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | flow bytes/s | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | flow iat mean | 5000 | 0.9999 |
| cicids2018 | G2 all groups x5 | flow iat min = fwd iat min | 5000 | 0.3532 |
| cicids2018 | G2 all groups x5 | flow packets/s | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | fwd iat mean | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | fwd packets/s | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | max packet length | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | min packet length | 5000 | 1.0000 |
| cicids2018 | G2 all groups x5 | packet length mean | 5000 | 0.1593 |
| cicids2018 | G2 all groups x5 | packet length variance | 5000 | 0.9999 |
| cicids2018 | G2 all groups x5 | packet length variance (pooled) | 1 | 0.1867 |
| cicids2018 | original | average packet size | 5000 | 0.7600 |
| cicids2018 | original | bwd packets/s | 5000 | 1.0000 |
| cicids2018 | original | down/up ratio | 5000 | 1.0000 |
| cicids2018 | original | flow bytes/s | 5000 | 1.0000 |
| cicids2018 | original | flow iat mean | 5000 | 1.0000 |
| cicids2018 | original | flow iat min = fwd iat min | 5000 | 0.3532 |
| cicids2018 | original | flow packets/s | 5000 | 1.0000 |
| cicids2018 | original | fwd iat mean | 4172 | 1.0000 |
| cicids2018 | original | fwd packets/s | 5000 | 1.0000 |
| cicids2018 | original | max packet length | 5000 | 1.0000 |
| cicids2018 | original | min packet length | 5000 | 0.9890 |
| cicids2018 | original | packet length mean | 5000 | 0.1641 |
| cicids2018 | original | packet length variance | 5000 | 1.0000 |
| cicids2018 | original | packet length variance (pooled) | 1 | 0.1705 |

## Headline table (FPR 1e-3; mean [95% bootstrap CI over seeds])

Clean recall: macro over families (known scenario). Worst-case recall: per family the minimum over attackers and budgets, macro over families. Mutated-benign FPR: benign test flows with random budgets at the clean threshold. Realised benign-test FPR: the share of benign test flows above the threshold (mean over seeds with bootstrap CI; pooled over seeds with a Wilson 95% interval on the pooled counts).

| dataset | defender | clean recall | worst-case recall G1 | worst-case recall G2 | mutated-benign FPR G1 | mutated-benign FPR G2 | realised test FPR | realised test FPR, pooled [Wilson 95%] |
|---|---|---|---|---|---|---|---|---|
| cicids2017 | adv_naive_G1 | 0.992 [0.989, 0.994] | 0.980 [0.976, 0.984] | 0.723 [0.698, 0.746] | 0.0182 [0.0162, 0.0203] | 0.0141 [0.0123, 0.0160] | 9.27e-04 [8.50e-04, 1.01e-03] | 9.28e-04 [8.75e-04, 9.84e-04] |
| cicids2017 | adv_sym_G1 | 0.992 [0.990, 0.994] | 0.968 [0.957, 0.978] | 0.720 [0.694, 0.742] | 0.0023 [0.0019, 0.0027] | 0.0021 [0.0016, 0.0026] | 9.40e-04 [8.79e-04, 1.01e-03] | 9.40e-04 [8.87e-04, 9.96e-04] |
| cicids2017 | adv_sym_G1G2 | 0.993 [0.992, 0.994] | 0.965 [0.951, 0.978] | 0.804 [0.788, 0.820] | 0.0026 [0.0022, 0.0029] | 0.0032 [0.0027, 0.0038] | 9.52e-04 [8.72e-04, 1.04e-03] | 9.52e-04 [8.98e-04, 1.01e-03] |
| cicids2017 | fusion | 0.970 [0.965, 0.975] | 0.567 [0.551, 0.589] | 0.376 [0.355, 0.399] | 0.0025 [0.0021, 0.0029] | 0.0026 [0.0021, 0.0030] | 9.26e-04 [8.09e-04, 1.04e-03] | 9.26e-04 [8.73e-04, 9.82e-04] |
| cicids2017 | iforest | 0.000 [0.000, 0.000] | n/a | n/a | 0.0031 [0.0028, 0.0034] | 0.0026 [0.0024, 0.0029] | 9.59e-04 [8.67e-04, 1.05e-03] | 9.59e-04 [9.05e-04, 1.02e-03] |
| cicids2017 | xgb | 0.993 [0.991, 0.994] | 0.695 [0.663, 0.730] | 0.447 [0.425, 0.471] | 0.0023 [0.0019, 0.0026] | 0.0030 [0.0026, 0.0034] | 9.34e-04 [8.55e-04, 1.02e-03] | 9.34e-04 [8.81e-04, 9.90e-04] |
| cicids2017 | xgb_robust | 0.556 [0.541, 0.572] | 0.556 [0.541, 0.571] | 0.556 [0.541, 0.571] | 0.0001 [0.0001, 0.0002] | 0.0001 [0.0001, 0.0002] | 1.46e-04 [8.00e-05, 2.12e-04] | 1.46e-04 [1.26e-04, 1.69e-04] |
| cicids2018 | adv_naive_G1 | 0.823 [0.823, 0.824] | 0.808 [0.804, 0.812] | 0.784 [0.777, 0.790] | 0.3303 [0.3168, 0.3448] | 0.1195 [0.1108, 0.1290] | 9.74e-04 [9.04e-04, 1.05e-03] | 9.74e-04 [9.10e-04, 1.04e-03] |
| cicids2018 | adv_sym_G1 | 0.824 [0.823, 0.825] | 0.804 [0.800, 0.807] | 0.793 [0.788, 0.797] | 0.0164 [0.0149, 0.0181] | 0.0074 [0.0064, 0.0086] | 9.88e-04 [9.02e-04, 1.06e-03] | 9.88e-04 [9.24e-04, 1.06e-03] |
| cicids2018 | adv_sym_G1G2 | 0.824 [0.823, 0.825] | 0.803 [0.799, 0.807] | 0.807 [0.803, 0.811] | 0.0169 [0.0149, 0.0190] | 0.0162 [0.0148, 0.0175] | 9.57e-04 [8.54e-04, 1.05e-03] | 9.57e-04 [8.93e-04, 1.02e-03] |
| cicids2018 | fusion | 0.820 [0.819, 0.822] | 0.275 [0.271, 0.280] | 0.275 [0.273, 0.277] | 0.0018 [0.0014, 0.0024] | 0.0012 [0.0010, 0.0015] | 9.74e-04 [8.26e-04, 1.13e-03] | 9.74e-04 [9.10e-04, 1.04e-03] |
| cicids2018 | iforest | 0.000 [0.000, 0.000] | n/a | n/a | 0.0021 [0.0017, 0.0024] | 0.0014 [0.0012, 0.0016] | 9.31e-04 [7.98e-04, 1.05e-03] | 9.31e-04 [8.69e-04, 9.98e-04] |
| cicids2018 | xgb | 0.824 [0.823, 0.825] | 0.285 [0.280, 0.289] | 0.282 [0.279, 0.285] | 0.0031 [0.0016, 0.0051] | 0.0017 [0.0010, 0.0028] | 1.02e-03 [9.40e-04, 1.09e-03] | 1.02e-03 [9.53e-04, 1.09e-03] |
| cicids2018 | xgb_robust | 0.776 [0.775, 0.777] | 0.777 [0.775, 0.778] | 0.777 [0.775, 0.778] | 0.0010 [0.0009, 0.0011] | 0.0010 [0.0009, 0.0011] | 1.02e-03 [9.48e-04, 1.11e-03] | 1.02e-03 [9.59e-04, 1.09e-03] |

## CSE-CIC-IDS2018 without Infiltration (label-noisy family excluded from the macro over families)

Same definitions as the headline table, with the Infiltration family removed from the clean and worst-case macros. The mutated-benign FPR is computed on the benign test rows and the thresholds of the models, which the family choice does not change, so its values equal the headline values.

| defender | clean recall | worst-case recall G1 | worst-case recall G2 | mutated-benign FPR G1 | mutated-benign FPR G2 |
|---|---|---|---|---|---|
| adv_naive_G1 | 0.999 [0.998, 0.999] | 0.987 [0.982, 0.991] | 0.961 [0.953, 0.970] | 0.3303 [0.3168, 0.3448] | 0.1195 [0.1108, 0.1290] |
| adv_sym_G1 | 0.999 [0.998, 0.999] | 0.984 [0.979, 0.988] | 0.973 [0.967, 0.978] | 0.0164 [0.0149, 0.0181] | 0.0074 [0.0064, 0.0086] |
| adv_sym_G1G2 | 0.999 [0.998, 0.999] | 0.983 [0.979, 0.988] | 0.986 [0.981, 0.991] | 0.0169 [0.0149, 0.0190] | 0.0162 [0.0148, 0.0175] |
| fusion | 0.998 [0.998, 0.998] | 0.339 [0.334, 0.345] | 0.338 [0.335, 0.341] | 0.0018 [0.0014, 0.0024] | 0.0012 [0.0010, 0.0015] |
| iforest | 0.000 [0.000, 0.000] | n/a | n/a | 0.0021 [0.0017, 0.0024] | 0.0014 [0.0012, 0.0016] |
| xgb | 0.999 [0.998, 0.999] | 0.349 [0.343, 0.354] | 0.345 [0.341, 0.348] | 0.0031 [0.0016, 0.0051] | 0.0017 [0.0010, 0.0028] |
| xgb_robust | 0.949 [0.948, 0.950] | 0.949 [0.948, 0.950] | 0.949 [0.948, 0.950] | 0.0010 [0.0009, 0.0011] | 0.0010 [0.0009, 0.0011] |

## Matched realised FPR: xgb against xgb_robust (RQ2)

For each seed and nominal FPR, xgb's threshold is set on the calibration scores of cal_full so that it alerts on the same number of calibration flows as xgb_robust's plateau-aware threshold, as far as the distinct scores allow (`exact` counts seeds where the match is exact). Both are scored on the known-family test flows, macro over families, mean over seeds with bootstrap CI. The difference is xgb (matched) minus xgb_robust. p is the paired Wilcoxon p, Holm-adjusted within dataset. Per-seed rows: `robust_rq2_matched.csv`.

| dataset | nominal FPR | exact | realised cal FPR (xgb_robust; xgb) | realised test FPR (xgb_robust; xgb) | clean recall xgb_robust | clean recall xgb matched | difference [CI] | p (Holm) | clean recall xgb at its nominal threshold |
|---|---|---|---|---|---|---|---|---|---|
| cicids2017 | 0.0001 | 9/10 | 3.67e-05; 3.75e-05 | 3.58e-05; 3.75e-05 | 0.533 [0.530, 0.536] | 0.913 [0.904, 0.920] | 0.380 [0.371, 0.388] | 0.008 | 0.929 [0.926, 0.933] |
| cicids2017 | 0.0005 | 10/10 | 1.64e-04; 1.64e-04 | 1.46e-04; 1.72e-04 | 0.556 [0.541, 0.572] | 0.937 [0.926, 0.948] | 0.381 [0.374, 0.388] | 0.008 | 0.968 [0.964, 0.973] |
| cicids2017 | 0.001 | 10/10 | 1.64e-04; 1.64e-04 | 1.46e-04; 1.72e-04 | 0.556 [0.541, 0.572] | 0.937 [0.926, 0.948] | 0.381 [0.374, 0.388] | 0.008 | 0.993 [0.991, 0.994] |
| cicids2017 | 0.01 | 9/10 | 6.61e-03; 6.62e-03 | 6.70e-03; 6.86e-03 | 0.895 [0.894, 0.897] | 0.998 [0.998, 0.998] | 0.103 [0.101, 0.105] | 0.008 | 0.998 [0.998, 0.999] |
| cicids2018 | 0.0001 | 10/10 | 1.28e-05; 1.28e-05 | 1.40e-05; 1.75e-05 | 0.417 [0.238, 0.539] | 0.769 [0.764, 0.773] | 0.352 [0.224, 0.531] | 0.008 | 0.803 [0.798, 0.807] |
| cicids2018 | 0.0005 | 10/10 | 1.28e-05; 1.28e-05 | 1.40e-05; 1.75e-05 | 0.417 [0.238, 0.539] | 0.769 [0.764, 0.773] | 0.352 [0.224, 0.531] | 0.008 | 0.820 [0.820, 0.821] |
| cicids2018 | 0.001 | 10/10 | 9.53e-04; 9.53e-04 | 1.02e-03; 1.00e-03 | 0.776 [0.775, 0.777] | 0.824 [0.823, 0.825] | 0.048 [0.047, 0.049] | 0.008 | 0.824 [0.823, 0.825] |
| cicids2018 | 0.01 | 9/10 | 9.98e-03; 9.98e-03 | 9.89e-03; 1.01e-02 | 0.807 [0.805, 0.808] | 0.854 [0.853, 0.855] | 0.047 [0.046, 0.048] | 0.008 | 0.854 [0.853, 0.855] |

## Cross-generator gaps (worst-case recall G1 minus G2; mean [CI] over seeds)

| dataset | defender | gap G1 - G2 | training generator |
|---|---|---|---|
| cicids2017 | adv_naive_G1 | 0.257 [0.235, 0.281] | G1 |
| cicids2017 | adv_sym_G1 | 0.248 [0.227, 0.273] | G1 |
| cicids2017 | adv_sym_G1G2 | 0.161 [0.152, 0.172] | G1+G2 |
| cicids2017 | fusion | 0.191 [0.179, 0.202] | none |
| cicids2017 | iforest | n/a |  |
| cicids2017 | xgb | 0.249 [0.217, 0.284] | none |
| cicids2017 | xgb_robust | 0.000 [0.000, 0.000] | none |
| cicids2018 | adv_naive_G1 | 0.024 [0.019, 0.030] | G1 |
| cicids2018 | adv_sym_G1 | 0.011 [0.007, 0.015] | G1 |
| cicids2018 | adv_sym_G1G2 | -0.004 [-0.006, -0.003] | G1+G2 |
| cicids2018 | fusion | 0.001 [-0.002, 0.004] | none |
| cicids2018 | iforest | n/a |  |
| cicids2018 | xgb | 0.003 [-0.001, 0.007] | none |
| cicids2018 | xgb_robust | 0.000 [0.000, 0.000] | none |

## Statistics (paired over seeds, Wilcoxon signed-rank; Holm within dataset and metric)

| dataset | metric | a | b | n seeds | mean diff a - b [CI] | p | p (Holm) |
|---|---|---|---|---|---|---|---|
| cicids2017 | worst_G2 | adv_naive_G1 | adv_sym_G1 | 10 | 0.0027 [-0.0161, 0.0183] | 0.4922 | 0.4922 |
| cicids2017 | worst_G2 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0841 [-0.1044, -0.0665] | 0.0020 | 0.0078 |
| cicids2017 | worst_G2 | adv_sym_G1G2 | xgb | 10 | 0.3575 [0.3411, 0.3738] | 0.0020 | 0.0078 |
| cicids2017 | worst_G2 | adv_naive_G1 | adv_sym_G1G2 | 10 | -0.0814 [-0.1033, -0.0582] | 0.0020 | 0.0078 |
| cicids2017 | mutben_fpr_G1 | adv_naive_G1 | adv_sym_G1 | 10 | 0.0158 [0.0141, 0.0177] | 0.0020 | 0.0078 |
| cicids2017 | mutben_fpr_G1 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0002 [-0.0005, 0.0000] | 0.2754 | 0.3281 |
| cicids2017 | mutben_fpr_G1 | adv_sym_G1G2 | xgb | 10 | 0.0003 [0.0001, 0.0006] | 0.1641 | 0.3281 |
| cicids2017 | mutben_fpr_G1 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.0156 [0.0138, 0.0175] | 0.0020 | 0.0078 |
| cicids2017 | mutben_fpr_G2 | adv_naive_G1 | adv_sym_G1 | 10 | 0.0120 [0.0106, 0.0135] | 0.0020 | 0.0078 |
| cicids2017 | mutben_fpr_G2 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0011 [-0.0015, -0.0008] | 0.0039 | 0.0078 |
| cicids2017 | mutben_fpr_G2 | adv_sym_G1G2 | xgb | 10 | 0.0003 [-0.0002, 0.0006] | 0.2422 | 0.2422 |
| cicids2017 | mutben_fpr_G2 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.0109 [0.0095, 0.0124] | 0.0020 | 0.0078 |
| cicids2017 | worst_G1 | adv_naive_G1 | adv_sym_G1 | 10 | 0.0121 [0.0023, 0.0217] | 0.0645 | 0.1934 |
| cicids2017 | worst_G1 | adv_sym_G1 | adv_sym_G1G2 | 10 | 0.0027 [-0.0140, 0.0170] | 0.6953 | 0.6953 |
| cicids2017 | worst_G1 | adv_sym_G1G2 | xgb | 10 | 0.2698 [0.2379, 0.3006] | 0.0020 | 0.0078 |
| cicids2017 | worst_G1 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.0148 [0.0021, 0.0282] | 0.0840 | 0.1934 |
| cicids2018 | worst_G2 | adv_naive_G1 | adv_sym_G1 | 10 | -0.0091 [-0.0140, -0.0038] | 0.0195 | 0.0195 |
| cicids2018 | worst_G2 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0143 [-0.0170, -0.0114] | 0.0020 | 0.0078 |
| cicids2018 | worst_G2 | adv_sym_G1G2 | xgb | 10 | 0.5254 [0.5198, 0.5307] | 0.0020 | 0.0078 |
| cicids2018 | worst_G2 | adv_naive_G1 | adv_sym_G1G2 | 10 | -0.0234 [-0.0280, -0.0190] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G1 | adv_naive_G1 | adv_sym_G1 | 10 | 0.3139 [0.2995, 0.3294] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G1 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0005 [-0.0014, 0.0005] | 0.4316 | 0.4316 |
| cicids2018 | mutben_fpr_G1 | adv_sym_G1G2 | xgb | 10 | 0.0138 [0.0115, 0.0165] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G1 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.3134 [0.2988, 0.3290] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G2 | adv_naive_G1 | adv_sym_G1 | 10 | 0.1121 [0.1039, 0.1208] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G2 | adv_sym_G1 | adv_sym_G1G2 | 10 | -0.0088 [-0.0108, -0.0069] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G2 | adv_sym_G1G2 | xgb | 10 | 0.0145 [0.0132, 0.0160] | 0.0020 | 0.0078 |
| cicids2018 | mutben_fpr_G2 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.1032 [0.0946, 0.1132] | 0.0020 | 0.0078 |
| cicids2018 | worst_G1 | adv_naive_G1 | adv_sym_G1 | 10 | 0.0038 [-0.0011, 0.0093] | 0.1855 | 0.3711 |
| cicids2018 | worst_G1 | adv_sym_G1 | adv_sym_G1G2 | 10 | 0.0011 [-0.0031, 0.0048] | 0.4062 | 0.4062 |
| cicids2018 | worst_G1 | adv_sym_G1G2 | xgb | 10 | 0.5183 [0.5122, 0.5248] | 0.0020 | 0.0078 |
| cicids2018 | worst_G1 | adv_naive_G1 | adv_sym_G1G2 | 10 | 0.0049 [0.0026, 0.0075] | 0.0059 | 0.0176 |

Minimum two-sided Wilcoxon p with n seeds: 2/2^n (0.031 for 6 seeds, 0.002 for 10).

## Recall versus budget and L-inf distances

Full curves: `robust_curves.md` / `robust_curves.csv`. L-inf distance of every mutated attack flow (strong attacker against xgb) from its original, in signed-log standardised space: z(x) = sign(x) log1p(|x|), divided by the train-set standard deviation of z per feature (the train mean cancels in the difference). Quantiles pooled over families and seeds.

| dataset | generator | multiplier | groups | flows | median | p90 |
|---|---|---|---|---|---|---|
| cicids2017 | G1 | 1.5 | count | 46180 | 0.452 | 1.905 |
| cicids2017 | G1 | 1.5 | length | 46180 | 0.192 | 0.269 |
| cicids2017 | G1 | 1.5 | length+count | 46180 | 0.475 | 1.905 |
| cicids2017 | G1 | 1.5 | timing | 46180 | 0.083 | 0.108 |
| cicids2017 | G1 | 1.5 | timing+count | 46180 | 0.475 | 1.905 |
| cicids2017 | G1 | 1.5 | timing+length | 46180 | 0.223 | 0.270 |
| cicids2017 | G1 | 1.5 | timing+length+count | 46180 | 0.475 | 1.905 |
| cicids2017 | G1 | 2 | count | 46180 | 0.725 | 1.910 |
| cicids2017 | G1 | 2 | length | 46180 | 0.393 | 0.462 |
| cicids2017 | G1 | 2 | length+count | 46180 | 0.794 | 1.910 |
| cicids2017 | G1 | 2 | timing | 46180 | 0.161 | 0.187 |
| cicids2017 | G1 | 2 | timing+count | 46180 | 0.739 | 1.907 |
| cicids2017 | G1 | 2 | timing+length | 46180 | 0.423 | 0.463 |
| cicids2017 | G1 | 2 | timing+length+count | 46180 | 0.748 | 1.907 |
| cicids2017 | G1 | 5 | count | 46180 | 1.777 | 1.913 |
| cicids2017 | G1 | 5 | length | 46180 | 0.747 | 1.076 |
| cicids2017 | G1 | 5 | length+count | 46180 | 1.784 | 1.913 |
| cicids2017 | G1 | 5 | timing | 46180 | 0.384 | 0.444 |
| cicids2017 | G1 | 5 | timing+count | 46180 | 1.779 | 1.913 |
| cicids2017 | G1 | 5 | timing+length | 46180 | 0.936 | 1.077 |
| cicids2017 | G1 | 5 | timing+length+count | 46180 | 1.777 | 1.913 |
| cicids2017 | G2 | 1.5 | count | 46180 | 0.475 | 1.905 |
| cicids2017 | G2 | 1.5 | length | 46180 | 0.052 | 0.218 |
| cicids2017 | G2 | 1.5 | length+count | 46180 | 0.476 | 1.905 |
| cicids2017 | G2 | 1.5 | timing | 46180 | 1.982 | 3.160 |
| cicids2017 | G2 | 1.5 | timing+count | 46180 | 1.981 | 3.142 |
| cicids2017 | G2 | 1.5 | timing+length | 46180 | 1.988 | 3.212 |
| cicids2017 | G2 | 1.5 | timing+length+count | 46180 | 1.989 | 3.188 |
| cicids2017 | G2 | 2 | count | 46180 | 1.083 | 1.910 |
| cicids2017 | G2 | 2 | length | 46180 | 0.128 | 0.378 |
| cicids2017 | G2 | 2 | length+count | 46180 | 0.748 | 1.907 |
| cicids2017 | G2 | 2 | timing | 46180 | 2.136 | 3.417 |
| cicids2017 | G2 | 2 | timing+count | 46180 | 2.130 | 3.352 |
| cicids2017 | G2 | 2 | timing+length | 46180 | 2.135 | 3.438 |
| cicids2017 | G2 | 2 | timing+length+count | 46180 | 2.130 | 3.406 |
| cicids2017 | G2 | 5 | count | 46180 | 1.776 | 1.913 |
| cicids2017 | G2 | 5 | length | 46180 | 0.397 | 0.821 |
| cicids2017 | G2 | 5 | length+count | 46180 | 1.779 | 1.913 |
| cicids2017 | G2 | 5 | timing | 46180 | 2.444 | 3.608 |
| cicids2017 | G2 | 5 | timing+count | 46180 | 2.476 | 3.542 |
| cicids2017 | G2 | 5 | timing+length | 46180 | 2.444 | 3.671 |
| cicids2017 | G2 | 5 | timing+length+count | 46180 | 2.497 | 3.587 |
| cicids2018 | G1 | 1.5 | count | 50000 | 0.512 | 1.973 |
| cicids2018 | G1 | 1.5 | length | 50000 | 0.186 | 0.227 |
| cicids2018 | G1 | 1.5 | length+count | 50000 | 0.465 | 1.973 |
| cicids2018 | G1 | 1.5 | timing | 50000 | 0.097 | 0.135 |
| cicids2018 | G1 | 1.5 | timing+count | 50000 | 0.494 | 1.973 |
| cicids2018 | G1 | 1.5 | timing+length | 50000 | 0.204 | 0.227 |
| cicids2018 | G1 | 1.5 | timing+length+count | 50000 | 0.401 | 1.971 |
| cicids2018 | G1 | 2 | count | 50000 | 1.962 | 1.976 |
| cicids2018 | G1 | 2 | length | 50000 | 0.323 | 0.388 |
| cicids2018 | G1 | 2 | length+count | 50000 | 0.712 | 1.973 |
| cicids2018 | G1 | 2 | timing | 50000 | 0.184 | 0.231 |
| cicids2018 | G1 | 2 | timing+count | 50000 | 1.153 | 1.976 |
| cicids2018 | G1 | 2 | timing+length | 50000 | 0.323 | 0.388 |
| cicids2018 | G1 | 2 | timing+length+count | 50000 | 0.709 | 1.971 |
| cicids2018 | G1 | 5 | count | 50000 | 1.967 | 1.976 |
| cicids2018 | G1 | 5 | length | 50000 | 0.572 | 0.843 |
| cicids2018 | G1 | 5 | length+count | 50000 | 1.965 | 1.976 |
| cicids2018 | G1 | 5 | timing | 50000 | 0.426 | 0.517 |
| cicids2018 | G1 | 5 | timing+count | 50000 | 1.962 | 1.976 |
| cicids2018 | G1 | 5 | timing+length | 50000 | 0.571 | 0.844 |
| cicids2018 | G1 | 5 | timing+length+count | 50000 | 1.965 | 1.992 |
| cicids2018 | G2 | 1.5 | count | 50000 | 1.962 | 1.976 |
| cicids2018 | G2 | 1.5 | length | 50000 | 0.116 | 0.239 |
| cicids2018 | G2 | 1.5 | length+count | 50000 | 0.402 | 1.976 |
| cicids2018 | G2 | 1.5 | timing | 50000 | 1.293 | 2.580 |
| cicids2018 | G2 | 1.5 | timing+count | 50000 | 1.971 | 2.585 |
| cicids2018 | G2 | 1.5 | timing+length | 50000 | 1.253 | 2.578 |
| cicids2018 | G2 | 1.5 | timing+length+count | 50000 | 1.832 | 2.586 |
| cicids2018 | G2 | 2 | count | 50000 | 1.962 | 1.976 |
| cicids2018 | G2 | 2 | length | 50000 | 0.170 | 0.347 |
| cicids2018 | G2 | 2 | length+count | 50000 | 0.712 | 1.973 |
| cicids2018 | G2 | 2 | timing | 50000 | 1.480 | 2.778 |
| cicids2018 | G2 | 2 | timing+count | 50000 | 1.971 | 2.780 |
| cicids2018 | G2 | 2 | timing+length | 50000 | 1.430 | 2.765 |
| cicids2018 | G2 | 2 | timing+length+count | 50000 | 1.962 | 2.777 |
| cicids2018 | G2 | 5 | count | 50000 | 1.967 | 2.180 |
| cicids2018 | G2 | 5 | length | 50000 | 0.343 | 0.657 |
| cicids2018 | G2 | 5 | length+count | 50000 | 1.530 | 1.976 |
| cicids2018 | G2 | 5 | timing | 50000 | 1.872 | 3.155 |
| cicids2018 | G2 | 5 | timing+count | 50000 | 1.976 | 3.168 |
| cicids2018 | G2 | 5 | timing+length | 50000 | 1.836 | 2.994 |
| cicids2018 | G2 | 5 | timing+length+count | 50000 | 1.976 | 3.124 |

Smallest multiplier at which the worst-case recall of a family drops below 0.5 is in `robust_curves_first_below_half.csv`.

## Game (secondary, cost lens)

See `game/SUMMARY_GAME.md`.

## Research questions (answered from the tables above)

All numbers are at the nominal FPR 1e-3 unless stated, mean over 10 seeds with 95% bootstrap intervals, and come from `robust_headline.csv`, `robust_rq2_matched.csv`, `robust_stats.csv` and `robust_fingerprint.csv`.

**RQ1 (attack surface): holds under both generators.** xgb's clean macro recall is 0.993 on CIC-IDS2017 and 0.824 on CSE-CIC-IDS2018. Its worst-case recall is 0.695 under G1 and 0.447 under G2 on CIC-IDS2017, and 0.285 (G1) and 0.282 (G2) on CSE-CIC-IDS2018. Without the label-noisy Infiltration family, CSE-CIC-IDS2018 xgb has worst-case recall 0.349 (G1) and 0.345 (G2). On CIC-IDS2017, G2 is the more damaging generator (the earlier draft said G1; that was wrong). The two generators are about equal on CSE-CIC-IDS2018.

**RQ2 (price of robust features): large on CIC-IDS2017, small on CSE-CIC-IDS2018.** xgb_robust's clean macro recall is 0.556 on CIC-IDS2017 (xgb 0.993, a loss of 0.437) and 0.776 on CSE-CIC-IDS2018 (xgb 0.824, a loss of 0.048). Without Infiltration, CSE-CIC-IDS2018 xgb_robust is 0.949 against 0.999 for xgb. Its worst-case recall equals its clean recall under both generators, so its generator gap is zero by construction.

*Matched realised FPR (new).* At the same realised calibration FPR as xgb_robust, xgb has higher clean macro recall at every nominal FPR on both datasets. On CIC-IDS2017 at nominal 1e-3 the realised calibration FPR is 1.64e-4 for both; xgb recall is 0.937 [0.926, 0.948] against 0.556 [0.541, 0.572] for xgb_robust (difference 0.381, Holm p = 0.008). On CSE-CIC-IDS2018 at nominal 1e-3 (realised calibration FPR 9.5e-4 for both) the difference is 0.048 [0.047, 0.049] (0.824 against 0.776; Holm p = 0.008). The matched comparison is exact in 9 or 10 seeds of 10 at every FPR, and the realised test FPRs are close (for example 1.46e-4 for xgb_robust and 1.72e-4 for xgb on CIC-IDS2017 at 1e-3). The plateau rule therefore does not explain the gap: at the same realised FPR, the robust feature set loses recall. Nominal 1e-2 gives the same ordering (CIC-IDS2017 0.998 against 0.895; CSE-CIC-IDS2018 0.854 against 0.807). Note that xgb_robust's realised test FPR is far below its nominal FPR on CIC-IDS2017 (1.46e-4 at nominal 1e-3), which is why the matched table is needed.

**RQ3 (fingerprint): supported for adv_naive_G1.** At nominal 1e-3, the mutated-benign FPR of adv_naive_G1 is 0.0182 under G1 and 0.0141 under G2 on CIC-IDS2017 (xgb: 0.0023 and 0.0030). On CSE-CIC-IDS2018 it is 0.330 under G1 and 0.120 under G2 (xgb: 0.0031 and 0.0017). Its worst-case recall is 0.980 under G1 but 0.723 under G2 on CIC-IDS2017 (gap 0.257). On CSE-CIC-IDS2018 the two worst cases are close (0.808 and 0.784, gap 0.023), so the false-alarm rate is the visible symptom there. The Infiltration-free macro gives the same picture (mutated-benign FPR 0.330 and 0.120; worst case 0.987 and 0.961).

**RQ4 (fix and protocol): partly supported.**
- *Symmetric augmentation (adv_sym_G1) removes most of the false-alarm excess on CIC-IDS2017.* Its mutated-benign FPR under G1 is 0.0023, the same as xgb, against 0.0182 for adv_naive_G1 (paired difference 0.0158, Holm p = 0.008). On CSE-CIC-IDS2018 it falls from 0.330 to 0.0164 under G1 and from 0.120 to 0.0074 under G2, but 0.0164 is still about 16 times nominal and about 5 times xgb.
- *Two generators (adv_sym_G1G2) reduce the cross-generator gap on CIC-IDS2017, not remove it.* The G1-minus-G2 worst-case gap is 0.248 for adv_sym_G1 and 0.161 for adv_sym_G1G2. Worst-case G2 recall is 0.804 for adv_sym_G1G2 against 0.720 for adv_sym_G1 (paired difference -0.084, Holm p = 0.008). On CSE-CIC-IDS2018 the best worst-case G2 recall is adv_sym_G1G2 (0.807 against 0.793 for adv_sym_G1; Holm p = 0.008), and its G1-minus-G2 gap is -0.004.
- *The cost of the fix is in the false-alarm rate.* adv_sym_G1G2 has mutated-benign FPR 0.0026 (G1) and 0.0032 (G2) on CIC-IDS2017, close to xgb. On CSE-CIC-IDS2018 it is 0.0169 and 0.0162, about 16 times nominal, with no significant difference from adv_sym_G1 under G1 (Holm p = 0.43).
- *Protocol.* The clean-recall-only protocol makes the adversarial models look like xgb on CIC-IDS2017 (worst-case G1 0.965 to 0.980 against 0.695). The mutated-benign FPR exposes adv_naive_G1, and the cross-generator gap exposes adv_sym_G1.

**Falsification checks (section 7 of the design), explicit.**
- RQ1 falsified if G2 does not reproduce the collapse. Not falsified: G2 worst-case recall is 0.447 on CIC-IDS2017 and 0.282 on CSE-CIC-IDS2018, against clean recall 0.993 and 0.824.
- RQ3 falsified if adv_naive_G1's G2 recall stays high and its mutated-benign FPR stays low. Not falsified: the mutated-benign FPR is 18 times nominal (0.0182) on CIC-IDS2017 and 330 times nominal (0.330) on CSE-CIC-IDS2018, and G2 recall is 0.723 and 0.784.
- RQ4 expects adv_sym_* to keep a low mutated-benign FPR. Partly met: adv_sym_G1 matches xgb on CIC-IDS2017 (0.0023 against 0.0023), but both are above nominal, and on CSE-CIC-IDS2018 adv_sym_* stays at 0.007 to 0.017. The cross-generator gap on CIC-IDS2017 is not closed by symmetric augmentation alone (0.248 for adv_sym_G1), so a second generator helps but does not fully remove it.

**Important context for the false-alarm numbers.** xgb itself exceeds the nominal FPR under mutation on CIC-IDS2017 (0.0023 under G1 and 0.0030 under G2, 2.3 to 3 times nominal). The mutated-benign FPR is therefore a relative measure: compare it with nominal and with xgb, not with zero.

**Game (cost lens, secondary).** Full results are in `game/SUMMARY_GAME.md`. On CIC-IDS2017, xgb_robust is the equilibrium model in all ten seeds; the attacker abstains at the closed-form capacity, and the upper FPR edge (1e-2) is optimal in all seeds. On CSE-CIC-IDS2018 the equilibrium is adv_sym_G1 in five seeds and adv_sym_G1G2 in five, with the capacity at the upper B edge (B = A). Raising the mutated-benign share rho from 0 to 0.1 changes the CSE-CIC-IDS2018 equilibrium to xgb (mean loss 45.8k to 47.2k) and leaves CIC-IDS2017 unchanged. Indicator (d) is 0.07 to 0.13 on CIC-IDS2017 and 0.46 to 0.54 on CSE-CIC-IDS2018. The loss levels depend on the illustrative reference parameters; only the sensitivity rows support conclusions.

## Limitations

- Feature-space mutation only (no problem-space realisability). The two generators share the CICFlowMeter feature space and the budget grid.
- Two lab datasets (CIC-IDS2017, CSE-CIC-IDS2018). The CSE-CIC-IDS2018 Infiltration family is label-noisy; macro numbers without it are in the second headline table.
- The Infiltration exclusion changes only the macro over families. Mutated-benign FPR is measured on benign test rows and the models are not retrained without Infiltration, so those values do not change.
- G2 now satisfies the Fwd IAT Mean identity after a count change on every row. It does not satisfy the packet-length mean identity on most original flows (0.20 on CIC-IDS2017 and 0.16 on CSE-CIC-IDS2018), and it preserves that offset rather than enforcing it, as G1 does. The identity hold rates in the table compare original and mutated flows.
- Fwd IAT Min is left unchanged by the count group, so the rule "flow IAT min = fwd IAT min" holds on the same share of mutated flows as on originals (0.42 on CIC-IDS2017, 0.35 on CSE-CIC-IDS2018).
- The fingerprint diagnostics use benign training rows of seed 0 only.
- The game's equilibria depend on the illustrative parameters, and the capacity closed form is only as good as the recall tables.
- The one-class IsolationForest has clean recall of 0 at these thresholds (by design: it is a lower bound).

## Changes since the previous run

- G2 recomputation was absolute for the packet-length aggregates, so a timing-only budget changed payload statistics (Average Packet Size fell on 55% of CIC-IDS2017 flows at timing x2). It is now in delta form; timing leaves every length column bit-identical. Checked on real CIC-IDS2017 and CSE-CIC-IDS2018 samples: no undocumented decrease under any group.
- The count group now updates Fwd IAT Mean to Fwd IAT Total divided by (n_fwd - 1). Previously it did not.
- G2 fingerprint AUROC (all groups, seed 0): CIC-IDS2017 0.9917 before, 0.9776 after; CSE-CIC-IDS2018 0.9961 before, 0.9885 after. G1 values are unchanged. Cross-generator AUROC: 0.9943 to 0.9903 (CIC-IDS2017) and 0.9969 to 0.9925 (CSE-CIC-IDS2018).
- The G2 numbers in the headline, worst-case and game results changed. The G1 numbers did not change (for example, adv_naive_G1 mutated-benign FPR on CIC-IDS2017 is 0.0182 before and after).

## Deviations from the design (and why)

1. **Budget-unit matching.** The worst case is the minimum over all attackers and budgets. "Matched budget units" is reported through the budget-unit column in `robust_e4.csv.gz` and the curves.
2. **Benign copies for adv_sym_G1G2.** "Half each" is read as half from G1 and half from G2 for both attack and benign copies, with the same total count as adv_sym_G1.
3. **Active and Bwd IAT under G2 coupling.** The coupled per-gap share is applied to Active Mean and Active Max as well. Both are excluded from xgb_robust.
4. **Mutated-benign FPR sample sizes.** The random-budget mutated-benign FPR uses all benign test rows: 120,000 on CIC-IDS2017 and 85,822 on CSE-CIC-IDS2018 (20% of the benign rows the loader keeps there; the design text said 120,000 for both). The fixed-budget mutated-benign FPR uses 30,000 rows per generator and budget, for compute.
5. **Label attacker dropped.** The design names greedy, strong and transfer; the label attacker from round 3 was not carried over.
6. **Plateau rule.** Implemented as written: if more than 0.5 fpr n calibration scores tie at the threshold, the threshold moves to the next distinct score above it. The realised calibration FPR is in `robust_thresholds.csv`, with the realised test FPR and its Wilson 95% interval.
7. **Matched-FPR comparison (RQ2).** xgb's threshold is set on cal_full, the calibration set on which the non-fusion thresholds are fitted, not on cal_thr (which is used only by fusion). It matches the number of calibration alerts of xgb_robust as far as the distinct scores allow. The matched count is exact in 9 or 10 seeds of 10 at each FPR; the per-seed table gives the achieved counts.
8. **Fwd Packet Length Max.** The design text says max(old max, T). The implementation uses max(old max, T / (1 - a)), where T / (1 - a) is the padded data-packet size and a is the zero-payload share. The maximum never falls, and the padded size is the physical value.
9. **Closed-form capacity.** The deterrence condition uses theta_a = (V e_a - c_a) / (V e_a + P), which reduces to V/(V+P) when efficacy is 1 and cost is 0. Tests check the closed form against a dense grid (1e-4 step) and that its loss is never above any deterring grid point.
10. **Geometric grid.** The capacity grid is geometric in x = B/A with step 0.5% (x from 1 down to 0.01), so B = xA.
11. **Sobol.** Base N = 128 (1,536 samples per dataset, efficacy setting and seed pair). Fixed seed pairs from a recorded RNG: (0, 9) and (3, 7). Both pairs are reported. rho is a Sobol input over [0, 0.2].
12. **X4 (lam sweep) not run for the robust game.** Only lam = 1 and lam = 0.05 (indicator c) are used.
13. **Novel action for the reduced LOFO protocol.** Not used: the full protocol ran LOFO for all seven models.
14. **Recall-versus-budget curves and L-inf distances (added after the design).** Curves are the minimum over attackers and group subsets at each multiplier, with the smallest multiplier at which each family's worst case falls below 0.5 in `robust_curves_first_below_half.csv`.
15. **Compute.** The full run took 232.6 minutes (10 seeds, 2 datasets, 1,000 flows, full LOFO, game with N = 128). The quick run took 10 minutes.

