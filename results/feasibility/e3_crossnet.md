# E3 cross-network

## AUROC matrix (rows = train A, cols = test B)

| A \ B | NF-ToN-IoT-v2 |
|---|---|
| NF-ToN-IoT-v2 | 0.9938 ± 0.0001 |

## Target FPR vs realised FPR on B benign (A-calibrated thresholds)

| A -> B | target 1e-2 realised | target 1e-3 realised | recall B @1e-3 |
|---|---|---|---|
| NF-ToN-IoT-v2 -> NF-ToN-IoT-v2 | 0.0094 ± 0.0003 | 0.0007 ± 0.0003 | 0.7123 ± 0.0257 |

## Conformal + BH (alpha = 0.1) on B: unweighted vs weighted (two variants)

Weighted (oracle) fits the domain classifier on B benign rows (uses B labels: upper bound). Weighted (label-free) fits it on B rows whose unweighted p-value is > 0.5 (presumed benign; no B labels). Weights: mean over A calibration, and effective sample size (sum w)^2 / sum w^2 of A calibration (unweighted ESS = n calibration).

| A -> B | unweighted FDR | unweighted power | oracle FDR | oracle power | label-free FDR | label-free power | mean w cal (oracle / label-free) | ESS cal (oracle / label-free) |
|---|---|---|---|---|---|---|---|---|
| NF-ToN-IoT-v2 -> NF-ToN-IoT-v2 | 0.0361 ± 0.0012 | 0.9868 ± 0.0006 | 0.0360 ± 0.0012 | 0.9868 ± 0.0004 | 0.1031 ± 0.0091 | 0.9999 ± 0.0001 | 1.000 ± 0.000 / 1.086 ± 0.009 | 19724 ± 11 / 9002 ± 552 |

Shared features used: 39.
Datasets not loaded: NF-UNSW-NB15-v3: ValueError: No mirror found for NF-UNSW-NB15-v3: keys-i/netFlow-v3 is empty on the HF hub and no other NF-UNSW-NB15-v3 copy was found by search. Only NF-ToN-IoT (v2 fallback) can be loaded.; NF-CICIDS2018-v3: ValueError: No mirror found for NF-CICIDS2018-v3: keys-i/netFlow-v3 is empty on the HF hub and no other NF-CICIDS2018-v3 copy was found by search. Only NF-ToN-IoT (v2 fallback) can be loaded.
