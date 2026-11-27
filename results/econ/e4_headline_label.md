# E4 headline: recall before and after the attack (FPR 0.001, query = label)

Recall of attack flows at the defender's threshold (known scenario). For each attacker the budget with the lowest mean recall over seeds is shown (the best budget for that attacker); mean ± sd over seeds. The worst case takes, per budget and seed, the minimum over the attackers of the query mode, then the best budget. Attackers: greedy (the E4 greedy, score access), strong (per-group level search, score access), transfer (strong attack found on xgb, submitted to the model; not run for xgb itself). The label attacker is a weak baseline (query = label) and appears only in the label file.

| dataset | model | family | recall before | greedy: best budget, after | strong: best budget, after | transfer: best budget, after | worst case: best budget, after | seeds |
|---|---|---|---|---|---|---|---|---|
| cicids2017 | fusion | Bot | 0.797 ± 0.081 | n/a | n/a | n/a | timing+length+count,x5: 0.249 ± 0.200 | 10 |
| cicids2017 | fusion | BruteForce | 0.996 ± 0.003 | n/a | n/a | n/a | timing+length+count,x5: 0.098 ± 0.137 | 10 |
| cicids2017 | fusion | DDoS | 0.998 ± 0.001 | n/a | n/a | n/a | timing+length+count,x5: 0.581 ± 0.052 | 10 |
| cicids2017 | fusion | DoS | 0.986 ± 0.007 | n/a | n/a | n/a | timing+length+count,x5: 0.890 ± 0.028 | 10 |
| cicids2017 | fusion | PortScan | 0.994 ± 0.003 | n/a | n/a | n/a | timing+length+count,x5: 0.548 ± 0.053 | 10 |
| cicids2017 | fusion | WebAttack | 0.971 ± 0.009 | n/a | n/a | n/a | timing+length,x5: 0.667 ± 0.269 | 10 |
| cicids2017 | iforest | Bot | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | BruteForce | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | DDoS | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | DoS | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | PortScan | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | WebAttack | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | xgb | Bot | 0.950 ± 0.029 | n/a | n/a | n/a | timing+length+count,x5: 0.621 ± 0.156 | 10 |
| cicids2017 | xgb | BruteForce | 0.999 ± 0.001 | n/a | n/a | n/a | timing+length+count,x5: 0.329 ± 0.190 | 10 |
| cicids2017 | xgb | DDoS | 0.999 ± 0.001 | n/a | n/a | n/a | timing+length+count,x5: 0.667 ± 0.070 | 10 |
| cicids2017 | xgb | DoS | 0.997 ± 0.002 | n/a | n/a | n/a | timing+length+count,x5: 0.942 ± 0.022 | 10 |
| cicids2017 | xgb | PortScan | 0.997 ± 0.002 | n/a | n/a | n/a | timing+length+count,x5: 0.641 ± 0.027 | 10 |
| cicids2017 | xgb | WebAttack | 0.985 ± 0.005 | n/a | n/a | n/a | timing+length,x5: 0.848 ± 0.171 | 10 |
| cicids2017 | xgb_adv | Bot | 0.940 ± 0.040 | n/a | n/a | n/a | timing,x1.5: 0.908 ± 0.080 | 10 |
| cicids2017 | xgb_adv | BruteForce | 0.999 ± 0.001 | n/a | n/a | n/a | length,x5: 0.982 ± 0.051 | 10 |
| cicids2017 | xgb_adv | DDoS | 0.999 ± 0.001 | n/a | n/a | n/a | timing+length+count,x5: 0.998 ± 0.001 | 10 |
| cicids2017 | xgb_adv | DoS | 0.997 ± 0.003 | n/a | n/a | n/a | timing+length+count,x1.5: 0.990 ± 0.006 | 10 |
| cicids2017 | xgb_adv | PortScan | 0.997 ± 0.002 | n/a | n/a | n/a | timing+length+count,x1.5: 0.996 ± 0.002 | 10 |
| cicids2017 | xgb_adv | WebAttack | 0.986 ± 0.006 | n/a | n/a | n/a | timing+length,x1.5: 0.983 ± 0.005 | 10 |
| cicids2017 | xgb_robustfeat | Bot | 0.685 ± 0.028 | n/a | n/a | n/a | count,x1.5: 0.685 ± 0.028 | 10 |
| cicids2017 | xgb_robustfeat | BruteForce | 0.788 ± 0.062 | n/a | n/a | n/a | count,x1.5: 0.788 ± 0.062 | 10 |
| cicids2017 | xgb_robustfeat | DDoS | 0.635 ± 0.021 | n/a | n/a | n/a | count,x1.5: 0.635 ± 0.021 | 10 |
| cicids2017 | xgb_robustfeat | DoS | 0.911 ± 0.011 | n/a | n/a | n/a | count,x1.5: 0.911 ± 0.011 | 10 |
| cicids2017 | xgb_robustfeat | PortScan | 0.494 ± 0.114 | n/a | n/a | n/a | count,x1.5: 0.494 ± 0.114 | 10 |
| cicids2017 | xgb_robustfeat | WebAttack | 0.080 ± 0.015 | n/a | n/a | n/a | count,x1.5: 0.080 ± 0.015 | 10 |
| cicids2018 | fusion | Bot | 0.995 ± 0.002 | n/a | n/a | n/a | timing+length+count,x5: 0.041 ± 0.050 | 10 |
| cicids2018 | fusion | BruteForce | 1.000 ± 0.000 | n/a | n/a | n/a | length+count,x5: 0.003 ± 0.002 | 10 |
| cicids2018 | fusion | DDoS | 0.997 ± 0.002 | n/a | n/a | n/a | timing+length+count,x5: 0.650 ± 0.075 | 10 |
| cicids2018 | fusion | DoS | 1.000 ± 0.000 | n/a | n/a | n/a | timing+length,x5: 0.833 ± 0.018 | 10 |
| cicids2018 | fusion | Infiltration | 0.108 ± 0.012 | n/a | n/a | n/a | timing+length,x5: 0.038 ± 0.010 | 10 |
| cicids2018 | iforest | Bot | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | BruteForce | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | DDoS | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | DoS | 0.000 ± 0.000 | n/a | n/a | n/a | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | Infiltration | 0.002 ± 0.001 | n/a | n/a | n/a | count,x1.5: 0.002 ± 0.001 | 10 |
| cicids2018 | xgb | Bot | 0.996 ± 0.002 | n/a | n/a | n/a | timing+length+count,x5: 0.116 ± 0.151 | 10 |
| cicids2018 | xgb | BruteForce | 1.000 ± 0.000 | n/a | n/a | n/a | length+count,x5: 0.005 ± 0.003 | 10 |
| cicids2018 | xgb | DDoS | 0.998 ± 0.001 | n/a | n/a | n/a | timing+length+count,x5: 0.693 ± 0.088 | 10 |
| cicids2018 | xgb | DoS | 1.000 ± 0.000 | n/a | n/a | n/a | timing+length+count,x5: 0.838 ± 0.017 | 10 |
| cicids2018 | xgb | Infiltration | 0.123 ± 0.015 | n/a | n/a | n/a | timing+length+count,x5: 0.049 ± 0.010 | 10 |
| cicids2018 | xgb_adv | Bot | 0.995 ± 0.001 | n/a | n/a | n/a | timing+length,x5: 0.993 ± 0.002 | 10 |
| cicids2018 | xgb_adv | BruteForce | 1.000 ± 0.001 | n/a | n/a | n/a | timing+length,x2: 0.999 ± 0.001 | 10 |
| cicids2018 | xgb_adv | DDoS | 0.998 ± 0.001 | n/a | n/a | n/a | timing+count,x2: 0.996 ± 0.003 | 10 |
| cicids2018 | xgb_adv | DoS | 1.000 ± 0.000 | n/a | n/a | n/a | timing+length+count,x2: 0.999 ± 0.001 | 10 |
| cicids2018 | xgb_adv | Infiltration | 0.122 ± 0.016 | n/a | n/a | n/a | timing+length,x2: 0.108 ± 0.009 | 10 |
| cicids2018 | xgb_robustfeat | Bot | 0.989 ± 0.004 | n/a | n/a | n/a | count,x1.5: 0.989 ± 0.004 | 10 |
| cicids2018 | xgb_robustfeat | BruteForce | 0.998 ± 0.002 | n/a | n/a | n/a | count,x1.5: 0.998 ± 0.002 | 10 |
| cicids2018 | xgb_robustfeat | DDoS | 0.810 ± 0.010 | n/a | n/a | n/a | count,x1.5: 0.810 ± 0.010 | 10 |
| cicids2018 | xgb_robustfeat | DoS | 0.999 ± 0.002 | n/a | n/a | n/a | count,x1.5: 0.999 ± 0.002 | 10 |
| cicids2018 | xgb_robustfeat | Infiltration | 0.072 ± 0.019 | n/a | n/a | n/a | count,x1.5: 0.072 ± 0.019 | 10 |
