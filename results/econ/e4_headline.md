# E4 headline: recall before and after the attack (FPR 0.001, query = score)

Recall of attack flows at the defender's threshold (known scenario). For each attacker the budget with the lowest mean recall over seeds is shown (the best budget for that attacker); mean ± sd over seeds. The worst case takes, per budget and seed, the minimum over the attackers of the query mode, then the best budget. Attackers: greedy (the E4 greedy, score access), strong (per-group level search, score access), transfer (strong attack found on xgb, submitted to the model; not run for xgb itself). The label attacker is a weak baseline (query = label) and appears only in the label file.

| dataset | model | family | recall before | greedy: best budget, after | strong: best budget, after | transfer: best budget, after | worst case: best budget, after | seeds |
|---|---|---|---|---|---|---|---|---|
| cicids2017 | fusion | Bot | 0.797 ± 0.081 | timing+length+count,x5: 0.440 ± 0.053 | timing+length+count,x5: 0.192 ± 0.197 | timing+length+count,x5: 0.183 ± 0.195 | timing+length+count,x5: 0.183 ± 0.195 | 10 |
| cicids2017 | fusion | BruteForce | 0.996 ± 0.003 | timing+length+count,x5: 0.378 ± 0.246 | timing+length+count,x5: 0.074 ± 0.116 | timing+length+count,x5: 0.068 ± 0.115 | timing+length+count,x5: 0.068 ± 0.115 | 10 |
| cicids2017 | fusion | DDoS | 0.998 ± 0.001 | timing+length+count,x5: 0.602 ± 0.053 | timing+length+count,x5: 0.566 ± 0.060 | timing+length+count,x5: 0.565 ± 0.061 | timing+length+count,x5: 0.565 ± 0.061 | 10 |
| cicids2017 | fusion | DoS | 0.986 ± 0.007 | timing+length+count,x5: 0.876 ± 0.047 | timing+length+count,x5: 0.870 ± 0.051 | timing+length+count,x5: 0.865 ± 0.053 | timing+length+count,x5: 0.865 ± 0.053 | 10 |
| cicids2017 | fusion | PortScan | 0.994 ± 0.003 | timing+length+count,x5: 0.510 ± 0.084 | timing+length+count,x5: 0.453 ± 0.088 | timing+length+count,x5: 0.446 ± 0.089 | timing+length+count,x5: 0.445 ± 0.089 | 10 |
| cicids2017 | fusion | WebAttack | 0.971 ± 0.009 | timing+length+count,x5: 0.669 ± 0.259 | timing+length,x5: 0.665 ± 0.267 | timing+length,x5: 0.665 ± 0.267 | timing+length+count,x5: 0.642 ± 0.250 | 10 |
| cicids2017 | iforest | Bot | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | BruteForce | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | DDoS | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | DoS | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | PortScan | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | iforest | WebAttack | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2017 | xgb | Bot | 0.950 ± 0.029 | timing+length+count,x5: 0.588 ± 0.177 | timing+length+count,x5: 0.541 ± 0.196 | n/a | timing+length+count,x5: 0.541 ± 0.196 | 10 |
| cicids2017 | xgb | BruteForce | 0.999 ± 0.001 | timing+length+count,x5: 0.269 ± 0.219 | timing+length+count,x5: 0.243 ± 0.201 | n/a | timing+length+count,x5: 0.243 ± 0.201 | 10 |
| cicids2017 | xgb | DDoS | 0.999 ± 0.001 | timing+length+count,x5: 0.662 ± 0.070 | timing+length+count,x5: 0.654 ± 0.060 | n/a | timing+length+count,x5: 0.654 ± 0.060 | 10 |
| cicids2017 | xgb | DoS | 0.997 ± 0.002 | timing+length+count,x5: 0.928 ± 0.022 | timing+length+count,x5: 0.923 ± 0.025 | n/a | timing+length+count,x5: 0.923 ± 0.025 | 10 |
| cicids2017 | xgb | PortScan | 0.997 ± 0.002 | timing+length+count,x5: 0.631 ± 0.022 | timing+length+count,x5: 0.619 ± 0.027 | n/a | timing+length+count,x5: 0.619 ± 0.027 | 10 |
| cicids2017 | xgb | WebAttack | 0.985 ± 0.005 | timing+length+count,x5: 0.833 ± 0.170 | timing+length+count,x5: 0.830 ± 0.167 | n/a | timing+length+count,x5: 0.829 ± 0.168 | 10 |
| cicids2017 | xgb_adv | Bot | 0.940 ± 0.040 | timing+length+count,x1.5: 0.891 ± 0.092 | timing+count,x2: 0.890 ± 0.093 | timing,x1.5: 0.914 ± 0.080 | timing+count,x2: 0.890 ± 0.094 | 10 |
| cicids2017 | xgb_adv | BruteForce | 0.999 ± 0.001 | timing+length+count,x5: 0.971 ± 0.071 | timing+length,x5: 0.969 ± 0.071 | length,x5: 0.977 ± 0.059 | timing+length,x5: 0.969 ± 0.071 | 10 |
| cicids2017 | xgb_adv | DDoS | 0.999 ± 0.001 | timing+length+count,x5: 0.998 ± 0.001 | timing+length+count,x5: 0.998 ± 0.001 | count,x1.5: 0.999 ± 0.001 | timing+length+count,x5: 0.998 ± 0.001 | 10 |
| cicids2017 | xgb_adv | DoS | 0.997 ± 0.003 | timing+length+count,x2: 0.986 ± 0.008 | timing+length+count,x1.5: 0.982 ± 0.004 | timing+length,x1.5: 0.982 ± 0.004 | timing+length+count,x1.5: 0.981 ± 0.003 | 10 |
| cicids2017 | xgb_adv | PortScan | 0.997 ± 0.002 | timing+length+count,x2: 0.995 ± 0.003 | timing+length,x5: 0.990 ± 0.012 | timing,x2: 0.996 ± 0.002 | timing+length,x5: 0.990 ± 0.012 | 10 |
| cicids2017 | xgb_adv | WebAttack | 0.986 ± 0.006 | timing+length+count,x5: 0.981 ± 0.007 | timing+length+count,x5: 0.978 ± 0.007 | timing+length,x1.5: 0.984 ± 0.005 | timing+length+count,x5: 0.978 ± 0.006 | 10 |
| cicids2017 | xgb_robustfeat | Bot | 0.685 ± 0.028 | count,x1.5: 0.685 ± 0.028 | count,x1.5: 0.685 ± 0.028 | count,x1.5: 0.685 ± 0.028 | count,x1.5: 0.685 ± 0.028 | 10 |
| cicids2017 | xgb_robustfeat | BruteForce | 0.788 ± 0.062 | count,x1.5: 0.788 ± 0.062 | count,x1.5: 0.788 ± 0.062 | count,x1.5: 0.788 ± 0.062 | count,x1.5: 0.788 ± 0.062 | 10 |
| cicids2017 | xgb_robustfeat | DDoS | 0.635 ± 0.021 | count,x1.5: 0.635 ± 0.021 | count,x1.5: 0.635 ± 0.021 | count,x1.5: 0.635 ± 0.021 | count,x1.5: 0.635 ± 0.021 | 10 |
| cicids2017 | xgb_robustfeat | DoS | 0.911 ± 0.011 | count,x1.5: 0.911 ± 0.011 | count,x1.5: 0.911 ± 0.011 | count,x1.5: 0.911 ± 0.011 | count,x1.5: 0.911 ± 0.011 | 10 |
| cicids2017 | xgb_robustfeat | PortScan | 0.494 ± 0.114 | count,x1.5: 0.494 ± 0.114 | count,x1.5: 0.494 ± 0.114 | count,x1.5: 0.494 ± 0.114 | count,x1.5: 0.494 ± 0.114 | 10 |
| cicids2017 | xgb_robustfeat | WebAttack | 0.080 ± 0.015 | count,x1.5: 0.080 ± 0.015 | count,x1.5: 0.080 ± 0.015 | count,x1.5: 0.080 ± 0.015 | count,x1.5: 0.080 ± 0.015 | 10 |
| cicids2018 | fusion | Bot | 0.995 ± 0.002 | timing+length+count,x5: 0.010 ± 0.004 | timing+length+count,x5: 0.008 ± 0.005 | timing+length+count,x5: 0.007 ± 0.002 | timing+length+count,x5: 0.007 ± 0.003 | 10 |
| cicids2018 | fusion | BruteForce | 1.000 ± 0.000 | timing+length+count,x5: 0.003 ± 0.002 | timing+length+count,x2: 0.003 ± 0.002 | timing+length+count,x2: 0.003 ± 0.002 | timing+length+count,x2: 0.003 ± 0.002 | 10 |
| cicids2018 | fusion | DDoS | 0.997 ± 0.002 | timing+length+count,x5: 0.617 ± 0.049 | timing+length+count,x5: 0.605 ± 0.032 | timing+length+count,x5: 0.593 ± 0.037 | timing+length+count,x5: 0.592 ± 0.038 | 10 |
| cicids2018 | fusion | DoS | 1.000 ± 0.000 | timing+length+count,x5: 0.830 ± 0.016 | timing+length,x5: 0.829 ± 0.016 | timing+length+count,x5: 0.829 ± 0.016 | timing+length+count,x5: 0.829 ± 0.016 | 10 |
| cicids2018 | fusion | Infiltration | 0.108 ± 0.012 | timing+length+count,x5: 0.027 ± 0.011 | timing+length+count,x5: 0.027 ± 0.015 | timing+length+count,x5: 0.026 ± 0.010 | timing+length+count,x5: 0.024 ± 0.011 | 10 |
| cicids2018 | iforest | Bot | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | BruteForce | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | DDoS | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | DoS | 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | count,x1.5: 0.000 ± 0.000 | 10 |
| cicids2018 | iforest | Infiltration | 0.002 ± 0.001 | count,x5: 0.002 ± 0.001 | count,x5: 0.001 ± 0.001 | count,x1.5: 0.002 ± 0.001 | count,x5: 0.001 ± 0.001 | 10 |
| cicids2018 | xgb | Bot | 0.996 ± 0.002 | timing+length+count,x5: 0.017 ± 0.008 | timing+length+count,x5: 0.014 ± 0.006 | n/a | timing+length+count,x5: 0.014 ± 0.006 | 10 |
| cicids2018 | xgb | BruteForce | 1.000 ± 0.000 | timing+length+count,x5: 0.003 ± 0.002 | timing+length+count,x2: 0.003 ± 0.002 | n/a | timing+length+count,x2: 0.003 ± 0.002 | 10 |
| cicids2018 | xgb | DDoS | 0.998 ± 0.001 | timing+length+count,x5: 0.646 ± 0.056 | timing+length+count,x5: 0.615 ± 0.035 | n/a | timing+length+count,x5: 0.615 ± 0.035 | 10 |
| cicids2018 | xgb | DoS | 1.000 ± 0.000 | timing+length+count,x5: 0.833 ± 0.013 | timing+length+count,x5: 0.832 ± 0.013 | n/a | timing+length+count,x5: 0.832 ± 0.013 | 10 |
| cicids2018 | xgb | Infiltration | 0.123 ± 0.015 | timing+length+count,x5: 0.035 ± 0.010 | timing+length+count,x5: 0.034 ± 0.012 | n/a | timing+length+count,x5: 0.034 ± 0.010 | 10 |
| cicids2018 | xgb_adv | Bot | 0.995 ± 0.001 | timing+length+count,x5: 0.992 ± 0.003 | timing+length+count,x5: 0.991 ± 0.004 | timing+length,x5: 0.994 ± 0.003 | timing+length+count,x5: 0.990 ± 0.004 | 10 |
| cicids2018 | xgb_adv | BruteForce | 1.000 ± 0.001 | timing+length+count,x2: 0.999 ± 0.001 | timing+length+count,x5: 0.999 ± 0.002 | timing+length,x5: 0.999 ± 0.001 | timing+length+count,x5: 0.999 ± 0.002 | 10 |
| cicids2018 | xgb_adv | DDoS | 0.998 ± 0.001 | timing+count,x2: 0.994 ± 0.004 | timing+length+count,x5: 0.991 ± 0.005 | timing+count,x2: 0.996 ± 0.004 | timing+length+count,x5: 0.991 ± 0.005 | 10 |
| cicids2018 | xgb_adv | DoS | 1.000 ± 0.000 | timing+length+count,x5: 0.997 ± 0.002 | timing+length+count,x5: 0.991 ± 0.004 | length,x5: 0.996 ± 0.002 | timing+length+count,x5: 0.991 ± 0.004 | 10 |
| cicids2018 | xgb_adv | Infiltration | 0.122 ± 0.016 | timing+length+count,x2: 0.100 ± 0.010 | timing+length,x5: 0.093 ± 0.012 | length,x1.5: 0.126 ± 0.014 | timing+length,x5: 0.093 ± 0.012 | 10 |
| cicids2018 | xgb_robustfeat | Bot | 0.989 ± 0.004 | count,x1.5: 0.989 ± 0.004 | count,x1.5: 0.989 ± 0.004 | count,x1.5: 0.989 ± 0.004 | count,x1.5: 0.989 ± 0.004 | 10 |
| cicids2018 | xgb_robustfeat | BruteForce | 0.998 ± 0.002 | count,x1.5: 0.998 ± 0.002 | count,x1.5: 0.998 ± 0.002 | count,x1.5: 0.998 ± 0.002 | count,x1.5: 0.998 ± 0.002 | 10 |
| cicids2018 | xgb_robustfeat | DDoS | 0.810 ± 0.010 | count,x1.5: 0.810 ± 0.010 | count,x1.5: 0.810 ± 0.010 | count,x1.5: 0.810 ± 0.010 | count,x1.5: 0.810 ± 0.010 | 10 |
| cicids2018 | xgb_robustfeat | DoS | 0.999 ± 0.002 | count,x1.5: 0.999 ± 0.002 | count,x1.5: 0.999 ± 0.002 | count,x1.5: 0.999 ± 0.002 | count,x1.5: 0.999 ± 0.002 | 10 |
| cicids2018 | xgb_robustfeat | Infiltration | 0.072 ± 0.019 | count,x1.5: 0.072 ± 0.019 | count,x1.5: 0.072 ± 0.019 | count,x1.5: 0.072 ± 0.019 | count,x1.5: 0.072 ± 0.019 | 10 |
