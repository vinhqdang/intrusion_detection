# E2 leave-one-family-out (recall at FPR 1e-3)

## cicids2017

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| Bot | 0.000 ± 0.000 | 0.942 ± 0.030 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.839 ± 0.060 | 0.538 ± 0.016 |
| BruteForce | 0.002 ± 0.002 | 0.998 ± 0.003 | 0.000 ± 0.000 | 0.000 ± 0.001 | 0.940 ± 0.009 | 0.713 ± 0.006 |
| DDoS | 0.617 ± 0.015 | 0.999 ± 0.001 | 0.000 ± 0.000 | 0.352 ± 0.308 | 0.925 ± 0.025 | 0.821 ± 0.009 |
| DoS | 0.051 ± 0.024 | 0.992 ± 0.010 | 0.000 ± 0.000 | 0.004 ± 0.003 | 0.976 ± 0.006 | 0.930 ± 0.003 |
| PortScan | 0.283 ± 0.226 | 0.992 ± 0.007 | 0.000 ± 0.000 | 0.117 ± 0.025 | 0.925 ± 0.015 | 0.625 ± 0.015 |
| WebAttack | 0.832 ± 0.049 | 0.984 ± 0.011 | 0.000 ± 0.000 | 0.267 ± 0.462 | 0.994 ± 0.003 | 0.644 ± 0.012 |

## cicids2018

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| Bot | 0.926 ± 0.049 | 0.991 ± 0.005 | 0.000 ± 0.000 | 0.508 ± 0.490 | 0.998 ± 0.001 | 0.683 ± 0.022 |
| BruteForce | 0.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.786 ± 0.125 | 0.870 ± 0.026 |
| DDoS | 0.337 ± 0.086 | 0.991 ± 0.004 | 0.000 ± 0.000 | 0.105 ± 0.116 | 0.960 ± 0.002 | 0.707 ± 0.011 |
| DoS | 0.010 ± 0.013 | 0.999 ± 0.001 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.703 ± 0.059 | 0.337 ± 0.100 |
| Infiltration | 0.010 ± 0.002 | 0.109 ± 0.013 | 0.002 ± 0.001 | 0.007 ± 0.003 | 0.555 ± 0.019 | 0.556 ± 0.006 |

## ciciot2023

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| BruteForce | 0.086 ± 0.005 | 0.307 ± 0.003 | 0.008 ± 0.003 | 0.035 ± 0.024 | 0.860 ± 0.014 | 0.691 ± 0.013 |
| DDoS | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.048 ± 0.022 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.954 ± 0.004 |
| DoS | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.143 ± 0.079 | 0.999 ± 0.000 | 1.000 ± 0.000 | 0.965 ± 0.004 |
| Mirai | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.002 ± 0.001 | 1.000 ± 0.001 | 1.000 ± 0.000 | 0.988 ± 0.002 |
| Recon | 0.040 ± 0.011 | 0.301 ± 0.006 | 0.010 ± 0.004 | 0.014 ± 0.005 | 0.824 ± 0.007 | 0.749 ± 0.004 |
| Spoofing | 0.059 ± 0.021 | 0.738 ± 0.031 | 0.004 ± 0.002 | 0.032 ± 0.024 | 0.882 ± 0.005 | 0.645 ± 0.002 |
| Web | 0.021 ± 0.010 | 0.112 ± 0.011 | 0.004 ± 0.001 | 0.006 ± 0.002 | 0.873 ± 0.006 | 0.682 ± 0.002 |

## ciciomt2024

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| DDoS | 0.860 ± 0.028 | 0.988 ± 0.004 | 0.000 ± 0.000 | 0.269 ± 0.466 | 0.996 ± 0.000 | 0.713 ± 0.038 |
| DoS | 0.945 ± 0.072 | 0.991 ± 0.001 | 0.000 ± 0.000 | 0.520 ± 0.453 | 0.998 ± 0.001 | 0.704 ± 0.052 |
| MQTT | 0.505 ± 0.123 | 0.909 ± 0.018 | 0.004 ± 0.003 | 0.353 ± 0.020 | 0.980 ± 0.006 | 0.807 ± 0.037 |
| Recon | 0.659 ± 0.525 | 0.985 ± 0.002 | 0.000 ± 0.000 | 0.252 ± 0.301 | 0.996 ± 0.002 | 0.606 ± 0.130 |
| Spoofing | 0.091 ± 0.032 | 0.487 ± 0.044 | 0.005 ± 0.004 | 0.031 ± 0.028 | 0.882 ± 0.019 | 0.531 ± 0.017 |

## edgeiiot

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| Backdoor | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.711 ± 0.018 |
| DDoS_HTTP | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.771 ± 0.019 |
| DDoS_ICMP | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.911 ± 0.026 |
| DDoS_TCP | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.048 ± 0.077 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.897 ± 0.013 |
| DDoS_UDP | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.942 ± 0.019 |
| Fingerprinting | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.897 ± 0.023 |
| Password | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.740 ± 0.014 |
| Port_Scanning | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.027 ± 0.047 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.875 ± 0.019 |
| Ransomware | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.725 ± 0.022 |
| SQL_injection | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.739 ± 0.016 |
| Uploading | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.770 ± 0.016 |
| Vulnerability_scanner | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.752 ± 0.037 |
| XSS | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 0.739 ± 0.018 |

## NF-ToN-IoT-v2

| family | XGB recall unseen | XGB recall when known | IForest recall | fusion recall | AUROC unseen (XGB) | AUROC unseen (IForest) |
|---|---|---|---|---|---|---|
| ddos | 0.395 ± 0.254 | 0.870 ± 0.010 | 0.001 ± 0.001 | 0.074 ± 0.075 | 0.985 ± 0.004 | 0.773 ± 0.007 |
| dos | 0.424 ± 0.149 | 0.782 ± 0.009 | 0.000 ± 0.000 | 0.011 ± 0.012 | 0.988 ± 0.001 | 0.093 ± 0.029 |
| injection | 0.459 ± 0.081 | 0.706 ± 0.015 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.986 ± 0.001 | 0.713 ± 0.012 |
| mitm | 0.438 ± 0.024 | 0.674 ± 0.002 | 0.000 ± 0.000 | 0.139 ± 0.241 | 0.905 ± 0.009 | 0.303 ± 0.018 |
| password | 0.828 ± 0.037 | 0.899 ± 0.002 | 0.000 ± 0.000 | 0.242 ± 0.420 | 0.993 ± 0.001 | 0.898 ± 0.009 |
| scanning | 0.004 ± 0.001 | 0.011 ± 0.004 | 0.000 ± 0.000 | 0.000 ± 0.000 | 0.770 ± 0.025 | 0.646 ± 0.007 |
| xss | 0.162 ± 0.072 | 0.416 ± 0.012 | 0.000 ± 0.000 | 0.058 ± 0.065 | 0.961 ± 0.003 | 0.259 ± 0.018 |

## Realised FPR on benign test at target 1e-3 (unseen-model thresholds)

| dataset | family | XGB | IForest | fusion (calibrated on cal_thr) |
|---|---|---|---|---|
| cicids2017 | Bot | 0.00070 ± 0.00036 | 0.00120 ± 0.00062 | 0.00067 ± 0.00074 |
| cicids2017 | BruteForce | 0.00107 ± 0.00023 | 0.00120 ± 0.00062 | 0.00067 ± 0.00031 |
| cicids2017 | DDoS | 0.00127 ± 0.00038 | 0.00120 ± 0.00062 | 0.00073 ± 0.00025 |
| cicids2017 | DoS | 0.00100 ± 0.00026 | 0.00120 ± 0.00062 | 0.00063 ± 0.00035 |
| cicids2017 | PortScan | 0.00113 ± 0.00047 | 0.00120 ± 0.00062 | 0.00070 ± 0.00056 |
| cicids2017 | WebAttack | 0.00090 ± 0.00010 | 0.00120 ± 0.00062 | 0.00070 ± 0.00017 |
| cicids2018 | Bot | 0.00123 ± 0.00040 | 0.00133 ± 0.00095 | 0.00103 ± 0.00086 |
| cicids2018 | BruteForce | 0.00130 ± 0.00020 | 0.00133 ± 0.00095 | 0.00050 ± 0.00078 |
| cicids2018 | DDoS | 0.00120 ± 0.00040 | 0.00133 ± 0.00095 | 0.00093 ± 0.00085 |
| cicids2018 | DoS | 0.00113 ± 0.00046 | 0.00133 ± 0.00095 | 0.00083 ± 0.00081 |
| cicids2018 | Infiltration | 0.00093 ± 0.00042 | 0.00133 ± 0.00095 | 0.00093 ± 0.00092 |
| ciciot2023 | BruteForce | 0.00127 ± 0.00040 | 0.00137 ± 0.00074 | 0.00097 ± 0.00057 |
| ciciot2023 | DDoS | 0.00067 ± 0.00045 | 0.00137 ± 0.00074 | 0.00077 ± 0.00072 |
| ciciot2023 | DoS | 0.00083 ± 0.00040 | 0.00137 ± 0.00074 | 0.00073 ± 0.00067 |
| ciciot2023 | Mirai | 0.00090 ± 0.00020 | 0.00137 ± 0.00074 | 0.00080 ± 0.00062 |
| ciciot2023 | Recon | 0.00080 ± 0.00036 | 0.00137 ± 0.00074 | 0.00077 ± 0.00064 |
| ciciot2023 | Spoofing | 0.00113 ± 0.00038 | 0.00137 ± 0.00074 | 0.00093 ± 0.00040 |
| ciciot2023 | Web | 0.00077 ± 0.00045 | 0.00137 ± 0.00074 | 0.00070 ± 0.00078 |
| ciciomt2024 | DDoS | 0.00122 ± 0.00029 | 0.00094 ± 0.00022 | 0.00019 ± 0.00033 |
| ciciomt2024 | DoS | 0.00099 ± 0.00037 | 0.00094 ± 0.00022 | 0.00047 ± 0.00050 |
| ciciomt2024 | MQTT | 0.00099 ± 0.00028 | 0.00094 ± 0.00022 | 0.00061 ± 0.00022 |
| ciciomt2024 | Recon | 0.00071 ± 0.00028 | 0.00094 ± 0.00022 | 0.00047 ± 0.00022 |
| ciciomt2024 | Spoofing | 0.00122 ± 0.00022 | 0.00094 ± 0.00022 | 0.00061 ± 0.00054 |
| edgeiiot | Backdoor | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | DDoS_HTTP | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | DDoS_ICMP | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | DDoS_TCP | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | DDoS_UDP | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Fingerprinting | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Password | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Port_Scanning | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Ransomware | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | SQL_injection | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Uploading | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | Vulnerability_scanner | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| edgeiiot | XSS | 0.00000 ± 0.00000 | 0.00107 ± 0.00015 | 0.00127 ± 0.00055 |
| NF-ToN-IoT-v2 | ddos | 0.00190 ± 0.00070 | 0.00083 ± 0.00012 | 0.00060 ± 0.00052 |
| NF-ToN-IoT-v2 | dos | 0.00160 ± 0.00020 | 0.00083 ± 0.00012 | 0.00077 ± 0.00068 |
| NF-ToN-IoT-v2 | injection | 0.00140 ± 0.00050 | 0.00083 ± 0.00012 | 0.00000 ± 0.00000 |
| NF-ToN-IoT-v2 | mitm | 0.00140 ± 0.00053 | 0.00083 ± 0.00012 | 0.00030 ± 0.00052 |
| NF-ToN-IoT-v2 | password | 0.00150 ± 0.00075 | 0.00083 ± 0.00012 | 0.00023 ± 0.00040 |
| NF-ToN-IoT-v2 | scanning | 0.00150 ± 0.00030 | 0.00083 ± 0.00012 | 0.00047 ± 0.00057 |
| NF-ToN-IoT-v2 | xss | 0.00170 ± 0.00044 | 0.00083 ± 0.00012 | 0.00073 ± 0.00067 |

## Conformal + BH on the pooled test set (mean over seeds)

| dataset | family | model | alpha | realized FDR | power unseen | power known |
|---|---|---|---|---|---|---|
| cicids2017 | Bot | xgb | 0.01 | 0.0053 | 0.000 | 0.999 |
| cicids2017 | Bot | xgb | 0.1 | 0.0494 | 0.029 | 1.000 |
| cicids2017 | Bot | fusion | 0.01 | 0.0055 | 0.000 | 0.999 |
| cicids2017 | Bot | fusion | 0.1 | 0.0486 | 0.034 | 1.000 |
| cicids2017 | BruteForce | xgb | 0.01 | 0.0064 | 0.017 | 0.999 |
| cicids2017 | BruteForce | xgb | 0.1 | 0.0490 | 0.391 | 1.000 |
| cicids2017 | BruteForce | fusion | 0.01 | 0.0048 | 0.006 | 0.997 |
| cicids2017 | BruteForce | fusion | 0.1 | 0.0523 | 0.133 | 0.999 |
| cicids2017 | DDoS | xgb | 0.01 | 0.0052 | 0.640 | 0.999 |
| cicids2017 | DDoS | xgb | 0.1 | 0.0497 | 0.647 | 1.000 |
| cicids2017 | DDoS | fusion | 0.01 | 0.0053 | 0.636 | 0.998 |
| cicids2017 | DDoS | fusion | 0.1 | 0.0492 | 0.641 | 1.000 |
| cicids2017 | DoS | xgb | 0.01 | 0.0049 | 0.226 | 0.999 |
| cicids2017 | DoS | xgb | 0.1 | 0.0498 | 0.839 | 1.000 |
| cicids2017 | DoS | fusion | 0.01 | 0.0042 | 0.081 | 0.997 |
| cicids2017 | DoS | fusion | 0.1 | 0.0505 | 0.949 | 0.999 |
| cicids2017 | PortScan | xgb | 0.01 | 0.0050 | 0.536 | 0.999 |
| cicids2017 | PortScan | xgb | 0.1 | 0.0497 | 0.650 | 1.000 |
| cicids2017 | PortScan | fusion | 0.01 | 0.0050 | 0.441 | 0.998 |
| cicids2017 | PortScan | fusion | 0.1 | 0.0491 | 0.555 | 1.000 |
| cicids2017 | WebAttack | xgb | 0.01 | 0.0043 | 0.922 | 0.999 |
| cicids2017 | WebAttack | xgb | 0.1 | 0.0500 | 0.960 | 1.000 |
| cicids2017 | WebAttack | fusion | 0.01 | 0.0046 | 0.891 | 0.999 |
| cicids2017 | WebAttack | fusion | 0.1 | 0.0506 | 0.959 | 1.000 |
| cicids2018 | Bot | xgb | 0.01 | 0.0045 | 0.975 | 0.798 |
| cicids2018 | Bot | xgb | 0.1 | 0.0390 | 0.995 | 0.891 |
| cicids2018 | Bot | fusion | 0.01 | 0.0051 | 0.974 | 0.787 |
| cicids2018 | Bot | fusion | 0.1 | 0.0354 | 0.983 | 0.857 |
| cicids2018 | BruteForce | xgb | 0.01 | 0.0047 | 0.000 | 0.789 |
| cicids2018 | BruteForce | xgb | 0.1 | 0.0376 | 0.010 | 0.876 |
| cicids2018 | BruteForce | fusion | 0.01 | 0.0062 | 0.000 | 0.784 |
| cicids2018 | BruteForce | fusion | 0.1 | 0.0365 | 0.001 | 0.843 |
| cicids2018 | DDoS | xgb | 0.01 | 0.0041 | 0.681 | 0.794 |
| cicids2018 | DDoS | xgb | 0.1 | 0.0392 | 0.820 | 0.890 |
| cicids2018 | DDoS | fusion | 0.01 | 0.0051 | 0.601 | 0.786 |
| cicids2018 | DDoS | fusion | 0.1 | 0.0360 | 0.794 | 0.855 |
| cicids2018 | DoS | xgb | 0.01 | 0.0043 | 0.059 | 0.789 |
| cicids2018 | DoS | xgb | 0.1 | 0.0381 | 0.098 | 0.878 |
| cicids2018 | DoS | fusion | 0.01 | 0.0054 | 0.041 | 0.781 |
| cicids2018 | DoS | fusion | 0.1 | 0.0359 | 0.092 | 0.844 |
| cicids2018 | Infiltration | xgb | 0.01 | 0.0040 | 0.051 | 1.000 |
| cicids2018 | Infiltration | xgb | 0.1 | 0.0388 | 0.193 | 1.000 |
| cicids2018 | Infiltration | fusion | 0.01 | 0.0045 | 0.038 | 1.000 |
| cicids2018 | Infiltration | fusion | 0.1 | 0.0388 | 0.197 | 1.000 |
| ciciot2023 | BruteForce | xgb | 0.01 | 0.0036 | 0.188 | 0.750 |
| ciciot2023 | BruteForce | xgb | 0.1 | 0.0320 | 0.500 | 0.857 |
| ciciot2023 | BruteForce | fusion | 0.01 | 0.0036 | 0.137 | 0.728 |
| ciciot2023 | BruteForce | fusion | 0.1 | 0.0291 | 0.413 | 0.825 |
| ciciot2023 | DDoS | xgb | 0.01 | 0.0033 | 1.000 | 0.640 |
| ciciot2023 | DDoS | xgb | 0.1 | 0.0315 | 1.000 | 0.807 |
| ciciot2023 | DDoS | fusion | 0.01 | 0.0031 | 1.000 | 0.607 |
| ciciot2023 | DDoS | fusion | 0.1 | 0.0286 | 1.000 | 0.759 |
| ciciot2023 | DoS | xgb | 0.01 | 0.0030 | 1.000 | 0.639 |
| ciciot2023 | DoS | xgb | 0.1 | 0.0314 | 1.000 | 0.805 |
| ciciot2023 | DoS | fusion | 0.01 | 0.0031 | 1.000 | 0.614 |
| ciciot2023 | DoS | fusion | 0.1 | 0.0287 | 1.000 | 0.760 |
| ciciot2023 | Mirai | xgb | 0.01 | 0.0033 | 1.000 | 0.644 |
| ciciot2023 | Mirai | xgb | 0.1 | 0.0315 | 1.000 | 0.806 |
| ciciot2023 | Mirai | fusion | 0.01 | 0.0029 | 1.000 | 0.604 |
| ciciot2023 | Mirai | fusion | 0.1 | 0.0295 | 1.000 | 0.763 |
| ciciot2023 | Recon | xgb | 0.01 | 0.0034 | 0.183 | 0.752 |
| ciciot2023 | Recon | xgb | 0.1 | 0.0299 | 0.470 | 0.881 |
| ciciot2023 | Recon | fusion | 0.01 | 0.0035 | 0.133 | 0.731 |
| ciciot2023 | Recon | fusion | 0.1 | 0.0291 | 0.439 | 0.847 |
| ciciot2023 | Spoofing | xgb | 0.01 | 0.0030 | 0.146 | 0.669 |
| ciciot2023 | Spoofing | xgb | 0.1 | 0.0324 | 0.552 | 0.822 |
| ciciot2023 | Spoofing | fusion | 0.01 | 0.0030 | 0.093 | 0.645 |
| ciciot2023 | Spoofing | fusion | 0.1 | 0.0290 | 0.425 | 0.775 |
| ciciot2023 | Web | xgb | 0.01 | 0.0028 | 0.100 | 0.768 |
| ciciot2023 | Web | xgb | 0.1 | 0.0306 | 0.479 | 0.862 |
| ciciot2023 | Web | fusion | 0.01 | 0.0033 | 0.065 | 0.755 |
| ciciot2023 | Web | fusion | 0.1 | 0.0286 | 0.375 | 0.834 |
| ciciomt2024 | DDoS | xgb | 0.01 | 0.0043 | 0.936 | 0.971 |
| ciciomt2024 | DDoS | xgb | 0.1 | 0.0398 | 0.981 | 0.985 |
| ciciomt2024 | DDoS | fusion | 0.01 | 0.0036 | 0.902 | 0.966 |
| ciciomt2024 | DDoS | fusion | 0.1 | 0.0415 | 0.986 | 0.983 |
| ciciomt2024 | DoS | xgb | 0.01 | 0.0050 | 0.992 | 0.972 |
| ciciomt2024 | DoS | xgb | 0.1 | 0.0399 | 0.995 | 0.986 |
| ciciomt2024 | DoS | fusion | 0.01 | 0.0038 | 0.990 | 0.967 |
| ciciomt2024 | DoS | fusion | 0.1 | 0.0402 | 0.994 | 0.983 |
| ciciomt2024 | MQTT | xgb | 0.01 | 0.0037 | 0.858 | 0.979 |
| ciciomt2024 | MQTT | xgb | 0.1 | 0.0420 | 0.935 | 0.991 |
| ciciomt2024 | MQTT | fusion | 0.01 | 0.0036 | 0.796 | 0.975 |
| ciciomt2024 | MQTT | fusion | 0.1 | 0.0390 | 0.950 | 0.987 |
| ciciomt2024 | Recon | xgb | 0.01 | 0.0046 | 0.893 | 0.974 |
| ciciomt2024 | Recon | xgb | 0.1 | 0.0417 | 0.991 | 0.988 |
| ciciomt2024 | Recon | fusion | 0.01 | 0.0035 | 0.875 | 0.969 |
| ciciomt2024 | Recon | fusion | 0.1 | 0.0415 | 0.991 | 0.984 |
| ciciomt2024 | Spoofing | xgb | 0.01 | 0.0047 | 0.323 | 0.991 |
| ciciomt2024 | Spoofing | xgb | 0.1 | 0.0398 | 0.557 | 0.994 |
| ciciomt2024 | Spoofing | fusion | 0.01 | 0.0033 | 0.189 | 0.989 |
| ciciomt2024 | Spoofing | fusion | 0.1 | 0.0392 | 0.525 | 0.993 |
| edgeiiot | Backdoor | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Backdoor | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Backdoor | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Backdoor | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | DDoS_HTTP | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_HTTP | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_HTTP | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | DDoS_HTTP | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | DDoS_ICMP | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_ICMP | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_ICMP | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | DDoS_ICMP | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | DDoS_TCP | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_TCP | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_TCP | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | DDoS_TCP | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | DDoS_UDP | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_UDP | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | DDoS_UDP | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | DDoS_UDP | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Fingerprinting | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Fingerprinting | xgb | 0.1 | 0.0066 | 1.000 | 1.000 |
| edgeiiot | Fingerprinting | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Fingerprinting | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Password | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Password | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Password | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Password | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Port_Scanning | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Port_Scanning | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Port_Scanning | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Port_Scanning | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Ransomware | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Ransomware | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Ransomware | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Ransomware | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | SQL_injection | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | SQL_injection | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | SQL_injection | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | SQL_injection | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Uploading | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Uploading | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Uploading | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Uploading | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | Vulnerability_scanner | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Vulnerability_scanner | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | Vulnerability_scanner | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | Vulnerability_scanner | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| edgeiiot | XSS | xgb | 0.01 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | XSS | xgb | 0.1 | 0.0000 | 1.000 | 1.000 |
| edgeiiot | XSS | fusion | 0.01 | 0.0009 | 1.000 | 1.000 |
| edgeiiot | XSS | fusion | 0.1 | 0.0110 | 1.000 | 1.000 |
| NF-ToN-IoT-v2 | ddos | xgb | 0.01 | 0.0042 | 0.604 | 0.649 |
| NF-ToN-IoT-v2 | ddos | xgb | 0.1 | 0.0358 | 0.923 | 0.933 |
| NF-ToN-IoT-v2 | ddos | fusion | 0.01 | 0.0046 | 0.498 | 0.622 |
| NF-ToN-IoT-v2 | ddos | fusion | 0.1 | 0.0358 | 0.846 | 0.796 |
| NF-ToN-IoT-v2 | dos | xgb | 0.01 | 0.0043 | 0.714 | 0.676 |
| NF-ToN-IoT-v2 | dos | xgb | 0.1 | 0.0352 | 0.958 | 0.931 |
| NF-ToN-IoT-v2 | dos | fusion | 0.01 | 0.0046 | 0.691 | 0.646 |
| NF-ToN-IoT-v2 | dos | fusion | 0.1 | 0.0349 | 0.823 | 0.808 |
| NF-ToN-IoT-v2 | injection | xgb | 0.01 | 0.0038 | 0.625 | 0.669 |
| NF-ToN-IoT-v2 | injection | xgb | 0.1 | 0.0358 | 0.935 | 0.933 |
| NF-ToN-IoT-v2 | injection | fusion | 0.01 | 0.0045 | 0.562 | 0.646 |
| NF-ToN-IoT-v2 | injection | fusion | 0.1 | 0.0354 | 0.815 | 0.802 |
| NF-ToN-IoT-v2 | mitm | xgb | 0.01 | 0.0042 | 0.454 | 0.699 |
| NF-ToN-IoT-v2 | mitm | xgb | 0.1 | 0.0345 | 0.607 | 0.938 |
| NF-ToN-IoT-v2 | mitm | fusion | 0.01 | 0.0045 | 0.449 | 0.668 |
| NF-ToN-IoT-v2 | mitm | fusion | 0.1 | 0.0354 | 0.533 | 0.818 |
| NF-ToN-IoT-v2 | password | xgb | 0.01 | 0.0037 | 0.908 | 0.646 |
| NF-ToN-IoT-v2 | password | xgb | 0.1 | 0.0354 | 0.956 | 0.931 |
| NF-ToN-IoT-v2 | password | fusion | 0.01 | 0.0044 | 0.882 | 0.618 |
| NF-ToN-IoT-v2 | password | fusion | 0.1 | 0.0351 | 0.941 | 0.786 |
| NF-ToN-IoT-v2 | scanning | xgb | 0.01 | 0.0043 | 0.013 | 0.809 |
| NF-ToN-IoT-v2 | scanning | xgb | 0.1 | 0.0362 | 0.190 | 0.998 |
| NF-ToN-IoT-v2 | scanning | fusion | 0.01 | 0.0042 | 0.006 | 0.786 |
| NF-ToN-IoT-v2 | scanning | fusion | 0.1 | 0.0355 | 0.067 | 0.935 |
| NF-ToN-IoT-v2 | xss | xgb | 0.01 | 0.0046 | 0.274 | 0.750 |
| NF-ToN-IoT-v2 | xss | xgb | 0.1 | 0.0348 | 0.683 | 0.944 |
| NF-ToN-IoT-v2 | xss | fusion | 0.01 | 0.0047 | 0.229 | 0.725 |
| NF-ToN-IoT-v2 | xss | fusion | 0.1 | 0.0342 | 0.517 | 0.863 |
