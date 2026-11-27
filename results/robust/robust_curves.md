# Recall versus budget (FPR 1e-3)

Worst case over attackers (greedy, strong, transfer) and group subsets at each multiplier; mean over seeds. Clean recall = known scenario, no attack. The last column is the smallest multiplier at which the worst-case recall drops below 0.5 (none: never below 0.5 in the grid).

## cicids2017

### generator G1

| model | family | clean | x1.5 | x2 | x5 | smallest x below 0.5 |
|---|---|---|---|---|---|---|
| adv_naive_G1 | Bot | 0.968 | 0.948 | 0.950 | 0.955 | none |
| adv_naive_G1 | BruteForce | 0.999 | 0.998 | 0.998 | 0.980 | none |
| adv_naive_G1 | DDoS | 0.999 | 0.999 | 0.998 | 0.998 | none |
| adv_naive_G1 | DoS | 0.997 | 0.981 | 0.982 | 0.987 | none |
| adv_naive_G1 | PortScan | 0.995 | 0.995 | 0.995 | 0.992 | none |
| adv_naive_G1 | WebAttack | 0.991 | 0.985 | 0.984 | 0.984 | none |
| adv_sym_G1 | Bot | 0.973 | 0.863 | 0.867 | 0.888 | none |
| adv_sym_G1 | BruteForce | 0.999 | 0.998 | 0.997 | 0.991 | none |
| adv_sym_G1 | DDoS | 0.999 | 0.998 | 0.997 | 0.997 | none |
| adv_sym_G1 | DoS | 0.997 | 0.983 | 0.982 | 0.981 | none |
| adv_sym_G1 | PortScan | 0.995 | 0.994 | 0.994 | 0.993 | none |
| adv_sym_G1 | WebAttack | 0.989 | 0.985 | 0.984 | 0.984 | none |
| adv_sym_G1G2 | Bot | 0.976 | 0.893 | 0.859 | 0.863 | none |
| adv_sym_G1G2 | BruteForce | 0.999 | 0.998 | 0.998 | 0.996 | none |
| adv_sym_G1G2 | DDoS | 0.999 | 0.998 | 0.998 | 0.998 | none |
| adv_sym_G1G2 | DoS | 0.998 | 0.982 | 0.981 | 0.978 | none |
| adv_sym_G1G2 | PortScan | 0.995 | 0.995 | 0.995 | 0.993 | none |
| adv_sym_G1G2 | WebAttack | 0.990 | 0.985 | 0.983 | 0.983 | none |
| fusion | Bot | 0.860 | 0.574 | 0.530 | 0.432 | 5 |
| fusion | BruteForce | 0.998 | 0.908 | 0.427 | 0.092 | 2 |
| fusion | DDoS | 0.998 | 0.995 | 0.976 | 0.626 | none |
| fusion | DoS | 0.987 | 0.966 | 0.961 | 0.898 | none |
| fusion | PortScan | 0.994 | 0.854 | 0.681 | 0.497 | 5 |
| fusion | WebAttack | 0.980 | 0.940 | 0.908 | 0.856 | none |
| xgb | Bot | 0.973 | 0.895 | 0.814 | 0.566 | none |
| xgb | BruteForce | 0.999 | 0.985 | 0.709 | 0.411 | 5 |
| xgb | DDoS | 0.999 | 0.997 | 0.992 | 0.708 | none |
| xgb | DoS | 0.997 | 0.973 | 0.969 | 0.932 | none |
| xgb | PortScan | 0.995 | 0.946 | 0.872 | 0.636 | none |
| xgb | WebAttack | 0.992 | 0.976 | 0.965 | 0.920 | none |
| xgb_robust | Bot | 0.553 | 0.553 | 0.553 | 0.553 | none |
| xgb_robust | BruteForce | 0.758 | 0.760 | 0.760 | 0.760 | none |
| xgb_robust | DDoS | 0.635 | 0.631 | 0.631 | 0.631 | none |
| xgb_robust | DoS | 0.912 | 0.913 | 0.913 | 0.913 | none |
| xgb_robust | PortScan | 0.404 | 0.404 | 0.404 | 0.404 | 1.5 |
| xgb_robust | WebAttack | 0.076 | 0.076 | 0.076 | 0.076 | 1.5 |

### generator G2

| model | family | clean | x1.5 | x2 | x5 | smallest x below 0.5 |
|---|---|---|---|---|---|---|
| adv_naive_G1 | Bot | 0.968 | 0.730 | 0.712 | 0.586 | none |
| adv_naive_G1 | BruteForce | 0.999 | 0.994 | 0.969 | 0.949 | none |
| adv_naive_G1 | DDoS | 0.999 | 0.783 | 0.770 | 0.784 | none |
| adv_naive_G1 | DoS | 0.997 | 0.978 | 0.979 | 0.975 | none |
| adv_naive_G1 | PortScan | 0.995 | 0.963 | 0.963 | 0.965 | none |
| adv_naive_G1 | WebAttack | 0.991 | 0.121 | 0.118 | 0.117 | 1.5 |
| adv_sym_G1 | Bot | 0.973 | 0.659 | 0.651 | 0.603 | none |
| adv_sym_G1 | BruteForce | 0.999 | 0.981 | 0.961 | 0.945 | none |
| adv_sym_G1 | DDoS | 0.999 | 0.758 | 0.743 | 0.743 | none |
| adv_sym_G1 | DoS | 0.997 | 0.979 | 0.978 | 0.972 | none |
| adv_sym_G1 | PortScan | 0.995 | 0.963 | 0.964 | 0.966 | none |
| adv_sym_G1 | WebAttack | 0.989 | 0.119 | 0.118 | 0.112 | 1.5 |
| adv_sym_G1G2 | Bot | 0.976 | 0.770 | 0.758 | 0.753 | none |
| adv_sym_G1G2 | BruteForce | 0.999 | 0.999 | 0.998 | 0.997 | none |
| adv_sym_G1G2 | DDoS | 0.999 | 0.992 | 0.985 | 0.978 | none |
| adv_sym_G1G2 | DoS | 0.998 | 0.981 | 0.980 | 0.980 | none |
| adv_sym_G1G2 | PortScan | 0.995 | 0.989 | 0.989 | 0.989 | none |
| adv_sym_G1G2 | WebAttack | 0.990 | 0.136 | 0.135 | 0.506 | 1.5 |
| fusion | Bot | 0.860 | 0.423 | 0.390 | 0.176 | 1.5 |
| fusion | BruteForce | 0.998 | 0.622 | 0.175 | 0.020 | 2 |
| fusion | DDoS | 0.998 | 0.652 | 0.642 | 0.613 | none |
| fusion | DoS | 0.987 | 0.959 | 0.953 | 0.898 | none |
| fusion | PortScan | 0.994 | 0.855 | 0.713 | 0.502 | none |
| fusion | WebAttack | 0.980 | 0.086 | 0.076 | 0.046 | 1.5 |
| xgb | Bot | 0.973 | 0.579 | 0.500 | 0.338 | 2 |
| xgb | BruteForce | 0.999 | 0.844 | 0.441 | 0.044 | 2 |
| xgb | DDoS | 0.999 | 0.706 | 0.683 | 0.654 | none |
| xgb | DoS | 0.997 | 0.968 | 0.964 | 0.944 | none |
| xgb | PortScan | 0.995 | 0.938 | 0.881 | 0.632 | none |
| xgb | WebAttack | 0.992 | 0.108 | 0.103 | 0.068 | 1.5 |
| xgb_robust | Bot | 0.553 | 0.553 | 0.553 | 0.553 | none |
| xgb_robust | BruteForce | 0.758 | 0.760 | 0.760 | 0.760 | none |
| xgb_robust | DDoS | 0.635 | 0.631 | 0.631 | 0.631 | none |
| xgb_robust | DoS | 0.912 | 0.913 | 0.913 | 0.913 | none |
| xgb_robust | PortScan | 0.404 | 0.404 | 0.404 | 0.404 | 1.5 |
| xgb_robust | WebAttack | 0.076 | 0.076 | 0.076 | 0.076 | 1.5 |

## cicids2018

### generator G1

| model | family | clean | x1.5 | x2 | x5 | smallest x below 0.5 |
|---|---|---|---|---|---|---|
| adv_naive_G1 | Bot | 0.997 | 0.994 | 0.991 | 0.990 | none |
| adv_naive_G1 | BruteForce | 1.000 | 1.000 | 0.999 | 0.999 | none |
| adv_naive_G1 | DDoS | 0.999 | 0.994 | 0.991 | 0.967 | none |
| adv_naive_G1 | DoS | 1.000 | 0.999 | 0.997 | 0.991 | none |
| adv_naive_G1 | Infiltration | 0.123 | 0.103 | 0.098 | 0.093 | 1.5 |
| adv_sym_G1 | Bot | 0.996 | 0.994 | 0.991 | 0.987 | none |
| adv_sym_G1 | BruteForce | 1.000 | 0.999 | 0.999 | 0.999 | none |
| adv_sym_G1 | DDoS | 0.999 | 0.992 | 0.978 | 0.958 | none |
| adv_sym_G1 | DoS | 1.000 | 1.000 | 0.998 | 0.992 | none |
| adv_sym_G1 | Infiltration | 0.126 | 0.101 | 0.096 | 0.084 | 1.5 |
| adv_sym_G1G2 | Bot | 0.996 | 0.995 | 0.991 | 0.990 | none |
| adv_sym_G1G2 | BruteForce | 1.000 | 1.000 | 1.000 | 1.000 | none |
| adv_sym_G1G2 | DDoS | 0.999 | 0.992 | 0.976 | 0.950 | none |
| adv_sym_G1G2 | DoS | 1.000 | 1.000 | 0.999 | 0.993 | none |
| adv_sym_G1G2 | Infiltration | 0.126 | 0.100 | 0.094 | 0.081 | 1.5 |
| fusion | Bot | 0.995 | 0.970 | 0.887 | 0.009 | 5 |
| fusion | BruteForce | 1.000 | 0.833 | 0.002 | 0.002 | 2 |
| fusion | DDoS | 0.997 | 0.976 | 0.849 | 0.519 | none |
| fusion | DoS | 1.000 | 0.998 | 0.924 | 0.828 | none |
| fusion | Infiltration | 0.110 | 0.073 | 0.052 | 0.019 | 1.5 |
| xgb | Bot | 0.996 | 0.987 | 0.967 | 0.012 | 5 |
| xgb | BruteForce | 1.000 | 0.914 | 0.002 | 0.002 | 2 |
| xgb | DDoS | 0.998 | 0.986 | 0.918 | 0.554 | none |
| xgb | DoS | 1.000 | 0.999 | 0.934 | 0.828 | none |
| xgb | Infiltration | 0.126 | 0.087 | 0.065 | 0.027 | 1.5 |
| xgb_robust | Bot | 0.990 | 0.990 | 0.990 | 0.990 | none |
| xgb_robust | BruteForce | 0.999 | 0.999 | 0.999 | 0.999 | none |
| xgb_robust | DDoS | 0.807 | 0.805 | 0.805 | 0.805 | none |
| xgb_robust | DoS | 1.000 | 1.000 | 1.000 | 1.000 | none |
| xgb_robust | Infiltration | 0.085 | 0.088 | 0.088 | 0.088 | 1.5 |

### generator G2

| model | family | clean | x1.5 | x2 | x5 | smallest x below 0.5 |
|---|---|---|---|---|---|---|
| adv_naive_G1 | Bot | 0.997 | 0.993 | 0.989 | 0.980 | none |
| adv_naive_G1 | BruteForce | 1.000 | 1.000 | 1.000 | 0.999 | none |
| adv_naive_G1 | DDoS | 0.999 | 0.992 | 0.968 | 0.926 | none |
| adv_naive_G1 | DoS | 1.000 | 0.999 | 0.985 | 0.941 | none |
| adv_naive_G1 | Infiltration | 0.123 | 0.090 | 0.084 | 0.073 | 1.5 |
| adv_sym_G1 | Bot | 0.996 | 0.993 | 0.989 | 0.981 | none |
| adv_sym_G1 | BruteForce | 1.000 | 0.999 | 0.999 | 0.999 | none |
| adv_sym_G1 | DDoS | 0.999 | 0.991 | 0.955 | 0.924 | none |
| adv_sym_G1 | DoS | 1.000 | 1.000 | 0.997 | 0.987 | none |
| adv_sym_G1 | Infiltration | 0.126 | 0.092 | 0.085 | 0.074 | 1.5 |
| adv_sym_G1G2 | Bot | 0.996 | 0.994 | 0.991 | 0.991 | none |
| adv_sym_G1G2 | BruteForce | 1.000 | 1.000 | 1.000 | 1.000 | none |
| adv_sym_G1G2 | DDoS | 0.999 | 0.991 | 0.977 | 0.958 | none |
| adv_sym_G1G2 | DoS | 1.000 | 1.000 | 1.000 | 0.996 | none |
| adv_sym_G1G2 | Infiltration | 0.126 | 0.101 | 0.096 | 0.092 | 1.5 |
| fusion | Bot | 0.995 | 0.969 | 0.256 | 0.022 | 2 |
| fusion | BruteForce | 1.000 | 0.999 | 0.904 | 0.002 | 5 |
| fusion | DDoS | 0.997 | 0.976 | 0.658 | 0.501 | none |
| fusion | DoS | 1.000 | 0.975 | 0.849 | 0.828 | none |
| fusion | Infiltration | 0.110 | 0.068 | 0.054 | 0.022 | 1.5 |
| xgb | Bot | 0.996 | 0.986 | 0.309 | 0.032 | 2 |
| xgb | BruteForce | 1.000 | 0.999 | 0.935 | 0.002 | 5 |
| xgb | DDoS | 0.998 | 0.985 | 0.721 | 0.517 | none |
| xgb | DoS | 1.000 | 0.979 | 0.861 | 0.828 | none |
| xgb | Infiltration | 0.126 | 0.080 | 0.066 | 0.030 | 1.5 |
| xgb_robust | Bot | 0.990 | 0.990 | 0.990 | 0.990 | none |
| xgb_robust | BruteForce | 0.999 | 0.999 | 0.999 | 0.999 | none |
| xgb_robust | DDoS | 0.807 | 0.805 | 0.805 | 0.805 | none |
| xgb_robust | DoS | 1.000 | 1.000 | 1.000 | 1.000 | none |
| xgb_robust | Infiltration | 0.085 | 0.088 | 0.088 | 0.088 | 1.5 |

