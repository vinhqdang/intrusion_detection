# E1 shortcut index

| dataset | n | dedup % | conflict % | XGB AUROC | depth-2 AUROC | best-1-feature AUROC (name) | #families with single-feature AUROC >= 0.99 |
|---|---|---|---|---|---|---|---|
| cicids2017 | 414,587 | 22.23 | 0.02 | 1.0000 ± 0.0000 | 0.9377 ± 0.0002 | 0.8180 ± 0.0010 (Fwd IAT Std (3)) | 0.0 ± 0.0 of 6 (0% of families, per seed = count / evaluated) |
| cicids2018 | 550,335 | 49.89 | 0.69 | 0.9859 ± 0.0003 | 0.8585 ± 0.0004 | 0.6664 ± 0.0005 (Fwd Seg Size Min (3)) | 1.0 ± 0.0 of 6 (17% of families, per seed = count / evaluated) |
| ciciot2023 | 486,743 | 10.37 | 0.05 | 0.9651 ± 0.0001 | 0.8249 ± 0.0001 | 0.8157 ± 0.0002 (HTTPS (3)) | 3.0 ± 0.0 of 7 (43% of families, per seed = count / evaluated) |
| ciciomt2024 | 187,976 | 19.43 | 0.01 | 0.9988 ± 0.0001 | 0.9710 ± 0.0007 | 0.9238 ± 0.0002 (Packet Length Max (3)) | 0.0 ± 0.0 of 5 (0% of families, per seed = count / evaluated) |
| edgeiiot | 753,978 | 0.08 | 0.00 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 (mqtt.conack.flags-0.0 (3)) | 14.0 ± 0.0 of 14 (100% of families, per seed = count / evaluated) |
| NF-ToN-IoT-v2 | 393,615 | 80.07 | 0.00 | 0.9939 ± 0.0001 | 0.7548 ± 0.0012 | 0.7105 ± 0.0009 (DNS_TTL_ANSWER (3)) | 0.0 ± 0.0 of 7 (0% of families, per seed = count / evaluated) |
