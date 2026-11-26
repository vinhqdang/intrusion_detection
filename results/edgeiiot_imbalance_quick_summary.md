# edgeiiot_imbalance_quick_summary

Mean ± sample std over seeds. Minority classes (share < 10% of training data): Backdoor, DDoS_HTTP, DDoS_ICMP, DDoS_TCP, DDoS_UDP, Fingerprinting, MITM, Normal, Password, Port_Scanning, Ransomware, SQL_injection, Uploading, Vulnerability_scanner, XSS.

| Protocol | Dedup | Sampler | Model | Seeds | Macro-F1 | Accuracy | MCC | FPR | FNR | F1 Backdoor | F1 DDoS_HTTP | F1 DDoS_ICMP | F1 DDoS_TCP | F1 DDoS_UDP | F1 Fingerprinting | F1 MITM | F1 Normal | F1 Password | F1 Port_Scanning | F1 Ransomware | F1 SQL_injection | F1 Uploading | F1 Vulnerability_scanner | F1 XSS | Synthetic in test |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| clean | false | none | lgbm | 1 | 0.9261 | 0.9317 | 0.9263 | 0.0000 | 0.0000 | 0.9553 | 0.9025 | 0.9997 | 1.0000 | 1.0000 | 0.7592 | 0.9953 | 1.0000 | 0.8374 | 0.9585 | 0.9379 | 0.8291 | 0.8451 | 0.9651 | 0.9059 | 0.0000 |
| clean | false | smote | lgbm | 1 | 0.9161 | 0.9272 | 0.9214 | 0.0000 | 0.0000 | 0.9568 | 0.8993 | 0.9980 | 1.0000 | 1.0000 | 0.6365 | 0.9953 | 1.0000 | 0.8367 | 0.9447 | 0.9372 | 0.8285 | 0.8392 | 0.9627 | 0.9070 | 0.0000 |
| clean | false | smote_tomek | lgbm | 1 | 0.9168 | 0.9274 | 0.9216 | 0.0000 | 0.0000 | 0.9601 | 0.9067 | 0.9977 | 1.0000 | 1.0000 | 0.6452 | 0.9953 | 1.0000 | 0.8241 | 0.9415 | 0.9373 | 0.8275 | 0.8410 | 0.9650 | 0.9108 | 0.0000 |
| clean | true | none | lgbm | 1 | 0.9267 | 0.9322 | 0.9268 | 0.0000 | 0.0000 | 0.9556 | 0.9034 | 0.9997 | 1.0000 | 1.0000 | 0.7623 | 0.9953 | 1.0000 | 0.8387 | 0.9588 | 0.9385 | 0.8294 | 0.8461 | 0.9651 | 0.9068 | 0.0000 |
| clean | true | smote | lgbm | 1 | 0.9166 | 0.9277 | 0.9220 | 0.0000 | 0.0000 | 0.9571 | 0.9002 | 0.9980 | 1.0000 | 1.0000 | 0.6386 | 0.9953 | 1.0000 | 0.8379 | 0.9450 | 0.9378 | 0.8285 | 0.8406 | 0.9627 | 0.9079 | 0.0000 |
| clean | true | smote_tomek | lgbm | 1 | 0.9172 | 0.9278 | 0.9221 | 0.0000 | 0.0000 | 0.9604 | 0.9072 | 0.9977 | 1.0000 | 1.0000 | 0.6472 | 0.9953 | 1.0000 | 0.8249 | 0.9418 | 0.9379 | 0.8277 | 0.8417 | 0.9650 | 0.9114 | 0.0000 |
