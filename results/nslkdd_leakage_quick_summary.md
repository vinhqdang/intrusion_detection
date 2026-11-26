# nslkdd_leakage_quick_summary

Mean ± sample std over seeds. Minority classes (share < 10% of training data): r2l, u2r.

| Protocol | Dedup | Sampler | Model | Seeds | Macro-F1 | Accuracy | MCC | FPR | FNR | F1 r2l | F1 u2r | Synthetic in test |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| clean | false | none | lgbm | 1 | 0.5819 | 0.7422 | 0.6712 | 0.0316 | 0.3377 | 0.2487 | 0.1913 | 0.0000 |
| clean | false | smote | lgbm | 1 | 0.5989 | 0.7460 | 0.6748 | 0.0320 | 0.3295 | 0.3390 | 0.2000 | 0.0000 |
| clean | false | smote_tomek | lgbm | 1 | 0.6020 | 0.7441 | 0.6722 | 0.0322 | 0.3308 | 0.3562 | 0.2075 | 0.0000 |
| clean | true | none | lgbm | 1 | 0.5654 | 0.7345 | 0.6616 | 0.0316 | 0.3485 | 0.1961 | 0.1732 | 0.0000 |
| clean | true | smote | lgbm | 1 | 0.5890 | 0.7463 | 0.6747 | 0.0316 | 0.3299 | 0.3287 | 0.1572 | 0.0000 |
| clean | true | smote_tomek | lgbm | 1 | 0.5994 | 0.7503 | 0.6797 | 0.0314 | 0.3244 | 0.3539 | 0.1780 | 0.0000 |
| leaky | false | none | lgbm | 1 | 0.9724 | 0.9896 | 0.9857 | 0.0120 | 0.0076 | 0.9719 | 0.9116 | 0.0000 |
| leaky | false | smote | lgbm | 1 | 0.9942 | 0.9942 | 0.9928 | 0.0170 | 0.0022 | 0.9907 | 0.9983 | 5542.0000 |
| leaky | false | smote_tomek | lgbm | 1 | 0.9952 | 0.9952 | 0.9940 | 0.0108 | 0.0021 | 0.9921 | 0.9982 | 5528.0000 |
| leaky | true | none | lgbm | 1 | 0.9722 | 0.9899 | 0.9861 | 0.0147 | 0.0059 | 0.9721 | 0.9091 | 0.0000 |
| leaky | true | smote | lgbm | 1 | 0.9947 | 0.9947 | 0.9934 | 0.0150 | 0.0017 | 0.9905 | 0.9983 | 5565.0000 |
| leaky | true | smote_tomek | lgbm | 1 | 0.9938 | 0.9938 | 0.9923 | 0.0151 | 0.0028 | 0.9896 | 0.9978 | 5543.0000 |
