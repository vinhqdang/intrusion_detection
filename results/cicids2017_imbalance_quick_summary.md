# cicids2017_imbalance_quick_summary

Mean ± sample std over seeds. Minority classes (share < 10% of training data): Bot, Heartbleed, Infiltration, WebAttack.

| Protocol | Dedup | Sampler | Model | Seeds | Macro-F1 | Accuracy | MCC | FPR | FNR | F1 Bot | F1 Heartbleed | F1 Infiltration | F1 WebAttack | Synthetic in test |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| clean | false | none | lgbm | 1 | 0.2468 | 0.4111 | 0.3187 | 0.3913 | 0.2685 | 0.4149 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| clean | false | smote | lgbm | 1 | 0.9790 | 0.9961 | 0.9954 | 0.0100 | 0.0021 | 0.9898 | 1.0000 | 0.8421 | 0.9946 | 0.0000 |
| clean | false | smote_tomek | lgbm | 1 | 0.9788 | 0.9959 | 0.9951 | 0.0087 | 0.0023 | 0.9898 | 1.0000 | 0.8421 | 0.9939 | 0.0000 |
| clean | true | none | lgbm | 1 | 0.4249 | 0.6307 | 0.5537 | 0.3573 | 0.2269 | 0.4098 | 0.0000 | 0.0000 | 0.8727 | 0.0000 |
| clean | true | smote | lgbm | 1 | 0.9826 | 0.9954 | 0.9944 | 0.0096 | 0.0012 | 0.9919 | 1.0000 | 0.9000 | 0.9945 | 0.0000 |
| clean | true | smote_tomek | lgbm | 1 | 0.9763 | 0.9956 | 0.9946 | 0.0082 | 0.0014 | 0.9919 | 1.0000 | 0.8421 | 0.9953 | 0.0000 |
