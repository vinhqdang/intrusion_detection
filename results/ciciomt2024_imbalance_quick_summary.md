# ciciomt2024_imbalance_quick_summary

Mean ± sample std over seeds. Minority classes (share < 10% of training data): MQTT, Spoofing.

| Protocol | Dedup | Sampler | Model | Seeds | Macro-F1 | Accuracy | MCC | FPR | FNR | F1 MQTT | F1 Spoofing | Synthetic in test |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| clean | false | none | lgbm | 1 | 0.8861 | 0.9084 | 0.8860 | 0.0520 | 0.0404 | 0.9375 | 0.7006 | 0.0000 |
| clean | false | smote | lgbm | 1 | 0.8826 | 0.9055 | 0.8826 | 0.0673 | 0.0381 | 0.9268 | 0.6932 | 0.0000 |
| clean | false | smote_tomek | lgbm | 1 | 0.8783 | 0.9004 | 0.8764 | 0.0760 | 0.0383 | 0.9311 | 0.6832 | 0.0000 |
| clean | true | none | lgbm | 1 | 0.8843 | 0.9019 | 0.8779 | 0.0556 | 0.0403 | 0.9426 | 0.7166 | 0.0000 |
| clean | true | smote | lgbm | 1 | 0.8746 | 0.8944 | 0.8690 | 0.0845 | 0.0381 | 0.9360 | 0.6798 | 0.0000 |
| clean | true | smote_tomek | lgbm | 1 | 0.8737 | 0.8947 | 0.8696 | 0.0731 | 0.0398 | 0.9325 | 0.6739 | 0.0000 |
