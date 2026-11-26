# Case study: evaluation issues in a 2026 imbalanced-IDS paper

Paper: S. Anwer, A. Shah, F. Wahab, S. M. Al Ghuribi, "LITE-GEN: An explainable lightweight
Transformer-guided generative ensemble network for imbalanced intrusion detection in IoT
environments", *Pervasive and Mobile Computing*, 2026, doi:10.1016/j.pmcj.2026.102304
(journal pre-proof).

This note is not about this one paper. It shows the evaluation patterns that P1 (see
[`ROADMAP.md`](ROADMAP.md)) measures systematically. Each point below can be checked against
the paper text or reproduced with `idsbench`.

## Pipeline (as described)

1. Min-max scaling of features, then SMOTE-Tomek.
2. A conditional GAN with attention blocks in G and D, trained with adversarial loss plus a
   class-consistency loss.
3. MC-dropout filtering of synthetic samples: keep x̂ if |Var(x̂) − μ| ≤ σ.
4. Base learners RF, XGBoost, LightGBM and MLP, combined by weighted hard vote. Weights come
   from replicator dynamics on validation accuracy.

Reported results: accuracy 99.18% and macro-F1 99.32% on CICIoT2023 (7 classes); 99.02% and
99.29% on NSL-KDD (5 classes).

## Issues

### 1. The split protocol is not specified
The paper says "the same train-test partition" was used across runs. It gives no split ratio,
does not say whether NSL-KDD's official KDDTest+ was used, and does not mention deduplication.
Eq. (1) computes the min/max "across the dataset". If scaling or SMOTE ran before the split,
synthetic points interpolated from test neighbours enter training. *idsbench:*
`protocol: leaky` vs `clean`.

### 2. NSL-KDD class counts do not match the standard files
Table 1 lists Normal 65,500 / DoS 10,600 / Probe 35,800 / U2R 52 / R2L 995. The official
KDDTrain+ has Normal 67,343 / DoS 45,927 / Probe 11,656 / R2L 995 / U2R 52. R2L and U2R match
the training file, but DoS and Probe are far off. So it is unclear which subset was evaluated.
*idsbench:* `load_nslkdd` prints the official counts (see `results/`).

### 3. The replicator ensemble reduces to best-model selection
Eq. (12) with fixed payoffs π_j = 1 − ε_j, iterated T′ times from uniform weights, has the
closed form

    w_j(T′) = π_j^{T′} / Σ_k π_k^{T′},

which converges to a one-hot vector on argmax_j π_j. Base learners score 97–99% accuracy, so
payoff differences are under 2%. For moderate T′ the weights are close to uniform; for large
T′ only one model's vote counts. Neither case is adaptive at test time. The +0.13 accuracy gain
in the ablation (V5 → full) is within a few standard deviations of seed noise. *idsbench:*
`replicator_closed_form` and its unit test.

### 4. The MC-dropout filter also discards the most confident samples
The rule |Var − μ| ≤ σ removes both tails of the variance distribution, including the
low-variance (most confident, most class-typical) synthetic points. The text says this is
deliberate ("overly certain, less informative"). However, the paper does not compare it with
the usual low-variance rule. *idsbench:* `mc_dropout_filter(rule="lites" | "low_var")`.

### 5. The reported Wilcoxon p-values cannot be attained with 5 runs
Section 4.2 reports 5 seeds and Wilcoxon signed-rank p-values of 0.009–0.018 (Table 2). With
n = 5 paired values, the exact two-sided Wilcoxon test can give no p below 2/2⁵ = 0.0625
(one-sided: 0.03125). Unless the test pooled other units (not described), these values are
impossible. *idsbench:* `stats.min_wilcoxon_p(5) == 0.0625`.

### 6. Per-class tables follow a fixed arithmetic pattern
In the class-wise baseline tables (Tables 6–7), every row satisfies
PRE = ACC − 0.05, REC = ACC − 0.15, F1 = ACC − 0.10 (e.g. Mirai_udpplain/NB: 88.20, 88.15,
88.05, 88.10; Benign/RF: 97.90, 97.85, 97.75, 97.80). Real per-class metrics do not behave like
this. The tables also give U2R (52 training samples, and an unseen-attack-heavy test set in
the official split) F1 near 98% for gradient boosting. That is far above what the literature
reports on KDDTest+.

### 7. Saturated benchmarks
NSL-KDD with a random split and a 7-class subset of CICIoT2023 (which has a high duplicate
rate) are both close to ceiling. Differences of 0.1–0.3 points are not informative without
dedup, official splits, or a cross-dataset test.

## What to take from it for our own papers

- Publish the split code and raw per-seed results.
- Fit every preprocessing step inside the training fold.
- Deduplicate and report cross-split duplicates.
- Use ≥10 seeds and Friedman/Nemenyi, or bootstrap CIs.
- Before claiming "adaptive" weights, derive their closed form.
- Report minority-class F1 on the official test set, not only on random splits.
