# Research roadmap: intrusion detection, 2027 restart

Last updated: 2026-11-26.

## 1. Where the earlier line of work stands

Work published 2019–2026, grouped by theme (DOIs checked against Crossref):

| Theme | Papers | What it gives the new line |
|---|---|---|
| ML baselines and benchmarks | Studying ML techniques for IDS (FDSE 2019, 10.1007/978-3-030-35653-8_28); Using ML for IDS (Computing and Informatics 2022, 10.31577/cai_2022_1_12); CIDDS-001 (2022) and CIDDS-002 (CSSE 2021); USB-IDS-1 multi-layer (2023); ML for IDS chapter (IGI 2022) | Experience with many datasets. The new protocol (below) puts that experience into a reusable benchmark. |
| Explainability | Understanding the decision of ML-based IDS (FDSE 2020, 10.1007/978-3-030-63924-2_22); Improving IDS performance by ML explainability (IJWIS 2021, 10.1108/ijwis-03-2021-0022) | XAI as a performance tool, not only a reporting tool. |
| Learning with few labels / self-learning | Active learning for IDS (RIVF 2020, 10.1109/rivf48685.2020.9140751); Towards an automatic self-learning IDS (2023); RL for intrusion detection (ICAIBD 2021; LNNS 2021) | Label budget and online adaptation. |
| Transfer and multi-dataset | Learning to transfer knowledge between datasets (LNEE 2023); Multiple datasets in SDN (2022); IDS in SDN (2021) | Cross-dataset generalisation, now a central open problem in the field. |
| Representation learning | Transformer for intrusion detection (2023); GNN for WiFi intrusion (2023); LLM embedding for intrusion detection (2025); Fuzzy embedding in SDN (2024) | Pretrained and foundation-style flow encoders. |
| Uncertainty | Utilizing uncertainty measures to improve IDS (SN Computer Science 2026, 10.1007/s42979-026-04923-8); Fuzzy-conformal GNN with coverage guarantees (IJMLC 2026, 10.1007/s13042-026-03371-3) | The strongest recent hook: distribution-free guarantees. |
| Lightweight / IoT / IoMT | Parallel optimisation for lightweight IDS (2023); IDS in IoT (ADS 2022); IDS in IoMT (2024) | Edge deployment. |

**Gap in the record:** most items are conference chapters (LNCS, LNNS, CCIS). The restart should
aim at two or three Q1 journal papers that build on the existing themes.

## 2. State of the field (2024–2026), in short

1. **Most of the current literature is tabular flow classification at ~99%**, on NSL-KDD,
   UNSW-NB15, CIC-IDS2017, ToN-IoT and CICIoT2023, with stacked components: SMOTE/GAN
   augmentation, Transformers on tabular features, and ensembles. LITE-GEN (Pervasive and Mobile
   Computing 2026, 10.1016/j.pmcj.2026.102304) is a typical example; see
   [`case_study_litegen.md`](case_study_litegen.md).
2. **Evaluation is the weak point, and reviewers are starting to notice.** 2025–2026 work reports
   that temporal or cross-dataset splits and realistic base rates make scores drop a lot
   (e.g. the NetFlow NIDS review, arXiv 2602.05594). It also reports heavy duplication in
   CICIoT2023 (about 55% exact duplicate rows in a 39-feature view, arXiv 2608.10349) and
   macro-F1 losses up to ~30 points across IIoT datasets (arXiv 2607.00553).
3. **LLMs and foundation models for NIDS** are a fast-growing survey topic (arXiv 2507.04752,
   2510.23313). Few papers yet show a pretrained flow encoder that transfers across datasets
   under a clean protocol.
4. **Uncertainty, conformal prediction and selective prediction** for IDS are still young. They
   fit SOC practice well: a model can abstain and pass the case to an analyst.

## 3. Proposed projects

> **Update 2026-11-27.** The main project is now the data-driven game-theoretic evaluation of ML-IDS in
> [`design_econ_game.md`](design_econ_game.md). The conformal project below is kept as background. Its
> E1–E3 results feed the new payoff tables, and [`lit_review_conformal_ids.md`](lit_review_conformal_ids.md)
> explains why conformal-for-IDS alone is too crowded.

### Former main project: FDR-controlled intrusion detection for unseen attacks and new networks

*Motivation.* On CIC-style benchmarks, flow classification with a random split is saturated:
XGBoost reaches AUROC ≈ 1.0, often through testbed shortcuts (destination port, TTL, window
size). The open problems are elsewhere:
(i) attack families never seen in training;
(ii) deployment on a network other than the training one;
(iii) operating at the alert budgets a SOC can afford, with a false-alarm rate that holds.

*Question.* Can conformal novelty detection give an IDS a finite-sample guarantee on the
false-discovery rate among its alerts, even for unseen attack families? Can it keep that
guarantee, or degrade gracefully, when moved to a new network?

*Method.*
- Score: fuse a supervised detector (GBDT) for known attacks with a benign-only one-class score
  for novel ones.
- Turn scores into conformal p-values against benign calibration flows.
- Use Benjamini–Hochberg for FDR-controlled alerting (Bates et al., 2023).
- Use weighted conformal (Tibshirani et al., 2019) with label-free domain weights for network
  shift.
- Send abstained or borderline flows to an analyst (link to active learning, 2020). Explain
  alerts by attributing the conformal score (link to XAI, 2020/2021).

*Evaluation.*
- Leave-one-family-out on CIC-IDS2017, CSE-CIC-IDS2018, CICIoT2023, CICIoMT2024 and
  Edge-IIoTset.
- Cross-network on the NetFlow v3 family, which shares one feature schema.
- Metrics: realized FPR/FDR vs target, recall on unseen families at FPR 1e-3/1e-4, and analyst
  workload.

*Feasibility check (running now).*
- E1, shortcut index: best single-feature and depth-2 tree AUROC per dataset.
- E2, leave-one-family-out recall gap.
- E3, cross-network AUROC matrix and how far A-calibrated thresholds drift on B.
Code: `src/idsbench/feasibility/`. Results: `results/feasibility/SUMMARY.md`.

*Feasibility outcome (2026-11-26): go.* Full numbers are in
`results/feasibility/SUMMARY.md`. The main results were also reproduced independently.
- **E1.** XGBoost AUROC is 0.965–1.000 on every dataset. On Edge-IIoTset a single feature
  (`mqtt.conack.flags`) separates all 14 attack families with AUROC 1.0, so it is excluded as a
  main benchmark and used only as a shortcut example.
- **E2.** Recall at FPR 1e-3 collapses when a family is unseen in training, even though AUROC on
  that family stays at 0.84–0.99. Examples:
  - CIC-IDS2017 Bot: 0.94 → 0.00; BruteForce: 1.00 → 0.002; DoS: 0.99 → 0.05.
  - CSE-CIC-IDS2018 DoS: 1.00 → 0.01.
  - CICIoT2023 Spoofing: 0.74 → 0.06.

  Benign-only IsolationForest has recall ≈ 0 at 1e-3. Naive Bonferroni fusion is worse than
  XGBoost alone. Conformal + BH holds FDR ≤ α in-domain.
- **E3.** CIC-IDS2017 ↔ CSE-CIC-IDS2018 (68 shared CICFlowMeter features):
  - AUROC is 0.75 (2017 → 2018) and 0.56 (2018 → 2017).
  - Thresholds calibrated on A for 1% FPR give 10.9% FPR on B.
  - Conformal + BH at α = 0.1 gives FDR 0.51 on B.
  - Weighted conformal does not restore the guarantee: the oracle and label-free variants both
    fail.
- **Method gaps this leaves:**
  - (i) a fusion score that keeps known-attack recall while detecting novel families at strict
    FPR;
  - (ii) shift-robust calibration that works when the target network contains attacks and
    density-ratio weights are poor, e.g. a small labelled benign target calibration set,
    or online / adaptive conformal on target traffic.
- **Data gaps:**
  - NetFlow v3 (NF-UNSW-NB15-v3, NF-CICIDS2018-v3) needs the official UQ download.
  - CSE-CIC-IDS2018 and CICIoMT2024 were only partly downloaded.
  - CICIoT2023 and CICIoMT2024 share no feature names.

*Targets.* IEEE TIFS / TDSC, Computers & Security.

### Side project: leakage-free re-evaluation of imbalance-aware pipelines (short reproducibility paper)

*Question.* Do the gains reported for augmentation (SMOTE-Tomek, conditional GANs, filtered
synthetic data) and adaptive ensembles survive a leakage-free protocol: official splits,
dedup across splits, resampling only inside the training fold, and proper statistics?

*Design.* This is what the `idsbench` package in this repo implements.
- Factors: protocol {leaky, clean} × dedup {no, yes} × sampler {none, ROS, SMOTE,
  SMOTE-Tomek, CGAN, CGAN+MC-filter, full chain} × model {LR, NB, RF, XGB, LGBM, MLP,
  soft-vote, replicator ensemble}.
- Datasets (modern, flow-based):
  - Enterprise: CIC-IDS2017 (preferably the corrected version, Engelen et al. 2021) and
    CSE-CIC-IDS2018 (or the BCCC revision).
  - IoT/IIoT/IoMT: CICIoT2023 (8 and 34 classes), CICIoMT2024, Edge-IIoTset, and
    CIC-IIoT-2025 (DataSense) once access is sorted.
  - Cross-dataset: the NetFlow v3 family (NF-UNSW-NB15-v3, NF-ToN-IoT-v3, NF-CICIDS2018-v3).
    These share one feature schema, which allows train-on-A / test-on-B.
  - NSL-KDD is legacy and is used only to reproduce the case-study claims. It is not part of
    the main benchmark.
- Metrics: macro-F1, per-class F1 for minority classes, MCC, FPR and FNR, plus cost (fit time,
  latency).
- Statistics: ≥10 seeds, Friedman + Nemenyi critical-difference diagrams, bootstrap CIs. Do not
  use Wilcoxon on 5 seeds: its smallest attainable two-sided p is 0.0625.
- Analytical result to include: with fixed payoffs, the replicator update gives
  `w_j(T) ∝ π_j^T`, which converges to selecting the single best base model. An "adaptive
  ensemble" built on it is therefore a model-selection step.

*Expected contribution.* A quantified leakage effect per factor, a ranking of what actually
helps on minority classes, and an open benchmark. Target venues: Computers & Security,
IEEE TNSM, JNCA, or a reproducibility track (e.g. ACM AISec, DIMVA).

### Follow-up: pretrained flow encoder for cross-dataset IDS (builds on Transformer/LLM-embedding work)

*Question.* Does self-supervised pretraining on unlabeled flows from several datasets (masked
feature modelling or contrastive learning on a common NetFlow v9 feature set, e.g. the
NF-* datasets by Sarhan et al.) beat GBDTs when testing on an unseen dataset with few labels?

*Design.* Shared NetFlow schema, leave-one-dataset-out, few-shot fine-tuning (1%, 5%, 10% labels),
and XAI stability across domains (linking to the 2020/2021 explainability papers).

*Target.* NeurIPS Datasets & Benchmarks or ACM CCS/AISec for the benchmark side;
Computer Networks or TNSM for the system side.

## 4. Order of work

1. Now: feasibility experiments E1–E3. Decide go / no-go from the unseen-family recall gap
   and the cross-network FPR drift.
2. Month 1–2: conformal method (fusion score, BH, weighted conformal); ablations; analyst
   workload curves.
3. Month 3: write the main paper. In parallel, write the side reproducibility paper from the
   same benchmark code.
4. Later: pretrained flow encoder (follow-up).

## 5. Ground rules for the code in this repo

- Never fit scalers, encoders, samplers or feature selectors on test data.
- Use the official split if one exists. Otherwise use a stratified split after dedup, and
  report the cross-split duplicate count.
- Report macro-F1 and per-class F1 with mean ± std over ≥10 seeds, plus cost.
- Release configs and raw JSONL results with every paper.
