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

### P1: Leakage-free re-evaluation of imbalance-aware IDS pipelines (start now, 2–3 months)

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

### P2: Conformal / selective IDS under distribution shift (4–6 months, builds on the 2026 uncertainty papers)

*Question.* Under cross-dataset and temporal shift, can conformal prediction sets plus
abstention keep a guaranteed error rate on the cases the IDS accepts, while sending a
controlled fraction to analysts?

*Design.* Train on dataset A or time window t and test on B or t+k. Compare split-conformal,
Mondrian (class-conditional) conformal, adaptive conformal inference for drift, and the
earlier fuzzy-conformal GNN. Report coverage, set size, abstention rate, and analyst workload
versus missed attacks. Link to active learning (2020): queried labels are the abstained cases.

*Target.* IEEE TIFS (stretch), IEEE TDSC, Computers & Security.

### P3: Pretrained flow encoder for cross-dataset IDS (6–9 months, builds on Transformer/LLM-embedding work)

*Question.* Does self-supervised pretraining on unlabeled flows from several datasets (masked
feature modelling or contrastive learning on a common NetFlow v9 feature set, e.g. the
NF-* datasets by Sarhan et al.) beat GBDTs when testing on an unseen dataset with few labels?

*Design.* Shared NetFlow schema, leave-one-dataset-out, few-shot fine-tuning (1%, 5%, 10% labels),
and XAI stability across domains (linking to the 2020/2021 explainability papers).

*Target.* NeurIPS Datasets & Benchmarks or ACM CCS/AISec for the benchmark side;
Computer Networks or TNSM for the system side.

## 4. Order of work

1. Week 1–2: finish `idsbench` on CIC-IDS2017, CICIoT2023 and CICIoMT2024, then run the
   leakage grid (P1).
2. Week 3–4: add CSE-CIC-IDS2018, Edge-IIoTset and the NetFlow v3 cross-dataset split; run
   10 seeds and produce CD diagrams.
3. Month 2: write P1. In parallel, set up the cross-dataset splits P2 needs (they reuse P1 code).
4. Month 3+: P2 experiments; collect the NetFlow-schema corpus for P3.

## 5. Ground rules for the code in this repo

- Never fit scalers, encoders, samplers or feature selectors on test data.
- Use the official split if one exists. Otherwise use a stratified split after dedup, and
  report the cross-split duplicate count.
- Report macro-F1 and per-class F1 with mean ± std over ≥10 seeds, plus cost.
- Release configs and raw JSONL results with every paper.
