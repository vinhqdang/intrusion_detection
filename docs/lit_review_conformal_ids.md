# Conformal methods for intrusion detection: what is already done (as of 2026-11-27)

Type: narrative literature review (lit-review mode). The goal is to find the remaining gap for the main
project in [`ROADMAP.md`](ROADMAP.md). This is **not** a systematic review. The searches ran on
2026-11-27 over web search, Crossref, OpenAlex and arXiv. Search terms covered conformal prediction,
conformal p-values, novelty/anomaly detection, FDR, Benjamini–Hochberg, distribution shift, drift,
zero-day/unseen attacks and intrusion detection. Read scope is noted for every entry, because several
journal papers are behind paywalls and only their abstracts could be read.

## 1. Short answer

Conformal + IDS is crowded. Crossref alone lists at least nine 2026 papers that apply conformal
methods to intrusion detection. Several of them already cover the parts of our feasibility study that
looked new:
- leave-one-family-out evaluation;
- a benign-calibrated FPR budget;
- class-conditional (Mondrian) conformal triage;
- drift-triggered recalibration;
- cross-dataset deployment.

A paper whose contribution is "conformal for IDS under unseen attacks" would not be novel.

What we found **not** done in IDS (within the limits of this search) is narrower:

- **G1. Using known attacks to gain power on unseen ones, with FDR control.**
  Integrative conformal p-values (Liang et al., 2024) and AdaDetect (Marandon et al., 2024) give
  FDR-controlled novelty detection that also uses labelled outliers. No IDS application was found.
  Our E2 shows naive fusion fails, so this is a concrete test case.
- **G2. Checking whether a guarantee survives a move to a new network, and the label cost of restoring it.**
  Cross-dataset conformal IDS work (FIRCE, FADES) reports accuracy and F1 after transfer. It does not
  test whether the FPR or coverage guarantee still holds. Our E3 shows it does not: a 1% target
  becomes 10.9%. Weighted conformal does not fix this in our runs. Lim (2026) proves BH on weighted
  conformal p-values is only "almost" FDR-controlled. How many labelled target benign flows are
  needed to restore validity is an open, practical question.
- **G3. Contaminated benign calibration.**
  CIC-style benign traffic contains mislabelled attacks (Engelen et al., 2021). Bashari et al. (2025)
  treat contaminated reference sets, but not in IDS and not with FDR.

G1 and G2 only count as gaps if the paywalled 2026 papers (§3) do not cover them. Check their full
text before claiming either.

## 2. Map of existing work

### 2.1 Conformal methods in intrusion and malware detection

| Work | Setting | Conformal method | Guarantee / target | Shift tested? | Read scope |
|---|---|---|---|---|---|
| Jordaney et al. (2017), *Transcend*, USENIX Security | Android malware, concept drift | Conformal evaluation (credibility/confidence) to reject aged decisions | Empirical rejection quality | Temporal drift | abstract + secondary summary |
| Barbero et al. (2022), *Transcending Transcend*, IEEE S&P | Malware, 5-year temporal data | Cheaper conformal evaluators (TRANSCENDENT); formal treatment | Empirical | Temporal | abstract |
| Arepalli et al. (2026), *Conformal prediction for network intrusion triage and analysis of unseen attack families*, Discover Informatics, doi:10.1007/s44564-026-00033-y | UNSW-NB15, CIC-IDS2017; **15 leave-one-family-out runs**; dedup | Marginal and class-conditional conformal as analyst-triage layer | Coverage (marginal ≈ 0.90; class-conditional ≥ 0.894) | Unseen families (in-dataset) | abstract only |
| Younas (2026), *Hybrid conformal abstention (HTCCA)*, J. Computer Virology and Hacking Techniques, doi:10.1007/s11416-026-00692-3 | CIC-IDS2017 (and UNSW-NB15 per search summary); **leave-one-family-out** | Benign-calibrated UNKNOWN gate at fixed FPR + class-conditional conformal with REVIEW | Benign FPR budget (1%) | Unseen families | abstract only |
| Farsimadan et al. (2026), *ConFID*, Internet of Things, doi:10.1016/j.iot.2026.102078 | IoT, unsupervised zero-day | One-class conformal | FPR control under exchangeability (per search snippet) | Zero-day | **title + search snippet only** |
| Barrett et al. (2026a), *FIRCE*, arXiv:2605.01962 (IEEE SmartNets'26) | DFAIR IoT testbed; train UNSW-NB15/CICIDS2018 → test DFAIR-Drift | Conformal evaluation (Approx-CCE) for drift detection + retraining | None formal; F1 and runtime | **Cross-dataset**, but guarantee not checked | full text (partly summarised) |
| Barrett et al. (2026b), *FADES*, Electronics 15(10):2114 | Same + contrastive-AE drift detector, 375 simulations | Conformal evaluation variants | Empirical | Cross-dataset transfer | abstract only |
| Ansaf et al. (2026), *ConformIDS*, IJIES, doi:10.22266/ijies2026.0831.28 | CICIoT2023, MedBIoT; held-out attack families | Adaptive conformal inference (ACI) with window from lag-1 autocorrelation | Empirical ≥ 90% coverage (not worst-case) | Temporal autocorrelation, unseen families | abstract only |
| Li (2026), *Robust conformal intrusion detection (ta-CP)*, arXiv:2609.19241 | CIC-IDS2018, RT-IoT2022, HIKARI-2021; LLM detectors | Calibrate on perturbed traffic; orbit-invariant scores | Coverage under known perturbation law; TV-distance bound | Adversarial perturbation (not cross-network) | partial full text |
| Massaad et al. (2026), *Conformal prediction for CAN bus IDS*, IEEE ICC | HCRL Car-Hacking | Percentile threshold = conformal; online adaptive threshold | Empirical | Benign drift | abstract only |
| Moccardi et al. (2026), *CRISP: conformal resilient IDS with selective prediction*, IEEE MLISE | not available | Conformal selective prediction | not available | not available | **title only** |
| Zhao et al. (2026), *SHAP-guided pruning + conformal*, IEEE SmartIoT | IoT | Conformal risk control (per title) | not available | not available | **title only** |
| Jang & Kim (2026), *SpikeGuard-LF*, IEEE ICUFN | WSN | Conformal forests | not available | not available | **title only** |
| Botnet detection with conformal layers, arXiv:2409.00667 | Botnet flows | Prediction sets; empty set → review | Coverage | Adversarial | search snippet |
| Dang (2026), *Fuzzy-conformal GNN*, Int. J. Mach. Learn. Cybern., doi:10.1007/s13042-026-03371-3 | Cybersecurity anomaly detection | Fuzzy-conformal GNN | Distribution-free coverage | — | own work |
| Dang (2026), *Utilizing uncertainty measures to improve IDS*, SN Computer Science, doi:10.1007/s42979-026-04923-8 | IDS | Uncertainty measures | — | — | own work |

Methods already used in IDS:
- split and class-conditional conformal;
- conformal evaluation (Transcend family);
- ACI;
- one-class conformal FPR control;
- benign-calibrated unknown gates;
- perturbation-aware calibration.

Protocols already used: leave-one-family-out, cross-dataset transfer, streaming drift.

### 2.2 Statistical methods not yet seen in IDS

| Work | What it gives | Relevance |
|---|---|---|
| Bates et al. (2023), *Testing for outliers with conformal p-values*, Ann. Statist. 51(1) | Conformal p-values are PRDS, so BH controls FDR (marginal sense) | Baseline used in our E2/E3 |
| Liang, Sesia & Sun (2024), *Integrative conformal p-values … with labeled outliers*, JRSSB, doi:10.1093/jrsssb/qkad138 | Uses labelled outliers plus inliers. Picks the best of one-class and binary models. FDR control via conditional calibration | Known attack families are exactly "labelled outliers". Directly addresses the failed fusion in E2 (G1) |
| Marandon, Lei, Mary & Roquain (2024), *Adaptive novelty detection with FDR guarantee (AdaDetect)*, Ann. Statist. 52(1) | Learns the score from null sample + test mixture; strong FDR control; near-oracle power | Label-free power gain on the test batch (G1) |
| Tibshirani et al. (2019), *Conformal prediction under covariate shift*, NeurIPS | Weighted conformal | Our E3 baseline; fails in practice |
| Lim (2026), *Almost controlled: FDR of BH on weighted conformal p-values*, arXiv:2611.21509 | BH on weighted conformal p-values can exceed q. Excess ~ sqrt(Bm/(nq)). Lowered BH level restores control | Explains part of the E3 failure; any cross-network FDR claim must use the corrected level (G2) |
| Bashari, Sesia & Romano (2025), *Robust conformal outlier detection under contaminated reference data*, arXiv:2502.04807 | Contamination makes the test conservative; active cleaning with a small label budget recovers power | Benign calibration in IDS is contaminated (G3); label-budget idea also fits G2 |
| Gibbs & Candès (2021), *Adaptive conformal inference under distribution shift*, NeurIPS | Long-run coverage under arbitrary shift, online | Already used in IDS (ConformIDS); gives long-run, not per-batch, control |
| Krönert et al. (2023), *FDR control for online anomaly detection*, arXiv:2312.01969; e-value online FDR (arXiv:2506.01452) | Online FDR with conformal p-values or e-values | Streaming alert FDR; no IDS deployment found |

## 3. What could already cover our gaps (check before claiming novelty)

1. **Arepalli et al. (2026)** and **Younas (2026)** both run leave-one-family-out on CIC-IDS2017 with
   conformal methods at a fixed benign FPR. Their abstracts report weak unseen-family detection:
   about 19.6–30.6% unknown detection at 1% FPR in Younas. This matches our E2. **E2 is therefore
   confirmation, not a contribution.** Their abstracts do not mention FDR, labelled-outlier methods or
   cross-network transfer. Their full texts were not read, so this is not confirmed.
2. **FIRCE / FADES** do cross-dataset transfer and drift-triggered recalibration. They do not check
   whether a coverage or FPR guarantee holds after transfer (FIRCE full text; FADES abstract only).
3. **ConFID** and **CRISP**: only titles or snippets are available. Either could contain
   FDR-controlled alerting. Get the full text.

## 4. Implications for our project

- **Drop as a contribution:** "conformal + unseen attacks + FPR budget", "Mondrian triage", "conformal
  drift detection", "ACI for IDS". All of these are published in 2026.
- **Keep as motivation:** E1 (shortcuts), E2 (recall collapse; now corroborated by two independent
  2026 papers), E3 (guarantee breaks across networks).
- **Candidate contribution A (G1).**
  - Bring integrative conformal p-values / AdaDetect to IDS. Known attack families act as labelled
    outliers, the test batch adapts the score, and FDR control holds.
  - Measure power on unseen families against the 2026 baselines (HTCCA-style gate, Mondrian triage).
  - Risk: the methods exist, so this is an application paper unless we add an IDS-specific piece. One
    option is family-structured outliers: leaving out a whole family breaks the "labelled outliers
    represent the outlier distribution" assumption. How the power of integrative p-values degrades
    in that case is a real question.
- **Candidate contribution B (G2).**
  - The "label price" of a guarantee on a new network: how many labelled target benign flows restore
    FPR/FDR validity, compared with weighted, lowered-level-BH (Lim 2026) and ACI alternatives.
  - Add contamination-robust calibration on the target (Bashari et al.).
  - Needs at least 3 network pairs. Today we have only CIC-IDS2017 ↔ CSE-CIC-IDS2018. NetFlow v3
    from UQ would add more.
- **Not recommended:** a pure "conformal IDS framework" paper. The field is saturated at that level.

## 5. Limitations of this review

- Narrative review: no protocol, single reviewer, no screening log. It can miss papers, especially in
  Chinese-language venues (one CNKI paper, *High-reliability intrusion detection algorithm under
  conformal prediction framework*, was seen and not read).
- Most 2026 journal papers were read at abstract level. ConFID, CRISP and the SmartIoT paper were read
  at title level only.
- One cited arXiv ID (2605.24696, originally *CALIBURN*) was withdrawn and replaced by its author with
  a different paper. Its conformal claims are not used here.
- A search snippet attributed a paper titled *Conformal prediction in the intrusion detection problem*
  to Dang. Neither this search nor Crossref could confirm it. Check your own publication list.
