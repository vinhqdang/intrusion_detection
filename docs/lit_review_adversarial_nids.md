# Narrative novelty check: client-side flow mutation, robust feature sets, mutation-fingerprint adversarial training

Date: 2026-11-27. Not a systematic review. Method: web search plus Crossref and arXiv API lookups to verify that each cited item exists (title, authors, DOI or arXiv id). **Read scope is abstract or landing page only for almost every item** (full texts were not read). Statements that something is "not covered" mean "not stated in the abstract or snippet", and are weaker than a full-text check. Before submission, the "high-risk" items below should be read in full.

## Planned claims

1. Client-only mutation (delay, padding up to MTU, dummy packets) with consistently recomputed derived features drives XGBoost recall at FPR 1e-3 from about 1.0 to about 0.01 on CIC-IDS2017 and CSE-CIC-IDS2018.
2. A "robust feature set" (dropping all client-controllable or derived features) removes the attack surface but costs much clean recall.
3. Attack-only adversarial training yields a "mutation fingerprint": benign flows passed through the same mutation are flagged at 19-91% FPR, and robustness does not transfer to a different generator. Fix and protocol: symmetric augmentation plus cross-generator evaluation.
4. Cost / Stackelberg framing of the SOC trade-off as a secondary lens.

## Closest prior work

| # | Citation (verified) | Shows | Overlap with claims | Read scope |
|---|---|---|---|---|
| A | Apruzzese, Andreolini, Ferretti, Marchetti, Colajanni. "Modeling Realistic Adversarial Attacks against Network Intrusion Detection Systems." ACM DTRAP 3(3):31, 2022. DOI 10.1145/3469659; arXiv 2106.09380 | Attacker-capability model (knowledge, access); realism of NIDS attacks | Threat-model framing for (1). No flow-level mutation numbers or defense. | abstract |
| B | Apruzzese, Laskov, Montes de Oca, Mallouli, Brdalo Rapa, Grammatopoulos, Di Franco. "SoK: Pragmatic Assessment of Machine Learning for Network Intrusion Detection." IEEE EuroS&P 2023. DOI 10.1109/EuroSP57164.2023.00042 (authors beyond first not checked) | Pragmatic evaluation criteria for ML-NIDS | Supports evaluating at low FPR and with realistic assumptions (relevant to 1, 4). Not a mutation or AT study. | abstract/snippet |
| C | Apruzzese, Anderson, Dambra et al. "Real Attackers Don't Compute Gradients." arXiv 2212.14315 (SaTML 2023) | Real attackers use simple, non-gradient manipulations | Motivates cheap client-side mutations (1). | abstract |
| D | Pierazzi, Pendlebury, Cortellazzi, Cavallaro. "Intriguing Properties of Adversarial ML Attacks in the Problem Space." IEEE S&P 2020. DOI 10.1109/SP40000.2020.00073. Extended: Cortellazzi et al., ACM TOPS 2025, DOI 10.1145/3742895 | Problem-space vs feature-space attacks; constraints | Conceptual basis for (1): mutations applied in packet space then features recomputed. Malware domain. | abstract |
| E | Chernikova, Oprea. "FENCE: Feasible Evasion Attacks on Neural Networks in Constrained Environments." ACM TOPS 2022. DOI 10.1145/3544746 | Feasible feature-space attacks with dependencies (incl. NIDS); adversarial training evaluated | Derived-feature consistency in (1) is covered in spirit by FENCE. | abstract |
| F | Sheatsley, Papernot, Weisman, Verma, McDaniel. "Adversarial examples for network intrusion detection systems." J. Computer Security 2022. DOI 10.3233/JCS-210094 | Constraint-aware attacks on NIDS | Same as E: constrained domains. | abstract |
| G | Teuffenbach, Piatkowska, Smith. "Subverting Network Intrusion Detection: Crafting Adversarial Examples Accounting for Domain-Specific Constraints." CD-MAKE 2020. DOI 10.1007/978-3-030-57321-8_17 | Domain-constrained adversarial examples on NIDS flows | Overlaps (1) in constraint handling. | abstract |
| H | Hashemi, Cusack, Keller. "Towards Evaluation of NIDSs in Adversarial Setting." ACM CoNEXT Big-DAMA 2019. DOI 10.1145/3359992.3366642 | Packet-level manipulation evaluated against NIDS | Early problem-space mutation evaluation (1). | citation only |
| I | Vitorino, Oliveira, Praca. "Adaptative Perturbation Patterns: Realistic Adversarial Learning for Robust Intrusion Detection." Future Internet 14(4):108, 2022 (DOI believed 10.3390/fi14040108, not independently resolved); arXiv 2203.04234 | A2PM; MLP and RF with regular and adversarial training on CIC-IDS2017 and IoT-23; AT improves robustness | Closest for (3) setup (AT with generated realistic perturbations). Reports gains, not fingerprint or benign-side FPR. | abstract |
| J | Vitorino, Silva, Maia. "An Adversarial Robustness Benchmark for Enterprise Network Intrusion Detection." arXiv 2402.16912 (2024) | RF, XGB, LGBM, EBM, regular vs adversarial training, CICIDS2017/NewCICIDS/HIKARI; constrained AEs; AT built by perturbing malicious samples only; reports no FP increase | **Highest risk for (1) and (3).** Same models/dataset, attack-only AT. Claims no false-alarm cost, measured on clean benign. Claim (3) directly contradicts or refines this. | abstract + snippet |
| K | Vitorino, Silva, Maia. "Reliable Feature Selection for Adversarially Robust Cyber-Attack Detection." arXiv 2404.04188 (2024) | Feature selection plus AT gives robust generalization without more false alarms | **Highest risk for (2).** Feature selection as defense is already published; they report no clean-performance loss, you report a large one. | abstract |
| L | elShehaby, Matrawy. "A Novel Perturb-ability Score to Mitigate Evasion Adversarial Attacks on Flow-Based ML-NIDS." arXiv 2409.07448 (v4 June 2025) | Scores flow features by problem-space manipulability; PS-guided feature selection/masking keeps accuracy and cuts evasion | **Highest risk for (2).** Same idea as the "robust feature set". Datasets not seen. Their claim is that masking costs little; yours is that it costs a lot. | abstract |
| M | elShehaby, Matrawy. "Evasion Adversarial Attacks Remain Impractical Against ML-based NIDS, Especially Dynamic Ones." arXiv 2306.05494 | Practicality critique; CSE-CIC-IDS2018; retraining reduces attack effect | Counterpoint to (1): you need to justify feasibility via client-only mutation. | abstract |
| N | elShehaby, Matrawy. "A No-Defense Defense Against Gradient-Based Adversarial Attacks on ML-NIDS: Is Less More?" arXiv 2605.18666 (2026) | Reduced-feature shallow model beats adversarially trained deep models (their claim) | Supports (2) direction. Draft status unknown. | snippet |
| O | Domico et al. (Domico, Noirot Ferrand, McDaniel). "The Role of Learning in Attacking ML-based NIDS." arXiv 2602.10299 (2026) | RL policies produce flow-level perturbations (bytes, packets, delay); transfer to unseen detectors and traffic | Closest 2026 attack paper for (1); maps padding/dummy packets/delay to flow features. Snippet says it defines false-positive inflation (not verified). | abstract + snippet |
| P | Zaro. "Adversarial Robustness Is Not Zero-Day Generalization." arXiv 2611.00713 (31 Oct 2026) | RF/XGB/CNN/FT-Transformer on corrected CIC-IDS2017 (and CSE-CIC-IDS2018): perturbation on 42 attacker-controllable features leaves detection at 90.9-99.7% at 1% FPR; leave-family-out is far lower | Very recent, same datasets and "attacker-controllable features". Finds *high* robustness to perturbation (opposite magnitude from claim 1 for tree models, though at FPR 1e-2 and different perturbation model). **Must be reconciled.** No AT, no benign-side. | abstract |
| Q | Bostani, Cortellazzi, Arp et al. "On the Effectiveness of Adversarial Training on Malware Classifiers." arXiv 2412.18218 (2024) | AT effectiveness depends on data, features, classifier, attack realism; lists evaluation pitfalls | General: AT results are fragile to evaluation choices; supports cross-generator protocol in spirit. Malware, Android. | abstract |
| R | Labaca-Castro et al. "Realizable Universal Adversarial Perturbations for Malware." arXiv 2102.06747 (2021) | Feature-space AT insufficient against problem-space attacks (per search summary) | Nearest malware evidence that AT does not transfer between perturbation spaces. | snippet |
| S | Debicha, Cochez, Kenaza et al. "Review on the Feasibility of Adversarial Evasion Attacks and Defenses for NIDS." arXiv 2303.07003 (2023); Debicha et al. "TAD." arXiv 2210.15700 (FGCS 2023, DOI 10.1016/j.future.2022.08.011); "Adv-Bot." Computers & Security 2023, DOI 10.1016/j.cose.2023.103176 | Review, detection of adversarial flows, botnet attacks. The specific "Adversarial training for deep learning-based IDS" (ICSNC 2021) was **not located or verified**. | Covers AT for NIDS generally; no fingerprint finding seen. | abstract/snippet |
| T | Tafreshian, Zhang. arXiv 2502.15561 (2025), "A Defensive Framework Against Adversarial Attacks on ML-Based NIDS" | AT plus other measures; NSL-KDD, UNSW-NB15; reports FP changes on clean data | AT's FP effect measured only on clean traffic. | abstract |
| U | Generalization-of-defense notes: Ennaji et al. arXiv 2409.18736 (survey, 2024); Saini et al. arXiv 2412.13880 (survey) | Surveys note AT overfits to specific attacks and defenses are attack-specific | Generic statements only. No experiment. | snippet |
| V | Kurakin, Goodfellow, Bengio. "Adversarial Machine Learning at Scale." arXiv 1611.01236 (ICLR 2017) | **Label leaking**: adversarial examples built with the true label let the model learn to detect the perturbation | Closest general concept for (3): a model exploiting an artifact of the generator. | abstract (known paper) |
| W | Wong, Rice, Kolter. "Fast is better than free." arXiv 2001.03994 (catastrophic overfitting); Raghunathan, Xie, Yang. "Adversarial Training Can Hurt Generalization." arXiv 1906.06032 | AT overfitting to a single-step generator; AT hurts clean generalization | Generic precedents for generator overfitting (3). Vision-style, not IDS. | abstract |
| X | Lisy, Kessl, Pevny. "Randomized Operating Point Selection in Adversarial Classification." ECML PKDD 2014, DOI 10.1007/978-3-662-44851-9_16 | Detector-vs-attacker game over operating points with FP/FN costs; Nash and Stackelberg | Direct prior for (4). | abstract |
| Y | Schlenker et al. "Don't Bury your Head in Warnings." IJCAI 2017, DOI 10.24963/ijcai.2017/54; Laszka et al. "A Game-Theoretic Approach for Alert Prioritization," AAAI workshop 2017 | Stackelberg alert allocation under analyst capacity | Direct prior for (4). | abstract |
| Z | Hossain, Moriano. "Evaluating False Alarm and Missing Attacks in CAN IDS." arXiv 2602.02781 (2026) | Evaluates both false alarms and misses under attack, including benign-side effects (per search summary) | Related to benign-side testing, different domain (CAN). | snippet |

## Assessment per claim

### Claim 1 (client-only mutation, derived features recomputed)
- Not novel as a concept: problem-space/constrained attacks (D, E, F, G, H, I, O) and capability-limited threat models (A, C) are established. Flow-level padding/delay/injection mapping to features appears in O (2026) and elShehaby et al. (L).
- Possibly novel: the specific strict **forward-only** attacker (no server response control) with consistent recomputation, evaluated at FPR 1e-3, and the magnitude (recall about 1.0 to about 0.01).
- Risk: P (Oct 2026) reports detection staying at 90-99% under perturbation of 42 attacker-controllable features on the same datasets, at FPR 1e-2. Reviewers will ask why your numbers differ (feature set, mutation magnitude, threshold, search budget). Also M argues evasion is impractical; address it explicitly.
- Verdict: **incremental / confirmation of known vulnerability, with a more realistic and sharper instantiation.** Do not claim first problem-space NIDS attack.

### Claim 2 (robust feature set costs recall)
- L and K already propose removing or masking manipulable features, and J/K/N claim little or no performance loss. N claims a reduced-feature model is a good defense.
- Your finding (large clean-recall cost) is a **contrasting empirical result**, not a new idea. Position it as a quantified trade-off under a strict low-FPR operating point, and compare against L's Perturb-ability Score directly.
- Verdict: **confirmation of the idea, possible novelty only in the contradicting magnitude.**

### Claim 3 (mutation fingerprint, symmetric augmentation, cross-generator evaluation)
- General mechanism has precedents: label leaking (V), generator overfitting (W), AT dependence on attack realism (Q), feature-space AT not transferring to problem space (R), and surveys stating AT overfits (U).
- In NIDS, I found **no paper** that (a) passes benign flows through the attack mutation to measure FPR, (b) shows attack-only augmentation makes "looks mutated" a label cue, or (c) evaluates AT across different mutation generators. Papers that do attack-only augmentation (J, K, I) report robustness gains and no FP increase, measured on **unmutated** benign flows. This is exactly the blind spot your test exposes, so the finding refines or challenges J and K.
- Related ideas of benign-side perturbation exist only loosely: a review notes attackers can craft examples from benign traffic to cause false positives (found via search, from the Debicha review, not verified in full text); Z measures false alarms under attack in CAN IDS. None frames it as a diagnostic for AT artifacts.
- Search coverage caveat: the searches were not exhaustive. Searches with terms such as shortcut, artifact, fingerprint found nothing NIDS-specific, but a missing hit is not proof of absence.
- Verdict: **most novel claim.** Safest wording: "to our knowledge, benign-side mutation as a false-positive control and cross-generator transfer for NIDS adversarial training have not been reported."

### Claim 4 (cost / Stackelberg SOC framing)
- Fully covered as a lens: X (operating-point Stackelberg with FP/FN cost), Y (analyst capacity, alert allocation), plus other security-game literature. Applying it to ML-NIDS mutation robustness is a small step.
- Verdict: **not novel; keep strictly secondary** and cite X and Y.

## Safest positioning
1. Lead with claim 3 as the contribution: an evaluation protocol (benign-mutation FPR control, symmetric augmentation, cross-generator held-out testing) showing that apparent AT robustness in NIDS can be a fingerprint artifact.
2. Present claim 1 as the realistic threat-model instantiation that makes the protocol meaningful, not as a new attack class. Explicitly cite D-I, O and reconcile with P and M.
3. Present claim 2 as a negative-result complement to L, K, N: quantify the cost at FPR 1e-3 rather than asserting novelty of feature removal.
4. Mention claim 4 in one paragraph with X and Y.
5. Avoid words such as "first", "novel attack", "robust feature selection". Use "to our knowledge" only for the benign-mutation control and cross-generator protocol.

## Open verification items
- Read in full: J (2402.16912), K (2404.04188), L (2409.07448), P (2611.00713), O (2602.10299). Check whether any of them already includes benign-side mutation or cross-generator tests.
- Resolve DOI for I (Future Internet) and the Debicha ICSNC 2021 AT paper; confirm SoK author list for B.
- Re-run searches on OpenAlex and Google Scholar with "adversarial training" plus "benign" plus "perturbed" plus "false positive" and "cross-attack" for 2025-2026, as the web search tool is US-only and snippet based.

## Addendum: full-text reads of the two highest-risk papers (2026-11-27)

**Zaro, "Adversarial Robustness Is Not Zero-Day Generalization" (arXiv 2611.00713, v1, 31 Oct 2026).** Full HTML text read.

*Setup.*
- Data: corrected CIC-IDS2017 (Liu et al. release) and CSE-CIC-IDS2018 (3 seeds).
- Attacker controls 42 of 82 features, listed in its Appendix VIII.
- Perturbation: two-sided L∞ with ε ≤ 0.2 in standardized signed-log space. There is no increase-only rule and no MTU cap.
- Derived features are not recomputed in the main runs, but a repair run (Table IX) recomputes them.
- Attacks: FGSM/PGD transfer, white-box PGD, SimBA, tree-aware search, and exact MILP for RF/XGB.
- Operating point: 1% FPR.

*Results.*
- Worst-case robustness at ε ≤ 0.2: RF 0.997, XGB 0.997 (Table VIII).
- MILP-certified detection at ε = 0.2: at least 0.998 for RF and XGB.
- Leave-one-attack-out detection: XGB 0.402 (gap 59.5 points).
- No adversarial training. No benign-side perturbation. No cross-generator test.

**Reconciliation with our numbers.** Zaro's budget is small. In our E4 table, xgb at FPR 1e-3, worst case over attackers and group subsets, at multiplier ×1.5 gives:

| Dataset | Family | Recall at ×1.5 |
|---|---|---|
| CIC-IDS2017 | DDoS | 0.996 |
| CIC-IDS2017 | DoS | 0.980 |
| CIC-IDS2017 | BruteForce | 0.985 |
| CIC-IDS2018 | DoS | 0.997 |

These agree with Zaro. The collapse appears at larger, but still client-feasible, budgets:
- ×2: CSE-CIC-IDS2018 BruteForce 0.003.
- ×5: CSE-CIC-IDS2018 Bot 0.013; CIC-IDS2017 BruteForce 0.24.

So the two results do not conflict. Robustness of tree detectors is budget-dependent. A small-ε certificate says little about an attacker who can add delay or padding freely, because waiting longer or sending more bytes costs a client almost nothing.

*Required in our paper.*
- Report recall-versus-budget curves.
- Map our multipliers to Zaro's ε (signed-log standardized distance of the mutated vectors).
- State the budget at which each family breaks.
- Ideally also run on the corrected CIC-IDS2017.

**Domico, Noirot Ferrand and McDaniel, "The Role of Learning in Attacking/Evading ML-based Network Intrusion Detection" (arXiv 2602.10299, v3).** The abstract and §2–4.2 were read verbatim. Later sections were only summarised and must be checked against the PDF.

*Setup.*
- NetFlow features (UNSW-NB15, ToN-IoT, CSE-CIC-IDS2018).
- Five increase-only perturbable features. Duration is derived from per-packet delay, and bytes per packet are kept in the benign band.
- Hard-label black-box attackers: HSJA, random search and RL policies.
- Detectors: RF and XGB at 1% and 0.1% FPR.

*Results.*
- Evasion succeeds in five of six environments, e.g. CSE-CIC XGB at 1% FPR: TPR 0.87 → 0.30 (summary-level figure).
- It also studies **alert inflation**: an adversary perturbs benign-looking traffic to raise FPR (0.09–0.24, summary-level).
- It also tests transfer across detectors and datasets.
- No adversarial training.

*Distinction from our claim 3.* Domico et al.'s benign-side perturbation is an *attack* (alert flooding against a clean detector). Our mutated-benign test is a *control* for adversarially trained detectors. It asks whether ordinary benign variation of the same kind is flagged because the defender learned the generator's fingerprint. These are different questions, but the paper must cite Domico et al. and explain the difference. Their cross-detector and cross-dataset transfer is not cross-generator transfer.

**Updated positioning.**
- Claim 1: a budget-resolved confirmation that reconciles Zaro (small ε, robust) and Domico et al. (larger budget, evasion).
- Claim 3 (mutation fingerprint, benign-side control for adversarial training, cross-generator protocol) remains the main contribution. No full-text read so far covers it.
