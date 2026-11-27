# Open issues in the round-3 results (read before using any number in SUMMARY.md)

An independent code review of this run confirmed that the fixes from the earlier reviews are in place:
- derived features are updated after mutation;
- the robust feature set is correct;
- the capacity grid is finer, and ties are reported as sets;
- AUROC ties and the regret indicator are implemented;
- equilibria are solved per seed;
- the realised FPR enters the alert volume;
- the strong and transfer attackers are correct;
- Sobol uses CIs.

The following problems remain. They change how parts of SUMMARY.md may be read.

1. **xgb_adv "immunity" is mostly a mutation fingerprint, not robustness.**
   - Augmentation only adds mutated *attack* copies, so the model learns "looks mutated → attack".
   - On CSE-CIC-IDS2018 (seed 0, FPR 1e-3), benign test flows passed through the same mutation get flagged:

     | Mutation of benign flows | xgb_adv FPR | xgb FPR |
     |---|---|---|
     | length ×5 | 0.66 | 0.0014 |
     | all groups ×5 | 0.91 | 0.0017 |
     | all groups ×1.5 | 0.19 | 0.0004 |

   - Transfer states that evade xgb *raise* xgb_adv's recall.
   - The near-1.0 recall_after of xgb_adv, its modal-equilibrium status, and the 2018 loss gap are therefore not evidence of robustness.
   - Needed:
     - mutated benign copies as negatives in augmentation;
     - FPR measured on mutated benign flows;
     - evaluation against a different mutation generator.
2. **The optimal FPR is not identified.**
   - The optimum sits on the lowest grid value (5e-4) in most cases.
   - At the reference parameters, extra recall above the deterrence point V/(V+P) is worthless, while alert and capacity costs grow with FPR.
   - So every loss is an upper bound, and the model ranking below 5e-4 is unknown.
   - On CSE-CIC-IDS2018, xgb_robustfeat's 5e-4 threshold lies on a score plateau: realised FPR ≈ 4e-5. That gives it an effective operating point the other models cannot reach.
   - The defender also selects on the same benign test set that measures realised FPR. This is a small selection bias.
   - Needed: lower FPR levels (1e-4, 2e-5) with larger benign calibration and test sets, plateau-aware thresholds, and lower-edge and upper-edge hits reported separately.
3. **Sobol indices of rare indicators are a noise floor.**
   - Each sample draws its own 2-seed subset, so seed noise is independent across Saltelli rows.
   - `b_auroc_disjoint` on CIC-IDS2017 has S1 ≈ 0 and ST 0.69–0.79 for every parameter. Its "drivers" ranking is meaningless.
   - `a_mut_nov` and `c_regret` carry an ST floor of about 0.06–0.25 for parameters that cannot matter (w, L, cB).
   - Needed: the same seeds for every Saltelli row, or replicate runs with the noise floor subtracted.
4. **The capacity grid step (5.8%) exceeds the 1% loss-tie tolerance.**
   - Ties between xgb and xgb_adv, and the `class_*`, c_cfg and c_act outputs, partly reflect grid rounding.
   - Needed: B solved in closed form at deterrence, or a step of 0.5% or less.
5. **The X4 switch on CIC-IDS2017 at lam = 0.336 is a deterrence collapse.**
   - The capable attacker moves to novel(worst unseen family), whose recall is ≈ 0 for every model.
   - The switch occurs at lam = V/kN by construction. It is a property of the parameters, not of the data.
6. **Indicators.**
   - (b) has a high chance level: xgb and xgb_adv are AUROC-tied by construction.
   - (c) uses a relative 1% threshold, which is insensitive when the loss saturates near N_attack·L.
   - The 2018 conclusions rest on Infiltration (recall ≈ 0.12, label-noisy).

**What does hold:**
- Standard detectors (xgb, fusion) lose most of their recall under forward-only feature-space mutation. For example, on CSE-CIC-IDS2018 Bot goes 0.996 → 0.014 and BruteForce 1.000 → 0.003.
- The tie-aware AUROC ranking agrees with the equilibrium-loss ranking on most of the sampled grid: indicator (b) is 0.05–0.30.
