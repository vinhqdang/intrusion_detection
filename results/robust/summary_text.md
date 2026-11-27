## Research questions (answered from the tables above)

All numbers are at the nominal FPR 1e-3 unless stated, mean over 10 seeds with 95% bootstrap intervals, and come from `robust_headline.csv`, `robust_rq2_matched.csv`, `robust_stats.csv` and `robust_fingerprint.csv`.

**RQ1 (attack surface): holds under both generators.** xgb's clean macro recall is 0.993 on CIC-IDS2017 and 0.824 on CSE-CIC-IDS2018. Its worst-case recall is 0.695 under G1 and 0.447 under G2 on CIC-IDS2017, and 0.285 (G1) and 0.282 (G2) on CSE-CIC-IDS2018. Without the label-noisy Infiltration family, CSE-CIC-IDS2018 xgb has worst-case recall 0.349 (G1) and 0.345 (G2). On CIC-IDS2017, G2 is the more damaging generator (the earlier draft said G1; that was wrong). The two generators are about equal on CSE-CIC-IDS2018.

**RQ2 (price of robust features): large on CIC-IDS2017, small on CSE-CIC-IDS2018.** xgb_robust's clean macro recall is 0.556 on CIC-IDS2017 (xgb 0.993, a loss of 0.437) and 0.776 on CSE-CIC-IDS2018 (xgb 0.824, a loss of 0.048). Without Infiltration, CSE-CIC-IDS2018 xgb_robust is 0.949 against 0.999 for xgb. Its worst-case recall equals its clean recall under both generators, so its generator gap is zero by construction.

*Matched realised FPR (new).* At the same realised calibration FPR as xgb_robust, xgb has higher clean macro recall at every nominal FPR on both datasets. On CIC-IDS2017 at nominal 1e-3 the realised calibration FPR is 1.64e-4 for both; xgb recall is 0.937 [0.926, 0.948] against 0.556 [0.541, 0.572] for xgb_robust (difference 0.381, Holm p = 0.008). On CSE-CIC-IDS2018 at nominal 1e-3 (realised calibration FPR 9.5e-4 for both) the difference is 0.048 [0.047, 0.049] (0.824 against 0.776; Holm p = 0.008). The matched comparison is exact in 9 or 10 seeds of 10 at every FPR, and the realised test FPRs are close (for example 1.46e-4 for xgb_robust and 1.72e-4 for xgb on CIC-IDS2017 at 1e-3). The plateau rule therefore does not explain the gap: at the same realised FPR, the robust feature set loses recall. Nominal 1e-2 gives the same ordering (CIC-IDS2017 0.998 against 0.895; CSE-CIC-IDS2018 0.854 against 0.807). Note that xgb_robust's realised test FPR is far below its nominal FPR on CIC-IDS2017 (1.46e-4 at nominal 1e-3), which is why the matched table is needed.

**RQ3 (fingerprint): supported for adv_naive_G1.** At nominal 1e-3, the mutated-benign FPR of adv_naive_G1 is 0.0182 under G1 and 0.0141 under G2 on CIC-IDS2017 (xgb: 0.0023 and 0.0030). On CSE-CIC-IDS2018 it is 0.330 under G1 and 0.120 under G2 (xgb: 0.0031 and 0.0017). Its worst-case recall is 0.980 under G1 but 0.723 under G2 on CIC-IDS2017 (gap 0.257). On CSE-CIC-IDS2018 the two worst cases are close (0.808 and 0.784, gap 0.023), so the false-alarm rate is the visible symptom there. The Infiltration-free macro gives the same picture (mutated-benign FPR 0.330 and 0.120; worst case 0.987 and 0.961).

**RQ4 (fix and protocol): partly supported.**
- *Symmetric augmentation (adv_sym_G1) removes most of the false-alarm excess on CIC-IDS2017.* Its mutated-benign FPR under G1 is 0.0023, the same as xgb, against 0.0182 for adv_naive_G1 (paired difference 0.0158, Holm p = 0.008). On CSE-CIC-IDS2018 it falls from 0.330 to 0.0164 under G1 and from 0.120 to 0.0074 under G2, but 0.0164 is still about 16 times nominal and about 5 times xgb.
- *Two generators (adv_sym_G1G2) reduce the cross-generator gap on CIC-IDS2017, not remove it.* The G1-minus-G2 worst-case gap is 0.248 for adv_sym_G1 and 0.161 for adv_sym_G1G2. Worst-case G2 recall is 0.804 for adv_sym_G1G2 against 0.720 for adv_sym_G1 (paired difference -0.084, Holm p = 0.008). On CSE-CIC-IDS2018 the best worst-case G2 recall is adv_sym_G1G2 (0.807 against 0.793 for adv_sym_G1; Holm p = 0.008), and its G1-minus-G2 gap is -0.004.
- *The cost of the fix is in the false-alarm rate.* adv_sym_G1G2 has mutated-benign FPR 0.0026 (G1) and 0.0032 (G2) on CIC-IDS2017, close to xgb. On CSE-CIC-IDS2018 it is 0.0169 and 0.0162, about 16 times nominal, with no significant difference from adv_sym_G1 under G1 (Holm p = 0.43).
- *Protocol.* The clean-recall-only protocol makes the adversarial models look like xgb on CIC-IDS2017 (worst-case G1 0.965 to 0.980 against 0.695). The mutated-benign FPR exposes adv_naive_G1, and the cross-generator gap exposes adv_sym_G1.

**Falsification checks (section 7 of the design), explicit.**
- RQ1 falsified if G2 does not reproduce the collapse. Not falsified: G2 worst-case recall is 0.447 on CIC-IDS2017 and 0.282 on CSE-CIC-IDS2018, against clean recall 0.993 and 0.824.
- RQ3 falsified if adv_naive_G1's G2 recall stays high and its mutated-benign FPR stays low. Not falsified: the mutated-benign FPR is 18 times nominal (0.0182) on CIC-IDS2017 and 330 times nominal (0.330) on CSE-CIC-IDS2018, and G2 recall is 0.723 and 0.784.
- RQ4 expects adv_sym_* to keep a low mutated-benign FPR. Partly met: adv_sym_G1 matches xgb on CIC-IDS2017 (0.0023 against 0.0023), but both are above nominal, and on CSE-CIC-IDS2018 adv_sym_* stays at 0.007 to 0.017. The cross-generator gap on CIC-IDS2017 is not closed by symmetric augmentation alone (0.248 for adv_sym_G1), so a second generator helps but does not fully remove it.

**Important context for the false-alarm numbers.** xgb itself exceeds the nominal FPR under mutation on CIC-IDS2017 (0.0023 under G1 and 0.0030 under G2, 2.3 to 3 times nominal). The mutated-benign FPR is therefore a relative measure: compare it with nominal and with xgb, not with zero.

**Game (cost lens, secondary).** Full results are in `game/SUMMARY_GAME.md`. On CIC-IDS2017, xgb_robust is the equilibrium model in all ten seeds; the attacker abstains at the closed-form capacity, and the upper FPR edge (1e-2) is optimal in all seeds. On CSE-CIC-IDS2018 the equilibrium is adv_sym_G1 in five seeds and adv_sym_G1G2 in five, with the capacity at the upper B edge (B = A). Raising the mutated-benign share rho from 0 to 0.1 changes the CSE-CIC-IDS2018 equilibrium to xgb (mean loss 45.8k to 47.2k) and leaves CIC-IDS2017 unchanged. Indicator (d) is 0.07 to 0.13 on CIC-IDS2017 and 0.46 to 0.54 on CSE-CIC-IDS2018. The loss levels depend on the illustrative reference parameters; only the sensitivity rows support conclusions.

## Limitations

- Feature-space mutation only (no problem-space realisability). The two generators share the CICFlowMeter feature space and the budget grid.
- Two lab datasets (CIC-IDS2017, CSE-CIC-IDS2018). The CSE-CIC-IDS2018 Infiltration family is label-noisy; macro numbers without it are in the second headline table.
- The Infiltration exclusion changes only the macro over families. Mutated-benign FPR is measured on benign test rows and the models are not retrained without Infiltration, so those values do not change.
- G2 now satisfies the Fwd IAT Mean identity after a count change on every row. It does not satisfy the packet-length mean identity on most original flows (0.20 on CIC-IDS2017 and 0.16 on CSE-CIC-IDS2018), and it preserves that offset rather than enforcing it, as G1 does. The identity hold rates in the table compare original and mutated flows.
- Fwd IAT Min is left unchanged by the count group, so the rule "flow IAT min = fwd IAT min" holds on the same share of mutated flows as on originals (0.42 on CIC-IDS2017, 0.35 on CSE-CIC-IDS2018).
- The fingerprint diagnostics use benign training rows of seed 0 only.
- The game's equilibria depend on the illustrative parameters, and the capacity closed form is only as good as the recall tables.
- The one-class IsolationForest has clean recall of 0 at these thresholds (by design: it is a lower bound).

## Changes since the previous run

- G2 recomputation was absolute for the packet-length aggregates, so a timing-only budget changed payload statistics (Average Packet Size fell on 55% of CIC-IDS2017 flows at timing x2). It is now in delta form; timing leaves every length column bit-identical. Checked on real CIC-IDS2017 and CSE-CIC-IDS2018 samples: no undocumented decrease under any group.
- The count group now updates Fwd IAT Mean to Fwd IAT Total divided by (n_fwd - 1). Previously it did not.
- G2 fingerprint AUROC (all groups, seed 0): CIC-IDS2017 0.9917 before, 0.9776 after; CSE-CIC-IDS2018 0.9961 before, 0.9885 after. G1 values are unchanged. Cross-generator AUROC: 0.9943 to 0.9903 (CIC-IDS2017) and 0.9969 to 0.9925 (CSE-CIC-IDS2018).
- The G2 numbers in the headline, worst-case and game results changed. The G1 numbers did not change (for example, adv_naive_G1 mutated-benign FPR on CIC-IDS2017 is 0.0182 before and after).

## Deviations from the design (and why)

1. **Budget-unit matching.** The worst case is the minimum over all attackers and budgets. "Matched budget units" is reported through the budget-unit column in `robust_e4.csv.gz` and the curves.
2. **Benign copies for adv_sym_G1G2.** "Half each" is read as half from G1 and half from G2 for both attack and benign copies, with the same total count as adv_sym_G1.
3. **Active and Bwd IAT under G2 coupling.** The coupled per-gap share is applied to Active Mean and Active Max as well. Both are excluded from xgb_robust.
4. **Mutated-benign FPR sample sizes.** The random-budget mutated-benign FPR uses all benign test rows: 120,000 on CIC-IDS2017 and 85,822 on CSE-CIC-IDS2018 (20% of the benign rows the loader keeps there; the design text said 120,000 for both). The fixed-budget mutated-benign FPR uses 30,000 rows per generator and budget, for compute.
5. **Label attacker dropped.** The design names greedy, strong and transfer; the label attacker from round 3 was not carried over.
6. **Plateau rule.** Implemented as written: if more than 0.5 fpr n calibration scores tie at the threshold, the threshold moves to the next distinct score above it. The realised calibration FPR is in `robust_thresholds.csv`, with the realised test FPR and its Wilson 95% interval.
7. **Matched-FPR comparison (RQ2).** xgb's threshold is set on cal_full, the calibration set on which the non-fusion thresholds are fitted, not on cal_thr (which is used only by fusion). It matches the number of calibration alerts of xgb_robust as far as the distinct scores allow. The matched count is exact in 9 or 10 seeds of 10 at each FPR; the per-seed table gives the achieved counts.
8. **Fwd Packet Length Max.** The design text says max(old max, T). The implementation uses max(old max, T / (1 - a)), where T / (1 - a) is the padded data-packet size and a is the zero-payload share. The maximum never falls, and the padded size is the physical value.
9. **Closed-form capacity.** The deterrence condition uses theta_a = (V e_a - c_a) / (V e_a + P), which reduces to V/(V+P) when efficacy is 1 and cost is 0. Tests check the closed form against a dense grid (1e-4 step) and that its loss is never above any deterring grid point.
10. **Geometric grid.** The capacity grid is geometric in x = B/A with step 0.5% (x from 1 down to 0.01), so B = xA.
11. **Sobol.** Base N = 128 (1,536 samples per dataset, efficacy setting and seed pair). Fixed seed pairs from a recorded RNG: (0, 9) and (3, 7). Both pairs are reported. rho is a Sobol input over [0, 0.2].
12. **X4 (lam sweep) not run for the robust game.** Only lam = 1 and lam = 0.05 (indicator c) are used.
13. **Novel action for the reduced LOFO protocol.** Not used: the full protocol ran LOFO for all seven models.
14. **Recall-versus-budget curves and L-inf distances (added after the design).** Curves are the minimum over attackers and group subsets at each multiplier, with the smallest multiplier at which each family's worst case falls below 0.5 in `robust_curves_first_below_half.csv`.
15. **Compute.** The full run took 232.6 minutes (10 seeds, 2 datasets, 1,000 flows, full LOFO, game with N = 128). The quick run took 10 minutes.
