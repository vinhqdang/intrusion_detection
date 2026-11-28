Figures marked "(cache)" come from one-off checks on the extraction cache (`data/pcap/cache/`), not from the CSVs in
this folder. Every other figure comes from the CSVs.

### Q1: realism of the feature-space generators

**Fingerprint AUROC.**
- P(x) against clean: 0.904 [0.904, 0.905].
- G1 against P: 0.983 [0.982, 0.984].
- G2 against P: 0.984 [0.983, 0.985].
- Against clean, G1 is 0.994 and G2 is 0.987.

Both feature-space generators are far from P.

**Relative error |G(x) − P(x)| / |P(x)| at matched budgets** (§3 table):

| group | G1 | G2 |
|---|---|---|
| count | 0.61 | 0.29 |
| length | 0.22 | 0.45 |
| timing | 0.39 | 0.27 |

**Why P against clean is about 0.90 rather than near 1: many random-budget P mutations change nothing.**
- (cache) On 30,000 benign flows, 17.8% of rows are unchanged after a random-budget P mutation. Count on a flow
  without a handshake is a no-op by design.
- Restricted to the rows that changed, the AUROC is 0.970. On all rows in the same check it is 0.906.

### P timing budget

**Attack flows** (cache, 6,000 flows). Realised added delay divided by expected delay:

| m | per-flow ratio | sum-based ratio |
|---|---|---|
| 1.5 | 0.99 | 1.00 |
| 2 | 0.99 | 1.00 |
| 5 | 0.88 | 0.83 |

At m = 5, the 120 s timeout cuts 3.3% of timing states. At m = 1.5 and m = 2 it cuts fewer than 0.1%.

**Benign flows, timing group alone** (`pcap_timing_check.csv`). The mean of added over expected delay is 0.783, 0.782
and 0.751 at m = 1.5, 2 and 5, against an expected 1.0.

Decomposition at m = 2 (cache, 24,219 benign flows with positive expected delay):

| flows | share | ratio |
|---|---|---|
| a client data packet was delayed | 74.7% | 1.06 |
| no client data packet that can be delayed | 11.0% | 0 |
| cut by the 120 s timeout | 14.4% | −0.09 |

The weighted sum is 0.78, which matches the CSV. 8.4% of benign connection flows last longer than 100 s (cache, 529,098
flows).

**Benign flow duration.** The median benign duration ratio is 1.001, 1.002 and 1.003. It stays near 1 because the
client's forward span is a small part of the whole flow. The median ratio of forward IAT total to duration is 0.02 for
benign flows and 1.0 for attack flows (cache).

**Timeout re-split.** 3.76% of all timing-active P states are re-split (1,211,141 of 32,219,434; `pcap_resplit.csv`).
The counter is not split by class. By class (cache):

| m | benign timing states | attack timing states |
|---|---|---|
| 1.5 | 9.4% | 0.03% |
| 2 | 11.6% | 0.08% |
| 5 | 15.2% | 3.3% |

**Limitation.** The timeout cut removes packets. For the states it touches, this breaks the no-reduction invariant of
design §8. It is also the largest reason the benign mean timing ratio is below 1.

### Q2: attack surface on packets

At FPR 1e-3 (primary analysis), xgb has a clean recall of 0.968. Its worst-case recall is 0.177 under P, 0.109 under
G1 and 0.088 under G2.

Worst-case recall under P for xgb, per family:

| family | worst-case P |
|---|---|
| FTP-Patator | 0.000 |
| SSH-Patator | 0.000 |
| Bot | 0.004 |
| DDoS | 0.022 |
| PortScan | 0.860 |

The collapse holds on packets. The falsifier in design §7 (worst-case P stays near clean recall) is not met.

### Q3: fingerprint on packets

The table gives the mutated-benign FPR at FPR 1e-3, measured on 30,000 benign test rows per seed
(`pcap_mutben_seeds.csv`). The interval is a percentile bootstrap over the 10 seeds. Wilcoxon tests are paired over
seeds, against xgb.

| defender | P-mutated FPR, per-seed mean [CI] | seeds above xgb | Wilcoxon p | worst G1 | worst G2 | worst P |
|---|---|---|---|---|---|---|
| xgb | 0.00141 [0.00116, 0.00172] | reference | reference | 0.109 | 0.088 | 0.177 |
| adv_naive_G1 | 0.00407 [0.00331, 0.00495] | 10 of 10 | 0.0020 | 0.911 | 0.328 | 0.270 |
| adv_sym_G1 | 0.00055 [0.00043, 0.00069] | 1 of 10 | 0.0039 (lower) | 0.920 | 0.293 | 0.242 |
| adv_sym_G1G2 | 0.00058 [0.00046, 0.00071] | 0 of 10 | 0.0020 (lower) | 0.937 | 0.929 | 0.489 |
| adv_sym_P | 0.00300 [0.00275, 0.00325] | 10 of 10 | 0.0020 | 0.463 | 0.566 | 0.834 |

**Robustness is generator-specific.**
- adv_sym_G1G2 holds up under G1 and G2 (about 0.93). Its P-mutated FPR is low (0.00058) and is above xgb on no seed.
  But its worst-case recall under P is only 0.489.
- adv_sym_P is the reverse: worst-case P 0.834, worst-case G1 0.463.

**Falsifier 1.** The fingerprint claim fails if adv_naive_G1 has a high P recall and a low P-mutated FPR. It has a low
P recall (0.270), and its P-mutated FPR is 2.9 times that of xgb on average and above xgb on every seed. The falsifier
does not trigger.

**Falsifier 2.** Symmetric G1+G2 augmentation transfers to packets if its P-mutated FPR is low and its P recall is
close to adv_sym_P's.
- The first part holds.
- The second does not: 0.489 against 0.834.

The strongest positive result does not carry over to packet-level recall.

### Q4: oracle adv_sym_P

- adv_sym_P is strong on P (worst case 0.834) and weak on G1 (0.463) and G2 (0.566).
- Its P-mutated FPR is 0.00300, about 2.9 times its clean FPR of 0.00103.
- The excess comes from large budgets. Fixed-budget FPR × 1000 from `pcap_mutben.csv`:

| budget | FPR × 1000 |
|---|---|
| m = 1.5 | 0.61 |
| m = 2 | 1.46 |
| m = 5 | 6.82 |
| combined budgets at m = 5 | 10.9 to 12.1 |

The cause is not established. A possible cause is an asymmetry in augmentation:
- attack copies use the full budget (all groups, m = 5, greedy against the base xgb);
- benign copies draw random budgets from the 21, from 4,000 source flows sampled with replacement.

This was not ablated. adv_sym_G1 uses the same augmentation design and shows no excess, so the asymmetry alone does not
explain it.

### xgb_robust

**Remaining columns.** P changes 58 columns on more than 1% of rows in 8 seeds, and 59 columns in 2 seeds. That leaves
16 or 15 columns, of which 8 are constant over the analysis population (`pcap_xgb_robust_columns.csv`).
- Non-constant: Bwd Packet Length Min, SYN Flag Count, RST Flag Count, CWE Flag Count, ECE Flag Count,
  Init_Win_bytes_backward, min_seg_size_forward.
- Constant: Bwd URG Flags, URG Flag Count, Fwd and Bwd Avg Bulk Rate, Fwd and Bwd Avg Bytes/Bulk, Fwd and Bwd Avg
  Packets/Bulk.
- Bwd Packet Length Max remains in 8 seeds.

The non-constant columns are flag counts and host-stack or server-side values that P does not change.

**Recall.** The headline value of 0.185 is a mean of clean recall over seeds and families at FPR 1e-3. It is not a
typical recall:
- five seeds have an infinite threshold, so recall is 0;
- seeds 3 and 4 have a finite threshold but recall 0 on every family;
- seeds 1, 6 and 8 have a recall of about 1.0 on FTP, SSH and Bot, and about 0.1 or 0 on PortScan and DDoS.

**AUROC.** Per family and seed it ranges from 0.895 (Bot, seeds 3 and 4) to 1.000. Most seeds are between 0.98 and
1.00.

**Conclusion.** On this extractor, no behavioural feature set that the client cannot control remains. RQ2 therefore
cannot be answered meaningfully at packet level.

### Labels

The primary rule is kept. A flow takes an attack label when its matched CIC rows include that label and the flow
matches the family's pattern. The DDoS pattern is 172.16.0.1 to 192.168.10.50, port 80, inside the LOIC window.

**Ambiguous DDoS connection flows: 20,716 of 85,295 (24.3%).**
- They match the DDoS pattern and have the same payload signature as unambiguous DDoS flows (cache): median forward
  payload 20 bytes in both, and median mean forward packet length 2.2 against 2.5.
- They differ in close behaviour (cache): 79.7% have a full FIN-FIN close, against 0.5% of unambiguous flows.
- They are harder to detect. Clean DDoS recall for xgb is 0.861 under the primary rule and 0.998 when they are dropped.
  Dropping them removes the hardest 24% of DDoS and inflates recall.

Headlines (mean over the five families):

| analysis | xgb clean | xgb worst P |
|---|---|---|
| primary | 0.968 | 0.177 |
| all_flows | 0.941 | 0.146 |
| drop_ambiguous | 0.998 | 0.306 |

**The ordering is stable at the top and bottom only.**
- adv_sym_P has the highest worst-case P in all three analyses (0.834, 0.896, 0.993), and xgb is low in all three.
- The middle changes. adv_sym_G1G2 is above adv_naive_G1 under primary (0.489 against 0.270) and drop_ambiguous (0.738
  against 0.504), but below it under all_flows (0.418 against 0.451).

### Population

- **PortScan.** 1,170 connection flows remain after dedup (1,176 before), which is 0.74% of the 158,822 PortScan
  flows. (cache) Of the 1,176 flows, 87.6% have zero forward payload.
- **Bot.** 738 of 2,199 flows are connection flows.
- **Weighting.** The headline averages the five families equally. Bot (738 flows) and FTP-Patator (3,973) therefore
  count as much as DDoS (85,295). The family means are not population means.

### Statistics

- The seeds are resamplings of one data pool, and their test rows overlap. Wilcoxon p-values over seeds are therefore
  not population inference.
- The mutated-benign comparisons use paired per-seed differences and bootstrap CIs over seeds. They do not use pooled
  Wilson intervals.
- The worst case is a minimum over 21 budgets and up to three attackers, on 300 flows per family per seed. Taking the
  minimum biases it downward, and it is sensitive to the 300-flow sample.

### Extractor and scope

About 30 of the 76 features agree with the CIC CSV within 1% on at least 90% of one-to-one pairs (§2). The results are
on this extractor's features, not on the CIC CSV values.

### Deviations from the design, as run

- **Label join.** Matching uses a one-minute window, because CIC times have minute precision, and corrects for CIC's
  12-hour clock. The time shift is +3.0 h on both days. The attack match rate is 99.7% on Friday and 91.5% on Tuesday,
  above the 90% check.
- **Seeds.** 10 seeds instead of 5. The minimum two-sided Wilcoxon p is 0.002.
- **E4 flows.** 300 per family instead of 500, for runtime.
- **Strong attacker.** 5 levels and 1 restart instead of 10 and 2, for runtime (`pcap_run.json`).
- **Attackers per defender.** xgb has two attackers, because transfer does not apply to it; the other defenders have
  three.
- **Benign packet storage.** Up to 300,000 benign flows per day instead of 20,000.
- **Extractor.** Trailing packets within 2 s are absorbed, and flows are cut at the 120 s timeout as described above.
- **MSS.** The MSS of 1,460 bytes assumes no TCP options. With the TCP timestamp option the payload limit would be
  1,448 bytes; P uses 1,460.
- **Mutated-benign FPR.** It uses 30,000 benign test rows per seed, drawn from about 106,000 benign test rows with
  packets.
