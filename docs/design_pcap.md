# Design: packet-level validation of the client-side robustness results

Status: design v1, 2026-11-28. This study follows [`design_robustness.md`](design_robustness.md) and
[`../results/robust/SUMMARY.md`](../results/robust/SUMMARY.md).

Both feature-space generators (G1 and G2) leave strong artefacts:
- the fingerprint AUROC is 0.97–1.00;
- the AUROC between G1 and G2 is about 0.99.

A reviewer will ask whether either generator matches what a real client can do to a real flow. This study answers by
mutating packets in the raw CIC-IDS2017 captures and re-extracting the flow features. The packet-level generator is
called **P**. It is the reference against which G1 and G2 are judged.

## 1. Questions

- **Q1 (realism of the feature-space generators).** How close are G1(x) and G2(x) to P(x) at matched budgets?
  Report:
  - cross-generator AUROC (G vs P);
  - per-feature agreement;
  - which features each generator gets wrong.
- **Q2 (attack surface, realised).** Does the recall collapse of RQ1 hold when the mutation is done on packets?
- **Q3 (fingerprint, realised).** Do the feature-space-trained defenders hold up under P? The defenders are
  `adv_naive_G1`, `adv_sym_G1` and `adv_sym_G1G2`. Report two things:
  - P-recall;
  - the false-positive rate on packet-mutated benign flows.
- **Q4 (oracle).** How does `adv_sym_P`, trained with P-mutated copies, compare? It is an upper reference, not a
  deployable defence: a defender does not know the attacker's real generator.

## 2. Data

- **Captures.** CIC-IDS2017 raw captures, pcapng and Ethernet, from a Hugging Face mirror. Each file's size equals
  the size listed by CIC. Record the SHA-256 in the results. The files are stored in `data/pcap/`, which git ignores.
  - **Tuesday** (11.0 GB): FTP-Patator and SSH-Patator. These form the BruteForce family, which collapsed in round
    3 (xgb 0.999 → 0.243).
  - **Friday** (8.8 GB): Bot (ARES), PortScan and DDoS (LOIC).
- **Labels.** Join each extracted flow to the CIC flow table, `data/cicids2017/raw/Network-Flows/CICIDS_Flow.parquet`.
  That table has `flow_id`, IPs, ports, protocol and `Timestamp`.
  - Matching rule: same 5-tuple in either direction, with the start time within ±2 s after the timezone shift. CIC
    timestamps are local time (UTC−3); pcap times are UTC.
  - Measure the shift, do not assume it. Choose it to maximise the number of matches on a 1-hour sample, then
    assert that the match rate is above 90% for attack flows.
  - Unmatched flows are dropped and their counts reported.
  - **Fallback**, if the join fails: rule-based labels from the published attack schedule (attacker
    172.16.0.1 / 205.174.165.73, victim and time window per attack). The fallback must be cross-checked against the
    CIC labels on the matched subset.
- **Benign.** Benign flows from the same two days. Use a benign cap of 300,000 per day, sampled after extraction.

## 3. Flow extractor (our own, shared by every condition)

The features must be identical for clean training data and for P-mutated test data. We therefore use **one
extractor for everything**: training, calibration and test, clean and mutated. The defenders are retrained on its
output; the CIC CSV values are not used as features.

- **Implementation.** `src/idsbench/pcap/extract.py`. A streaming pcap(ng) reader (dpkt) feeds a flow table, and
  the CICFlowMeter feature definitions are implemented in numpy.
- **Features.** The same names as the CIC-IDS2017 CSV, so that `econ.mutation.build_group_index`, the G2 layout
  and `robust_columns` work unchanged.
- **Flow rules** (corrected CICFlowMeter semantics, Engelen et al. 2021):
  - bidirectional 5-tuple; the first packet sets the forward direction;
  - flow timeout 120 s;
  - active/idle threshold 5 s;
  - a TCP flow ends on FIN from both sides or on RST, and a packet after termination starts a new flow;
  - TCP and UDP only.
- **Per-packet state.** Store `ts`, `dir`, `ip_len`, `payload_len`, `hdr_len` (IP+TCP/UDP), `flags`, `win` and the
  index of the flow it belongs to.
- **Packet storage.**
  - Keep packets only for flows we may mutate: all attack flows (after the label join), plus a sample of benign
    flows for the mutated-benign test (20,000 per day).
  - For every other flow, store features only.
  - Persist to `data/pcap/cache/*.parquet` or `.npz`.
- **Validation** (a diagnostic, not a requirement).
  - For matched flows, report per-feature agreement with the CIC CSV: share within 1% relative error.
  - Known CICFlowMeter-V3 bugs make disagreement expected for some features, for example TCP termination and
    `Fwd Header Length`. List them.
- **Speed target.** One pass per capture in under 30 min on 4 CPUs. If needed, pre-split by flow hash and run 3
  worker processes.

## 4. Packet-level generator P (client = forward direction = flow initiator)

The attacker controls the client socket only. It may:
- delay client packets;
- pad client payload;
- insert client packets.

It cannot change server packets, but the server's packets move in time when the client's packets that cause them
move. P rewrites the packet list of a flow and calls the same extractor, so the flow is re-extracted from the
packets.

- **Timing.**
  - Before each client data packet after the first, add a delay drawn from Exp(mean δ). δ = (m − 1)·(mean forward
    inter-arrival of that flow), as in G2, with a floor of 1 ms.
  - **Causal shift:** every later packet in the flow, client or server, moves by the total delay added so far. A
    server packet answers an earlier client packet, so it moves with it.
  - Pure ACKs from the client are not delayed on their own; they move with the shift.
  - Re-split the flow if a gap now exceeds the 120 s timeout. Report how often this happens, and score the first
    sub-flow, the one that carries the handshake.
- **Length.** For each client packet with payload > 0, draw a per-flow target per-packet size:
  - target ~ Uniform(current, min(MSS, m·current)), with MSS = 1460 for IPv4 TCP and 1472 for UDP;
  - set the payload length to the target and update `ip_len`.
  - Pure ACKs, SYN and FIN without payload are not padded. Server packets are unchanged.
- **Count.** Insert k = ⌈(m − 1)·n_fwd_orig⌉ client packets.
  - TCP: pure ACKs (flags ACK, header length as in the flow's existing client ACKs, payload 0), placed at uniform
    random times strictly inside the flow's span, after the handshake.
  - UDP: zero-payload datagrams with the same placement.
  - Server packets are unchanged.
- **Budgets.** The same 21 budgets (7 group subsets × m ∈ {1.5, 2, 5}). When several groups apply, the order is
  count → length → timing, so that inserted packets also take part in the timing shift.
- **Randomness.** Seeded per (flow, budget). The randomness belongs to P; the attacker does not choose the per-packet
  draws.
- **Realisability notes,** to be stated in the paper:
  - SSH can pad with `SSH_MSG_IGNORE`;
  - HTTP can pad headers;
  - FTP commands accept trailing spaces;
  - a pure ACK can always be added;
  - delays are always possible.
  - No protocol-specific caps are applied beyond the MSS. Feasibility is per protocol and is discussed, not
    enforced.

**Attackers against P.**
- greedy (score mode, levels √m and m per group);
- strong (10 levels in [1, m], coordinate sweep, 2 restarts);
- transfer from xgb.

These reuse the generator-agnostic attackers in `idsbench.econ.mutation` through an `apply(X_flows, group, level)`
adapter. The adapter maps the rows back to their packet lists, mutates, re-extracts and returns the feature rows.
- Batch the re-extraction across flows: the attackers call `apply` on the whole batch.
- Profile it. If the strong attacker exceeds the budget, use 5 levels and 1 restart, and record it.

## 5. Defenders (retrained on extracted features, per seed)

| id | training data |
|---|---|
| `xgb` | clean |
| `xgb_robust` | clean, robust columns only (drops every column touched by G1, G2 **or** P; derive P's set empirically: any column that changes on > 1% of P-mutated training flows) |
| `adv_naive_G1` | + G1 attack copies (greedy against base xgb) |
| `adv_sym_G1` | + G1 attack copies + G1 benign copies (random budgets) |
| `adv_sym_G1G2` | + G1 and G2 attack and benign copies, half each |
| `adv_sym_P` | + P attack and benign copies (oracle) |

- Augmentation uses training rows only, as in `robust/defenders.py`.
- `adv_sym_P` needs packet lists for training flows. Keep packets for a sample of 4,000 benign training flows plus
  every attack training flow.

## 6. Evaluation

- **Splits and seeds.**
  - 5 seeds (compute). Benign: 60/20/20 split as before. Attack families: 70/30.
  - Families: FTP-Patator and SSH-Patator (the BruteForce family, also reported separately), Bot, PortScan, DDoS.
  - Use at most 500 E4 test flows per family.
- **FPR grid.** {1e-4, 1e-3, 1e-2}, with plateau-aware thresholds and Wilson intervals, reusing
  `robust/evaluate.py`.
- **Metrics,** per (seed, defender, FPR, family):
  - clean recall;
  - worst-case recall under G1, G2 and P (attackers × budgets);
  - mutated-benign FPR under G1, G2 and P (random budgets, benign test rows with packets).
- **Realism (Q1).**
  - Fingerprint AUROC of P(x) vs x.
  - Cross-generator AUROC: G1 vs P and G2 vs P at matched budgets, on the same flows.
  - Per-feature median relative error |G(x) − P(x)| / |P(x)|, per group.
  - The share of flows re-split by the timeout under P.
- **Headline table,** at FPR 1e-3, one row per defender:
  - clean recall;
  - worst-case G1, G2 and P;
  - mutated-benign FPR under G1, G2 and P;
  - realised FPR.
- **Statistics.** Wilcoxon over seeds with Holm correction. With only 5 seeds the minimum two-sided p is 0.0625,
  which the write-up must state, so give effect sizes with bootstrap CIs and do not claim significance.
  - **Optional:** if time allows, run 10 seeds.

## 7. Expected results and falsification

- **Q1.**
  - If G2 is much closer to P than G1 is, G2 should become the primary generator in the paper.
  - If both are far from P (AUROC ≈ 1 against P), the feature-space results are presented as generator-specific,
    and P carries the main claims.
- **Q2.** If xgb's worst-case P recall stays near its clean recall, the RQ1 collapse is a feature-space artefact.
  The paper must then say so.
- **Q3.**
  - If `adv_naive_G1` has a high P-recall **and** a low P-mutated-benign FPR, the fingerprint claim does not hold
    on real packets.
  - If `adv_sym_G1G2` keeps a low P-mutated-benign FPR and a P-recall close to `adv_sym_P`, feature-space symmetric
    augmentation transfers to real packets. That would be the strongest positive result.

## 8. Implementation plan

- `src/idsbench/pcap/`:
  - `extract.py`: reader, flow table and features;
  - `label.py`: the CIC join and its fallback;
  - `pgen.py`: generator P and the attacker adapter;
  - `build.py`: one pass per capture, writing the cache;
  - `evaluate.py`: reuses `robust.evaluate` and `robust.defenders` where possible;
  - `run_all.py`.
- **Tests,** on small synthetic packet lists:
  - extractor features on hand-computed flows: a handshake plus data, FIN/RST termination, timeout split, and
    active/idle;
  - P invariants: server packet sizes and flags unchanged, causal order kept, no client quantity reduced, budget
    m = 1 gives a bit-identical flow;
  - the label-join shift;
  - the adapter round trip (identity at level 1).
- **Outputs** go to `results/pcap/`: SUMMARY.md and CSVs, with anything over 50 MB gzipped. Caches stay in
  `data/pcap/cache` (ignored).
- **Compute.**
  - Extraction takes about 1 h per capture at most.
  - Budget the evaluation for about 4 h.
  - Run datasets and seeds sequentially in one process; XGBoost uses all cores.
