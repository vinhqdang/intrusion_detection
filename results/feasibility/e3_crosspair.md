# E3 cross-pair transfer

Dataset pairs that share a feature extractor. Features canonicalised by name, then intersected.
Caps: 100,000 benign, 20,000 per attack family per dataset. Seeds: 0, 1, 2. Wall-clock: 2.7 min.

## Feature canonicalisation

### cicids2017 <-> cicids2018

- matched features: 68
- excluded (port / protocol / timestamp / IP / flow id): protocol
- unmatched in cicids2017: none
- unmatched in cicids2018: none
- aliases applied: 'ACK Flag Cnt' -> 'ack flag count', 'Bwd Header Len' -> 'bwd header length', 'Bwd IAT Tot' -> 'bwd iat total', 'Bwd Pkt Len Max' -> 'bwd packet length max', 'Bwd Pkt Len Mean' -> 'bwd packet length mean', 'Bwd Pkt Len Min' -> 'bwd packet length min', 'Bwd Pkt Len Std' -> 'bwd packet length std', 'Bwd Pkts/s' -> 'bwd packets/s', 'Bwd Seg Size Avg' -> 'avg bwd segment size', 'ECE Flag Cnt' -> 'ece flag count', 'FIN Flag Cnt' -> 'fin flag count', 'Flow Byts/s' -> 'flow bytes/s', 'Flow Pkts/s' -> 'flow packets/s', 'Fwd Act Data Pkts' -> 'act_data_pkt_fwd', 'Fwd Header Len' -> 'fwd header length', 'Fwd IAT Tot' -> 'fwd iat total', 'Fwd Pkt Len Max' -> 'fwd packet length max', 'Fwd Pkt Len Mean' -> 'fwd packet length mean', 'Fwd Pkt Len Min' -> 'fwd packet length min', 'Fwd Pkt Len Std' -> 'fwd packet length std', 'Fwd Pkts/s' -> 'fwd packets/s', 'Fwd Seg Size Avg' -> 'avg fwd segment size', 'Fwd Seg Size Min' -> 'min_seg_size_forward', 'Init Bwd Win Byts' -> 'init_win_bytes_backward', 'Init Fwd Win Byts' -> 'init_win_bytes_forward', 'PSH Flag Cnt' -> 'psh flag count', 'Pkt Len Max' -> 'max packet length', 'Pkt Len Mean' -> 'packet length mean', 'Pkt Len Min' -> 'min packet length', 'Pkt Len Std' -> 'packet length std', 'Pkt Len Var' -> 'packet length variance', 'Pkt Size Avg' -> 'average packet size', 'RST Flag Cnt' -> 'rst flag count', 'SYN Flag Cnt' -> 'syn flag count', 'Subflow Bwd Byts' -> 'subflow bwd bytes', 'Subflow Bwd Pkts' -> 'subflow bwd packets', 'Subflow Fwd Byts' -> 'subflow fwd bytes', 'Subflow Fwd Pkts' -> 'subflow fwd packets', 'Tot Bwd Pkts' -> 'total backward packets', 'Tot Fwd Pkts' -> 'total fwd packets', 'TotLen Bwd Pkts' -> 'total length of bwd packets', 'TotLen Fwd Pkts' -> 'total length of fwd packets', 'URG Flag Cnt' -> 'urg flag count'
- matched: ack flag count, act_data_pkt_fwd, active max, active mean, active min, active std, average packet size, avg bwd segment size, avg fwd segment size, bwd header length, bwd iat max, bwd iat mean, bwd iat min, bwd iat std, bwd iat total, bwd packet length max, bwd packet length mean, bwd packet length min, bwd packet length std, bwd packets/s, cwe flag count, down/up ratio, ece flag count, fin flag count, flow bytes/s, flow duration, flow iat max, flow iat mean, flow iat min, flow iat std, flow packets/s, fwd header length, fwd iat max, fwd iat mean, fwd iat min, fwd iat std, fwd iat total, fwd packet length max, fwd packet length mean, fwd packet length min, fwd packet length std, fwd packets/s, fwd psh flags, fwd urg flags, idle max, idle mean, idle min, idle std, init_win_bytes_backward, init_win_bytes_forward, max packet length, min packet length, min_seg_size_forward, packet length mean, packet length std, packet length variance, psh flag count, rst flag count, subflow bwd bytes, subflow bwd packets, subflow fwd bytes, subflow fwd packets, syn flag count, total backward packets, total fwd packets, total length of bwd packets, total length of fwd packets, urg flag count

### ciciot2023 <-> ciciomt2024

- matched features: 0
- excluded (port / protocol / timestamp / IP / flow id): protocol, protocol type
- unmatched in ciciot2023: ack_count, ack_flag_number, arp, avg, cwr_flag_number, dhcp, dns, ece_flag_number, fin_count, fin_flag_number, header_length, http, https, iat, icmp, igmp, ipv, irc, llc, max, min, number, psh_flag_number, rate, rst_count, rst_flag_number, smtp, ssh, std, syn_count, syn_flag_number, tcp, telnet, time_to_live, tot size, tot sum, udp, variance
- unmatched in ciciomt2024: ack flag count, active max, active mean, active min, active std, average packet size, bwd bulk rate avg, bwd bytes/bulk avg, bwd header length, bwd iat max, bwd iat mean, bwd iat min, bwd iat std, bwd iat total, bwd init win bytes, bwd packet length max, bwd packet length mean, bwd packet length min, bwd packet length std, bwd packet/bulk avg, bwd packets/s, bwd psh flags, bwd segment size avg, cwr flag count, down/up ratio, ece flag count, fin flag count, flow bytes/s, flow duration, flow iat max, flow iat mean, flow iat min, flow iat std, flow packets/s, fwd act data pkts, fwd header length, fwd iat max, fwd iat mean, fwd iat min, fwd iat std, fwd iat total, fwd init win bytes, fwd packet length max, fwd packet length mean, fwd packet length min, fwd packet length std, fwd packets/s, fwd psh flags, fwd seg size min, fwd segment size avg, fwd urg flags, idle max, idle mean, idle min, idle std, packet length max, packet length mean, packet length min, packet length std, packet length variance, psh flag count, rst flag count, subflow bwd bytes, subflow bwd packets, subflow fwd bytes, subflow fwd packets, syn flag count, total bwd packets, total fwd packet, total length of bwd packet, total length of fwd packet, urg flag count
- aliases applied: none
- matched: none

## Shared-feature pool cleaning (rows removed after restricting to shared features)

| pair | dataset | rows before | exact duplicates | label conflicts | feature-only duplicates | rows kept |
|---|---|---|---|---|---|---|
| cicids2017 <-> cicids2018 | cicids2017 | 2,198,384 | 0 | 0 | 0 | 2,198,384 |
| cicids2017 <-> cicids2018 | cicids2018 | 1,116,734 | 0 | 0 | 0 | 1,116,734 |

## Results per pair

### cicids2017 <-> cicids2018

### AUROC matrix (rows = train A, cols = test B)

| A \ B | cicids2017 | cicids2018 |
|---|---|---|
| cicids2017 | 0.9999 ± 0.0000 | 0.7492 ± 0.0119 |
| cicids2018 | 0.5597 ± 0.0368 | 0.9840 ± 0.0005 |

### Target FPR vs realised FPR on B benign (A-calibrated thresholds)

| A -> B | target 1e-2 realised | target 1e-3 realised | recall B @1e-3 |
|---|---|---|---|
| cicids2017 -> cicids2017 | 0.0102 ± 0.0007 | 0.0009 ± 0.0002 | 0.9952 ± 0.0020 |
| cicids2017 -> cicids2018 | 0.0207 ± 0.0016 | 0.0044 ± 0.0061 | 0.0027 ± 0.0039 |
| cicids2018 -> cicids2017 | 0.1086 ± 0.0094 | 0.0378 ± 0.0050 | 0.0994 ± 0.0560 |
| cicids2018 -> cicids2018 | 0.0101 ± 0.0013 | 0.0008 ± 0.0002 | 0.8196 ± 0.0005 |

### Conformal + BH (alpha = 0.1) on B: unweighted vs weighted (two variants)

Weighted (oracle) fits the domain classifier on B benign rows (uses B labels: upper bound). Weighted (label-free) fits it on B rows whose unweighted p-value is > 0.5 (presumed benign; no B labels). Weights: mean over A calibration, and effective sample size (sum w)^2 / sum w^2 of A calibration (unweighted ESS = n calibration).

| A -> B | unweighted FDR | unweighted power | oracle FDR | oracle power | label-free FDR | label-free power | mean w cal (oracle / label-free) | ESS cal (oracle / label-free) |
|---|---|---|---|---|---|---|---|---|
| cicids2017 -> cicids2017 | 0.0637 ± 0.0024 | 0.9996 ± 0.0001 | 0.0641 ± 0.0022 | 0.9996 ± 0.0001 | 0.2946 ± 0.1077 | 0.9999 ± 0.0001 | 1.000 ± 0.000 / 1.010 ± 0.012 | 13932 ± 10 / 8303 ± 1037 |
| cicids2017 -> cicids2018 | 0.0447 ± 0.0417 | 0.2654 ± 0.2505 | 0.3499 ± 0.5636 | 0.1643 ± 0.2846 | 0.3892 ± 0.3839 | 0.3389 ± 0.2918 | 0.694 ± 0.017 / 0.407 ± 0.275 | 1075 ± 521 / 1264 ± 1393 |
| cicids2018 -> cicids2017 | 0.5130 ± 0.0652 | 0.2553 ± 0.0780 | 0.3161 ± 0.2747 | 0.1974 ± 0.1713 | 0.6432 ± 0.0196 | 0.6404 ± 0.1338 | 0.801 ± 0.288 / 0.407 ± 0.086 | 1555 ± 631 / 819 ± 38 |
| cicids2018 -> cicids2018 | 0.0503 ± 0.0012 | 0.9107 ± 0.0014 | 0.0506 ± 0.0011 | 0.9109 ± 0.0018 | 0.0938 ± 0.0168 | 0.9401 ± 0.0067 | 1.000 ± 0.000 / 1.062 ± 0.004 | 13945 ± 22 / 6498 ± 231 |

Shared features used: 68.
Datasets not loaded: none

### ciciot2023 <-> ciciomt2024

Not run: no feature names shared after canonicalisation; the pair cannot be analysed.
