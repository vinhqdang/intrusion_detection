# E4 feature groups (mapping used by mutation.py)

Columns are matched by canonical name (lowercase; CIC-IDS2018 abbreviations mapped to CIC-IDS2017 names). Only forward-direction features are controllable; every backward (server-side) feature is uncontrollable.

Derived features are recomputed by delta updates (Y = X + f(Y) - f(X)), so a value keeps its offset from the identity where the identity does not hold exactly. Approximations (not checkable on the cache, since per-packet lengths and gaps are not stored): Fwd Packet Length Std (Bhatia-Davis bound on the level-scaled std), Flow IAT Std (duration ratio), Flow IAT Min (fwd-minimum rule).

Robust model (xgb_robustfeat): input = every column outside the mutated set and outside ROBUST_DROP_DEPENDENT; the explicit lists are below for each dataset.

## cicids2017

- timing group, controllable (7): Flow Duration, Flow IAT Max, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Total
- length group, controllable (4): Avg Fwd Segment Size, Fwd Packet Length Max, Fwd Packet Length Mean, Fwd Packet Length Min
- count group, controllable (6): Fwd Header Length, Subflow Fwd Bytes, Subflow Fwd Packets, Total Fwd Packets, Total Length of Fwd Packets, act_data_pkt_fwd
- derived, recomputed by a rule (7): flow iat mean, flow iat std, flow iat min, fwd packet length std, packet length std, packet length variance, down/up ratio
- all columns a mutation can change (32): Average Packet Size, Avg Fwd Segment Size, Bwd Packets/s, Down/Up Ratio, Flow Bytes/s, Flow Duration, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Packets/s, Fwd Header Length, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Total, Fwd Packet Length Max, Fwd Packet Length Mean, Fwd Packet Length Min, Fwd Packet Length Std, Fwd Packets/s, Max Packet Length, Min Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, Subflow Fwd Bytes, Subflow Fwd Packets, Total Fwd Packets, Total Length of Fwd Packets, act_data_pkt_fwd
- uncontrollable, never changed (36): ACK Flag Count, Active Max, Active Mean, Active Min, Active Std, Avg Bwd Segment Size, Bwd Header Length, Bwd IAT Max, Bwd IAT Mean, Bwd IAT Min, Bwd IAT Std, Bwd IAT Total, Bwd Packet Length Max, Bwd Packet Length Mean, Bwd Packet Length Min, Bwd Packet Length Std, CWE Flag Count, ECE Flag Count, FIN Flag Count, Fwd PSH Flags, Fwd URG Flags, Idle Max, Idle Mean, Idle Min, Idle Std, Init_Win_bytes_backward, Init_Win_bytes_forward, PSH Flag Count, RST Flag Count, SYN Flag Count, Subflow Bwd Bytes, Subflow Bwd Packets, Total Backward Packets, Total Length of Bwd Packets, URG Flag Count, min_seg_size_forward
- robust model input (25): ACK Flag Count, Avg Bwd Segment Size, Bwd Header Length, Bwd IAT Max, Bwd IAT Mean, Bwd IAT Min, Bwd IAT Std, Bwd IAT Total, Bwd Packet Length Max, Bwd Packet Length Mean, Bwd Packet Length Min, Bwd Packet Length Std, CWE Flag Count, ECE Flag Count, FIN Flag Count, Init_Win_bytes_backward, PSH Flag Count, RST Flag Count, SYN Flag Count, Subflow Bwd Bytes, Subflow Bwd Packets, Total Backward Packets, Total Length of Bwd Packets, URG Flag Count, min_seg_size_forward
- robust model excluded (43): Active Max, Active Mean, Active Min, Active Std, Average Packet Size, Avg Fwd Segment Size, Bwd Packets/s, Down/Up Ratio, Flow Bytes/s, Flow Duration, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Packets/s, Fwd Header Length, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Total, Fwd PSH Flags, Fwd Packet Length Max, Fwd Packet Length Mean, Fwd Packet Length Min, Fwd Packet Length Std, Fwd Packets/s, Fwd URG Flags, Idle Max, Idle Mean, Idle Min, Idle Std, Init_Win_bytes_forward, Max Packet Length, Min Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance, Subflow Fwd Bytes, Subflow Fwd Packets, Total Fwd Packets, Total Length of Fwd Packets, act_data_pkt_fwd

Identity hold rates on the cached pool (sample of cicids2017; relative tolerance 0.01 unless the rule is exact):

| feature | rule | rows checked | share of rows where the rule holds |
|---|---|---|---|
| flow iat mean | Flow Duration / (Total packets - 1) | 234587 | 1.0000 |
| fwd iat mean | Fwd IAT Total / (Total Fwd Packets - 1) | 186774 | 1.0000 |
| down/up ratio | floor(Total Bwd Packets / Total Fwd Packets) | 234587 | 1.0000 |
| packet length variance | Packet Length Std ** 2 (identity used only to define the variance rule) | 234587 | 1.0000 |
| packet length variance (pooled) | pooled variance of fwd and bwd directions | 1 | 0.2164 |
| packet length mean | (fwd bytes + bwd bytes) / (fwd packets + bwd packets) | 234587 | 0.2056 |
| flow iat min = fwd iat min | rule applies when the minimum gap is forward | 234303 | 0.4332 |
| max packet length | max(fwd max, bwd max) | 234587 | 1.0000 |
| min packet length | min(fwd min, bwd min) | 234587 | 0.9507 |
| flow packets/s | (fwd + bwd packets) / duration | 234575 | 1.0000 |
| fwd packets/s | fwd packets / duration | 234575 | 1.0000 |
| bwd packets/s | bwd packets / duration | 234575 | 1.0000 |
| average packet size | (fwd bytes + bwd bytes) / (fwd packets + bwd packets) | 234587 | 0.4516 |
| flow bytes/s | (fwd bytes + bwd bytes) / duration | 234575 | 1.0000 |

## cicids2018

- timing group, controllable (7): Flow Duration, Flow IAT Max, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Tot
- length group, controllable (4): Fwd Pkt Len Max, Fwd Pkt Len Mean, Fwd Pkt Len Min, Fwd Seg Size Avg
- count group, controllable (6): Fwd Act Data Pkts, Fwd Header Len, Subflow Fwd Byts, Subflow Fwd Pkts, Tot Fwd Pkts, TotLen Fwd Pkts
- derived, recomputed by a rule (7): flow iat mean, flow iat std, flow iat min, fwd packet length std, packet length std, packet length variance, down/up ratio
- all columns a mutation can change (32): Bwd Pkts/s, Down/Up Ratio, Flow Byts/s, Flow Duration, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Pkts/s, Fwd Act Data Pkts, Fwd Header Len, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Tot, Fwd Pkt Len Max, Fwd Pkt Len Mean, Fwd Pkt Len Min, Fwd Pkt Len Std, Fwd Pkts/s, Fwd Seg Size Avg, Pkt Len Max, Pkt Len Mean, Pkt Len Min, Pkt Len Std, Pkt Len Var, Pkt Size Avg, Subflow Fwd Byts, Subflow Fwd Pkts, Tot Fwd Pkts, TotLen Fwd Pkts
- uncontrollable, never changed (37): ACK Flag Cnt, Active Max, Active Mean, Active Min, Active Std, Bwd Header Len, Bwd IAT Max, Bwd IAT Mean, Bwd IAT Min, Bwd IAT Std, Bwd IAT Tot, Bwd Pkt Len Max, Bwd Pkt Len Mean, Bwd Pkt Len Min, Bwd Pkt Len Std, Bwd Seg Size Avg, CWE Flag Count, ECE Flag Cnt, FIN Flag Cnt, Fwd PSH Flags, Fwd Seg Size Min, Fwd URG Flags, Idle Max, Idle Mean, Idle Min, Idle Std, Init Bwd Win Byts, Init Fwd Win Byts, PSH Flag Cnt, Protocol, RST Flag Cnt, SYN Flag Cnt, Subflow Bwd Byts, Subflow Bwd Pkts, Tot Bwd Pkts, TotLen Bwd Pkts, URG Flag Cnt
- robust model input (26): ACK Flag Cnt, Bwd Header Len, Bwd IAT Max, Bwd IAT Mean, Bwd IAT Min, Bwd IAT Std, Bwd IAT Tot, Bwd Pkt Len Max, Bwd Pkt Len Mean, Bwd Pkt Len Min, Bwd Pkt Len Std, Bwd Seg Size Avg, CWE Flag Count, ECE Flag Cnt, FIN Flag Cnt, Fwd Seg Size Min, Init Bwd Win Byts, PSH Flag Cnt, Protocol, RST Flag Cnt, SYN Flag Cnt, Subflow Bwd Byts, Subflow Bwd Pkts, Tot Bwd Pkts, TotLen Bwd Pkts, URG Flag Cnt
- robust model excluded (43): Active Max, Active Mean, Active Min, Active Std, Bwd Pkts/s, Down/Up Ratio, Flow Byts/s, Flow Duration, Flow IAT Max, Flow IAT Mean, Flow IAT Min, Flow IAT Std, Flow Pkts/s, Fwd Act Data Pkts, Fwd Header Len, Fwd IAT Max, Fwd IAT Mean, Fwd IAT Min, Fwd IAT Std, Fwd IAT Tot, Fwd PSH Flags, Fwd Pkt Len Max, Fwd Pkt Len Mean, Fwd Pkt Len Min, Fwd Pkt Len Std, Fwd Pkts/s, Fwd Seg Size Avg, Fwd URG Flags, Idle Max, Idle Mean, Idle Min, Idle Std, Init Fwd Win Byts, Pkt Len Max, Pkt Len Mean, Pkt Len Min, Pkt Len Std, Pkt Len Var, Pkt Size Avg, Subflow Fwd Byts, Subflow Fwd Pkts, Tot Fwd Pkts, TotLen Fwd Pkts

Identity hold rates on the cached pool (sample of cicids2018; relative tolerance 0.01 unless the rule is exact):

| feature | rule | rows checked | share of rows where the rule holds |
|---|---|---|---|
| flow iat mean | Flow Duration / (Total packets - 1) | 250335 | 1.0000 |
| fwd iat mean | Fwd IAT Total / (Total Fwd Packets - 1) | 214567 | 1.0000 |
| down/up ratio | floor(Total Bwd Packets / Total Fwd Packets) | 250335 | 1.0000 |
| packet length variance | Packet Length Std ** 2 (identity used only to define the variance rule) | 250335 | 1.0000 |
| packet length variance (pooled) | pooled variance of fwd and bwd directions | 1 | 0.1859 |
| packet length mean | (fwd bytes + bwd bytes) / (fwd packets + bwd packets) | 250335 | 0.1810 |
| flow iat min = fwd iat min | rule applies when the minimum gap is forward | 250335 | 0.3477 |
| max packet length | max(fwd max, bwd max) | 250335 | 1.0000 |
| min packet length | min(fwd min, bwd min) | 250335 | 0.9908 |
| flow packets/s | (fwd + bwd packets) / duration | 250335 | 1.0000 |
| fwd packets/s | fwd packets / duration | 250335 | 1.0000 |
| bwd packets/s | bwd packets / duration | 250335 | 1.0000 |
| average packet size | (fwd bytes + bwd bytes) / (fwd packets + bwd packets) | 250335 | 0.7920 |
| flow bytes/s | (fwd bytes + bwd bytes) / duration | 250335 | 1.0000 |

