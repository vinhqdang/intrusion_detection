"""Labels from the CIC-IDS2017 flow table (design/design_pcap.md section 2).

A flow matches a CIC row when both have the same direction-free 5-tuple and the CIC start time, shifted to UTC,
falls in the flow's start window. CIC start times are local to the capture site and have minute precision on the
Tuesday to Friday files (the format is ``D/M/YYYY H:MM``), so a CIC time t_c matches a flow start t when
t_c <= t < t_c + 60 s after the shift. Seconds-precision rows (Monday format) use a 1 s window.

The shift is measured, not assumed: candidate shifts are scored by the number of matches on the busiest hour of
the capture, first on a one-hour grid and then at one-minute resolution around the best coarse value.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .extract import TCP, UDP, canonical_keys

CIC_PATH = "data/cicids2017/raw/Network-Flows/CICIDS_Flow.parquet"
DAY_PREFIX = {"tuesday": "4/7/2017", "friday": "7/7/2017"}
LABELS = ("BENIGN", "FTP-Patator", "SSH-Patator", "Bot", "PortScan", "DDoS")
MINUTE_US = 60_000_000
SECOND_US = 1_000_000
CIC_COLUMNS = ["source_ip", "source_port", "destination_ip", "destination_port", "protocol", "Timestamp",
               "attack_label"]


def _ip_to_u32(series: pd.Series) -> np.ndarray:
    uniq, inv = np.unique(series.to_numpy(dtype=object).astype(str), return_inverse=True)
    vals = np.array([int.from_bytes(bytes(int(x) for x in u.split(".")), "big") for u in uniq], dtype=np.uint64)
    return vals[inv]


def parse_cic_local(timestamps) -> tuple[np.ndarray, np.ndarray]:
    """Naive local start time of CIC rows in microseconds, and a flag for seconds precision.

    Monday rows use ``DD/MM/YYYY HH:MM:SS`` (24-hour, seconds). Tuesday to Friday rows use ``D/M/YYYY H:MM``
    (minutes): the hour is on a 12-hour clock without AM/PM, so 13:05 is written ``1:05``. The capture window is
    08:00 to 17:00 local, so hours 1 to 7 are read as 13 to 19 and hours 8 to 12 are kept.
    """
    ts = pd.Series(timestamps).astype(str).reset_index(drop=True)
    prec_sec = (ts.str.len() == 19).to_numpy()
    out = pd.Series(pd.NaT, index=ts.index, dtype="datetime64[ns]")
    out[prec_sec] = pd.to_datetime(ts[prec_sec], format="%d/%m/%Y %H:%M:%S")
    out[~prec_sec] = pd.to_datetime(ts[~prec_sec], format="%d/%m/%Y %H:%M")
    pm = (~prec_sec) & out.dt.hour.between(1, 7).to_numpy()
    out[pm] = out[pm] + pd.Timedelta(hours=12)
    us = out.astype("datetime64[ns]").astype(np.int64) // 1000
    us = np.where(out.isna().to_numpy(), np.nan, us.astype(np.float64))
    return us, prec_sec


def load_cic(day: str, path: str = CIC_PATH, with_features: bool = False):
    """CIC rows of one capture day with canonical keys and the local start window (naive microseconds).

    Rows of other protocols (``other``) are dropped; they cannot match an IP packet flow here. With
    ``with_features`` also returns the CIC feature matrix (rows aligned with the returned frame; used only for
    validation of the extractor, never as model input).
    """
    import pyarrow.parquet as pq
    from .extract import FEATURES

    prefix = DAY_PREFIX[day]
    cols = CIC_COLUMNS + (list(FEATURES) if with_features else [])
    d = pq.read_table(path, columns=cols).to_pandas()
    ts = d["Timestamp"].astype(str)
    d = d[ts.str.startswith(prefix)].copy()
    lo_us, prec_sec = parse_cic_local(d["Timestamp"])
    if np.isnan(lo_us).any():
        raise ValueError("unparsed CIC timestamps")
    lo = pd.Series(lo_us, index=d.index)
    proto = d["protocol"].astype(str).str.lower().map({"tcp": TCP, "udp": UDP})
    keep = proto.notna().to_numpy()
    d = d[keep].copy()
    lo = lo[keep]
    prec_sec = prec_sec[keep]
    out = pd.DataFrame({
        "src": _ip_to_u32(d["source_ip"]), "dst": _ip_to_u32(d["destination_ip"]),
        "sport": d["source_port"].to_numpy(np.int64), "dport": d["destination_port"].to_numpy(np.int64),
        "proto": proto[keep].to_numpy(np.int64),
        "lo_local": lo.to_numpy(np.float64).astype(np.int64),   # naive local time, microseconds
        "window": np.where(prec_sec, SECOND_US, MINUTE_US).astype(np.int64),
        "label": d["attack_label"].astype(str).to_numpy(),
    })
    out["row"] = np.arange(len(out))
    k1, k2 = canonical_keys(out["src"], out["dst"], out["sport"], out["dport"], out["proto"])
    out["k1"], out["k2"] = k1, k2
    out = out.reset_index(drop=True)
    if with_features:
        return out, d[list(FEATURES)].to_numpy(dtype=np.float64)
    return out


def _composite_searchsorted(rk1, rk2, rlo, lk1, lk2, lt) -> np.ndarray:
    """Insertion positions (side='right') of (lk1, lk2, lt) in right arrays sorted by (k1, k2, time)."""
    n = len(rlo)
    lo_ = np.zeros(len(lt), dtype=np.int64)
    hi_ = np.full(len(lt), n, dtype=np.int64)
    steps = int(np.ceil(np.log2(max(n, 2)))) + 1
    for _ in range(steps):
        mid = (lo_ + hi_) // 2
        midc = np.clip(mid, 0, max(n - 1, 0))
        a1, a2, a3 = rk1[midc], rk2[midc], rlo[midc]
        le = (a1 < lk1) | ((a1 == lk1) & ((a2 < lk2) | ((a2 == lk2) & (a3 <= lt))))
        active = lo_ < hi_
        lo_ = np.where(active & le, mid + 1, lo_)
        hi_ = np.where(active & ~le, mid, hi_)
    return lo_


def candidate_pairs(first_ts, k1, k2, cic: pd.DataFrame, shift_us: int):
    """All (flow, CIC row) pairs with the same 5-tuple and the CIC start window containing the flow start.

    The CIC start is local time: UTC = local + shift_us. Returns two int64 arrays (flow index, CIC row index).
    """
    lo = cic["lo_local"].to_numpy(np.int64) + shift_us
    win = cic["window"].to_numpy(np.int64)
    ck1, ck2 = cic["k1"].to_numpy(), cic["k2"].to_numpy()
    o = np.lexsort((lo, ck2, ck1))
    ck1, ck2, clo, cwin, crow = ck1[o], ck2[o], lo[o], win[o], cic["row"].to_numpy(np.int64)[o]
    t = np.asarray(first_ts, dtype=np.int64)
    fk1, fk2 = np.asarray(k1), np.asarray(k2)
    if len(t) == 0 or len(clo) == 0:
        z = np.zeros(0, dtype=np.int64)
        return z, z
    maxw = int(cwin.max())
    a = _composite_searchsorted(ck1, ck2, clo, fk1, fk2, t - maxw - 1)
    b = _composite_searchsorted(ck1, ck2, clo, fk1, fk2, t)
    counts = np.maximum(b - a, 0)
    total = int(counts.sum())
    if total == 0:
        z = np.zeros(0, dtype=np.int64)
        return z, z
    flow = np.repeat(np.arange(len(t), dtype=np.int64), counts)
    starts_rep = np.repeat(a, counts)
    within = np.arange(total, dtype=np.int64) - np.repeat(np.cumsum(counts) - counts, counts)
    idx = starts_rep + within
    keep = (ck1[idx] == fk1[flow]) & (ck2[idx] == fk2[flow]) & (t[flow] < clo[idx] + cwin[idx])
    return flow[keep], crow[idx][keep]


def assign_labels(n_flows: int, pair_flow: np.ndarray, pair_row: np.ndarray, cic: pd.DataFrame) -> dict:
    """Per flow: label code (index into LABELS, -1 unmatched, -2 ambiguous) and the number of candidates."""
    codes = pd.Categorical(cic["label"].to_numpy(), categories=list(LABELS)).codes.astype(np.int64)
    other = codes < 0
    if other.any():
        raise ValueError(f"unexpected CIC labels: {sorted(set(cic['label'][other]))}")
    row_code = np.full(cic["row"].max() + 1, -1, dtype=np.int64)
    row_code[cic["row"].to_numpy()] = codes
    label = np.full(n_flows, -1, dtype=np.int64)
    ncand = np.bincount(pair_flow, minlength=n_flows).astype(np.int64)
    if len(pair_flow):
        pc = row_code[pair_row]
        # distinct label codes per flow
        key = pair_flow * len(LABELS) + pc
        uk = np.unique(key)
        distinct = np.bincount(uk // len(LABELS), minlength=n_flows)
        one_code = np.full(n_flows, -1, dtype=np.int64)
        one_code[uk // len(LABELS)] = uk % len(LABELS)
        label = np.where(distinct == 1, one_code, np.where(distinct > 1, -2, -1))
    return {"label": label, "n_candidates": ncand}


def estimate_shift(first_ts, k1, k2, cic: pd.DataFrame, coarse_hours=range(-13, 14)) -> dict:
    """Shift (UTC minus local, microseconds) that maximises the number of flows with a candidate CIC row.

    Scored on the busiest hour of the flows: a one-hour grid over +-13 h, then one-minute steps within +-60 min of
    the best grid value.
    """
    first_ts = np.asarray(first_ts, dtype=np.int64)
    hour = first_ts // (3600 * 1_000_000)
    vals, counts = np.unique(hour, return_counts=True)
    h = vals[np.argmax(counts)]
    sel = hour == h
    s_t, s_k1, s_k2 = first_ts[sel], k1[sel], k2[sel]

    def score(s):
        f, _ = candidate_pairs(s_t, s_k1, s_k2, cic, s)
        return int(len(np.unique(f)))

    curve = {hh * 3600 * 1_000_000: score(hh * 3600 * 1_000_000) for hh in coarse_hours}
    best_c = max(curve, key=lambda s: curve[s])
    fine = {}
    for mm in range(-60, 61):
        s = best_c + mm * 60 * 1_000_000
        fine[s] = score(s)
    best = max(fine, key=lambda s: fine[s])
    best_n = fine[best]
    second = sorted((c for s, c in fine.items() if s != best), reverse=True)[0]
    plateau = sum(1 for c in fine.values() if c == best_n)
    return {"shift_us": int(best), "shift_hours": best / 3.6e9, "sample_hour_utc": int(h) * 3600,
            "sample_flows": int(sel.sum()), "flows_matched_at_best": int(best_n),
            "flows_matched_best_hour_grid": int(curve[best_c]), "second_best_minute_flows": int(second),
            "plateau_minutes": int(plateau)}




# ----------------------------------------------------------------------------- primary label rule
def _ip(s: str) -> int:
    return int.from_bytes(bytes(int(x) for x in s.split(".")), "big")


BOT_IP = _ip("205.174.165.73")
ATTACK_IP = _ip("172.16.0.1")
VICTIM_IP = _ip("192.168.10.50")
VICTIM_NET = (_ip("192.168.10.0"), 0xFFFFFF00)


def pattern_match(name: str, src, dst, sport, dport) -> np.ndarray:
    """Whether a flow (initiator endpoints) matches the published attacker and victim pattern of a family.

    FTP-Patator, SSH-Patator and DDoS: 172.16.0.1 to 192.168.10.50 on port 21, 22 and 80.
    PortScan: 172.16.0.1 to 192.168.10.50 on any port.
    Bot (ARES): 205.174.165.73 and a 192.168.10.x host, port 8080 on either side.
    """
    src = np.asarray(src, np.int64)
    dst = np.asarray(dst, np.int64)
    dport = np.asarray(dport, np.int64)
    sport = np.asarray(sport, np.int64)
    if name in ("FTP-Patator", "SSH-Patator", "DDoS", "PortScan"):
        port = {"FTP-Patator": 21, "SSH-Patator": 22, "DDoS": 80, "PortScan": None}[name]
        ok = (src == ATTACK_IP) & (dst == VICTIM_IP)
        return ok if port is None else ok & (dport == port)
    if name == "Bot":
        in_net = (dst & VICTIM_NET[1]) == VICTIM_NET[0]
        in_net_s = (src & VICTIM_NET[1]) == VICTIM_NET[0]
        ok = ((src == BOT_IP) & in_net) | ((dst == BOT_IP) & in_net_s)
        return ok & ((dport == 8080) | (sport == 8080))
    return np.zeros(len(src), dtype=bool)


def primary_labels(n_flows: int, pair_flow: np.ndarray, pair_row: np.ndarray, cic: pd.DataFrame,
                   src, dst, sport, dport) -> dict:
    """Primary label rule. A flow whose matched CIC rows include an attack label that matches the family's published
    attacker and victim pattern takes that label. Otherwise it takes the majority label of its matched rows (ties go
    to BENIGN). Flows without a matched row are -1. Returns labels and how each label was chosen."""
    codes = pd.Categorical(cic["label"].to_numpy(), categories=list(LABELS)).codes.astype(np.int64)
    row_code = np.full(cic["row"].max() + 1, -1, dtype=np.int64)
    row_code[cic["row"].to_numpy()] = codes
    label = np.full(n_flows, -1, dtype=np.int64)
    how = np.zeros(n_flows, dtype=np.int64)            # 0 none, 1 pattern, 2 majority
    if len(pair_flow) == 0:
        return {"label": label, "how": how}
    pc = row_code[pair_row]
    pf = pair_flow
    pat = np.zeros(len(pf), dtype=bool)
    for c, name in enumerate(LABELS):
        if c == 0:
            continue
        m = pc == c
        if m.any():
            idx = pf[m]
            pat[np.flatnonzero(m)] = pattern_match(name, src[idx], dst[idx], sport[idx], dport[idx])
    hit = np.flatnonzero(pat)
    label[pf[hit]] = pc[hit]
    how[pf[hit]] = 1
    counts = np.bincount(pf * len(LABELS) + pc, minlength=n_flows * len(LABELS)).reshape(n_flows, len(LABELS))
    rest = (how == 0) & (counts.sum(axis=1) > 0)
    label[rest] = np.argmax(counts[rest], axis=1)       # first maximum: BENIGN wins ties
    how[rest] = 2
    return {"label": label, "how": how}
