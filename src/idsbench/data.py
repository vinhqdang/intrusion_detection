"""Dataset loaders: NSL-KDD (official train/test split) and CICIoT2023 (no official split)."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np
import pandas as pd

NSLKDD_BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
NSLKDD_REMOTE = {"train": "KDDTrain%2B.txt", "test": "KDDTest%2B.txt"}
NSLKDD_NORMAL = "normal"
NSLKDD_CATEGORICAL = ["protocol_type", "service", "flag"]
NSLKDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]
# Standard NSL-KDD attack-name -> family mapping (includes test-only attacks).
NSLKDD_ATTACK_CLASS = {
    "normal": "normal",
    # DoS
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos", "smurf": "dos",
    "teardrop": "dos", "mailbomb": "dos", "apache2": "dos", "processtable": "dos",
    "udpstorm": "dos",
    # Probe
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    # U2R
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r",
    "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r", "httptunnel": "u2r",
    # R2L
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "named": "r2l", "sendmail": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "worm": "r2l", "xlock": "r2l", "xsnoop": "r2l",
}

CIC_HF_REPO = "MaheshBaja/CIC-IoT-2023"
CIC_HF_FILES = [
    "random/train-00000-of-00001.parquet",
    "random/test-00000-of-00001.parquet",
]
CIC_CACHE_NAME = "ciciot2023_random_all.parquet"
CIC_NORMAL = "Benign"
CIC_LABEL_COLUMNS = ("Label", "attack_class", "label")
CIC_FAMILIES = ("Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce")
# Ordered keyword rules; "ddos" must be checked before "dos".
_CIC_FAMILY_RULES = [
    ("benign", "Benign"),
    ("ddos", "DDoS"),
    ("dos", "DoS"),
    ("mirai", "Mirai"),
    ("scan", "Recon"),
    ("discovery", "Recon"),
    ("pingsweep", "Recon"),
    ("spoof", "Spoofing"),
    ("bruteforce", "BruteForce"),
    ("backdoor", "Web"),
    ("browserhijack", "Web"),
    ("injection", "Web"),
    ("uploading", "Web"),
    ("xss", "Web"),
]


def map_nslkdd_label(name: str) -> str:
    """Map a raw NSL-KDD attack name to normal/dos/probe/r2l/u2r. Unknown names raise ValueError."""
    key = str(name).strip().rstrip(".").strip()
    if key not in NSLKDD_ATTACK_CLASS:
        raise ValueError(f"Unknown NSL-KDD attack name: {name!r}")
    return NSLKDD_ATTACK_CLASS[key]


def ciciot_family(label: str) -> str:
    """Map a CICIoT2023 fine-grained label (34 names) to one of the 8 families by keyword prefix."""
    low = str(label).lower()
    for keyword, family in _CIC_FAMILY_RULES:
        if keyword in low:
            return family
    raise ValueError(f"Cannot map CICIoT2023 label to a family: {label!r}")


def _download(url: str, dest: Path) -> Path:
    """Download url to dest atomically (plain HTTPS)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    with urllib.request.urlopen(url, timeout=300) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    tmp.replace(dest)
    return dest


HF_MAX_DATASET_BYTES = 2 * 1024**3
HF_USER_AGENT = "idsbench/0.1 (benchmark loader)"


def _hf_request(url: str, method: str = "GET", max_tries: int = 8, timeout: int = 300,
                headers_extra: dict | None = None):
    """Open a HuggingFace URL with plain HTTPS. Retries on HTTP 429/5xx and network errors,
    honouring Retry-After. HF_TOKEN (env) is sent when set."""
    headers = {"User-Agent": HF_USER_AGENT, **(headers_extra or {})}
    token = os.environ.get("HF_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(max_tries):
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as err:
            if err.code in (429, 500, 502, 503, 504) and attempt < max_tries - 1:
                retry_after = err.headers.get("Retry-After") if err.headers else None
                wait = float(retry_after) if retry_after and retry_after.isdigit() else min(
                    300.0, 15.0 * 2 ** attempt)
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError:
            if attempt < max_tries - 1:
                time.sleep(5.0 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"gave up after {max_tries} attempts: {url}")


def _hf_url(repo: str, filename: str) -> str:
    return f"https://huggingface.co/datasets/{repo}/resolve/main/{filename}"


def _hf_size(repo: str, filename: str) -> int:
    """Size in bytes of one file in a HuggingFace dataset repo (HEAD request)."""
    with _hf_request(_hf_url(repo, filename), method="HEAD") as resp:
        return int(resp.headers.get("Content-Length", "0"))


def _hf_list(repo: str) -> list[str]:
    """List file paths of a HuggingFace dataset repo through the public API."""
    with _hf_request(f"https://huggingface.co/api/datasets/{repo}") as resp:
        info = json.loads(resp.read().decode("utf-8"))
    return [s["rfilename"] for s in info.get("siblings", [])]


def _hf_fetch(repo: str, filename: str, root: str | Path) -> Path:
    """Download one file of a HuggingFace dataset repo to root/filename (cached if present)."""
    dest = Path(root) / filename
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    with _hf_request(_hf_url(repo, filename), timeout=600) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh, length=1024 * 1024)
    tmp.replace(dest)
    return dest


def _hf_fetch_prefix(repo: str, filename: str, root: str | Path, nbytes: int) -> Path:
    """Download the first ``nbytes`` of a large CSV (HTTP Range) and cut it at the last newline."""
    dest = Path(root) / f"{filename}.first{nbytes}"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _hf_request(_hf_url(repo, filename), timeout=600,
                     headers_extra={"Range": f"bytes=0-{nbytes - 1}"}) as resp:
        data = resp.read()
    cut = data.rfind(b"\n")
    if cut > 0:
        data = data[:cut + 1]
    dest.write_bytes(data)
    return dest


def _check_budget(repo: str, files: list[str], budget: int = HF_MAX_DATASET_BYTES) -> int:
    """Sum the sizes of files and raise if the total would exceed the per-dataset budget."""
    total = sum(_hf_size(repo, f) for f in files)
    if total > budget:
        raise ValueError(f"{repo}: selected files total {total / 1e9:.2f} GB, "
                         f"above the {budget / 1e9:.0f} GB budget")
    return total


def _read_nslkdd(path: Path, label: str) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path, header=None, names=NSLKDD_COLUMNS, index_col=False)
    raw = df["label"].astype(str).str.strip().str.rstrip(".")
    families = raw.map(map_nslkdd_label)  # raises ValueError on unknown names
    y = families if label == "5class" else families.where(families == NSLKDD_NORMAL, "attack")
    X = df.drop(columns=["label", "difficulty"])
    for col in X.columns:
        if col in NSLKDD_CATEGORICAL:
            X[col] = X[col].astype(str)
        else:
            X[col] = pd.to_numeric(X[col], errors="raise").astype(float)
    return X, pd.Series(y.to_numpy(), name="label")


def load_nslkdd(root: str | Path = "data/nslkdd", label: str = "5class"
                ) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, pd.Series]:
    """Return (X_train, y_train, X_test, y_test) using the official NSL-KDD split.

    Files are downloaded to ``root`` if missing. ``label`` is "5class" (normal/dos/probe/r2l/u2r)
    or "binary" (normal/attack). KDDTest+ contains attack types unseen in KDDTrain+.
    """
    if label not in ("5class", "binary"):
        raise ValueError(f"label must be '5class' or 'binary', got {label!r}")
    root = Path(root)
    parts = {}
    for split, remote in NSLKDD_REMOTE.items():
        local = root / remote.replace("%2B", "+")
        if not local.exists():
            _download(NSLKDD_BASE_URL + remote, local)
        parts[split] = _read_nslkdd(local, label)
    X_tr, y_tr = parts["train"]
    X_te, y_te = parts["test"]
    return X_tr, y_tr, X_te, y_te


def cap_per_class(X: pd.DataFrame, y, cap: int | None, seed: int = 0
                  ) -> tuple[pd.DataFrame, pd.Series]:
    """Randomly subsample each class to at most ``cap`` rows (cap=None keeps everything)."""
    y_arr = np.asarray(y)
    rng = np.random.default_rng(seed)
    keep = []
    for cls in np.unique(y_arr):
        idx = np.flatnonzero(y_arr == cls)
        if cap is not None and len(idx) > cap:
            idx = rng.choice(idx, size=cap, replace=False)
        keep.append(np.sort(idx))
    keep_idx = np.concatenate(keep)
    return X.iloc[keep_idx].reset_index(drop=True), pd.Series(y_arr[keep_idx], name="label")


def _normalise_cic(full: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Keep numeric features plus Label; drop rows with non-finite feature values."""
    feats = [c for c in full.columns if c not in CIC_LABEL_COLUMNS]
    frame = full[feats + ["Label"]].copy()
    for col in feats:
        frame[col] = pd.to_numeric(frame[col], errors="raise").astype(float)
    finite = np.isfinite(frame[feats].to_numpy()).all(axis=1)
    n_bad = int((~finite).sum())
    return frame.loc[finite].reset_index(drop=True), n_bad


def load_ciciot2023(root: str | Path = "data/ciciot2023", n_per_class_cap: int | None = 20000,
                    seed: int = 0, label: str = "8class") -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load CICIoT2023 (HuggingFace mirror MaheshBaja/CIC-IoT-2023, 'random' config).

    The mirror holds the original flow features (39 numeric columns), a 34-way ``Label``
    and an 8-way ``attack_class``. Both parquet files of the 'random' config are fetched
    (about 60 MB) and cached once as ``root/ciciot2023_random_all.parquet``. Each class of
    the requested granularity ("8class", "34class" or "binary") is then capped at
    ``n_per_class_cap`` rows, sampled with ``seed``.

    Returns (X, y, meta). ``meta`` reports row counts, class counts, exact duplicate counts
    (features + label) before and after the cap, and agreement of the prefix-based family
    mapping with the mirror's ``attack_class`` column. There is no official split.
    """
    if label not in ("8class", "34class", "binary"):
        raise ValueError(f"label must be '8class', '34class' or 'binary', got {label!r}")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    cache = root / CIC_CACHE_NAME
    cache_meta = root / "ciciot2023_random_all.json"
    if not cache.exists():
        raw_dir = root / "raw"
        _check_budget(CIC_HF_REPO, CIC_HF_FILES)
        frames = [pd.read_parquet(_hf_fetch(CIC_HF_REPO, f, raw_dir)) for f in CIC_HF_FILES]
        raw = pd.concat(frames, ignore_index=True)
        n_raw = len(raw)
        mirror_family = raw["attack_class"].astype(str)
        frame, n_bad = _normalise_cic(raw)
        frame["attack_class"] = mirror_family.loc[np.isfinite(
            raw[[c for c in raw.columns if c not in CIC_LABEL_COLUMNS]].astype(float).to_numpy()
        ).all(axis=1)].to_numpy()
        frame.to_parquet(cache, index=False)
        cache_meta.write_text(json.dumps({"repo": CIC_HF_REPO, "files": CIC_HF_FILES,
                                          "n_rows_raw": n_raw, "n_nonfinite_dropped": n_bad}))
    full = pd.read_parquet(cache)
    info = json.loads(cache_meta.read_text()) if cache_meta.exists() else {}
    feats = [c for c in full.columns if c not in ("Label", "attack_class")]
    fine = full["Label"].astype(str)
    family = fine.map(ciciot_family)
    mirror_names = full["attack_class"].astype(str).replace({"Web-based": "Web"})
    agreement = float((family.to_numpy() == mirror_names.to_numpy()).mean())
    if label == "8class":
        target = family
    elif label == "34class":
        target = fine
    else:
        target = pd.Series(np.where(family == CIC_NORMAL, CIC_NORMAL, "Attack"))

    dup_full = int(pd.DataFrame({**{c: full[c] for c in feats}, "__y": target.to_numpy()})
                   .duplicated().sum())
    X_sub, y_sub = cap_per_class(full[feats], target, n_per_class_cap, seed=seed)
    dup_sub = int(pd.DataFrame({**{c: X_sub[c] for c in feats}, "__y": y_sub.to_numpy()})
                  .duplicated().sum())
    meta = {
        "source": CIC_HF_REPO,
        "files": CIC_HF_FILES,
        "label": label,
        "n_per_class_cap": n_per_class_cap,
        "seed": seed,
        "n_features": len(feats),
        "n_rows_raw": info.get("n_rows_raw"),
        "n_nonfinite_dropped": info.get("n_nonfinite_dropped"),
        "n_rows_full": int(len(full)),
        "n_rows_returned": int(len(X_sub)),
        "n_exact_duplicates_full": dup_full,
        "n_exact_duplicates_returned": dup_sub,
        "family_agreement_with_mirror": agreement,
        "class_counts": {str(k): int(v) for k, v in y_sub.value_counts().items()},
    }
    return X_sub, y_sub, meta


def make_synthetic(n: int = 5000, n_classes: int = 5,
                   weights: tuple[float, ...] = (0.6, 0.25, 0.1, 0.04, 0.01),
                   seed: int = 0) -> tuple[pd.DataFrame, pd.Series]:
    """Imbalanced synthetic data for tests: 11 numeric columns plus one string column."""
    from sklearn.datasets import make_classification

    X, y = make_classification(
        n_samples=n, n_features=12, n_informative=6, n_redundant=2, n_classes=n_classes,
        weights=list(weights), n_clusters_per_class=1, class_sep=1.0, random_state=seed,
    )
    proto = np.where(X[:, 0] > 0, "tcp", np.where(X[:, 1] > 0, "udp", "icmp"))
    frame = pd.DataFrame(X[:, 1:], columns=[f"f{i}" for i in range(X.shape[1] - 1)])
    frame["proto"] = proto
    return frame, pd.Series(y, name="label")


def _bundle_nslkdd(root: str = "data/nslkdd", label: str = "5class", **_: Any) -> dict:
    X, y, X_te, y_te = load_nslkdd(root=root, label=label)
    return {"X": X, "y": y, "X_test": X_te, "y_test": y_te, "normal_label": "normal",
            "meta": {"source": "defcom17/NSL_KDD (official split)", "label": label,
                     "n_rows_train": len(X), "n_rows_test": len(X_te)}}


def _bundle_ciciot2023(root: str = "data/ciciot2023", label: str = "8class",
                       n_per_class_cap: int | None = 20000, seed: int = 0, **_: Any) -> dict:
    X, y, meta = load_ciciot2023(root=root, n_per_class_cap=n_per_class_cap, seed=seed,
                                 label=label)
    return {"X": X, "y": y, "X_test": None, "y_test": None, "normal_label": CIC_NORMAL,
            "meta": meta}


DATASETS: dict[str, Callable[..., dict]] = {
    "nslkdd": _bundle_nslkdd,
    "ciciot2023": _bundle_ciciot2023,
}


def load_dataset(name: str, **kwargs: Any) -> dict:
    """Load a registered dataset by name. Returns a bundle dict with keys
    X, y, X_test, y_test (None if no official split), normal_label, meta."""
    if name not in DATASETS:
        raise ValueError(f"Unknown dataset {name!r}; choose from {sorted(DATASETS)}")
    return DATASETS[name](**kwargs)


# ---------------------------------------------------------------------------------------------
# Generic flow-dataset engine (CICIDS2017/2018, CICIoMT2024, Edge-IIoT, NetFlow v2/v3)
# ---------------------------------------------------------------------------------------------

LABEL_LIKE_COLUMNS = {"label", "attack", "attack_label", "attack_type", "attack_class", "class"}
LABEL_HEADER_ROWS = {"label", "attack", "attack_type", "attack_label"}  # repeated CSV headers
_IDENT_EXACT = {
    "flow id", "flow_id", "source ip", "src ip", "source_ip", "src_ip", "source port",
    "src port", "source_port", "src_port", "destination ip", "dst ip", "destination_ip",
    "dst_ip", "destination port", "dst port", "destination_port", "dst_port", "src ip dec",
    "dst ip dec", "timestamp", "frame.time", "ip.src", "ip.dst", "ip.src_host", "ip.dst_host",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "ipv4_src_addr",
    "ipv4_dst_addr", "l4_src_port", "l4_dst_port", "flow_start_milliseconds",
    "flow_end_milliseconds", "flow_start", "flow_end",
}
_IDENT_PATTERNS = [re.compile(p) for p in (r"payload", r"file_data", r"full_uri")]


@dataclass(frozen=True)
class _Source:
    """One file of a flow dataset. prefix_bytes: download only the first N bytes (CSV)."""

    filename: str
    fmt: str = "csv"
    prefix_bytes: int | None = None


def _is_identifier(col: Any) -> bool:
    low = str(col).strip().lower()
    return low in _IDENT_EXACT or any(p.search(low) for p in _IDENT_PATTERNS)


def cic17_family(label: str) -> str:
    low = str(label).lower()
    rules = [("benign", "BENIGN"), ("ddos", "DDoS"), ("dos", "DoS"), ("portscan", "PortScan"),
             ("web attack", "WebAttack"), ("patator", "BruteForce"), ("brute", "BruteForce"),
             ("bot", "Bot"), ("infil", "Infiltration"), ("heartbleed", "Heartbleed")]
    return _first_match(low, rules, label)


def cic18_family(label: str) -> str:
    low = str(label).lower()
    rules = [("benign", "BENIGN"), ("ddos", "DDoS"), ("dos", "DoS"), ("bot", "Bot"),
             ("web", "WebAttack"), ("xss", "WebAttack"), ("sql", "WebAttack"),
             ("brute", "BruteForce"), ("ftp", "BruteForce"), ("ssh", "BruteForce"),
             ("infil", "Infiltration"), ("heartbleed", "Heartbleed")]
    return _first_match(low, rules, label)


def ciciomt_family(label: str) -> str:
    """CICIoMT2024 fine label (filename-derived, e.g. 'MQTT-DDoS-Connect_Flood') -> family."""
    low = str(label).lower()
    rules = [("benign", "Benign"), ("ddos", "DDoS"), ("dos", "DoS"), ("recon", "Recon"),
             ("spoof", "Spoofing"), ("mqtt", "MQTT")]
    return _first_match(low, rules, label)


def _first_match(low: str, rules: Sequence[tuple[str, str]], original: Any) -> str:
    for keyword, family in rules:
        if keyword in low:
            return family
    raise ValueError(f"Cannot map label to a family: {original!r}")


def _read_source(repo: str, src: _Source, raw_root: Path) -> pd.DataFrame:
    if src.prefix_bytes is not None:
        path = _hf_fetch_prefix(repo, src.filename, raw_root, src.prefix_bytes)
    else:
        path = _hf_fetch(repo, src.filename, raw_root)
    if src.fmt == "parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def _clean_source(df: pd.DataFrame, fine: pd.Series | None, label_col: str | None,
                  benign_fine: str) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Drop identifiers and label-like columns, coerce numeric, drop inf/NaN rows and header copies."""
    if label_col is not None:
        fine = df[label_col].astype(str).str.strip()
    assert fine is not None
    fine = fine.astype(str).str.strip().reset_index(drop=True)
    keep_cols = [c for c in df.columns if not _is_identifier(c)
                 and str(c).strip().lower() not in LABEL_LIKE_COLUMNS]
    X = pd.DataFrame({c: pd.to_numeric(df[c], errors="coerce").to_numpy(dtype="float64",
                                                                      na_value=np.nan)
                      for c in keep_cols})
    X = X.replace([np.inf, -np.inf], np.nan).dropna(axis=1, how="all")
    header_copy = fine.str.lower().isin(LABEL_HEADER_ROWS)
    ok = X.notna().all(axis=1).to_numpy() & (~header_copy.to_numpy())
    info = {"rows_raw": int(len(df)), "rows_clean": int(ok.sum()),
            "rows_dropped_nan_inf": int((~X.notna().all(axis=1).to_numpy()).sum()),
            "rows_header_copies": int(header_copy.sum())}
    return X.loc[ok].reset_index(drop=True), fine.loc[ok].reset_index(drop=True), info


def _assemble(frames: list[pd.DataFrame], fines: list[pd.Series], family_fn: Callable[[str], str],
              benign_family: str, benign_fine: str, label: str, cap: int | None, seed: int,
              meta: dict) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Concatenate cleaned sources, compute duplicate statistics, then cap per target class."""
    cols = sorted(set.intersection(*[set(f.columns) for f in frames]))
    X_all = pd.concat([f[cols] for f in frames], ignore_index=True)
    y_fine = pd.concat(fines, ignore_index=True).astype(str)
    hashes = pd.util.hash_pandas_object(X_all.assign(__y=y_fine.to_numpy()), index=False)
    n_full = len(X_all)
    n_dup_full = int(n_full - hashes.nunique())
    uniq_fine = pd.unique(y_fine)
    fam_map = {v: family_fn(v) for v in uniq_fine}
    fam = y_fine.map(fam_map)
    meta.update({
        "n_features": len(cols), "features": cols, "n_rows_clean": int(n_full),
        "n_exact_duplicates_full": n_dup_full,
        "duplicate_rate_full": float(n_dup_full / max(n_full, 1)),
        "fine_class_counts_full": {str(k): int(v) for k, v in y_fine.value_counts().items()},
        "family_class_counts_full": {str(k): int(v) for k, v in fam.value_counts().items()},
        "family_mapping": fam_map,
    })
    if label == "family":
        target = fam
        normal = benign_family
    elif label == "fine":
        target = y_fine
        normal = benign_fine
    else:
        target = pd.Series(np.where(y_fine == benign_fine, "benign", "attack"))
        normal = "benign"
    # Cap fine labels first, then the requested granularity (family caps are never smaller).
    X_f, y_f = cap_per_class(X_all, y_fine.to_numpy(), cap, seed=seed)
    fam_f = y_f.map(fam_map)
    tgt_f = fam_f if label == "family" else (y_f if label == "fine" else
                                             pd.Series(np.where(y_f == benign_fine, "benign", "attack")))
    X_out, y_out = cap_per_class(X_f, np.asarray(tgt_f), cap, seed=seed)
    dup_out = int(pd.DataFrame({**{c: X_out[c] for c in cols}, "__y": y_out.to_numpy()})
                  .duplicated().sum())
    meta.update({
        "label": label, "n_per_class_cap": cap, "seed": seed,
        "n_rows_returned": int(len(X_out)), "n_exact_duplicates_returned": dup_out,
        "class_counts": {str(k): int(v) for k, v in y_out.value_counts().items()},
        "normal_label": normal,
    })
    return X_out, y_out, meta


def _build_flow_dataset(repo: str, sources: Sequence[_Source], root: Path, *, label_col: str | None,
                        family_fn: Callable[[str], str], benign_family: str, benign_fine: str,
                        label: str, cap: int | None, seed: int, fine_from_filename: bool = False,
                        extra_meta: dict | None = None) -> tuple[pd.DataFrame, pd.Series, dict]:
    raw_root = root / "raw"
    frames, fines, per_source = [], [], []
    for src in sources:
        df = _read_source(repo, src, raw_root)
        fine_const = None
        if fine_from_filename:
            stem = Path(src.filename).name.split("_train")[0].split("_test")[0]
            fine_const = re.sub(r"\d+$", "", stem)
        fine_series = pd.Series([fine_const] * len(df)) if fine_const is not None else None
        X, y, info = _clean_source(df, fine_series, label_col, benign_fine)
        per_source.append({"file": src.filename, "prefix_bytes": src.prefix_bytes, **info})
        del df
        frames.append(X)
        fines.append(y)
    meta = {"source": repo, "files": [s.filename for s in sources], "per_source": per_source,
            **(extra_meta or {})}
    if not frames or all(len(f) == 0 for f in frames):
        raise RuntimeError(f"{repo}: no usable rows after cleaning")
    return _assemble(frames, fines, family_fn, benign_family, benign_fine, label, cap, seed, meta)


def _check_label_mode(label: str, allowed: Sequence[str]) -> None:
    if label not in allowed:
        raise ValueError(f"label must be one of {list(allowed)}, got {label!r}")


CIC17_REPO = "rdpahalavan/CIC-IDS2017"
CIC17_SOURCES = (_Source("Network-Flows/CICIDS_Flow.parquet", fmt="parquet"),)
CIC18_REPO = "pcy12345BSU/CSE-CIC-IDS-2018"
# Seven day-files (about 1.6 GB) plus the first 100 MB of the 4 GB Tuesday file (about 1.96 GB). Bot, infiltration,
# brute force, web attacks and DoS/DDoS are all represented. Excluded: the rest of the files.
CIC18_SOURCES = (
    _Source("data/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"),
    _Source("data/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"),
    _Source("data/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv", prefix_bytes=100_000_000),
    _Source("data/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"),
    _Source("data/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"),
    _Source("data/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"),
    _Source("data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"),
)
CIOMT_REPO = "somnath0100/CICIoMT2024Small"
CIOMT_BIG = 150_000_000  # files larger than this are read only up to CIOMT_PREFIX bytes
CIOMT_PREFIX = 100_000_000
EDGE_REPO = "RonaldoMPF/Edge-IIoTset"
EDGE_SOURCES = (_Source("train.csv"), _Source("test.csv"))
NF_FALLBACK_REPO = "Nora9029/NF-ToN-IoT-v2"
NF_FALLBACK_FILES = ("NF-ToN-IoT-v2-test.csv",)  # train file (2.1 GB) would exceed the budget
NF_V3_REPO = "keys-i/netFlow-v3"
NETFLOW_NAMES = ("NF-ToN-IoT-v3", "NF-UNSW-NB15-v3", "NF-CICIDS2018-v3", "NF-ToN-IoT-v2")


def load_cicids2017(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                    root: str | Path = "data/cicids2017") -> tuple[pd.DataFrame, pd.Series, dict]:
    """CICIDS2017 flows (rdpahalavan/CIC-IDS2017, one parquet, 2.83M rows).

    label: "family" (BENIGN, DoS, DDoS, PortScan, Bot, WebAttack, BruteForce, Infiltration,
    Heartbleed), "fine" (15 original labels) or "binary". Identifier columns are dropped.
    """
    _check_label_mode(label, ("family", "fine", "binary"))
    root = Path(root)
    _check_budget(CIC17_REPO, [s.filename for s in CIC17_SOURCES])
    return _build_flow_dataset(
        CIC17_REPO, CIC17_SOURCES, root, label_col="attack_label", family_fn=cic17_family,
        benign_family="BENIGN", benign_fine="BENIGN", label=label, cap=n_per_class_cap, seed=seed)


def load_cicids2018(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                    root: str | Path = "data/cicids2018") -> tuple[pd.DataFrame, pd.Series, dict]:
    """CSE-CIC-IDS2018 CICFlowMeter CSVs (pcy12345BSU/CSE-CIC-IDS-2018), a subset of days.

    Only the day-files listed in CIC18_SOURCES are downloaded (about 2 GB budget). Repeated
    header rows inside the CSVs are removed. label as for load_cicids2017.
    """
    _check_label_mode(label, ("family", "fine", "binary"))
    root = Path(root)
    total = 0
    for src in CIC18_SOURCES:
        if src.prefix_bytes is None:
            total += _hf_size(CIC18_REPO, src.filename)
        else:
            total += src.prefix_bytes
    if total > HF_MAX_DATASET_BYTES:
        raise ValueError(f"CIC18 selection totals {total / 1e9:.2f} GB, over the 2 GB budget")
    return _build_flow_dataset(
        CIC18_REPO, CIC18_SOURCES, root, label_col="Label", family_fn=cic18_family,
        benign_family="BENIGN", benign_fine="Benign", label=label, cap=n_per_class_cap, seed=seed,
        extra_meta={"bytes_budget_used": int(total)})


def _ciciomt_group(filename: str) -> str:
    """Fine label of a CICIoMT2024 file: stem before '_train'/'_test', without split digits."""
    stem = Path(filename).name.split("_train")[0].split("_test")[0]
    return re.sub(r"\d+$", "", stem)


def _ciciomt_sources() -> list[_Source]:
    """Enumerate CICIoMT2024 CSVs. Small files are read whole. For an attack group that has
    files above CIOMT_BIG, only its first file is read, up to CIOMT_PREFIX bytes."""
    with _hf_request(f"https://huggingface.co/api/datasets/{CIOMT_REPO}/tree/main/CSVS") as resp:
        tree = json.loads(resp.read().decode("utf-8"))
    files = sorted((i for i in tree if i.get("type") == "file" and i["path"].endswith(".csv")),
                   key=lambda x: x["path"])
    groups: dict[str, list[dict]] = {}
    for item in files:
        groups.setdefault(_ciciomt_group(item["path"]), []).append(item)
    sources = []
    for members in groups.values():
        if any(int(m.get("size", 0)) > CIOMT_BIG for m in members):
            sources.append(_Source(members[0]["path"], prefix_bytes=CIOMT_PREFIX))
        else:
            sources.extend(_Source(m["path"]) for m in members)
    return sources


def load_ciciomt2024(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                     root: str | Path = "data/ciciomt2024") -> tuple[pd.DataFrame, pd.Series, dict]:
    """CICIoMT2024 flow CSVs (somnath0100/CICIoMT2024Small). Fine labels come from file names.

    The full mirror is 16.7 GB. For each attack group whose files exceed 150 MB only the first
    file is read, up to its first 100 MB; meta['per_source'] records the bytes read per file. Families: Benign, DDoS, DoS, Recon, Spoofing, MQTT. MQTT-DDoS and
    MQTT-DoS are grouped with DDoS and DoS by keyword.
    """
    _check_label_mode(label, ("family", "fine", "binary"))
    root = Path(root)
    sources = _ciciomt_sources()
    planned = sum(s.prefix_bytes if s.prefix_bytes else _hf_size(CIOMT_REPO, s.filename)
                  for s in sources)
    if planned > HF_MAX_DATASET_BYTES:
        raise ValueError(f"CICIoMT2024 plan totals {planned / 1e9:.2f} GB, over the 2 GB budget")
    return _build_flow_dataset(
        CIOMT_REPO, sources, root, label_col=None, family_fn=ciciomt_family,
        benign_family="Benign", benign_fine="Benign", label=label, cap=n_per_class_cap, seed=seed,
        fine_from_filename=True, extra_meta={"bytes_budget_used": int(planned)})


def load_edgeiiot(label: str = "fine", n_per_class_cap: int | None = 20000, seed: int = 0,
                  root: str | Path = "data/edgeiiot") -> tuple[pd.DataFrame, pd.Series, dict]:
    """Edge-IIoTset (RonaldoMPF/Edge-IIoTset, processed train/test CSVs).

    label: "fine" (Attack_type, 15 classes, default) or "binary" (Normal vs attack).
    Attack_label and Attack_type are removed from the features; identifier and payload-text
    columns are dropped when present.
    """
    _check_label_mode(label, ("fine", "binary"))
    root = Path(root)
    _check_budget(EDGE_REPO, [s.filename for s in EDGE_SOURCES])
    return _build_flow_dataset(
        EDGE_REPO, EDGE_SOURCES, root, label_col="Attack_type", family_fn=lambda x: x,
        benign_family="Normal", benign_fine="Normal", label=label if label == "binary" else "fine",
        cap=n_per_class_cap, seed=seed)


def _resolve_netflow(name: str) -> tuple[str, list[_Source], str]:
    """Find NetFlow files for ``name``: keys-i/netFlow-v3 first, then the documented fallback."""
    if name not in NETFLOW_NAMES:
        raise ValueError(f"Unknown NetFlow dataset {name!r}; choose from {NETFLOW_NAMES}")
    try:
        files = _hf_list(NF_V3_REPO)
    except (urllib.error.URLError, RuntimeError, ValueError):
        files = []
    matches = [f for f in files if f.lower().endswith((".csv", ".parquet"))
               and name.lower() in f.lower()]
    if matches:
        return NF_V3_REPO, [_Source(f, fmt="parquet" if f.endswith(".parquet") else "csv")
                            for f in matches], f"{NF_V3_REPO} ({len(matches)} files)"
    if name in ("NF-ToN-IoT-v3", "NF-ToN-IoT-v2"):
        note = ("keys-i/netFlow-v3 has no data files; fell back to the NF-ToN-IoT-v2 mirror "
                f"{NF_FALLBACK_REPO} (NetFlow v2 schema, same ToN-IoT traffic)")
        return NF_FALLBACK_REPO, [_Source(f) for f in NF_FALLBACK_FILES], note
    raise ValueError(
        f"No mirror found for {name}: {NF_V3_REPO} is empty on the HF hub and no other "
        f"{name} copy was found by search. Only NF-ToN-IoT (v2 fallback) can be loaded.")


def load_netflow_v3(dataset: str = "NF-ToN-IoT-v3", label: str = "fine",
                    n_per_class_cap: int | None = 20000, seed: int = 0,
                    root: str | Path = "data/netflow") -> tuple[pd.DataFrame, pd.Series, dict]:
    """NetFlow datasets with the shared NetFlow feature schema.

    dataset: one of NF-ToN-IoT-v3, NF-UNSW-NB15-v3, NF-CICIDS2018-v3 (or NF-ToN-IoT-v2).
    label: "fine" (the 'Attack' column, default) or "binary" (benign vs attack).
    IPV4_SRC/DST_ADDR, L4 ports and flow start/end timestamps are dropped.
    """
    _check_label_mode(label, ("fine", "binary"))
    root = Path(root)
    repo, sources, note = _resolve_netflow(dataset)
    _check_budget(repo, [s.filename for s in sources])
    return _build_flow_dataset(
        repo, sources, root, label_col="Attack", family_fn=lambda x: x,
        benign_family="Benign", benign_fine="Benign", label=label, cap=n_per_class_cap, seed=seed,
        extra_meta={"dataset": dataset, "mirror_note": note})


def _bundle_flow(X: pd.DataFrame, y: pd.Series, meta: dict) -> dict:
    return {"X": X, "y": y, "X_test": None, "y_test": None,
            "normal_label": meta.pop("normal_label"), "meta": meta}


def _bundle_cicids2017(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                       root: str = "data/cicids2017", **_: Any) -> dict:
    return _bundle_flow(*load_cicids2017(label, n_per_class_cap, seed, root))


def _bundle_cicids2018(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                       root: str = "data/cicids2018", **_: Any) -> dict:
    return _bundle_flow(*load_cicids2018(label, n_per_class_cap, seed, root))


def _bundle_ciciomt2024(label: str = "family", n_per_class_cap: int | None = 20000, seed: int = 0,
                        root: str = "data/ciciomt2024", **_: Any) -> dict:
    return _bundle_flow(*load_ciciomt2024(label, n_per_class_cap, seed, root))


def _bundle_edgeiiot(label: str = "fine", n_per_class_cap: int | None = 20000, seed: int = 0,
                     root: str = "data/edgeiiot", **_: Any) -> dict:
    return _bundle_flow(*load_edgeiiot(label, n_per_class_cap, seed, root))


def _bundle_netflow(dataset: str = "NF-ToN-IoT-v3", label: str = "fine",
                    n_per_class_cap: int | None = 20000, seed: int = 0,
                    root: str = "data/netflow", **_: Any) -> dict:
    return _bundle_flow(*load_netflow_v3(dataset, label, n_per_class_cap, seed, root))


DATASETS.update({
    "cicids2017": _bundle_cicids2017,
    "cicids2018": _bundle_cicids2018,
    "ciciomt2024": _bundle_ciciomt2024,
    "edgeiiot": _bundle_edgeiiot,
    "netflow_v3": _bundle_netflow,
})
