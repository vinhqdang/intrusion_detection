"""Population view and leakage-safe dedup of the packet study (design v2, section 5 and 3)."""

import numpy as np

from idsbench.feasibility.common import clean_pool
from idsbench.pcap.evaluate import dedup_indices, select_view


def test_dedup_matches_the_feasibility_pool_cleaning_counts():
    import pandas as pd

    rng = np.random.default_rng(4)
    base = rng.normal(size=(60, 5))
    X = np.vstack([base, base[:20], base[10:15] + 0.0])          # exact copies
    fam = np.array(["Benign"] * 60 + ["Bot"] * 20 + ["PortScan"] * 5, dtype=object)
    fam[60 + 3] = "Bot"                                          # copy of a benign vector with an attack label
    X[65] = base[3]
    keep, per = dedup_indices(X, fam)
    _, _, counts = clean_pool(pd.DataFrame(X), fam)
    assert len(keep) == counts["n_rows_clean"]
    total_dup = sum(v["exact_duplicates"] for v in per.values())
    assert total_dup == counts["n_exact_duplicates"]
    assert sum(v["label_conflicts"] for v in per.values()) == counts["n_conflict"]
    assert sum(v["feature_duplicates"] for v in per.values()) == counts["n_feature_duplicates"]


def test_population_view_keeps_connection_flows_only_and_uses_the_chosen_rule():
    cache = {
        "X": np.arange(24, dtype=float).reshape(6, 4) + 1.0,
        "label": np.array([0, 1, 0, 5, 2, 0]),
        "label_drop": np.array([0, 1, -2, 5, 2, 0]),
        "connection": np.array([True, True, False, True, False, True]),
        "pool_row": np.array([0, 1, 2, 3, 4, 5]),
    }
    view, X, lab, dedup = select_view(cache, "connection", "primary")
    assert lab.tolist() == [0, 1, 5, 0]                # rows 0, 1, 3, 5
    view_all, X_all, lab_all, _ = select_view(cache, "all", "drop")
    assert lab_all.tolist() == [0, 1, 5, 2, 0]         # row 2 (ambiguous under the drop rule) removed
    assert view["pool_row"].tolist() == [0, 1, 3, 5]
