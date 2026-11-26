import numpy as np
from scipy import stats as sps

from idsbench.data import ciciot_family, map_nslkdd_label
from idsbench.metrics import compute_metrics
from idsbench.stats import bootstrap_ci, friedman_nemenyi, min_wilcoxon_p


def test_fpr_fnr_hand_example():
    # normal = 0. Normal rows 0..3 predict 0,1,0,0 -> FPR 1/4.
    # Attack rows 4..7 predict 0,1,2,2 -> predicted normal 1 of 4 -> FNR 1/4.
    y_true = [0, 0, 0, 0, 1, 1, 1, 2]
    y_pred = [0, 1, 0, 0, 0, 1, 2, 2]
    m = compute_metrics(y_true, y_pred, labels=[0, 1, 2], normal_label=0)
    assert m["fpr"] == 0.25
    assert m["fnr"] == 0.25
    assert m["confusion"] == [[3, 1, 0], [1, 1, 1], [0, 0, 1]]
    assert m["per_class"]["1"]["support"] == 3


def test_min_wilcoxon_p_five_seeds():
    assert min_wilcoxon_p(5) == 0.0625
    res = sps.wilcoxon([1, 2, 3, 4, 5], [0, 0, 0, 0, 0])
    assert abs(res.pvalue - min_wilcoxon_p(5)) < 1e-12


def test_friedman_nemenyi_runs():
    rng = np.random.default_rng(0)
    M = rng.random((5, 3)) + np.array([0.0, 0.1, 0.9])
    out = friedman_nemenyi(M, ["a", "b", "c"])
    assert out["average_ranks"]["c"] < out["average_ranks"]["a"]
    assert out["critical_difference"] > 0


def test_bootstrap_ci_brackets_point():
    y = np.array([0, 1] * 50)
    p = y.copy()
    p[:5] = 1 - p[:5]
    from sklearn.metrics import accuracy_score
    point, lo, hi = bootstrap_ci(y, p, accuracy_score, n=200, seed=0)
    assert lo <= point <= hi


def test_label_mappings():
    assert map_nslkdd_label("ps") == "u2r"
    assert map_nslkdd_label("apache2") == "dos"
    assert map_nslkdd_label("mscan") == "probe"
    assert map_nslkdd_label("snmpguess") == "r2l"
    try:
        map_nslkdd_label("not_an_attack")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert ciciot_family("DDoS-SYN_Flood") == "DDoS"
    assert ciciot_family("DoS-UDP_Flood") == "DoS"
    assert ciciot_family("Mirai-greip_flood") == "Mirai"
    assert ciciot_family("VulnerabilityScan") == "Recon"
    assert ciciot_family("DictionaryBruteForce") == "BruteForce"
    assert ciciot_family("SqlInjection") == "Web"
    assert ciciot_family("BenignTraffic") == "Benign"
