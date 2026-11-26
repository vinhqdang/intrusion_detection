from idsbench.feasibility.e3_crosspair import CIC_2018_TO_2017, canonical_name, is_excluded, match_columns


def test_canonicalisation_maps_2018_abbreviations_onto_2017_names():
    assert canonical_name("Tot Fwd Pkts", CIC_2018_TO_2017) == "total fwd packets"
    assert canonical_name("  Fwd Pkt Len Max ", CIC_2018_TO_2017) == "fwd packet length max"
    assert canonical_name("Destination Port") == "destination port"
    rep = match_columns(
        ["Total Fwd Packets", "Fwd Packet Length Max", "Destination Port", "Protocol", "Flow ID"],
        ["Tot Fwd Pkts", "Fwd Pkt Len Max", "Dst Port", "Protocol", "Flow ID"],
        None, CIC_2018_TO_2017,
    )
    assert rep["matched"] == ["fwd packet length max", "total fwd packets"]
    assert rep["unmatched_a"] == [] and rep["unmatched_b"] == []
    assert "protocol" in rep["excluded"] and "destination port" in rep["excluded"]
    assert is_excluded("flow id") and is_excluded("timestamp") and not is_excluded("flow duration")
