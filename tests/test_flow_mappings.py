from idsbench.data import (
    DATASETS, _is_identifier, cic17_family, cic18_family, ciciomt_family, _ciciomt_group,
)


def test_cicids2017_families():
    assert cic17_family("BENIGN") == "BENIGN"
    assert cic17_family("DoS Hulk") == "DoS"
    assert cic17_family("DoS slowloris") == "DoS"
    assert cic17_family("DDoS") == "DDoS"
    assert cic17_family("PortScan") == "PortScan"
    assert cic17_family("FTP-Patator") == "BruteForce"
    assert cic17_family("SSH-Patator") == "BruteForce"
    assert cic17_family("Web Attack – Brute Force") == "WebAttack"
    assert cic17_family("Web Attack – Sql Injection") == "WebAttack"
    assert cic17_family("Infiltration") == "Infiltration"
    assert cic17_family("Heartbleed") == "Heartbleed"


def test_cicids2018_families():
    assert cic18_family("Benign") == "BENIGN"
    assert cic18_family("DDOS attack-HOIC") == "DDoS"
    assert cic18_family("DoS attacks-Hulk") == "DoS"
    assert cic18_family("Bot") == "Bot"
    assert cic18_family("Brute Force -Web") == "WebAttack"
    assert cic18_family("Brute Force -XSS") == "WebAttack"
    assert cic18_family("SQL Injection") == "WebAttack"
    assert cic18_family("FTP-BruteForce") == "BruteForce"
    assert cic18_family("SSH-Bruteforce") == "BruteForce"
    assert cic18_family("Infilteration") == "Infiltration"


def test_ciciomt_families_and_groups():
    assert ciciomt_family("Benign") == "Benign"
    assert ciciomt_family("MQTT-DDoS-Connect_Flood") == "DDoS"
    assert ciciomt_family("TCP_IP-DoS-SYN") == "DoS"
    assert ciciomt_family("Recon-Port_Scan") == "Recon"
    assert ciciomt_family("ARP_Spoofing") == "Spoofing"
    assert ciciomt_family("MQTT-Malformed_Data") == "MQTT"
    assert _ciciomt_group("CSVS/TCP_IP-DDoS-SYN3_train.pcap_Flow.csv") == "TCP_IP-DDoS-SYN"


def test_identifier_columns_detected():
    for col in ["Flow ID", "Src IP", "Dst Port", "Timestamp", "source_ip", "destination_port",
                "ip.src_host", "tcp.payload", "http.file_data"]:
        assert _is_identifier(col), col
    for col in ["Flow Duration", "Init_Win_bytes_forward", "udp.time_delta", "Protocol"]:
        assert not _is_identifier(col), col


def test_registry_has_all_loaders():
    for name in ["nslkdd", "ciciot2023", "cicids2017", "cicids2018", "ciciomt2024",
                 "edgeiiot", "netflow_v3"]:
        assert name in DATASETS
