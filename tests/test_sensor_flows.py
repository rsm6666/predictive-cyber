import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from sensor.flows import FEATURES, FlowTable, from_scapy

CLIENT, SERVER = "203.0.114.9", "198.51.100.20"


def pkt(layer, ts, src=CLIENT, dst=SERVER, payload=b""):
    p = Ether() / IP(src=src, dst=dst) / layer
    if payload:
        p = p / Raw(payload)
    p = Ether(bytes(p))      # يحسب الأطوال كما تُلتقط فعلًا
    p.time = ts
    return p


def handshake(t0=100.0, sport=40000, dport=22):
    return [
        pkt(TCP(sport=sport, dport=dport, flags="S", window=64240), t0),
        pkt(TCP(sport=dport, dport=sport, flags="SA", window=65160), t0 + 0.01, src=SERVER, dst=CLIENT),
        pkt(TCP(sport=sport, dport=dport, flags="A", window=502), t0 + 0.02),
        pkt(TCP(sport=sport, dport=dport, flags="PA", window=502), t0 + 0.03, payload=b"x" * 100),
        pkt(TCP(sport=dport, dport=sport, flags="FA", window=509), t0 + 0.05, src=SERVER, dst=CLIENT),
    ]


def table(packets):
    t = FlowTable()
    for p in packets:
        t.add(from_scapy(p))
    return t.rows()


def feat(row, name):
    return row["f"][FEATURES.index(name)]


def test_tcp_handshake_is_one_flow_with_cicids_semantics():
    [row] = table(handshake())
    assert (row["src"], row["dst"], row["sport"], row["dport"], row["proto"]) == (CLIENT, SERVER, 40000, 22, 6)
    assert row["start"] == pytest.approx(100.0) and row["end"] == pytest.approx(100.05)
    assert len(row["f"]) == len(FEATURES) == 77
    assert feat(row, "Total Fwd Packets") == 3 and feat(row, "Total Backward Packets") == 2
    assert feat(row, "Flow Duration") == pytest.approx(50_000)          # ميكروثانية
    assert feat(row, "SYN Flag Count") == 2 and feat(row, "FIN Flag Count") == 1 and feat(row, "PSH Flag Count") == 1
    assert feat(row, "Fwd Header Length") == 60 and feat(row, "Bwd Header Length") == 40   # TCP فقط: 20 لكل حزمة
    assert feat(row, "min_seg_size_forward") == 20 and feat(row, "act_data_pkt_fwd") == 1
    assert feat(row, "Init_Win_bytes_forward") == 64240 and feat(row, "Init_Win_bytes_backward") == 65160
    assert feat(row, "Fwd Packet Length Max") == 154        # 14 + 20 + 20 + 100 كما في live_capture


def test_udp_icmp_and_distinct_ports_are_separate_flows():
    rows = table(handshake(sport=40000) + handshake(sport=40001, dport=443) + [
        pkt(UDP(sport=5353, dport=53), 101.0, payload=b"q" * 30),
        pkt(ICMP(), 102.0), pkt(ICMP(), 102.5)])
    by = {(r["proto"], r["dport"]): r for r in rows}
    assert set(by) == {(6, 22), (6, 443), (17, 53), (1, 0)}
    assert feat(by[(17, 53)], "Fwd Header Length") == 8 and feat(by[(17, 53)], "act_data_pkt_fwd") == 1
    assert feat(by[(1, 0)], "Total Fwd Packets") == 2 and feat(by[(1, 0)], "Fwd Header Length") == 0


def test_non_ip_packets_are_ignored():
    assert from_scapy(Ether() / Raw(b"arp-ish")) is None


def test_live_capture_wrapper_keeps_its_columns_for_existing_tools(tmp_path):
    """behavioral_detector وlive_monitor وcapture_helper تقرأ هذه الأعمدة من live_capture."""
    from scapy.utils import wrpcap
    import live_capture
    packets = handshake() + [pkt(UDP(sport=5000, dport=53), 101.0, payload=b"q")]
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), packets)
    df = live_capture.flows_to_df(live_capture.build_flows(str(path)))
    assert len(df) == 2 and list(df.columns[:77]) == FEATURES
    assert sorted(zip(df["_src"], df["_dst"], df["_dport"], df["_proto"])) == [
        (CLIENT, SERVER, 22, 6), (CLIENT, SERVER, 53, 17)]
    tcp = df[df["_proto"] == 6].iloc[0]
    assert tcp["Fwd Header Length"] == 60 and tcp["act_data_pkt_fwd"] == 1
