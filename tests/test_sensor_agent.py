import gzip
import ipaddress
import json

import pytest
from scapy.layers.inet import TCP
from scapy.utils import wrpcap
from test_sensor_flows import CLIENT, SERVER, handshake, pkt

from sensor.agent import MAX_FLOWS, Sender, Windower, decode, make_batch, run_pcap
from sensor.flows import Packet, from_scapy

NOW = 1_800_000_000.0


class Transport:
    def __init__(self, *statuses):
        self.statuses, self.sent = list(statuses), []

    def __call__(self, url, headers, body):
        status = self.statuses.pop(0) if self.statuses else 200
        if status is None:
            raise OSError("الشبكة منقطعة")
        if status < 300:
            self.sent.append((url, headers, decode(body)))
        return status


def batch(start, n=1):
    return make_batch(start, [{"src": CLIENT, "dst": SERVER, "sport": 1, "dport": 22, "proto": 6,
                               "start": start, "end": start + 1, "f": [0.0] * 77}] * n, host="web-1")


def test_windows_follow_packet_time_and_platform_traffic_is_excluded():
    out = []
    w = Windower(lambda s, rows: out.append((s, rows)), exclude={("10.9.9.9", 8001)})
    for p in handshake(t0=NOW + 5) + handshake(t0=NOW + 65, sport=40001):
        w.add(from_scapy(p))
    w.add(Packet(NOW + 66, CLIENT, "10.9.9.9", 50000, 8001, 6, 60, 0, 20))   # اتصال الوكيل بالمنصة
    w.close()
    assert [(s, len(rows)) for s, rows in out] == [(NOW, 1), (NOW + 60, 1)]


def test_live_tick_emits_empty_windows_as_heartbeat():
    out = []
    w = Windower(lambda s, rows: out.append((s, rows)), start=NOW)
    w.tick(NOW + 30)
    w.tick(NOW + 61)
    w.tick(NOW + 125)
    assert out == [(NOW, []), (NOW + 60, [])]


def test_batch_caps_flows_and_marks_truncated():
    b = batch(NOW, MAX_FLOWS + 7)
    assert len(b["flows"]) == MAX_FLOWS and b["truncated"] is True
    assert b["window_start"] == NOW and b["window_end"] == NOW + 60 and b["agent"]["host"] == "web-1"
    assert batch(NOW)["truncated"] is False


def test_failed_sends_are_buffered_and_resent_in_order(tmp_path):
    t = Transport(None, 503)
    s = Sender("http://p", "pc_ing_x", tmp_path, transport=t, clock=lambda: NOW + 200)
    s.send(batch(NOW))            # انقطاع
    s.send(batch(NOW + 60))       # 503 على الأقدم، فيبقى الاثنان
    assert t.sent == [] and len(list(tmp_path.iterdir())) == 2
    s.send(batch(NOW + 120))
    assert [b["window_start"] for _, _, b in t.sent] == [NOW, NOW + 60, NOW + 120]
    url, headers, _ = t.sent[0]
    assert url == "http://p/api/v1/ingest/flows" and headers["Authorization"] == "Bearer pc_ing_x"
    assert headers["Content-Encoding"] == "gzip" and list(tmp_path.iterdir()) == []


def test_rejected_batches_are_dropped_but_auth_errors_keep_them(tmp_path):
    t = Transport(422, 401)
    s = Sender("http://p", "k", tmp_path, transport=t, clock=lambda: NOW)
    s.send(batch(NOW))            # معطوبة: لن تنجح بإعادتها
    assert list(tmp_path.iterdir()) == []
    s.send(batch(NOW + 60))       # مفتاح خاطئ: تبقى حتى يُصحّح
    assert len(list(tmp_path.iterdir())) == 1


def test_buffer_drops_old_and_oversized(tmp_path):
    s = Sender("http://p", "k", tmp_path, transport=Transport(*[None] * 10), clock=lambda: NOW, max_bytes=10**9)
    s.send(batch(NOW - 2 * 86400))
    s.send(batch(NOW))
    assert len(list(tmp_path.iterdir())) == 1          # أقدم من 24 ساعة
    s.max_bytes = 1
    s.send(batch(NOW + 60))
    assert len(list(tmp_path.iterdir())) == 1          # يبقى الأحدث فقط


def test_pcap_replays_ending_now(tmp_path):
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), handshake(t0=1000.0) + handshake(t0=1100.0, sport=40001))
    sent = []
    run_pcap(str(path), sent.append, host="web-1", now=NOW)
    assert len(sent) == 2 and all(len(b["flows"]) == 1 for b in sent)
    assert sent[-1]["flows"][0]["end"] == pytest.approx(NOW)
    assert sent[1]["window_start"] - sent[0]["window_start"] == 60   # 1000 و1100 بعد الإزاحة: نافذتان متتاليتان


def test_simulator_builds_valid_batches_with_public_attackers(data):
    import numpy as np
    from simulate_flows import ATTACKERS, SERVER as SIM_SERVER, generate
    act, _ = data
    batches = generate(act, minutes=6, start=NOW, rng=np.random.default_rng(1), attack="PortScan", attack_at=2)
    assert len(batches) == 6 and [b["window_start"] for b in batches] == [NOW + 60 * i for i in range(6)]
    flows = [f for b in batches for f in b["flows"]]
    assert all(f["dst"] == SIM_SERVER and len(f["f"]) == 77 for f in flows)
    attackers = {f["src"] for b in batches[2:] for f in b["flows"]} & set(ATTACKERS.values())
    assert attackers and all(ipaddress.ip_address(ip).is_global for ip in attackers)
    assert not {f["src"] for b in batches[:2] for f in b["flows"]} & set(ATTACKERS.values())
    assert all(b["window_start"] <= f["start"] <= f["end"] <= b["window_end"] for b in batches for f in b["flows"])
