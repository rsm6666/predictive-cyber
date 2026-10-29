import json

import numpy as np
import pytest

from ingest.store import LogStore
from netdetect.detect import process_flows
from netdetect.store import NetStore
from netdetect.validate import validate
from sensor.agent import make_batch
from simulate_flows import ATTACKERS, SERVER, generate

NOW = 1_800_000_000.0


@pytest.fixture
def stores(tmp_path):
    path = tmp_path / "tenant.db"
    return NetStore(path), LogStore(path)


def feed(stores, resources, batches):
    net, logs = stores
    out = []
    for b in batches:
        b = validate(json.dumps(b), now=b["window_end"])      # كما تصل المنصة
        out.append(process_flows(net, logs, resources, b, received_at=b["window_end"]))
    return out


def replay(data, attack=None, minutes=8, seed=1, at=4):
    act, _ = data
    return generate(act, minutes, NOW, np.random.default_rng(seed), attack=attack, attack_at=at, attack_minutes=2)


def incident_types(logs):
    return {i["id"]: (i["kind"], sorted({a["type"] for a in logs.alerts(i["id"])})) for i in logs.incidents()}


def test_benign_replay_opens_nothing(stores, resources, data):
    out = feed(stores, resources, replay(data, minutes=12))
    assert sum(o["alerts"] for o in out) == 0 and stores[1].incidents() == []


@pytest.mark.parametrize("attack,expected", [("PortScan", "net_scan"), ("DoS", "net_model")])
def test_attack_replay_opens_one_network_incident(stores, resources, data, attack, expected):
    feed(stores, resources, replay(data, attack=attack))
    [(kind, types)] = incident_types(stores[1]).values()
    assert kind == "network" and expected in types
    alert = next(a for a in stores[1].alerts(stores[1].incidents()[0]["id"]) if a["type"] == expected)
    assert alert["ip"] == ATTACKERS[attack] and alert["details"]["model"]["verdict"] != "BENIGN"


def test_source_under_evidence_gate_is_not_a_model_alert(stores, resources, data):
    act, _ = data
    batches = replay(data, minutes=1)
    dos = act[act["family"] == "DoS"].head(10)            # أقل من 20 تدفقًا
    from simulate_flows import _flows
    batches[0]["flows"] += _flows(dos, ["185.220.101.99"] * len(dos), NOW, np.random.default_rng(2))
    feed(stores, resources, batches)
    assert stores[1].incidents() == []


def test_ddos_needs_volume_above_baseline(stores, resources, data):
    batches = replay(data, minutes=6)
    surge = replay(data, minutes=8, seed=9)[1:]            # نافذة سابعة فيها أضعاف الترافيك من مئات المصادر
    big = make_batch(NOW + 6 * 60, [dict(f, start=f["start"] - (f["start"] // 60 * 60) + NOW + 360,
                                         end=NOW + 360 + 1) for b in surge for f in b["flows"]], host="demo-server")
    out = feed(stores, resources, batches + [big])
    assert sum(o["alerts"] for o in out[:-1]) == 0
    kinds = incident_types(stores[1])
    assert any("net_ddos" in types for _, types in kinds.values())
    ddos = next(a for i in stores[1].incidents() for a in stores[1].alerts(i["id"]) if a["type"] == "net_ddos")
    assert ddos["ip"] == SERVER and ddos["severity"] == "critical"


def test_network_alerts_do_not_join_log_incidents(stores, resources, data):
    _, logs = stores
    _, log_incident, _ = logs.add_alert({"type": "brute_force", "source": "web", "ip": "185.220.101.7",
                                         "first_ts": NOW + 200, "last_ts": NOW + 200, "count": 30,
                                         "severity": "high", "evidence": [], "details": {}})
    feed(stores, resources, replay(data, attack="PortScan"))
    kinds = incident_types(logs)
    assert kinds[log_incident] == ("log", ["brute_force"])
    assert sorted(k for k, _ in kinds.values()) == ["log", "network"]


def test_resent_window_is_ignored_and_status_reports_agent(stores, resources, data):
    net, _ = stores
    batches = replay(data, minutes=2)
    out = feed(stores, resources, batches + batches[:1])
    assert out[-1]["duplicate"] and len(net.flows_between(NOW, NOW + 120)) == sum(len(b["flows"]) for b in batches)
    status = net.status(now=NOW + 150)
    assert status["state"] == "connected" and status["windows"] == 2 and status["flows_per_minute"] == 200
    assert net.status(now=NOW + 120 + 4 * 60)["state"] == "offline"
    w = net.windows(until=NOW + 60)
    assert list(w["total_flows"]) == [200.0, 200.0] and w["unique_src_ips"].iloc[0] > 150
