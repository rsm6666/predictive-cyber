from collections import defaultdict
from datetime import datetime, timezone

import numpy as np
import pytest

from ingest.parsers import parse_firewall, parse_web
from ingest.pipeline import process_batch
from ingest.store import LogStore
from simulate_logs import ATTACKS, EXPECTED_RULE, generate

T0 = datetime(2026, 10, 26, 18, 0, tzinfo=timezone.utc).timestamp()


def alerts_by_ip(store):
    out = defaultdict(set)
    for inc in store.incidents():
        for a in store.alerts(inc["id"]):
            out[a["ip"]].add(a["type"])
    return out


def feed(store, web, fw):
    process_batch(store, None, "web", "\n".join(web), year=2026)
    process_batch(store, None, "firewall", "\n".join(fw), year=2026)


def test_same_seed_same_logs():
    a = generate(T0, 20, np.random.default_rng(3), attacks=ATTACKS)
    b = generate(T0, 20, np.random.default_rng(3), attacks=ATTACKS)
    assert a == b


def test_all_lines_parse():
    web, fw, _ = generate(T0, 30, np.random.default_rng(1), attacks=ATTACKS)
    assert len(web) > 500 and len(fw) > 100
    assert all(parse_web(line) for line in web)
    assert all(parse_firewall(line, 2026) for line in fw)


@pytest.mark.parametrize("attack", [a for a in ATTACKS if EXPECTED_RULE[a] != "anomaly"])
def test_each_attack_triggers_its_rule(tmp_path, attack):
    web, fw, labels = generate(T0, 30, np.random.default_rng(2), attacks=(attack,))
    store = LogStore(tmp_path / "tenant.db")
    feed(store, web, fw)
    assert EXPECTED_RULE[attack] in alerts_by_ip(store)[labels[attack]]


def test_clean_hour_has_no_rule_alerts(tmp_path):
    web, fw, labels = generate(T0, 60, np.random.default_rng(4))
    store = LogStore(tmp_path / "tenant.db")
    feed(store, web, fw)
    assert labels == {} and alerts_by_ip(store) == {}


def test_campaign_simulator_builds_linked_stages_and_a_decoy(data):
    import simulate_campaign as sc
    act, _ = data
    now = T0 + 3 * 86400
    plan = sc.build(act, now, np.random.default_rng(3))
    assert plan["attacker"] == "45.155.205.12" and plan["decoy_ip"] != plan["attacker"]
    srcs = {f["src"] for b in plan["flows"] for f in b["flows"]}
    assert plan["attacker"] in srcs and all(b["window_end"] <= now for b in plan["flows"])
    assert any('"GET /.env HTTP/1.1" 200' in line for line in plan["web"])
    assert all(line.startswith(plan["attacker"]) for line in plan["web"])
    assert all(line.startswith(plan["decoy_ip"]) for line in plan["decoy"])
    assert not any('"GET /.env HTTP/1.1" 200' in line for line in sc.build(act, now, np.random.default_rng(3),
                                                                              env_status=404)["web"])


def test_campaign_simulator_opens_expected_incidents(tmp_path, data):
    import simulate_campaign as sc
    act, _ = data
    plan = sc.build(act, T0 + 3 * 86400, np.random.default_rng(3))
    store = LogStore(tmp_path / "t.db")
    process_batch(store, None, "web", "\n".join(plan["decoy"]), year=2026)
    process_batch(store, None, "web", "\n".join(plan["web"]), year=2026)
    by_ip = alerts_by_ip(store)
    assert by_ip[plan["attacker"]] == {"path_scan", "brute_force"} and by_ip[plan["decoy_ip"]] == {"flood"}
    assert len(store.incidents()) == 2
