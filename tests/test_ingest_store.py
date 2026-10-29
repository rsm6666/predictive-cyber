import pytest

from ingest.store import LogStore

T0 = 1_800_000_000.0


def web(ts, ip="203.0.113.7", path="/", status=200):
    return {"ts": ts, "ip": ip, "method": "GET", "path": path, "status": status, "bytes": 10, "referer": "", "ua": "ua"}


def alert(type_="brute_force", ip="203.0.113.7", first=T0, last=None, count=20, severity="high"):
    return {"type": type_, "source": "web", "ip": ip, "first_ts": first, "last_ts": last or first + 60,
            "count": count, "severity": severity, "evidence": ["POST /login → 401"], "details": {}}


@pytest.fixture
def store(tmp_path):
    return LogStore(tmp_path / "tenant.db")


def test_insert_and_query_window(store):
    store.insert_web([web(T0), web(T0 + 10, ip="198.51.100.1"), web(T0 + 1000)])
    assert len(store.web_between(T0, T0 + 100)) == 2
    assert [e["ip"] for e in store.web_between(T0, T0 + 100, ip="198.51.100.1")] == ["198.51.100.1"]
    store.insert_fw([{"ts": T0, "action": "BLOCK", "src": "192.0.2.1", "dst": "10.0.0.5", "proto": "TCP", "dport": 22}])
    stats = store.source_stats()
    assert stats["web"] == {"events": 3, "last_ts": T0 + 1000} and stats["firewall"]["events"] == 1


def test_retention_by_age_and_size(store):
    store.insert_web([web(T0 - 8 * 86400), web(T0 - 10), web(T0)])
    store.prune(now=T0)
    assert len(store.web_between(0, T0 + 1)) == 2
    store.prune(now=T0, max_rows=1)
    assert [e["ts"] for e in store.web_between(0, T0 + 1)] == [T0]


def test_same_alert_merges_within_15_minutes(store):
    a1, inc1, new1 = store.add_alert(alert(first=T0))
    a2, inc2, new2 = store.add_alert(alert(first=T0 + 600, count=5))
    a3, inc3, _ = store.add_alert(alert(first=T0 + 600 + 60 + 901))
    assert a1 == a2 != a3 and new1 and not new2 and inc1 == inc2 == inc3
    assert store.alerts(inc1)[0]["count"] == 25


def test_rechecking_same_bucket_keeps_max_count(store):
    store.add_alert(alert(first=T0, last=T0 + 60, count=20))
    store.add_alert(alert(first=T0, last=T0 + 120, count=26))
    assert store.alerts(store.incidents()[0]["id"])[0]["count"] == 26


def test_incident_grouping_and_severity(store):
    _, inc1, _ = store.add_alert(alert(first=T0, severity="medium"))
    _, inc2, _ = store.add_alert(alert("flood", ip="198.51.100.9", first=T0 + 300, severity="critical"))
    _, inc3, new3 = store.add_alert(alert("path_scan", first=T0 + 4000))
    assert inc1 == inc2 != inc3 and new3
    assert store.incident(inc1)["severity"] == "critical" and inc1.startswith("log-")


def test_closed_incident_gets_no_new_alerts(store):
    _, inc1, _ = store.add_alert(alert(first=T0))
    store.set_incident_status(inc1, "closed")
    _, inc2, new2 = store.add_alert(alert("flood", first=T0 + 60))
    assert inc2 != inc1 and new2


def test_rule_spans_and_state(store):
    store.add_alert(alert(first=T0, last=T0 + 60))
    store.add_alert(alert("anomaly", ip="198.51.100.3", first=T0))
    assert store.rule_alert_spans() == [("203.0.113.7", T0, T0 + 60)]
    assert store.state_get("x", 5) == 5
    store.state_set("x", {"a": 1})
    assert store.state_get("x") == {"a": 1}
