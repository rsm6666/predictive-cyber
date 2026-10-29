import sqlite3

import pytest
from test_ingest_store import T0, alert, web

from ingest.store import LogStore


@pytest.fixture
def store(tmp_path):
    return LogStore(tmp_path / "tenant.db")


def test_campaign_is_an_incident_without_alerts(store):
    _, member, _ = store.add_alert(alert())
    cid = store.new_campaign(T0, "high")
    c = store.incident(cid)
    assert c["kind"] == "campaign" and c["status"] == "open" and c["campaign"] is None and store.alerts(cid) == []
    store.set_campaign(member, cid)
    assert store.incident(member)["campaign"] == cid
    assert [m["id"] for m in store.campaign_members(cid)] == [member]


def test_links_are_not_duplicated(store):
    cid = store.new_campaign(T0, "high")
    args = (cid, "log-1", "log-2", "same_ip", "45.155.205.12", "نفس العنوان", False, T0)
    assert store.add_link(*args) is True
    assert store.add_link(*args) is False
    [link] = store.links(cid)
    assert link["rule"] == "same_ip" and link["downloaded"] is False and link["reason"] == "نفس العنوان"


def test_move_campaign_moves_members_and_links(store):
    _, m1, _ = store.add_alert(alert(ip="192.0.2.1"))
    old, new = store.new_campaign(T0, "high"), store.new_campaign(T0, "medium")
    store.set_campaign(m1, new)
    store.add_link(new, m1, "log-9", "same_ip", "192.0.2.1", "r", False, T0)
    store.move_campaign(new, old)
    assert store.incident(m1)["campaign"] == old and store.campaign_members(new) == []
    assert [l["campaign"] for l in store.links(old)] == [old]


def test_update_incident_fields(store):
    cid = store.new_campaign(T0, "medium")
    store.update_incident(cid, severity="critical", updated_at=T0 + 50, status="closed")
    c = store.incident(cid)
    assert (c["severity"], c["updated_at"], c["status"]) == ("critical", T0 + 50, "closed")


def test_incidents_with_ip_by_window_and_kind(store):
    _, web_inc, _ = store.add_alert(alert(ip="45.155.205.12", first=T0))
    _, net_inc, _ = store.add_alert({**alert(type_="net_scan", ip="45.155.205.12", first=T0 + 3600),
                                     "source": "network"}, kind="network")
    store.open_incident({**alert(type_="exposed_file", ip="45.155.205.12", first=T0), "source": "monitor"})
    assert store.incidents_with_ip("45.155.205.12", T0 - 10, T0 + 4000) == [web_inc, net_inc]
    assert store.incidents_with_ip("45.155.205.12", T0 + 3000, T0 + 4000) == [net_inc]
    assert store.incidents_with_ip("198.51.100.1", 0, T0 * 2) == []


def test_path_requests_ignore_query_string(store):
    store.insert_web([web(T0, path="/.env", status=200), web(T0 + 1, path="/.env?x=1", status=404),
                      web(T0 + 2, path="/.envx"), web(T0 + 3, ip="198.51.100.1", path="/.env")])
    assert [e["ts"] for e in store.path_requests("/.env", T0, T0 + 10)] == [T0, T0 + 1, T0 + 3]
    assert len(store.path_requests("/.env", T0, T0 + 10, ip="198.51.100.1")) == 1


def test_old_database_gets_campaign_column(tmp_path):
    path = tmp_path / "tenant.db"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE incidents (n INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, opened_at REAL,
                   updated_at REAL, severity TEXT, kind TEXT NOT NULL DEFAULT 'log')""")
    con.execute("INSERT INTO incidents (status, opened_at, updated_at, severity) VALUES ('open', 1, 1, 'high')")
    con.commit()
    con.close()
    assert LogStore(path).incident("log-1")["campaign"] is None
