import pytest
from test_ingest_store import T0, alert, web

from campaign.linker import link
from ingest.store import LogStore

ATTACKER = "45.155.205.12"


@pytest.fixture
def store(tmp_path):
    return LogStore(tmp_path / "tenant.db")


def net(store, ip=ATTACKER, at=T0, type_="net_scan"):
    return store.add_alert({**alert(type_=type_, ip=ip, first=at, severity="medium"), "source": "network"},
                           kind="network")[1]


def log(store, ip=ATTACKER, at=T0, type_="path_scan"):
    return store.add_alert(alert(type_=type_, ip=ip, first=at, severity="medium"))[1]


def exposed(store, at=T0, path="/.env", severity="high"):
    return store.open_incident({"type": "exposed_file", "source": "monitor", "ip": "shop.example", "first_ts": at,
                                "last_ts": at, "count": 1, "severity": severity, "evidence": [f"{path} مكشوف"],
                                "details": {"url": "http://shop.example", "detail": f"{path} مكشوف", "path": path}})


def test_same_attacker_in_network_and_logs_forms_a_campaign(store):
    a = net(store)
    assert link(store, a).campaign is None            # لا شيء يرتبط به بعد
    b = log(store, at=T0 + 600)
    r = link(store, b)
    assert r.changed and r.merged == []
    c = store.incident(r.campaign)
    assert c["kind"] == "campaign" and c["status"] == "open" and c["severity"] == "medium"
    assert {m["id"] for m in store.campaign_members(r.campaign)} == {a, b}
    [l] = store.links(r.campaign)
    assert (l["rule"], l["ip"], {l["a"], l["b"]}) == ("same_ip", ATTACKER, {a, b})
    assert ATTACKER in l["reason"] and "الشبكة" in l["reason"] and "السجلات" in l["reason"]


def test_relinking_changes_nothing(store):
    net(store)
    b = log(store, at=T0 + 600)
    first = link(store, b)
    again = link(store, b)
    assert again.campaign == first.campaign and not again.changed


def test_same_kind_returning_attacker_links(store):
    a = log(store)
    b = log(store, at=T0 + 2 * 3600)      # خارج نافذة التجميع (30 دقيقة) ← حادثة ثانية
    assert a != b and link(store, b).campaign


@pytest.mark.parametrize("case", ["late", "allowlisted", "other_ip"])
def test_no_link(store, case):
    net(store)
    if case == "late":
        b = log(store, at=T0 + 25 * 3600)
    elif case == "allowlisted":
        b = log(store, at=T0 + 600)
    else:
        b = log(store, ip="198.51.100.9", at=T0 + 600)
    r = link(store, b, allowlist=[ATTACKER] if case == "allowlisted" else ())
    assert r.campaign is None and not r.changed and store.incidents()[0]["kind"] != "campaign"


def test_downloaded_exposed_file_links_and_raises_severity(store):
    m = exposed(store)
    b = log(store, at=T0 + 300)
    store.insert_web([web(T0 + 310, ip=ATTACKER, path="/.env", status=200)])
    r = link(store, b)
    assert {x["id"] for x in store.campaign_members(r.campaign)} == {m, b}
    [l] = store.links(r.campaign)
    assert l["rule"] == "exposed_file" and l["downloaded"] and l["at"] == T0 + 310 and "/.env" in l["reason"]
    assert store.incident(r.campaign)["severity"] == "critical"


def test_monitor_side_links_requester_with_incident(store):
    b = log(store, at=T0)
    store.insert_web([web(T0 + 30, ip=ATTACKER, path="/.env", status=404),
                      web(T0 + 40, ip="198.51.100.9", path="/.env", status=200)])   # بلا حادثة ← لا ربط
    m = exposed(store, at=T0 + 3600)
    r = link(store, m)
    [l] = store.links(r.campaign)
    assert {l["a"], l["b"]} == {b, m} and not l["downloaded"]
    assert store.incident(r.campaign)["severity"] == "high"          # أعلى خطورة بين الأعضاء، بلا تحميل


def test_exposed_file_requested_by_nobody_with_incident(store):
    store.insert_web([web(T0, ip="198.51.100.9", path="/.env", status=200)])
    assert link(store, exposed(store)).campaign is None


def test_new_member_joins_existing_campaign(store):
    a, b = net(store), log(store, at=T0 + 600)
    cid = link(store, b).campaign
    c = log(store, type_="brute_force", at=T0 + 3 * 3600)
    r = link(store, c)
    assert r.campaign == cid and r.changed
    assert {m["id"] for m in store.campaign_members(cid)} == {a, b, c}


def test_closed_campaign_reopens_when_it_grows(store):
    net(store)
    cid = link(store, log(store, at=T0 + 600)).campaign
    store.update_incident(cid, status="closed")
    link(store, log(store, type_="brute_force", at=T0 + 3 * 3600))
    assert store.incident(cid)["status"] == "open"


def test_two_campaigns_merge_into_the_older(store):
    net(store)
    older = link(store, log(store, at=T0 + 600)).campaign
    other = "198.51.100.9"
    net(store, ip=other, at=T0 + 5 * 3600)
    newer = link(store, log(store, ip=other, at=T0 + 5 * 3600 + 600)).campaign
    assert newer != older
    bridge = store.add_alert(alert(type_="brute_force", ip=ATTACKER, first=T0 + 10 * 3600))[1]
    store.add_alert(alert(type_="injection", ip=other, first=T0 + 10 * 3600 + 30))
    r = link(store, bridge)
    assert r.campaign == older and r.merged == [newer] and r.changed
    assert store.incident(newer)["status"] == "merged" and store.campaign_members(newer) == []
    assert len(store.campaign_members(older)) == 5
