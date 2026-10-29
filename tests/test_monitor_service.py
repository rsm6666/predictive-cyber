import pytest
from sites import LocalSite, page

from monitor.fetch import Response
from monitor.service import Monitor, MonitorError
from monitor.verify import FILE_PATH
from tenancy.store import TenantStore

TID = "t_aaaaaaaaaaaa"
NOW = 1_800_000_000.0
ENV = (200, [("Content-Type", "text/plain")], b"DB_PASSWORD=hunter2\n")


class FakeNotifier:
    def __init__(self):
        self.events = []

    def emit(self, tenant_id, event, data, only=None):
        self.events.append((tenant_id, event, data))

    def kinds(self):
        return [d["kind"] for _, e, d in self.events if e == "monitor.alert"]


@pytest.fixture
def store(tmp_path):
    return TenantStore(tmp_path / "tenants")


@pytest.fixture
def mon(store):
    return Monitor(store, FakeNotifier())


def add_verified(mon, s):
    site_id = mon.add_site(TID, s.url, NOW)
    s.routes[FILE_PATH] = page(body=mon.sites(TID).get(site_id)["token"].encode())
    assert mon.verify(TID, site_id, NOW)["method"] == "file"
    return site_id


def summary(mon, site_id, now=NOW):
    return next(x for x in mon.summary(TID, now) if x["id"] == site_id)


def test_verify_by_file_dns_and_wrong_token(store):
    with LocalSite({"/": page()}) as s:
        mon = Monitor(store, FakeNotifier(), resolve_txt=lambda name: ["pc-verify-wrong"])
        site_id = mon.add_site(TID, s.url, NOW)
        assert mon.verify(TID, site_id, NOW)["verified"] is False
        token = mon.sites(TID).get(site_id)["token"]
        s.routes[FILE_PATH] = page(body=f"  {token}\n".encode())
        assert mon.verify(TID, site_id, NOW) == {"verified": True, "method": "file", "dns_unavailable": False}
    seen = []
    with LocalSite({"/": page()}) as s:
        mon = Monitor(store, FakeNotifier(), resolve_txt=lambda name: seen.append(name) or [token2])
        site_id = mon.add_site(TID, s.url.replace("127.0.0.1", "localhost"), NOW)
        token2 = mon.sites(TID).get(site_id)["token"]
        assert mon.verify(TID, site_id, NOW)["method"] == "dns"
    assert seen == ["_pc-verify.localhost"]


def test_no_deep_checks_before_verification(mon):
    with LocalSite({"/": page(), "/.env": ENV}) as s:
        site_id = mon.add_site(TID, s.url, NOW)
        mon.run_site(TID, site_id, NOW)
        mon.run_site(TID, site_id, NOW + 86400 * 2)
    assert s.hits == ["/", "/"]
    info = summary(mon, site_id)
    assert info["state"] == "up" and info["grade"] is None and info["findings"] == []


def test_two_downs_open_incident_and_recovery_closes_it(mon, store):
    with LocalSite({"/": page()}) as s:
        site_id = mon.add_site(TID, s.url, NOW)
        s.down = True
        mon.run_site(TID, site_id, NOW)
        assert summary(mon, site_id)["incident_id"] is None and mon.notifier.kinds() == []
        mon.run_site(TID, site_id, NOW + 300)
        incident = summary(mon, site_id)["incident_id"]
        row = store.logs(TID).incident(incident)
        assert row["kind"] == "monitor" and row["severity"] == "critical" and row["status"] == "open"
        assert store.logs(TID).alerts(incident)[0]["type"] == "site_down"
        mon.run_site(TID, site_id, NOW + 600)   # ما زال متعطلًا: لا حادثة ثانية
        s.down = False
        mon.run_site(TID, site_id, NOW + 900)
    assert store.logs(TID).incident(incident)["status"] == "closed"
    assert mon.notifier.kinds() == ["down", "recovered"]
    assert summary(mon, site_id, NOW + 900)["uptime_24h"] == 25.0


def test_three_slow_checks_alert_once(store):
    notifier = FakeNotifier()
    mon = Monitor(store, notifier, fetcher=lambda url, allow_private: Response(200, ms=3500))
    site_id = mon.add_site(TID, "https://shop.example", NOW)
    for i in range(5):
        mon.run_site(TID, site_id, NOW + i * 300)
    assert notifier.kinds() == ["slow"] and summary(mon, site_id)["state"] == "slow"


def test_exposed_file_opens_incident_and_fix_closes_it(mon, store):
    with LocalSite({"/": page([("Server", "nginx/1.18.0")]), "/.env": ENV}, fallback=page()) as s:
        site_id = add_verified(mon, s)
        info = summary(mon, site_id)
        exposed = next(f for f in info["findings"] if f["key"] == "exposed:/.env")
        assert info["grade"] == "F" and exposed["severity"] == "critical"
        row = store.logs(TID).incident(exposed["incident_id"])
        assert row["kind"] == "monitor" and row["severity"] == "critical"
        assert mon.notifier.kinds() == ["exposed_file"] and mon.notifier.events[0][2]["fix"]["nginx"]
        del s.routes["/.env"]
        mon.check_now(TID, site_id, NOW + 61)
    after = summary(mon, site_id, NOW + 61)
    assert "exposed:/.env" not in [f["key"] for f in after["findings"]] and after["score"] > info["score"]
    assert store.logs(TID).incident(exposed["incident_id"])["status"] == "closed"


def test_exposed_file_reports_path_and_calls_on_incident(mon, store):
    opened = []
    mon.on_incident = lambda tid, inc: opened.append((tid, inc))
    with LocalSite({"/": page(), "/.env": ENV}, fallback=page()) as s:
        site_id = add_verified(mon, s)
    incident = next(f for f in summary(mon, site_id)["findings"] if f["key"] == "exposed:/.env")["incident_id"]
    assert opened == [(TID, incident)]
    assert store.logs(TID).alerts(incident)[0]["details"]["path"] == "/.env"


def test_monitor_incident_is_not_merged_with_log_incident(mon, store):
    logs = store.logs(TID)
    log_alert = {"type": "brute_force", "source": "web", "ip": "185.220.101.7", "first_ts": NOW, "last_ts": NOW,
                 "count": 30, "severity": "high", "evidence": [], "details": {}}
    _, log_incident, _ = logs.add_alert(log_alert)
    with LocalSite({"/": page()}) as s:
        s.down = True
        site_id = mon.add_site(TID, s.url, NOW)
        mon.run_site(TID, site_id, NOW + 60)
        mon.run_site(TID, site_id, NOW + 120)
    down_incident = summary(mon, site_id)["incident_id"]
    assert down_incident != log_incident
    _, again, new = logs.add_alert({**log_alert, "type": "path_scan", "first_ts": NOW + 180, "last_ts": NOW + 180})
    assert again == log_incident and not new
    assert [i["kind"] for i in logs.incidents()] == ["monitor", "log"]


def test_limits_normalization_and_private_targets(store):
    mon = Monitor(store, FakeNotifier())
    first = mon.add_site(TID, "http://Shop.Example:80/products?x=1", NOW)
    assert mon.sites(TID).get(first)["url"] == "http://shop.example"
    with pytest.raises(MonitorError) as e:
        mon.add_site(TID, "http://shop.example/", NOW)
    assert e.value.status == 409
    for i in range(4):
        mon.add_site(TID, f"https://s{i}.example", NOW)
    with pytest.raises(MonitorError) as e:
        mon.add_site(TID, "https://s9.example", NOW)
    assert e.value.status == 409
    with pytest.raises(MonitorError) as e:
        mon.add_site(TID, "ftp://shop.example", NOW)
    assert e.value.status == 422
    with pytest.raises(MonitorError) as e:
        Monitor(store, allow_private=False).add_site("t_bbbbbbbbbbbb", "http://127.0.0.1:9", NOW)
    assert e.value.status == 422


def test_check_now_is_rate_limited(mon):
    with LocalSite({"/": page()}) as s:
        site_id = mon.add_site(TID, s.url, NOW)
        mon.check_now(TID, site_id, NOW)
        with pytest.raises(MonitorError) as e:
            mon.check_now(TID, site_id, NOW + 10)
        assert e.value.status == 429 and e.value.retry_after == 51
        mon.check_now(TID, site_id, NOW + 61)


def test_scheduler_runs_only_due_sites(mon):
    with LocalSite({"/": page()}) as s:
        site_id = mon.add_site(TID, s.url, NOW)
        assert mon._due(mon.sites(TID).get(site_id), NOW)
        mon.run_site(TID, site_id, NOW)
        site = mon.sites(TID).get(site_id)
        assert not mon._due(site, NOW + 60) and mon._due(site, NOW + 300)
