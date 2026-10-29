import json

import pytest
from helpers import auth, signup
from sites import LocalSite, page
from test_enforcer import make, request

from monitor.verify import FILE_PATH
from notify.channels import telegram_request

BASE = "/api/v1/monitor/sites"


@pytest.fixture
def mapi(api, platform):
    platform.monitor.submit = lambda tenant_id, site_id: None   # بلا فحص خلفي يسابق الاختبار
    return api


def test_add_list_verify_and_delete(mapi):
    t = signup(mapi)
    h = auth(t["dashboard_key"])
    assert mapi.get(BASE).status_code == 401
    with LocalSite({"/": page()}) as s:
        r = mapi.post(BASE, json={"url": s.url + "/shop"}, headers=h)
        assert r.status_code == 201
        site = r.json()
        assert site["url"] == s.url and not site["verified"] and site["grade"] is None
        assert site["verification"]["file_url"] == s.url + FILE_PATH
        s.routes[FILE_PATH] = page(body=site["verification"]["token"].encode())
        r = mapi.post(f"{BASE}/{site['id']}/verify", headers=h).json()
        assert r["verified"] and r["method"] == "file" and r["site"]["grade"] in "ABCDF"
    assert [x["id"] for x in mapi.get(BASE, headers=h).json()["sites"]] == [site["id"]]
    assert mapi.delete(f"{BASE}/{site['id']}", headers=h).json() == {"deleted": True}
    assert mapi.get(BASE, headers=h).json()["sites"] == []


def test_tenants_are_isolated(mapi):
    a, b = signup(mapi, "أ"), signup(mapi, "ب")
    site = mapi.post(BASE, json={"url": "https://shop.example"}, headers=auth(a["dashboard_key"])).json()
    hb = auth(b["dashboard_key"])
    assert mapi.get(BASE, headers=hb).json()["sites"] == []
    for method, path in (("delete", ""), ("post", "/verify"), ("post", "/check")):
        assert getattr(mapi, method)(f"{BASE}/{site['id']}{path}", headers=hb).status_code == 404
    assert len(mapi.get(BASE, headers=auth(a["dashboard_key"])).json()["sites"]) == 1


def test_private_targets_rejected_when_disallowed(mapi, platform):
    h = auth(signup(mapi)["dashboard_key"])
    platform.monitor.allow_private = False
    r = mapi.post(BASE, json={"url": "http://127.0.0.1:9"}, headers=h)
    assert r.status_code == 422 and "داخلي" in r.json()["detail"]
    assert mapi.post(BASE, json={"url": "not a url"}, headers=h).status_code == 422


def test_check_now_rate_limit(mapi):
    h = auth(signup(mapi)["dashboard_key"])
    with LocalSite({"/": page()}) as s:
        site = mapi.post(BASE, json={"url": s.url}, headers=h).json()
        r = mapi.post(f"{BASE}/{site['id']}/check", headers=h)
        assert r.status_code == 200 and r.json()["state"] == "up" and r.json()["uptime_24h"] == 100.0
        r = mapi.post(f"{BASE}/{site['id']}/check", headers=h)
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_monitor_incidents_listed_with_kind_and_not_investigated(mapi, platform):
    t = signup(mapi)
    h = auth(t["dashboard_key"])
    incident = platform.store.logs(t["tenant_id"]).open_incident(
        {"type": "site_down", "source": "monitor", "ip": "shop.example", "first_ts": 1.0, "last_ts": 1.0,
         "count": 1, "severity": "critical", "evidence": ["لا يستجيب"], "details": {}})
    listed = mapi.get("/api/v1/incidents", headers=h).json()["incidents"]
    assert listed[0]["id"] == incident and listed[0]["kind"] == "monitor" and listed[0]["types"] == ["site_down"]
    assert mapi.post(f"/api/v1/incidents/{incident}/investigate", headers=h).status_code == 422


ALERT = {"site": "https://shop.example", "kind": "exposed_file", "severity": "critical",
         "detail": "ملف حساس مكشوف للعامة: /.env", "incident_id": "log-3",
         "fix": {"nginx": "location = /.env { deny all; }", "apache": "x"}}


def test_enforcer_acknowledges_monitor_alert():
    code, out = make(apply=True).handle(*request(ALERT, event="monitor.alert"))
    assert code == 200 and out["status"] == "ignored"


def test_telegram_text_for_monitor_alert():
    msg = json.loads(telegram_request("t", "42", "monitor.alert", ALERT)[2])
    assert "ملف حساس مكشوف" in msg["text"] and "https://shop.example" in msg["text"]
    assert "location = /.env { deny all; }" in msg["text"] and "حرجة" in msg["text"] and "reply_markup" not in msg
