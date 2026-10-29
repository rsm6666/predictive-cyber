import json
import time

import numpy as np
from helpers import auth, signup
from test_approval_flow import post_decision
from test_net_agent import network_incident

from notify.channels import telegram_request
from notify.outbox import Outbox
from simulate_flows import ATTACKERS
from simulate_logs import _attack

ATTACKER = ATTACKERS["PortScan"]          # نفس عنوان «scan» في محاكي السجلات
TEXT = {"Content-Type": "text/plain"}


def deliveries(platform, tenant_id, event):
    return [d for d in Outbox(platform.store.dir(tenant_id) / "tenant.db").due(now=1e12) if d["event"] == event]


def wait_run(platform, tenant_id, incident_id):
    for _ in range(200):
        run = platform.runs.get((tenant_id, incident_id))
        if run and run.settled.wait(timeout=0.05):
            return run
        time.sleep(0.05)
    raise AssertionError(f"التحقيق في {incident_id} لم ينتهِ")


def campaign_id(api, t):
    for _ in range(100):
        rows = api.get("/api/v1/incidents", headers=auth(t["dashboard_key"])).json()["incidents"]
        camp = [i for i in rows if i["kind"] == "campaign"]
        if camp:
            return camp[0]["id"], rows
        time.sleep(0.05)
    raise AssertionError("لم تتكون حملة")


def scan_campaign(api, platform, data):
    """فحص منافذ من وكيل الخادم ← فحص مسارات من نفس العنوان في سجلات الموقع ← حملة."""
    t, net_incident, net_run = network_incident(api, platform, data, minutes=6, attack="PortScan")
    lines = [line for _, line in _attack("scan", time.time() - 120, np.random.default_rng(1))[0]]
    log_incident = api.post("/api/v1/ingest/web", content="\n".join(lines).encode(),
                            headers={**auth(t["ingest_key"]), **TEXT}).json()["incident_id"]
    wait_run(platform, t["tenant_id"], log_incident)
    cid, rows = campaign_id(api, t)
    return t, net_incident, net_run, log_incident, wait_run(platform, t["tenant_id"], cid), rows


def test_network_and_logs_form_one_campaign_with_one_approval(api, platform, data):
    t, net_incident, net_run, log_incident, run, rows = scan_campaign(api, platform, data)
    tid, h = t["tenant_id"], auth(t["dashboard_key"])
    assert run.status == "done" and run.incident.kind == "campaign"
    assert {r["id"]: r["campaign"] for r in rows if r["id"] in (net_incident, log_incident)} == \
        {net_incident: run.incident.id, log_incident: run.incident.id}
    camp_row = next(r for r in rows if r["id"] == run.incident.id)
    assert {"path_scan"} <= set(camp_row["types"])

    detail = api.get(f"/api/v1/incidents/{run.incident.id}", headers=h).json()
    assert {m["incident_id"] for m in detail["campaign"]["members"]} == {net_incident, log_incident}
    assert ATTACKER in detail["campaign"]["links"][0]["reason"]

    reports = deliveries(platform, tid, "incident.report")
    by_incident = {d["payload"]["incident_id"]: d["payload"] for d in reports}
    assert log_incident not in by_incident                 # انضمت لحملة ← لا تقرير منفصل
    campaign = by_incident[run.incident.id]
    assert campaign["kind"] == "campaign" and campaign["stages"]
    [proposal] = [p for p in campaign["proposals"] if p["source_ip"] == ATTACKER]
    text = json.loads(telegram_request("t", "42", "incident.report", campaign)[2])["text"]
    assert "حملة هجوم منسّقة" in text and "المراحل" in text

    old = [p for p in by_incident[net_incident]["proposals"] if p["source_ip"] == ATTACKER]
    assert old and post_decision(api, old[0]["approve_url"].rsplit("/", 1)[1], "approve").status_code == 410
    assert next(p for p in net_run.ws.proposals.values() if p.source_ip == ATTACKER).status == "merged"

    assert post_decision(api, proposal["approve_url"].rsplit("/", 1)[1], "approve").status_code == 200
    executes = [d for d in deliveries(platform, tid, "action.execute") if d["payload"]["ip"] == ATTACKER]
    assert len(executes) == 1 and executes[0]["payload"]["incident_id"] == run.incident.id
    status = {i: api.get(f"/api/v1/incidents/{i}", headers=h).json()["incident"]["status"]
              for i in (run.incident.id, log_incident)}
    assert status == {run.incident.id: "closed", log_incident: "closed"}


def test_exposed_file_from_monitor_joins_through_on_incident(api, platform, data):
    t, _, _, log_incident, run, _ = scan_campaign(api, platform, data)
    tid, store = t["tenant_id"], platform.store.logs(t["tenant_id"])
    store.insert_web([{"ts": time.time() - 30, "ip": ATTACKER, "method": "GET", "path": "/.env", "status": 200,
                       "bytes": 90, "referer": "-", "ua": "zgrab"}])
    exposed = store.open_incident({"type": "exposed_file", "source": "monitor", "ip": "shop.example",
                                   "first_ts": time.time(), "last_ts": time.time(), "count": 1, "severity": "high",
                                   "evidence": [], "details": {"url": "http://shop.example", "detail": "/.env",
                                                                "path": "/.env"}})
    first = run
    platform.monitor.on_incident(tid, exposed)
    for _ in range(200):
        again = platform.runs.get((tid, first.incident.id))
        if again is not first and again.settled.wait(timeout=0.05):
            break
        time.sleep(0.05)
    assert store.incident(exposed)["campaign"] == first.incident.id
    assert store.incident(first.incident.id)["severity"] == "critical"
    assert any(s["stage"] == "exploit" for s in again.report["stages"])


def test_campaigns_are_isolated_between_tenants(api, platform, data):
    t, *_ , run, _ = scan_campaign(api, platform, data)
    other = signup(api, "أخرى")
    r = api.get(f"/api/v1/incidents/{run.incident.id}", headers=auth(other["dashboard_key"]))
    assert r.status_code == 404 or r.json()["incident"]["kind"] != "campaign"
