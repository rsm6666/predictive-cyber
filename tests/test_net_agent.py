import json
import time

import numpy as np
from helpers import auth, signup
from test_approval_flow import HOOK, approve_token, pending, post_decision

from notify.channels import telegram_request
from sensor.agent import encode
from simulate_flows import ATTACKERS, generate

GZ = {"Content-Encoding": "gzip", "Content-Type": "application/json"}


def network_incident(api, platform, data, minutes, attack="DoS"):
    """تسجيل ← Webhook ← نوافذ وكيل فيها هجوم في آخر دقيقتين ← انتظار التحقيق."""
    t = signup(api)
    api.put("/api/v1/settings", json={"webhook_url": HOOK, "allowlist": []}, headers=auth(t["dashboard_key"]))
    act, _ = data
    start = (time.time() // 60 - minutes) * 60
    incident = None
    for b in generate(act, minutes, start, np.random.default_rng(5), attack=attack, attack_at=minutes - 2,
                      attack_minutes=2):
        r = api.post("/api/v1/ingest/flows", content=encode(b), headers={**auth(t["ingest_key"]), **GZ})
        incident = incident or r.json()["incident_id"]
    for _ in range(200):
        run = platform.runs.get((t["tenant_id"], incident))
        if run and run.settled.wait(timeout=0.05):
            return t, incident, run
        time.sleep(0.05)
    raise AssertionError("التحقيق لم ينتهِ")


def test_analyst_investigates_network_incident_and_approval_reaches_enforcer(api, platform, data):
    t, incident, run = network_incident(api, platform, data, minutes=6)
    attacker = ATTACKERS["DoS"]
    assert run.status == "done" and run.incident.kind == "network" and run.incident.truth == {}
    assert "التنبؤ غير متاح" in run.report["watch_next"]               # 6 نوافذ فقط
    detail = api.get(f"/api/v1/incidents/{incident}", headers=auth(t["dashboard_key"])).json()
    assert detail["incident"]["kind"] == "network" and detail["incident"]["status"] == "investigating"
    [proposal] = [p for p in detail["proposals"] if p["source_ip"] == attacker]
    assert proposal["action"] == "block_ip" and proposal["status"] == "pending"

    report = pending(platform, t["tenant_id"], "incident.report")[0]["payload"]
    assert report["kind"] == "network"
    text = json.loads(telegram_request("t", "42", "incident.report", report)[2])["text"]
    assert "تنبيه أمني" in text and "محاكاة" not in text

    assert post_decision(api, approve_token(platform, t), "approve").status_code == 200
    [execute] = pending(platform, t["tenant_id"], "action.execute")
    assert execute["payload"]["ip"] == attacker and execute["payload"]["action"] == "block_ip"
    status = api.get(f"/api/v1/incidents/{incident}", headers=auth(t["dashboard_key"])).json()["incident"]["status"]
    assert status == "closed"


def test_forecast_is_used_once_ten_windows_exist(api, platform, data):
    _, _, run = network_incident(api, platform, data, minutes=12)
    assert "50%" in run.report["watch_next"]          # التنبؤ الثابت في المنصة المؤقتة = 0.5
