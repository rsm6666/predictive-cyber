import time
from datetime import datetime, timezone

from helpers import auth, signup

from notify.outbox import Outbox

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc).timestamp()
HOOK = "https://hooks.example.test/sec"


def brute(ip="203.0.113.7"):
    stamp = lambda i: datetime.fromtimestamp(T0 + i, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return "\n".join(f'{ip} - - [{stamp(i)}] "POST /login HTTP/1.1" 401 10 "-" "curl"' for i in range(25))


def incident_with_proposal(api, platform, t):
    h = auth(t["dashboard_key"])
    api.put("/api/v1/settings", json={"webhook_url": HOOK, "allowlist": []}, headers=h)
    inc = api.post("/api/v1/ingest/web", content=brute().encode(),
                   headers={**auth(t["ingest_key"]), "Content-Type": "text/plain"}).json()["incident_id"]
    for _ in range(200):
        run = platform.runs.get((t["tenant_id"], inc))
        if run and run.settled.wait(timeout=0.05):
            return inc, run
        time.sleep(0.05)
    raise AssertionError("التحقيق لم ينتهِ")


def pending(platform, tenant_id, event):
    return [d for d in Outbox(platform.store.dir(tenant_id) / "tenant.db").due(now=1e12) if d["event"] == event]


def approve_token(platform, t):
    url = pending(platform, t["tenant_id"], "incident.report")[0]["payload"]["proposals"][0]["approve_url"]
    assert url.startswith(platform.public_url + "/approve/")
    return url.rsplit("/", 1)[1]


def post_decision(api, token, decision):
    return api.post(f"/approve/{token}", content=f"decision={decision}".encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})


def test_settings_secret_and_masked_telegram(api, platform):
    t = signup(api)
    h = auth(t["dashboard_key"])
    api.put("/api/v1/settings", json={"webhook_url": HOOK, "telegram_token": "123456:SECRET-TOKEN",
                                      "telegram_chat_id": "42"}, headers=h)
    s = api.get("/api/v1/me", headers=h).json()["settings"]
    assert len(s["webhook_secret"]) > 30 and "SECRET" not in s["telegram_token"] and s["telegram_chat_id"] == "42"
    rotated = api.post("/api/v1/settings/webhook-secret/rotate", headers=h).json()["webhook_secret"]
    assert rotated != s["webhook_secret"]
    api.put("/api/v1/settings", json={"webhook_url": HOOK}, headers=h)            # التوكن لا يُمسح ضمنيًا
    assert platform.store.settings(t["tenant_id"])["telegram_token"] == "123456:SECRET-TOKEN"


def test_private_webhook_rejected_when_disallowed(api, platform):
    platform.allow_private_webhooks = False
    h = auth(signup(api)["dashboard_key"])
    assert api.put("/api/v1/settings", json={"webhook_url": "http://127.0.0.1:9000/hook"}, headers=h).status_code == 422


def test_report_link_get_does_not_decide_and_post_does(api, platform):
    t = signup(api)
    inc, run = incident_with_proposal(api, platform, t)
    token = approve_token(platform, t)
    page = api.get(f"/approve/{token}")
    assert page.status_code == 200 and "203.0.113.7" in page.text
    assert run.ws.proposals[1].status == "pending"                # الفتح (أو المعاينة) لا يغيّر شيئًا

    done = post_decision(api, token, "approve")
    assert done.status_code == 200 and run.ws.proposals[1].status == "applied"
    execute = pending(platform, t["tenant_id"], "action.execute")
    assert execute[0]["channel"] == "webhook" and execute[0]["payload"]["ip"] == "203.0.113.7"
    assert pending(platform, t["tenant_id"], "action.result")[0]["payload"]["status"] == "applied"
    assert api.get(f"/api/v1/incidents/{inc}", headers=auth(t["dashboard_key"])).json()["incident"]["status"] == "closed"
    assert post_decision(api, token, "approve").status_code == 410   # لمرة واحدة


def test_reject_sends_no_execute(api, platform):
    t = signup(api)
    _, run = incident_with_proposal(api, platform, t)
    assert post_decision(api, approve_token(platform, t), "reject").status_code == 200
    assert run.ws.proposals[1].status == "rejected" and pending(platform, t["tenant_id"], "action.execute") == []


def test_token_only_touches_its_own_tenant(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    _, run_a = incident_with_proposal(api, platform, a)
    _, run_b = incident_with_proposal(api, platform, b)
    post_decision(api, approve_token(platform, a), "approve")
    assert run_a.ws.proposals[1].status == "applied" and run_b.ws.proposals[1].status == "pending"


def test_unknown_token_and_bad_decision(api):
    assert api.get("/approve/nope").status_code == 410
    assert post_decision(api, "nope", "maybe").status_code == 400


def test_dashboard_decision_also_notifies(api, platform):
    t = signup(api)
    inc, _ = incident_with_proposal(api, platform, t)
    body = {"incident_id": inc, "proposal_id": 1, "decision": "approve"}
    assert api.post("/api/v1/agent/decide", json=body, headers=auth(t["dashboard_key"])).json()["status"] == "applied"
    assert pending(platform, t["tenant_id"], "action.execute")


def test_executor_result_updates_proposal(api, platform):
    t = signup(api)
    inc, run = incident_with_proposal(api, platform, t)
    platform.notifier.on_result(t["tenant_id"], {"incident_id": inc, "proposal_id": 1},
                                {"status": "dry_run", "detail": "ufw insert 1 deny from 203.0.113.7"})
    assert "تجربة" in run.ws.proposals[1].rationale


def test_test_message_and_delivery_log(api):
    t = signup(api)
    h = auth(t["dashboard_key"])
    assert api.post("/api/v1/notify/test", json={"channel": "webhook"}, headers=h).status_code == 422
    api.put("/api/v1/settings", json={"webhook_url": HOOK}, headers=h)
    assert api.post("/api/v1/notify/test", json={"channel": "webhook"}, headers=h).status_code == 200
    log = api.get("/api/v1/deliveries", headers=h).json()["deliveries"]
    assert log[0]["event"] == "test" and log[0]["status"] == "pending"
