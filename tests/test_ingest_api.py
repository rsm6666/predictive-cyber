import time
from datetime import datetime, timezone

from helpers import auth, signup

from tenancy.api import MAX_INGEST_BYTES, MAX_INGEST_LINES
from tenancy.auth import RateLimiter

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc).timestamp()
ATTACKER = "203.0.113.7"


def line(i, ip=ATTACKER, path="/login", status=401, method="POST"):
    t = datetime.fromtimestamp(T0 + i, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} 10 "-" "python-requests/2.31"'


def brute(n=25):
    return "\n".join(line(i) for i in range(n))


def ingest(api, key, text, source="web"):
    return api.post(f"/api/v1/ingest/{source}", content=text.encode(), headers={**auth(key), "Content-Type": "text/plain"})


def wait_run(platform, tenant_id, incident_id):
    for _ in range(200):
        run = platform.runs.get((tenant_id, incident_id))
        if run and run.settled.wait(timeout=0.05):
            return run
        time.sleep(0.05)
    raise AssertionError("التحقيق لم ينتهِ")


def test_key_permissions(api):
    t = signup(api)
    assert ingest(api, t["dashboard_key"], brute()).status_code == 403
    assert api.get("/api/v1/me", headers=auth(t["ingest_key"])).status_code == 403
    r = ingest(api, t["ingest_key"], brute() + "\ngarbage")
    assert r.status_code == 200 and r.json()["accepted"] == 25 and r.json()["rejected"] == 1


def test_limits_and_unknown_source(api, platform):
    t = signup(api)
    assert ingest(api, t["ingest_key"], "x" * (MAX_INGEST_BYTES + 1)).status_code == 413
    assert ingest(api, t["ingest_key"], "\n".join(["x"] * (MAX_INGEST_LINES + 1))).status_code == 413
    assert ingest(api, t["ingest_key"], brute(), source="dns").status_code == 404
    platform.ingests = RateLimiter(limit=1, window=60)
    assert ingest(api, t["ingest_key"], "x").status_code == 200
    assert ingest(api, t["ingest_key"], "x").status_code == 429


def test_attack_is_investigated_and_closed_on_approval(api, platform):
    t = signup(api)
    h = auth(t["dashboard_key"])
    inc = ingest(api, t["ingest_key"], brute()).json()["incident_id"]
    run = wait_run(platform, t["tenant_id"], inc)
    assert run.status == "done" and run.report["attack_types"] == ["brute_force"]
    detail = api.get(f"/api/v1/incidents/{inc}", headers=h).json()
    assert detail["incident"]["status"] == "investigating" and detail["investigation"] == inc
    assert [a["type"] for a in detail["alerts"]] == ["brute_force"]
    listed = api.get("/api/v1/incidents", headers=h).json()["incidents"]
    assert listed[0]["id"] == inc and listed[0]["types"] == ["brute_force"]

    pid = next(iter(run.ws.proposals))
    body = {"incident_id": inc, "proposal_id": pid, "decision": "approve"}
    assert api.post("/api/v1/agent/decide", json=body, headers=h).json()["status"] == "applied"
    assert api.get(f"/api/v1/incidents/{inc}", headers=h).json()["incident"]["status"] == "closed"


def test_logs_and_incidents_are_isolated(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    inc = ingest(api, a["ingest_key"], brute()).json()["incident_id"]
    wait_run(platform, a["tenant_id"], inc)
    hb = auth(b["dashboard_key"])
    assert api.get("/api/v1/incidents", headers=hb).json()["incidents"] == []
    assert api.get(f"/api/v1/incidents/{inc}", headers=hb).status_code == 404
    assert api.get("/api/v1/sources", headers=hb).json()["web"]["events"] == 0


def test_sources_report_counts_and_learning(api):
    t = signup(api)
    ingest(api, t["ingest_key"], "\n".join(line(i, path="/", status=200, method="GET") for i in range(30)))
    fw = "\n".join(f"Oct 26 12:00:{i:02d} shop kernel: [UFW BLOCK] SRC=192.0.2.9 DST=10.0.0.5 PROTO=TCP DPT=23"
                   for i in range(5))
    ingest(api, t["ingest_key"], fw, source="firewall")
    s = api.get("/api/v1/sources", headers=auth(t["dashboard_key"])).json()
    assert s["web"]["events"] == 30 and s["firewall"]["events"] == 5
    assert s["anomaly"]["state"] == "learning" and s["anomaly"]["windows"] == 1
