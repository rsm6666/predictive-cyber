from agent.tools import ENFORCING
from helpers import auth, signup
from tenancy.auth import RateLimiter


def investigate(api, platform, tenant, family="PortScan"):
    r = api.post("/api/v1/agent/investigate", params={"family": family}, headers=auth(tenant["dashboard_key"]))
    iid = r.json()["incident_id"]
    run = platform.runs[(tenant["tenant_id"], iid)]
    assert run.settled.wait(timeout=10)
    return iid, run


def test_dashboard_endpoints_require_dashboard_key(api):
    t = signup(api)
    assert api.get("/api/v1/me").status_code == 401
    assert api.get("/api/v1/me", headers=auth("pc_dash_nope")).status_code == 401
    assert api.get("/api/v1/me", headers=auth(t["ingest_key"])).status_code == 403
    me = api.get("/api/v1/me", headers=auth(t["dashboard_key"])).json()
    assert me["tenant_id"] == t["tenant_id"] and me["settings"]["webhook_url"] is None


def test_rotated_keys_replace_old_ones(api):
    t = signup(api)
    new = api.post("/api/v1/keys/rotate", headers=auth(t["dashboard_key"])).json()
    assert api.get("/api/v1/me", headers=auth(t["dashboard_key"])).status_code == 401
    assert api.get("/api/v1/me", headers=auth(new["dashboard_key"])).status_code == 200


def test_signup_validation_and_rate_limit(api, platform):
    assert api.post("/api/v1/tenants", json={"name": "  "}).status_code == 422
    platform.signups = RateLimiter(limit=1)
    signup(api)
    assert api.post("/api/v1/tenants", json={"name": "ب"}).status_code == 429


def test_settings_are_validated_and_saved(api):
    h = auth(signup(api)["dashboard_key"])
    assert api.put("/api/v1/settings", json={"webhook_url": "ftp://x"}, headers=h).status_code == 422
    assert api.put("/api/v1/settings", json={"allowlist": ["999.1.1.1"]}, headers=h).status_code == 422
    body = {"webhook_url": "https://hooks.example.test/sec", "allowlist": [" 10.0.0.5 ", ""]}
    assert api.put("/api/v1/settings", json=body, headers=h).status_code == 200
    settings = api.get("/api/v1/me", headers=h).json()["settings"]
    assert settings["webhook_url"] == "https://hooks.example.test/sec" and settings["allowlist"] == ["10.0.0.5"]


def test_other_tenant_cannot_touch_incident(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    iid, run = investigate(api, platform, a)
    pid = next(iter(run.ws.proposals))
    decide = {"incident_id": iid, "proposal_id": pid, "decision": "approve"}
    hb = auth(b["dashboard_key"])
    assert api.post("/api/v1/agent/decide", json=decide, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/stream-token", json={"incident_id": iid}, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/chat", json={"incident_id": iid, "message": "هل آمن؟"}, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/decide", json=decide, headers=auth(a["dashboard_key"])).json()["status"] == "applied"


def test_tenant_files_stay_in_tenant_folder(api, platform, tmp_path):
    a, b = signup(api, "أ"), signup(api, "ب")
    iid, _ = investigate(api, platform, a)
    assert (tmp_path / "tenants" / a["tenant_id"] / "agent_runs" / f"{iid}.json").exists()
    assert not list((tmp_path / "tenants" / b["tenant_id"]).rglob("*.json"))


def test_allowlist_is_per_tenant(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    api.put("/api/v1/settings", json={"allowlist": ["172.16.0.1"]}, headers=auth(a["dashboard_key"]))
    _, run_a = investigate(api, platform, a)
    _, run_b = investigate(api, platform, b)

    def enforced(run):
        return {p.source_ip for p in run.ws.proposals.values() if p.action in ENFORCING}

    assert "172.16.0.1" not in enforced(run_a)
    assert "172.16.0.1" in enforced(run_b)


def test_stream_token_works_once(api, platform):
    t = signup(api)
    h = auth(t["dashboard_key"])
    iid, _ = investigate(api, platform, t)
    token = api.post("/api/v1/agent/stream-token", json={"incident_id": iid}, headers=h).json()["token"]
    with api.stream("GET", f"/api/v1/agent/stream/{iid}", params={"token": token}) as s:
        events = [line[7:] for line in s.iter_lines() if line.startswith("event: ")]
    assert events[-1] == "done"
    assert api.get(f"/api/v1/agent/stream/{iid}", params={"token": token}).status_code == 403
