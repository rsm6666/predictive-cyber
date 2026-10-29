import gzip
import json
import time

import numpy as np
from helpers import auth, signup

from sensor.agent import encode
from simulate_flows import generate

URL = "/api/v1/ingest/flows"
GZ = {"Content-Encoding": "gzip", "Content-Type": "application/json"}


def batches(data, minutes=2, attack=None):
    act, _ = data
    start = (time.time() // 60 - minutes) * 60
    return generate(act, minutes, start, np.random.default_rng(3), attack=attack, attack_at=0, attack_minutes=minutes)


def post(api, key, body, headers=GZ):
    return api.post(URL, content=body, headers={**auth(key), **headers})


def test_key_permissions_and_formats(api, data):
    t = signup(api)
    b = batches(data)
    assert api.post(URL, content=encode(b[0]), headers=GZ).status_code == 401
    assert post(api, t["dashboard_key"], encode(b[0])).status_code == 403
    r = post(api, t["ingest_key"], encode(b[0]))
    assert r.status_code == 200 and r.json()["accepted"] == 200 and not r.json()["duplicate"]
    r = post(api, t["ingest_key"], json.dumps(b[1]).encode(), headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert post(api, t["ingest_key"], encode(b[1])).json()["duplicate"] is True


def test_size_limits_and_zip_bomb(api, data):
    t = signup(api)
    bomb = gzip.compress(b"[" + b" " * (25 * 1024 * 1024) + b"]")
    assert len(bomb) < 100_000 and post(api, t["ingest_key"], bomb).status_code == 413
    assert post(api, t["ingest_key"], b"x" * (5 * 1024 * 1024 + 1), headers={}).status_code == 413
    assert post(api, t["ingest_key"], b"not gzip").status_code == 422


def test_invalid_batches_are_rejected_whole(api, data):
    t = signup(api)
    good = batches(data, minutes=1)[0]
    bad_ip = json.loads(json.dumps(good)); bad_ip["flows"][3]["src"] = "999.1.1.1"
    short = json.loads(json.dumps(good)); short["flows"][0]["f"] = short["flows"][0]["f"][:76]
    old = dict(good, window_start=good["window_start"] - 8 * 86400, window_end=good["window_end"] - 8 * 86400)
    for b in (bad_ip, short, old):
        r = post(api, t["ingest_key"], encode(b))
        assert r.status_code == 422, r.json()
    marked = json.loads(json.dumps(good)); marked["flows"][0]["f"][5] = 123456.789
    text = json.dumps(marked).replace("123456.789", "1e999")      # inf في خاصية، كما قد يرسله عميل معطوب
    assert post(api, t["ingest_key"], text.encode(), headers={}).status_code == 422
    assert api.get("/api/v1/sources", headers=auth(t["dashboard_key"])).json()["agent"]["state"] == "never"


def test_attack_opens_network_incident_and_tenants_are_isolated(api, data):
    a, b = signup(api, "أ"), signup(api, "ب")
    ids = [post(api, a["ingest_key"], encode(x)).json()["incident_id"] for x in batches(data, attack="PortScan")]
    incident = next(i for i in ids if i)
    listed = api.get("/api/v1/incidents", headers=auth(a["dashboard_key"])).json()["incidents"]
    assert listed[0]["id"] == incident and listed[0]["kind"] == "network" and "net_scan" in listed[0]["types"]
    src = api.get("/api/v1/sources", headers=auth(a["dashboard_key"])).json()["agent"]
    assert src["state"] == "connected" and src["windows"] == 2 and src["host"] == "demo-server"
    assert src["forecast"] == {"state": "learning", "windows": 2, "needed": 10}
    other = auth(b["dashboard_key"])
    assert api.get("/api/v1/sources", headers=other).json()["agent"]["state"] == "never"
    assert api.get(f"/api/v1/incidents/{incident}", headers=other).status_code == 404
