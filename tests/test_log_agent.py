import json
from datetime import datetime, timezone

import pytest

from agent.analyst import run_investigation
from agent.demo import DemoClient
from agent.evaluate import hallucinated_ips, unsupported_numbers
from agent.log_tools import LOG_TYPES, LogWorkspace
from agent.store import Run
from agent.tools import ENFORCING, ToolError, decide
from ingest.pipeline import process_batch
from ingest.store import LogStore

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc).timestamp()
ATTACKER = "203.0.113.7"


def line(i, ip=ATTACKER, path="/login", status=401, method="POST"):
    t = datetime.fromtimestamp(T0 + i, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} 10 "-" "python-requests/2.31"'


@pytest.fixture
def store(tmp_path):
    return LogStore(tmp_path / "tenant.db")


def brute_incident(store):
    out = process_batch(store, None, "web", "\n".join([line(i) for i in range(25)] +
                                                      [line(i, ip="198.51.100.4", path="/", status=200, method="GET")
                                                       for i in range(5)]), year=2026)
    return next(iter(out["incidents"]))


def anomaly_incident(store, ip="198.51.100.66"):
    store.insert_web([{"ts": T0 + i, "ip": ip, "method": "GET", "path": f"/x{i}", "status": 404, "bytes": 99,
                       "referer": "", "ua": "bot"} for i in range(12)])
    _, inc, _ = store.add_alert({"type": "anomaly", "source": "web", "ip": ip, "first_ts": T0, "last_ts": T0 + 299,
                                 "count": 12, "severity": "medium", "evidence": ["paths = 12.0 (z=+9.5)"],
                                 "details": {"score": 0.71, "threshold": 0.64,
                                             "features": [{"feature": "paths", "value": 12.0, "z": 9.5}]}})
    return inc


def investigate(store, inc, tmp_path, allowlist=()):
    ws = LogWorkspace(store, inc, allowlist=allowlist)
    run = Run(ws.incident, ws, save_dir=tmp_path / "runs")
    run_investigation(DemoClient(), ws, run)
    return ws, run


def enforced(ws):
    return [(p.source_ip, p.action, p.duration_min) for p in ws.proposals.values() if p.action in ENFORCING]


def test_demo_investigates_brute_force_with_grounded_report(store, tmp_path):
    ws, run = investigate(store, brute_incident(store), tmp_path)
    assert run.status == "done" and run.report["attack_types"] == ["brute_force"]
    assert enforced(ws) == [(ATTACKER, "block_ip", 60)]
    tool_text = " ".join(json.dumps(e["result"], ensure_ascii=False) for e in run.events if e["type"] == "step")
    assert hallucinated_ips(run.report, tool_text) == [] and unsupported_numbers(run.report, tool_text) == []
    assert run.events[-1]["truth_family"] is None


def test_anomaly_alone_never_blocks(store, tmp_path):
    inc = anomaly_incident(store)
    ws, run = investigate(store, inc, tmp_path)
    assert run.status == "done" and enforced(ws) == []
    assert ws.run_tool("check_policy", {"source_ip": "198.51.100.66"})["max_action"] == "monitor"
    assert run.report["attack_types"] == ["anomaly"]


def test_allowlisted_source_is_not_blocked(store, tmp_path):
    ws, _ = investigate(store, brute_incident(store), tmp_path, allowlist=[ATTACKER])
    assert enforced(ws) == []
    assert ws.run_tool("check_policy", {"source_ip": ATTACKER})["max_action"] == "none"


def test_tools_are_scoped_to_incident_sources(store):
    ws = LogWorkspace(store, brute_incident(store))
    with pytest.raises(ToolError):
        ws.run_tool("source_activity", {"source_ip": "198.51.100.4"})   # في السجلات لكن ليس في الحادثة
    activity = ws.run_tool("source_activity", {"source_ip": ATTACKER})
    assert activity["web"]["requests"] == 25 and activity["web"]["statuses"] == {"401": 25}
    assert len(ws.run_tool("sample_requests", {"source_ip": ATTACKER})["lines"]) == 10


def test_incident_status_follows_decisions(store, tmp_path):
    inc = brute_incident(store)
    ws, _ = investigate(store, inc, tmp_path)
    ws.sync_incident_status()
    assert store.incident(inc)["status"] == "investigating"
    decide(ws, next(iter(ws.proposals)), "approve")
    ws.sync_incident_status()
    assert store.incident(inc)["status"] == "closed"


def test_incident_without_proposals_closes(store, tmp_path):
    inc = anomaly_incident(store)
    ws, _ = investigate(store, inc, tmp_path)
    ws.sync_incident_status()
    assert store.incident(inc)["status"] == "closed"


def test_log_tool_specs():
    ws_specs = LogWorkspace.tool_specs_static()
    assert all(t["strict"] for t in ws_specs)
    report = next(t for t in ws_specs if t["name"] == "submit_report")
    assert report["input_schema"]["properties"]["attack_types"]["items"]["enum"] == LOG_TYPES
