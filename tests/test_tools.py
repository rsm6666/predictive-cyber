import json

import pytest

from agent.tools import (TOOL_SPECS, ToolError, Workspace, check_policy, decide,
                         rules_proposals, run_tool)

TRUTH_KEYS = {"family", "attack_label", "Label", "attack_flows", "attack_next_window"}


def _keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys(v)


@pytest.fixture
def ws(resources, portscan):
    return Workspace(portscan, resources)


def attacker(ws):
    return next(iter(ws.sources))      # المصدر الأكثر اتصالات هجومية (172.16.0.1)


def test_read_tools_return_plain_json_without_truth(ws):
    ip = attacker(ws)
    for name, args in [("incident_overview", {}), ("suspicious_sources", {}),
                       ("explain_source", {"source_ip": ip}), ("forecast_next_minute", {}),
                       ("check_policy", {"source_ip": ip})]:
        out = run_tool(ws, name, args)
        json.dumps(out)                                  # يفشل لو بقيت أنواع numpy
        assert not TRUTH_KEYS & set(_keys(out)), name


def test_all_tools_are_strict():
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in TOOL_SPECS)


def test_unknown_source_is_tool_error(ws):
    with pytest.raises(ToolError):
        run_tool(ws, "explain_source", {"source_ip": "1.2.3.4"})


def test_non_suspicious_source_is_capped_at_monitor(ws):
    ip = next(i for i in ws.flows["source_ip"].unique() if i not in ws.sources)
    assert check_policy(ws, ip)["max_action"] == "monitor"


def test_propose_cannot_escalate_beyond_policy(ws):
    ip = attacker(ws)
    assert check_policy(ws, ip)["max_action"] == "block_ip"
    out = run_tool(ws, "propose_action", {"source_ip": ip, "action": "quarantine_host", "justification": "x"})
    assert out["accepted"] is False and ws.proposals == {}


def test_propose_registers_pending_without_applying(ws):
    out = run_tool(ws, "propose_action", {"source_ip": attacker(ws), "action": "block_ip", "justification": "x"})
    assert out["accepted"] and ws.proposals[out["proposal_id"]].status == "pending"
    assert ws.firewall.rules == []


def test_duplicate_pending_proposal_is_refused(ws):
    args = {"source_ip": attacker(ws), "action": "block_ip", "justification": "x"}
    run_tool(ws, "propose_action", args)
    assert run_tool(ws, "propose_action", args)["accepted"] is False


def test_approve_applies_and_reject_rejects(ws):
    ip = attacker(ws)
    pid = run_tool(ws, "propose_action", {"source_ip": ip, "action": "block_ip", "justification": "x"})["proposal_id"]
    assert decide(ws, pid, "approve")["status"] == "applied" and len(ws.firewall.rules) == 1
    assert decide(ws, pid, "approve")["status"] == "applied"          # لا تنفيذ مزدوج
    other = run_tool(ws, "propose_action", {"source_ip": ip, "action": "monitor", "justification": "y"})
    assert other["accepted"] is True
    assert decide(ws, other["proposal_id"], "reject")["status"] == "rejected"


def test_allowlist_is_enforced_at_execution(ws):
    ip = attacker(ws)
    pid = run_tool(ws, "propose_action", {"source_ip": ip, "action": "block_ip", "justification": "x"})["proposal_id"]
    ws.firewall.allowlist.add(ip)
    assert decide(ws, pid, "approve")["status"] == "refused"
    assert ws.firewall.rules == []


def test_rules_proposals_match_static_policy(ws):
    props = rules_proposals(ws)
    assert props and all(p.status == "pending" for p in props)
    assert next(p for p in props if p.source_ip == attacker(ws)).action == "block_ip"
