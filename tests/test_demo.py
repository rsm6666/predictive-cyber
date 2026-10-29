import json

import pytest

from agent.analyst import chat, run_investigation
from agent.demo import DemoClient
from agent.evaluate import hallucinated_ips, unsupported_numbers
from agent.scenarios import ATTACK_FAMILIES, build_incident
from agent.store import Run
from agent.tools import ENFORCING, Workspace, decide


def investigate(resources, incident, tmp_path):
    ws = Workspace(incident, resources)
    run = Run(incident, ws, save_dir=tmp_path)
    run_investigation(DemoClient(), ws, run)
    return ws, run


@pytest.mark.parametrize("family", ATTACK_FAMILIES)
def test_demo_investigates_every_attack_type(resources, data, tmp_path, family):
    ws, run = investigate(resources, build_incident(*data, family, seed=1), tmp_path)
    assert run.status == "done"
    assert family in run.report["attack_types"]
    tool_text = " ".join(json.dumps(e["result"], ensure_ascii=False) for e in run.events if e["type"] == "step")
    assert hallucinated_ips(run.report, tool_text) == []
    assert unsupported_numbers(run.report, tool_text) == []


def test_demo_blocks_portscan_attacker(resources, portscan, tmp_path):
    ws, run = investigate(resources, portscan, tmp_path)
    enforced = [p for p in ws.proposals.values() if p.action in ENFORCING]
    assert [(p.source_ip, p.action) for p in enforced] == [("172.16.0.1", "block_ip")]
    assert run.report["proposal_ids"] == [enforced[0].id]


def test_demo_benign_traffic_needs_no_action(resources, data, tmp_path):
    ws, run = investigate(resources, build_incident(*data, "BENIGN", seed=3), tmp_path)
    assert run.status == "done" and ws.proposals == {}
    assert run.report["attack_types"] == [] and run.report["severity"] in ("none", "low")


def test_demo_chat_follows_decisions(resources, portscan, tmp_path):
    ws, run = investigate(resources, portscan, tmp_path)
    client = DemoClient()
    assert "بانتظار موافقتك" in chat(client, ws, run, "هل شبكتي آمنة الحين؟")["reply"]
    decide(ws, run.report["proposal_ids"][0], "approve")
    assert "تحت السيطرة" in chat(client, ws, run, "هل شبكتي آمنة الحين؟")["reply"]
    assert "172.16.0.1" in chat(client, ws, run, "ليش اقترحت الحظر؟")["reply"]
