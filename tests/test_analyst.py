import pytest
from fakes import REPORT, FakeClient, block, reply, tool_use

from agent.analyst import FALLBACK_BETA, MAX_STEPS, MODEL, AgentError, chat, run_investigation
from agent.store import Run
from agent.tools import READ_TOOLS, Workspace


@pytest.fixture
def setup(resources, portscan, tmp_path):
    ws = Workspace(portscan, resources)
    return ws, Run(portscan, ws, save_dir=tmp_path)


def test_investigation_streams_steps_then_report(setup, tmp_path):
    ws, run = setup
    client = FakeClient([reply(tool_use("incident_overview")),
                         reply(tool_use("suspicious_sources")),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert [e["type"] for e in run.events] == ["step", "step", "report", "done"]
    assert run.status == "done" and run.report["severity"] == "high"
    assert run.events[-1]["truth_family"] == "PortScan"
    assert (tmp_path / f"{run.incident.id}.json").exists()


def test_request_shape(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    kw = client.calls[0]
    assert kw["model"] == MODEL and kw["fallbacks"] == "default" and FALLBACK_BETA in kw["betas"]
    assert "tool_choice" not in kw and "thinking" not in kw
    assert all(t["strict"] for t in kw["tools"])


def test_tool_error_does_not_stop_investigation(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("explain_source", {"source_ip": "1.2.3.4"})),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert run.events[0]["is_error"] and "غير موجود" in run.events[0]["result"]["error"]
    assert run.status == "done"


def test_step_limit_turns_tools_into_errors(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("incident_overview")) for _ in range(MAX_STEPS + 1)]
                        + [reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert sum(e["type"] == "step" for e in run.events) == MAX_STEPS
    results = [m["content"][0] for m in client.calls[-1]["messages"]
               if m["role"] == "user" and isinstance(m["content"], list)]
    assert results[MAX_STEPS - 1]["is_error"] is False
    assert results[MAX_STEPS]["is_error"] is True
    assert run.status == "done"


def test_text_only_reply_is_reprompted(setup):
    ws, run = setup
    client = FakeClient([reply(block("text", text="انتهيت")),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert "submit_report" in client.calls[-1]["messages"][2]["content"]
    assert run.status == "done"


def test_refusal_falls_back_to_rules(setup):
    ws, run = setup
    run_investigation(FakeClient([reply(stop="refusal")]), ws, run)
    err = next(e for e in run.events if e["type"] == "agent_error")
    assert run.status == "failed" and err["proposals"]
    assert run.events[-1]["type"] == "done"


def test_chat_uses_read_tools_only(setup):
    ws, run = setup
    run.report = REPORT
    client = FakeClient([
        reply(tool_use("propose_action", {"source_ip": "172.16.0.1", "action": "block_ip", "justification": "x"})),
        reply(tool_use("check_policy", {"source_ip": "172.16.0.1"})),
        reply(block("text", text="الوضع تحت السيطرة بعد الحظر.")),
    ])
    out = chat(client, ws, run, "هل شبكتي آمنة؟")
    assert out["reply"] == "الوضع تحت السيطرة بعد الحظر." and len(out["steps"]) == 1
    assert ws.proposals == {}
    assert {t["name"] for t in client.calls[0]["tools"]} == set(READ_TOOLS)
    assert run.chat_log[-1] == {"role": "agent", "text": "الوضع تحت السيطرة بعد الحظر."}


def test_chat_keeps_history_append_only(setup):
    ws, run = setup
    client = FakeClient([reply(block("text", text="أ")), reply(block("text", text="ب"))])
    chat(client, ws, run, "سؤال 1")
    first_turns = list(run.chat_messages)
    chat(client, ws, run, "سؤال 2")
    assert run.chat_messages[:len(first_turns)] == first_turns


def test_chat_rolls_back_on_failure(setup):
    ws, run = setup
    with pytest.raises(AgentError):
        chat(FakeClient([reply(stop="refusal")]), ws, run, "سؤال")
    assert run.chat_messages == []
