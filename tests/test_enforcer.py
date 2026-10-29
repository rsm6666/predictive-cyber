import json
from types import SimpleNamespace

import pytest

from enforcer.receiver import Enforcer
from notify.channels import webhook_request

NOW = 1_800_000_000
SECRET = "sec"


def request(data, event="action.execute", delivery="d1", secret=SECRET, now=NOW):
    _, headers, body = webhook_request("http://x", secret, delivery, event, "t_a", data, now=now)
    return headers, body


BLOCK = {"incident_id": "log-1", "proposal_id": 1, "action": "block_ip", "ip": "185.220.101.7", "duration_min": 60}


class Runner:
    def __init__(self, code=0):
        self.calls, self.code = [], code

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return SimpleNamespace(returncode=self.code, stdout="", stderr="boom" if self.code else "")


def make(**kw):
    scheduled = []
    e = Enforcer(SECRET, clock=lambda: NOW, schedule=lambda delay, fn: scheduled.append((delay, fn)), **kw)
    e.scheduled = scheduled
    return e


def test_dry_run_returns_command_without_running():
    runner = Runner()
    code, out = make(runner=runner).handle(*request(BLOCK))
    assert code == 200 and out["status"] == "dry_run" and out["detail"] == "ufw insert 1 deny from 185.220.101.7 to any"
    assert runner.calls == []


def test_apply_runs_ufw_without_shell_and_schedules_removal():
    runner = Runner()
    e = make(apply=True, runner=runner)
    code, out = e.handle(*request(BLOCK))
    assert out["status"] == "applied" and runner.calls == [["ufw", "insert", "1", "deny", "from", "185.220.101.7", "to", "any"]]
    delay, remove = e.scheduled[0]
    assert delay == 3600
    remove()
    assert runner.calls[-1] == ["ufw", "delete", "deny", "from", "185.220.101.7", "to", "any"]


def test_failed_ufw_is_refused():
    assert make(apply=True, runner=Runner(code=1)).handle(*request(BLOCK))[1]["status"] == "refused"


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "192.168.1.9", "not-an-ip"])
def test_private_and_invalid_addresses_are_refused(ip):
    assert make().handle(*request({**BLOCK, "ip": ip}))[1]["status"] == "refused"


def test_local_allowlist_is_refused():
    out = make(allowlist=["185.220.101.7"]).handle(*request(BLOCK))[1]
    assert out["status"] == "refused" and "محمي" in out["detail"]


def test_unsupported_action_is_refused():
    out = make().handle(*request({**BLOCK, "action": "rate_limit_target"}))[1]
    assert out["status"] == "refused" and "غير مدعوم" in out["detail"]


def test_bad_signature_and_stale_message_rejected():
    assert make().handle(*request(BLOCK, secret="wrong"))[0] == 401
    assert make().handle(*request(BLOCK, now=NOW - 301))[0] == 401
    headers, body = request(BLOCK)
    assert make().handle(headers, body.replace(b"185.220.101.7", b"185.220.101.8"))[0] == 401


def test_duplicate_delivery_is_ignored():
    runner = Runner()
    e = make(apply=True, runner=runner)
    e.handle(*request(BLOCK))
    code, out = e.handle(*request(BLOCK))
    assert code == 200 and out["status"] == "duplicate" and len(runner.calls) == 1


def test_test_event():
    code, out = make().handle(*request({"tenant_name": "أ"}, event="test", delivery="d9"))
    assert code == 200 and out["status"] == "ok"


def test_active_rule_cap():
    e = make(apply=True, runner=Runner(), max_rules=1)
    e.handle(*request(BLOCK, delivery="a"))
    out = e.handle(*request({**BLOCK, "ip": "91.240.118.33"}, delivery="b"))[1]
    assert out["status"] == "refused" and "سقف" in out["detail"]


def test_other_platform_events_are_acknowledged_not_executed():
    runner = Runner()
    code, out = make(apply=True, runner=runner).handle(*request({"summary": "x"}, event="incident.report"))
    assert code == 200 and out["status"] == "ignored" and runner.calls == []
    assert make().handle(*request({}, event="unknown.event", delivery="z"))[0] == 400
