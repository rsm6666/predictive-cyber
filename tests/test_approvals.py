import json

import pytest

from notify.service import Notifier
from notify.signing import verify
from tenancy.approvals import ApprovalTokens
from tenancy.store import TenantStore

NOW = 1_800_000_000
TID = "t_abcdefghijkl"


@pytest.fixture
def tokens(tmp_path):
    clock = [NOW]
    t = ApprovalTokens(tmp_path / "registry.db", clock=lambda: clock[0])
    t.clock_ref = clock
    return t


def test_token_stored_hashed_and_single_use(tokens, tmp_path):
    token = tokens.issue(TID, "log-1", 3)
    assert token.encode() not in (tmp_path / "registry.db").read_bytes()
    assert tokens.peek(token) == {"tenant_id": TID, "incident_id": "log-1", "proposal_id": 3}
    assert tokens.peek(token) is not None                      # النظر لا يستهلك
    assert tokens.consume(token)["proposal_id"] == 3
    assert tokens.consume(token) is None and tokens.peek(token) is None
    assert tokens.peek("nope") is None


def test_token_expires(tokens):
    token = tokens.issue(TID, "log-1", 1)
    tokens.clock_ref[0] = NOW + ApprovalTokens.TTL + 1
    assert tokens.peek(token) is None and tokens.consume(token) is None


class FakeTransport:
    def __init__(self, responses=None):
        self.requests, self.responses = [], list(responses or [])

    def __call__(self, url, headers, body, timeout):
        self.requests.append((url, headers, body))
        return self.responses.pop(0) if self.responses else (200, "ok")


@pytest.fixture
def store(tmp_path):
    return TenantStore(tmp_path / "tenants")


def make(store, transport):
    return Notifier(store, transport=transport, clock=lambda: NOW)


def test_emit_without_channels_does_nothing(store):
    n = make(store, FakeTransport())
    assert n.emit(TID, "test", {"tenant_name": "أ"}) == []


def test_emit_and_dispatch_both_channels(store):
    store.save_settings(TID, {"webhook_url": "https://hooks.example.test/x", "webhook_secret": "sec",
                              "telegram_token": "123:ABC", "telegram_chat_id": "42"})
    transport = FakeTransport()
    n = make(store, transport)
    assert len(n.emit(TID, "test", {"tenant_name": "أ"})) == 2
    n.dispatch_once()
    urls = sorted(u for u, _, _ in transport.requests)
    assert urls == ["https://api.telegram.org/bot123:ABC/sendMessage", "https://hooks.example.test/x"]
    _, headers, body = next(r for r in transport.requests if "hooks" in r[0])
    assert verify("sec", headers["X-PC-Timestamp"], body, headers["X-PC-Signature"], now=NOW)
    assert [d["status"] for d in n.recent(TID)] == ["delivered", "delivered"]


def test_execute_goes_to_webhook_only_and_reports_result(store):
    store.save_settings(TID, {"webhook_url": "https://hooks.example.test/x", "webhook_secret": "sec",
                              "telegram_token": "123:ABC", "telegram_chat_id": "42"})
    transport = FakeTransport([(200, json.dumps({"status": "dry_run", "detail": "ufw insert 1 deny from 203.0.113.7"}))])
    n = make(store, transport)
    seen = []
    n.on_result = lambda tid, data, resp: seen.append((tid, data["proposal_id"], resp["status"]))
    n.emit(TID, "action.execute", {"incident_id": "log-1", "proposal_id": 2, "ip": "203.0.113.7"}, only="webhook")
    n.dispatch_once()
    assert len(transport.requests) == 1 and seen == [(TID, 2, "dry_run")]


def test_failed_send_is_retried_later(store):
    store.save_settings(TID, {"webhook_url": "https://hooks.example.test/x", "webhook_secret": "sec"})
    transport = FakeTransport([(500, "boom")])
    n = make(store, transport)
    n.emit(TID, "test", {})
    n.dispatch_once()
    row = n.recent(TID)[0]
    assert row["status"] == "pending" and row["attempts"] == 1 and "500" in row["last_error"]
    n.dispatch_once()                                # لم يحن موعد المحاولة التالية
    assert len(transport.requests) == 1
