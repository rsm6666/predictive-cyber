import json

import pytest

from notify.channels import is_local_url, telegram_request, webhook_request
from notify.outbox import BACKOFF, MAX_ATTEMPTS, Outbox
from notify.signing import sign, verify

NOW = 1_800_000_000


def test_signature_roundtrip_and_tamper():
    body = b'{"a": 1}'
    sig = sign("s3cret", NOW, body)
    assert sig.startswith("sha256=") and verify("s3cret", str(NOW), body, sig, now=NOW)
    assert not verify("s3cret", str(NOW), b'{"a": 2}', sig, now=NOW)
    assert not verify("other", str(NOW), body, sig, now=NOW)


def test_signature_rejects_stale_future_and_garbage_timestamps():
    body = b"x"
    assert not verify("s", str(NOW - 301), body, sign("s", NOW - 301, body), now=NOW)
    assert not verify("s", str(NOW + 61), body, sign("s", NOW + 61, body), now=NOW)
    assert not verify("s", "abc", body, sign("s", NOW, body), now=NOW)


@pytest.fixture
def outbox(tmp_path):
    return Outbox(tmp_path / "tenant.db")


def test_enqueue_due_and_deliver(outbox):
    d = outbox.enqueue("test", "webhook", {"x": 1}, now=NOW)
    assert [x["id"] for x in outbox.due(NOW)] == [d] and outbox.due(NOW)[0]["payload"] == {"x": 1}
    outbox.delivered(d, "ok")
    assert outbox.due(NOW) == [] and outbox.recent()[0]["status"] == "delivered"


def test_retry_schedule_then_failed(outbox):
    d = outbox.enqueue("test", "webhook", {}, now=NOW)
    t = NOW
    for i in range(MAX_ATTEMPTS - 1):
        assert outbox.attempt_failed(d, "timeout", now=t) == "pending"
        assert outbox.due(t + BACKOFF[i] - 1) == [] and outbox.due(t + BACKOFF[i])
        t += BACKOFF[i]
    assert outbox.attempt_failed(d, "timeout", now=t) == "failed"
    row = outbox.recent()[0]
    assert row["status"] == "failed" and row["attempts"] == MAX_ATTEMPTS and row["last_error"] == "timeout"


def test_webhook_request_is_signed():
    url, headers, body = webhook_request("https://hooks.example.test/x", "sec", "d1", "action.execute", "t_a",
                                         {"ip": "203.0.113.7"}, now=NOW)
    assert url == "https://hooks.example.test/x" and headers["X-PC-Event"] == "action.execute"
    assert verify("sec", headers["X-PC-Timestamp"], body, headers["X-PC-Signature"], now=NOW)
    assert json.loads(body)["data"]["ip"] == "203.0.113.7"


REPORT = {"tenant_name": "متجر التمور", "incident_id": "log-1", "severity": "high",
          "summary": "رصدنا <تخمين> كلمات مرور", "proposals": [
              {"id": 1, "source_ip": "203.0.113.7", "action": "block_ip", "duration_min": 60,
               "approve_url": "https://shop.example/approve/tok"}]}


def test_telegram_report_with_buttons_for_public_url():
    url, _, body = telegram_request("123:ABC", "42", "incident.report", REPORT)
    msg = json.loads(body)
    assert url == "https://api.telegram.org/bot123:ABC/sendMessage" and msg["chat_id"] == "42"
    assert "متجر التمور" in msg["text"] and "&lt;تخمين&gt;" in msg["text"] and msg["parse_mode"] == "HTML"
    row = msg["reply_markup"]["inline_keyboard"][0]
    assert row[0]["url"] == "https://shop.example/approve/tok?d=approve" and row[1]["url"].endswith("?d=reject")


def test_telegram_report_without_buttons_for_local_url():
    local = {**REPORT, "proposals": [{**REPORT["proposals"][0], "approve_url": "http://localhost:8001/approve/tok"}]}
    msg = json.loads(telegram_request("t", "42", "incident.report", local)[2])
    assert "reply_markup" not in msg and "http://localhost:8001/approve/tok" in msg["text"]


def test_local_url_detection():
    assert is_local_url("http://localhost:8001/x") and is_local_url("http://127.0.0.1/x")
    assert is_local_url("http://192.168.1.5/x") and not is_local_url("https://shop.example/x")
