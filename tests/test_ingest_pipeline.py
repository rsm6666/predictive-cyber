from datetime import datetime, timezone

import pytest

from ingest.anomaly import AnomalyDetector
from ingest.pipeline import process_batch
from ingest.store import LogStore

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc).timestamp()


def line(i, ip="203.0.113.7", path="/login", status=401, method="POST"):
    t = datetime.fromtimestamp(T0 + i, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} 10 "-" "python-requests/2.31"'


@pytest.fixture
def ctx(tmp_path):
    return LogStore(tmp_path / "tenant.db"), AnomalyDetector(tmp_path / "anomaly.joblib")


def run(ctx, lines, source="web"):
    store, det = ctx
    return process_batch(store, det, source, "\n".join(lines), year=2026)


def test_clean_batch_has_no_alerts(ctx):
    out = run(ctx, [line(i, path="/products", status=200, method="GET") for i in range(50)])
    assert out == {"accepted": 50, "rejected": 0, "alerts": 0, "incidents": {}}


def test_brute_force_opens_incident_and_counts_rejects(ctx):
    out = run(ctx, [line(i) for i in range(25)] + ["garbage", ""])
    assert out["accepted"] == 25 and out["rejected"] == 1 and out["alerts"] == 1
    (inc, new), = out["incidents"].items()
    assert new and ctx[0].alerts(inc)[0]["type"] == "brute_force"


def test_attack_split_across_batches_is_detected(ctx):
    assert run(ctx, [line(i) for i in range(12)])["alerts"] == 0
    assert run(ctx, [line(i) for i in range(12, 24)])["alerts"] == 1


def test_resending_same_batch_does_not_duplicate_alerts(ctx):
    batch = [line(i) for i in range(25)]
    first = run(ctx, batch)
    second = run(ctx, batch)
    inc = next(iter(first["incidents"]))
    assert second["incidents"] == {inc: False} and len(ctx[0].alerts(inc)) == 1


def test_firewall_batch(ctx):
    fw = [f"Oct 26 12:00:{i % 60:02d} shop kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.9 DST=10.0.0.5 PROTO=TCP SPT=4000 DPT={1000 + i}"
          for i in range(25)]
    out = run(ctx, fw, source="firewall")
    assert out["accepted"] == 25 and ctx[0].alerts(next(iter(out["incidents"])))[0]["type"] == "fw_port_scan"
