import numpy as np
import pytest

from ingest.anomaly import MIN_WINDOWS, Z_MIN, AnomalyDetector, window_features
from ingest.rules import BUCKET
from ingest.store import LogStore

T0 = 1_800_000_000.0
PAGES = ["/", "/products/1", "/products/2", "/cart", "/static/app.js", "/static/logo.png"]


def normal_windows(rng, buckets, ips_per_bucket=5, start_bucket=0):
    events = []
    for b in range(start_bucket, start_bucket + buckets):
        for k in range(ips_per_bucket):
            ip = f"198.51.{b % 200}.{k + 1}"
            for _ in range(int(rng.integers(6, 15))):
                events.append({"ts": T0 + b * BUCKET + float(rng.uniform(0, BUCKET - 1)), "ip": ip,
                               "method": "GET" if rng.random() > 0.1 else "POST",
                               "path": PAGES[int(rng.integers(len(PAGES)))], "status": 200 if rng.random() > 0.03 else 404,
                               "bytes": int(rng.integers(500, 5000)), "referer": "", "ua": "Mozilla/5.0"})
    return sorted(events, key=lambda e: e["ts"])


def abnormal_window(bucket, ip="203.0.113.66"):
    return [{"ts": T0 + bucket * BUCKET + i, "ip": ip, "method": "GET", "path": f"/x{i}", "status": 404,
             "bytes": 120, "referer": "", "ua": f"bot-{i % 7}"} for i in range(200)]


@pytest.fixture
def store(tmp_path):
    return LogStore(tmp_path / "tenant.db")


def test_window_features():
    f = window_features(abnormal_window(0))
    row = f.iloc[0]
    assert (row["requests"], row["paths"], row["ratio_4xx"], row["agents"]) == (200, 200, 1.0, 7)


def test_learning_below_minimum(store, tmp_path):
    rng = np.random.default_rng(0)
    events = normal_windows(rng, buckets=(MIN_WINDOWS // 5) - 10)
    store.insert_web(events)
    det = AnomalyDetector(tmp_path / "anomaly.joblib")
    assert det.update(store, events[0]["ts"], events[-1]["ts"]) == []
    status = det.status(store)
    assert status["state"] == "learning" and status["windows"] == MIN_WINDOWS - 50 and status["needed"] == MIN_WINDOWS


def test_detects_clear_anomaly_after_learning(store, tmp_path):
    rng = np.random.default_rng(1)
    history = normal_windows(rng, buckets=70)
    store.insert_web(history)
    det = AnomalyDetector(tmp_path / "anomaly.joblib")
    assert det.update(store, history[0]["ts"], history[-1]["ts"]) == []      # نوافذ التدريب لا تُنبَّه
    assert det.status(store)["state"] == "ready"

    live = normal_windows(rng, buckets=1, start_bucket=80) + abnormal_window(80)
    store.insert_web(live)
    alerts = AnomalyDetector(tmp_path / "anomaly.joblib").update(store, T0 + 80 * BUCKET, T0 + 81 * BUCKET)
    assert [a["ip"] for a in alerts] == ["203.0.113.66"]
    a = alerts[0]
    assert a["type"] == "anomaly" and a["severity"] == "medium"
    assert {f["feature"] for f in a["details"]["features"]} & {"requests", "paths", "ratio_4xx"}
    assert abs(a["details"]["features"][0]["z"]) >= Z_MIN


def test_two_visitors_behind_one_address_is_not_anomalous(store, tmp_path):
    rng = np.random.default_rng(5)
    history = normal_windows(rng, buckets=70)
    store.insert_web(history)
    det = AnomalyDetector(tmp_path / "anomaly.joblib")
    det.update(store, history[0]["ts"], history[-1]["ts"])
    nat = [{"ts": T0 + 90 * BUCKET + i * 20, "ip": "198.51.100.200", "method": "GET", "path": PAGES[i % 4],
            "status": 404 if i == 0 else 200, "bytes": 2000, "referer": "", "ua": f"Mozilla/{i % 2}"} for i in range(10)]
    store.insert_web(nat)
    assert det.update(store, T0 + 90 * BUCKET, T0 + 91 * BUCKET) == []


def test_rule_flagged_windows_are_excluded(store, tmp_path):
    rng = np.random.default_rng(2)
    history = normal_windows(rng, buckets=50) + abnormal_window(10)
    store.insert_web(sorted(history, key=lambda e: e["ts"]))
    store.add_alert({"type": "path_scan", "source": "web", "ip": "203.0.113.66", "first_ts": T0 + 10 * BUCKET,
                     "last_ts": T0 + 10 * BUCKET + 199, "count": 200, "severity": "medium", "evidence": [], "details": {}})
    det = AnomalyDetector(tmp_path / "anomaly.joblib")
    det.update(store, T0, T0 + 50 * BUCKET)
    assert det.status(store)["windows"] == 250
