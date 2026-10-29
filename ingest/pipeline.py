"""
خط معالجة دفعة سجلات لمنشأة واحدة:
تحليل ← تخزين ← احتفاظ ← قواعد على كل الدلاء التي تلمسها الدفعة (من قاعدة
البيانات، فهجوم موزع على دفعتين يُرى كاملًا) ← شذوذ (للويب) ← تنبيهات وحوادث.
"""

import time
from datetime import datetime, timezone

from ingest.parsers import parse_firewall, parse_web
from ingest.rules import BUCKET, firewall_rules, web_rules

SOURCES = ("web", "firewall")


def process_batch(store, detector, source, text, year=None):
    """← {accepted, rejected, alerts, incidents: {incident_id: هل فُتحت جديدة}}"""
    year = year or datetime.now(timezone.utc).year
    events, rejected = [], 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        e = parse_web(raw) if source == "web" else parse_firewall(raw, year)
        if e is None:
            rejected += 1
        else:
            events.append(e)
    out = {"accepted": len(events), "rejected": rejected, "alerts": 0, "incidents": {}}
    if not events:
        return out

    events.sort(key=lambda e: e["ts"])
    start, end = int(events[0]["ts"] // BUCKET) * BUCKET, events[-1]["ts"]
    if source == "web":
        store.insert_web(events)
        alerts = web_rules(store.web_between(start, end))
    else:
        store.insert_fw(events)
        alerts = firewall_rules(store.fw_between(start, end))
    store.prune(now=max(end, time.time()))

    for a in alerts:          # تنبيهات القواعد أولًا، حتى يستبعد نموذج الشذوذ نوافذها من التعلم
        _, inc, new = store.add_alert(a)
        out["incidents"][inc] = out["incidents"].get(inc, False) or new
    if source == "web" and detector is not None:
        for a in detector.update(store, start, end):
            _, inc, new = store.add_alert(a)
            out["incidents"][inc] = out["incidents"].get(inc, False) or new
            alerts.append(a)
    out["alerts"] = len(alerts)
    return out
