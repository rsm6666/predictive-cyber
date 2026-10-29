"""
===================================================================
الكشف على نافذة من تدفقات وكيل الخادم
===================================================================
طبقتان تفتحان التنبيه:
  1) الكاشف السلوكي (behavioral_detector.py بعتباته) ← net_scan/net_sweep/net_brute/net_flood/net_ddos
  2) النموذج بحاجز الأدلة (عتبات sandbox_firewall) ← net_model بنوع الهجوم
ورأي النموذج مرفق بكل تنبيه سلوكي دليلًا داعمًا. LSTM لا يفتح تنبيهًا (forecast).

تكييف DDoS لسياق الخادم: «مصادر كثيرة لهدف واحد» هو كل دقيقة عادية على
خادم عام، فنطلب معه حجمًا ≥ 1000 تدفق و≥ 5 أضعاف وسيط النوافذ السابقة.
===================================================================
"""

import statistics

from act_demo import aggregate_by_source
from behavioral_detector import behavioral_pass
from sandbox_firewall import MIN_ATTACK_RATIO, MIN_CONFIDENCE, MIN_FLOWS

from agent.tools import ToolError

NET_TYPE = {"PortScan": "net_scan", "UDPScan": "net_scan", "StealthScan": "net_scan", "HostSweep": "net_sweep",
            "BruteForce": "net_brute", "DoS": "net_flood", "SYNFlood": "net_flood", "ICMPFlood": "net_flood",
            "DDoS": "net_ddos"}
NET_SEVERITY = {"net_scan": "medium", "net_sweep": "medium", "net_brute": "high", "net_flood": "critical",
                "net_ddos": "critical"}
FAMILY_SEVERITY = {"DoS": "critical", "DDoS": "critical", "Botnet": "critical", "Brute Force (FTP/SSH)": "high",
                   "Web Attack": "high", "PortScan": "medium"}
DDOS_MIN_FLOWS = 1000
DDOS_BASELINE_FACTOR = 5
DDOS_MIN_HISTORY = 3
SEQ = 10


def _ddos_volume_ok(target_flows, previous_totals):
    if target_flows < DDOS_MIN_FLOWS or len(previous_totals) < DDOS_MIN_HISTORY:
        return False
    return target_flows >= DDOS_BASELINE_FACTOR * statistics.median(previous_totals)


def detect_window(df, res, start, end, previous_totals=()):
    """df: تدفقات النافذة (NetStore.flows_between). ← تنبيهات بصيغة LogStore.add_alert."""
    if df.empty:
        return []
    proba = res.model.predict_proba(df[res.feature_names])
    flows = df.assign(pred=res.model.classes_[proba.argmax(axis=1)], conf=proba.max(axis=1))
    per_source = {s["source_ip"]: s for s in aggregate_by_source(flows)}

    def model_view(ip):
        s = per_source.get(ip)
        if s is None:
            return {"verdict": "BENIGN"}
        return {"verdict": s["attack_type"], "flows": int(s["n_flows"]),
                "attack_ratio": round(float(s["attack_ratio"]), 2), "confidence": round(float(s["mean_confidence"]), 2)}

    alerts = {}
    for b in behavioral_pass(df):
        kind = NET_TYPE.get(b["type"])
        if kind is None:
            continue
        if kind == "net_ddos" and not _ddos_volume_ok(int((df["_dst"] == b["entity"]).sum()), previous_totals):
            continue
        key = (kind, b["entity"])
        if key not in alerts:
            alerts[key] = {"type": kind, "source": "network", "ip": b["entity"], "first_ts": start, "last_ts": end,
                           "count": int((df["_src"] == b["entity"]).sum()) or int((df["_dst"] == b["entity"]).sum()),
                           "severity": NET_SEVERITY[kind], "evidence": [],
                           "details": {"patterns": [], "model": model_view(b["entity"])}}
        alerts[key]["evidence"].append(b["evidence"])
        alerts[key]["details"]["patterns"].append(b["type"])

    for ip, s in per_source.items():
        if s["n_flows"] >= MIN_FLOWS and s["mean_confidence"] >= MIN_CONFIDENCE and s["attack_ratio"] >= MIN_ATTACK_RATIO:
            alerts[("net_model", ip)] = {
                "type": "net_model", "source": "network", "ip": ip, "first_ts": start, "last_ts": end,
                "count": int(s["n_flows"]), "severity": FAMILY_SEVERITY.get(s["attack_type"], "high"),
                "evidence": [f"صنّف النموذج {int(s['n_flows'])} تدفقًا «{s['attack_type']}» بنسبة "
                             f"{s['attack_ratio']:.0%} من تدفقاته وثقة {s['mean_confidence']:.0%}"],
                "details": {"family": s["attack_type"], "model": model_view(ip), "target": s["top_target"]}}
    return list(alerts.values())


def forecast(net_store, res, now):
    """مؤشر LSTM على آخر 10 نوافذ؛ لا يفتح حادثة."""
    w = net_store.windows(until=now, limit=SEQ)
    if len(w) < SEQ:
        return {"state": "learning", "windows": len(w), "needed": SEQ}
    try:
        p = float(res.forecast_fn(w[res.forecast_cols].values))
    except ToolError as e:
        return {"state": "unavailable", "detail": str(e)}
    return {"state": "ready", "probability": round(p, 3), "threshold": round(res.threshold, 3),
            "alert": p >= res.threshold}


def process_flows(net_store, log_store, res, batch, received_at):
    """دفعة نافذة واحدة مُتحقق منها ← تخزين ← كشف ← تنبيهات وحوادث شبكية."""
    out = {"accepted": len(batch["flows"]), "duplicate": False, "alerts": 0, "incidents": {}}
    start, end = batch["window_start"], batch["window_end"]
    previous = [float(v) for v in net_store.windows(until=start - 1, limit=SEQ)["total_flows"]]
    if not net_store.add_window(batch, received_at):
        out["duplicate"] = True
        return out
    net_store.prune(now=max(end, received_at))
    alerts = detect_window(net_store.flows_between(start, end), res, start, end, previous)
    for a in alerts:
        _, inc, new = log_store.add_alert(a, kind="network")
        out["incidents"][inc] = out["incidents"].get(inc, False) or new
    out["alerts"] = len(alerts)
    return out
