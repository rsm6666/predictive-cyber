"""
===================================================================
تقييم كشف السجلات بالمولّد (بلا API وبلا تكلفة)
===================================================================
لكل بذرة: يوم تاريخ طبيعي (يتعلم منه نموذج الشذوذ) ← 30 دقيقة فيها كل
الهجمات ← 30 دقيقة نظيفة. البث على دفعات 5 دقائق كما يحدث فعليًا.
يقيس لكل هجوم: هل التقطته قاعدته المقصودة، وهل التقطه نموذج الشذوذ،
والتنبيهات الكاذبة (قواعد وشذوذ) على عناوين بريئة.

  python -m ingest.evaluate
النتائج: eval_results/log_detection.json و .md

قيد معلن: البيانات مولّدة لا حقيقية؛ الأرقام تقيس منطق الكشف على أنماط
معروفة، لا الأداء على ترافيك حقيقي متنوع.
===================================================================
"""

import json
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from ingest.anomaly import AnomalyDetector
from ingest.parsers import parse_firewall, parse_web
from ingest.pipeline import process_batch
from ingest.store import LogStore
from simulate_logs import ATTACKS, EXPECTED_RULE, generate

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "eval_results"
SEEDS = (1, 2, 3, 4, 5)
CHUNK = 300
START = datetime(2026, 10, 20, 0, 0, tzinfo=timezone.utc).timestamp()


def _feed(store, det, web, fw, year):
    """يرسل السطور على دفعات 5 دقائق ← قائمة كل التنبيهات المضافة (النوع، العنوان، الفترة)."""
    chunks = defaultdict(lambda: ([], []))
    for line in web:
        chunks[int(parse_web(line)["ts"] // CHUNK)][0].append(line)
    for line in fw:
        chunks[int(parse_firewall(line, year)["ts"] // CHUNK)][1].append(line)
    for key in sorted(chunks):
        w, f = chunks[key]
        if w:
            process_batch(store, det, "web", "\n".join(w), year=year)
        if f:
            process_batch(store, det, "firewall", "\n".join(f), year=year)


def _alerts(store):
    return [a for inc in store.incidents(limit=10_000) for a in store.alerts(inc["id"])]


def run_seed(seed):
    rng = np.random.default_rng(seed)
    year = 2026
    with tempfile.TemporaryDirectory() as tmp:
        store, det = LogStore(Path(tmp) / "tenant.db"), AnomalyDetector(Path(tmp) / "anomaly.joblib")
        web, fw, _ = generate(START, 24 * 60, rng)
        _feed(store, det, web, fw, year)
        history_ids = {a["id"] for a in _alerts(store)}
        trained = det.status(store)["state"] == "ready"

        t_attack = START + 24 * 3600
        web, fw, labels = generate(t_attack, 30, rng, attacks=ATTACKS, attack_at=600)
        _feed(store, det, web, fw, year)
        web, fw, _ = generate(t_attack + 1800, 30, rng)
        _feed(store, det, web, fw, year)
        live = [a for a in _alerts(store) if a["id"] not in history_ids]
        history = [a for a in _alerts(store) if a["id"] in history_ids]

    attackers = set(labels.values())
    by_ip = defaultdict(set)
    for a in live:
        by_ip[a["ip"]].add(a["type"])
    return {
        "seed": seed, "anomaly_ready": trained,
        "attacks": {k: {"rule": bool(by_ip[ip] - {"anomaly"}), "intended": EXPECTED_RULE[k] in by_ip[ip],
                        "anomaly": "anomaly" in by_ip[ip]} for k, ip in labels.items()},
        "false_rule_alerts": sum(1 for a in live if a["ip"] not in attackers and a["type"] != "anomaly"),
        "false_anomaly_alerts": sum(1 for a in live if a["ip"] not in attackers and a["type"] == "anomaly"),
        "history_rule_alerts": sum(1 for a in history if a["type"] != "anomaly"),
        "history_anomaly_alerts": sum(1 for a in history if a["type"] == "anomaly"),
    }


def summarize(rows):
    n = len(rows)
    per_attack = {k: {"rule_recall": sum(r["attacks"][k]["rule"] for r in rows) / n,
                      "intended_recall": sum(r["attacks"][k]["intended"] for r in rows) / n,
                      "anomaly_recall": sum(r["attacks"][k]["anomaly"] for r in rows) / n,
                      "anomaly_only": sum(r["attacks"][k]["anomaly"] and not r["attacks"][k]["rule"] for r in rows)}
                  for k in ATTACKS}
    return {"seeds": n, "anomaly_ready": sum(r["anomaly_ready"] for r in rows), "per_attack": per_attack,
            "false_rule_alerts_per_hour": sum(r["false_rule_alerts"] for r in rows) / n,
            "false_anomaly_alerts_per_hour": sum(r["false_anomaly_alerts"] for r in rows) / n,
            "history_rule_alerts_per_day": sum(r["history_rule_alerts"] for r in rows) / n,
            "history_anomaly_alerts_per_day": sum(r["history_anomaly_alerts"] for r in rows) / n}


def to_markdown(s):
    lines = [f"# تقييم كشف السجلات ({s['seeds']} بذور، بيانات مولّدة)", "",
             "| الهجوم | الكاشف المقصود | التقطه المقصود | التقطته أي قاعدة | التقطه الشذوذ | الشذوذ وحده (بذور) |",
             "|---|---|---|---|---|---|"]
    for k, v in s["per_attack"].items():
        lines.append(f"| {k} | {EXPECTED_RULE[k]} | {v['intended_recall']:.0%} | {v['rule_recall']:.0%} | "
                     f"{v['anomaly_recall']:.0%} | {v['anomaly_only']} |")
    lines += ["",
              f"- نموذج الشذوذ جاهز بعد يوم التاريخ: {s['anomaly_ready']} من {s['seeds']}",
              f"- تنبيهات قواعد كاذبة في ساعة البث: {s['false_rule_alerts_per_hour']:.1f}",
              f"- تنبيهات شذوذ كاذبة في ساعة البث: {s['false_anomaly_alerts_per_hour']:.1f}",
              f"- تنبيهات أثناء يوم التاريخ الطبيعي: قواعد {s['history_rule_alerts_per_day']:.1f}، "
              f"شذوذ {s['history_anomaly_alerts_per_day']:.1f}",
              "- `scrape` (سحب الكتالوج بإيقاع تحت عتبة الإغراق) بلا قاعدة عمدًا، لقياس ما يضيفه نموذج الشذوذ.",
              "- نوافذ القواعد مستبعدة من تقييم الشذوذ (تفاديًا للتكرار)، فلا يظهر الشذوذ على هجمات التقطتها القواعد.",
              "", "قيد: البيانات مولّدة؛ الأرقام تقيس منطق الكشف على أنماط معروفة لا الأداء على ترافيك حقيقي."]
    return "\n".join(lines) + "\n"


def main():
    rows = []
    for seed in SEEDS:
        rows.append(run_seed(seed))
        print(f"بذرة {seed}: {rows[-1]}")
    summary = summarize(rows)
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "log_detection.json").write_text(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False,
                                                           indent=2), encoding="utf-8")
    (OUT_DIR / "log_detection.md").write_text(to_markdown(summary), encoding="utf-8")
    print(to_markdown(summary))


if __name__ == "__main__":
    main()
