"""
===================================================================
تقييم ربط الحملات بحقيقة معروفة (بلا API وبلا تكلفة)
===================================================================
لكل بذرة ولكل حالة (حُمّل الملف المكشوف أو لا): خط زمني على قاعدة منشأة مؤقتة،
عبر نفس الرابط الذي تستدعيه المنصة بعد كل تحقيق وعند فتح حادثة مراقبة:
  حملة:  ملف /.env مكشوف ← فحص منافذ (شبكة) ← فحص مسارات (سجلات) ← تخمين بعد ساعات
  طُعوم: مهاجم آخر في نفس اليوم، مهاجم عاد بعد أكثر من 24 ساعة، عنوان في القائمة
         البيضاء في الشبكة والسجلات، وطلب /.env من عنوان بلا حادثة
يقيس: دقة الربط على أزواج الحوادث، والموافقات الموفّرة، ووسم التحميل الفعلي critical.

  python -m campaign.evaluate
النتائج: eval_results/campaign_linking.json و docs/results/campaign_linking.md
===================================================================
"""

import ipaddress
import json
import tempfile
from itertools import combinations
from pathlib import Path

import numpy as np

from campaign.linker import link
from ingest.store import LogStore

ROOT = Path(__file__).resolve().parent.parent
SEEDS = (1, 2, 3, 4, 5)
T0 = 1_800_000_000.0
H = 3600


def _ips(rng, n):
    out = set()
    while len(out) < n:
        ip = ipaddress.ip_address(int(rng.integers(1 << 24, 223 << 24)))
        if ip.is_global:
            out.add(str(ip))
    return sorted(out)


def _alert(type_, ip, ts, severity, source):
    return {"type": type_, "source": source, "ip": ip, "first_ts": ts, "last_ts": ts + 60, "count": 40,
            "severity": severity, "evidence": [], "details": {}}


def _web(ts, ip, path, status):
    return {"ts": ts, "ip": ip, "method": "GET", "path": path, "status": status, "bytes": 90, "referer": "-", "ua": "x"}


def scenario(store, rng, downloaded):
    """يبني الخط الزمني ويربط كما تفعل المنصة. ← (الحقيقة: الحوادث في الحملة، كل الحوادث، عنوان المهاجم)"""
    a, b, c, d, e = _ips(rng, 5)
    j = lambda lo, hi: float(rng.uniform(lo, hi))
    events = []        # (الوقت، نوع الحدث، المعطيات)
    events.append((T0 - j(2.5, 3.5) * H, "monitor", None))
    events.append((T0, "network", _alert("net_scan", a, T0, "medium", "network")))
    scan_at = T0 + j(10, 60) * 60
    events.append((scan_at, "log", _alert("path_scan", a, scan_at, "medium", "web")))
    events.append((T0 + j(2.8, 3.2) * H, "log", _alert("flood", b, 0, "critical", "web")))           # مهاجم آخر
    events.append((T0 + j(4, 5) * H, "log", _alert("brute_force", a, 0, "high", "web")))
    events.append((T0 + j(7.5, 8.5) * H, "network", _alert("net_scan", c, 0, "medium", "network")))
    events.append((T0 + j(34, 40) * H, "log", _alert("brute_force", c, 0, "high", "web")))         # عاد بعد > 24 ساعة
    d_at = T0 + j(11.5, 12.5) * H
    events.append((d_at, "network", _alert("net_flood", d, 0, "high", "network")))                 # قائمة بيضاء
    events.append((d_at + 600, "log", _alert("flood", d, 0, "critical", "web")))

    store.insert_web([_web(scan_at + 5, a, "/.env", 200 if downloaded else 404),
                      _web(T0 + j(1, 2) * H, e, "/.env", 200)])                                    # بلا حادثة
    truth, everything = set(), []
    for ts, kind, al in sorted(events, key=lambda x: x[0]):
        if kind == "monitor":
            inc = store.open_incident({"type": "exposed_file", "source": "monitor", "ip": "shop.example",
                                       "first_ts": ts, "last_ts": ts, "count": 1, "severity": "high", "evidence": [],
                                       "details": {"url": "http://shop.example", "detail": "/.env", "path": "/.env"}})
            truth.add(inc)          # المهاجم طلب مساره (200 أو 404) ← القاعدة 2
        else:
            al = {**al, "first_ts": ts, "last_ts": ts + 60}
            inc = store.add_alert(al, kind=kind)[1]
            if al["ip"] == a:
                truth.add(inc)
        everything.append(inc)
        link(store, inc, allowlist=[d])
    return truth, list(dict.fromkeys(everything)), a


def _pairs(groups):
    return {frozenset(p) for g in groups for p in combinations(sorted(g), 2)}


def evaluate():
    rows = []
    for seed in SEEDS:
        for downloaded in (True, False):
            with tempfile.TemporaryDirectory() as tmp:
                store = LogStore(Path(tmp) / "t.db")
                truth, incidents, attacker = scenario(store, np.random.default_rng(seed), downloaded)
                camps = {}
                for i in incidents:
                    cid = store.incident(i)["campaign"]
                    if cid:
                        camps.setdefault(cid, set()).add(i)
                predicted, expected = _pairs(camps.values()), _pairs([truth])
                attacker_incidents = [i for i in incidents if store.incident(i)["kind"] != "monitor"
                                      and any(al["ip"] == attacker for al in store.alerts(i))]
                camp_of_truth = {store.incident(i)["campaign"] for i in truth}
                severity = store.incident(next(iter(camp_of_truth))).get("severity") if len(camp_of_truth) == 1 else None
                rows.append({"seed": seed, "downloaded": downloaded, "campaigns": len(camps),
                             "true_pairs": len(expected), "predicted_pairs": len(predicted),
                             "correct_pairs": len(predicted & expected),
                             "approvals_before": len(attacker_incidents), "approvals_after": 1 if camps else None,
                             "critical": severity == "critical"})
    return rows


def summarize(rows):
    correct = sum(r["correct_pairs"] for r in rows)
    pred, true = sum(r["predicted_pairs"] for r in rows), sum(r["true_pairs"] for r in rows)
    return {"scenarios": len(rows), "precision": correct / pred if pred else 0.0, "recall": correct / true if true else 0.0,
            "one_campaign": float(np.mean([r["campaigns"] == 1 for r in rows])),
            "approvals_before": float(np.mean([r["approvals_before"] for r in rows])),
            "downloads_critical": float(np.mean([r["critical"] for r in rows if r["downloaded"]])),
            "no_download_critical": float(np.mean([r["critical"] for r in rows if not r["downloaded"]]))}


def to_markdown(s):
    pct = lambda v: f"{v:.0%}"
    return "\n".join([
        f"# تقييم ربط الحملات ({len(SEEDS)} بذور × حالتان = {s['scenarios']} سيناريو)", "",
        "| المقياس | النتيجة |", "|---|---|",
        f"| دقة الربط (precision) على أزواج الحوادث | {pct(s['precision'])} |",
        f"| استرجاع الربط (recall) | {pct(s['recall'])} |",
        f"| سيناريوهات تكوّنت فيها حملة واحدة فقط (لا طُعم مربوط) | {pct(s['one_campaign'])} |",
        f"| الموافقات لكل مهاجم: قبل ← بعد | {s['approvals_before']:.0f} ← 1 |",
        f"| تحميل فعلي للملف المكشوف وُسم critical | {pct(s['downloads_critical'])} |",
        f"| طلب الملف بلا تحميل (404) وُسم critical | {pct(s['no_download_critical'])} |", "",
        "- الحملة: ملف ‎/.env مكشوف، ثم فحص منافذ من الشبكة، ثم فحص مسارات في السجلات، ثم تخمين بعد ساعات، من عنوان واحد.",
        "- الطُعوم في نفس الأيام: مهاجم آخر، مهاجم عاد بعد أكثر من 24 ساعة، عنوان في القائمة البيضاء ظهر في "
        "الشبكة والسجلات، وطلب ‎/.env برد 200 من عنوان بلا حادثة.",
        "- في حالة «بلا تحميل» طلب المهاجم ‎/.env برد 404: تبقى حادثة المراقبة مربوطة (طلب المسار نفسه دليل) "
        "لكن الحملة لا تُرفع إلى critical.", "",
        "قيد: السيناريوهات مركّبة بأوقات وعناوين عشوائية لكل بذرة، فالأرقام تقيس منطق القواعد على حالات "
        "معروفة الحقيقة، لا دقة الربط على حملات حقيقية. التجميع داخل النوع خلال 30 دقيقة قد يضم عناوين "
        "أخرى إلى حادثة عضو؛ المنسّق يقرر لكل عنوان على حدة.",
    ]) + "\n"


def main():
    rows = evaluate()
    s = summarize(rows)
    (ROOT / "eval_results").mkdir(exist_ok=True)
    (ROOT / "eval_results" / "campaign_linking.json").write_text(
        json.dumps({"summary": s, "rows": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "docs" / "results" / "campaign_linking.md").write_text(to_markdown(s), encoding="utf-8")
    print(to_markdown(s))


if __name__ == "__main__":
    main()
