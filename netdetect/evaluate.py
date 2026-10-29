"""
===================================================================
تقييم الكشف الشبكي بإعادة تشغيل CICIDS (بلا API وبلا تكلفة)
===================================================================
لكل بذرة ولكل نوع هجوم: 8 دقائق ترافيك طبيعي، فيها هجوم في الدقيقتين 5 و6 بحجمين
(150 تدفقًا في الدقيقة، ومنخفض 25)،
عبر نفس مسار المنصة (تحقق ← تخزين ← كشف ← حوادث). ثم ساعة طبيعية كاملة.
يقيس: هل رُصد المهاجم، وبأي طبقة (سلوكية/نموذج)، وهل صحّ نوع النموذج،
والتنبيهات على عناوين بريئة.

  python -m netdetect.evaluate
النتائج: eval_results/network_detection.json و docs/results/network_detection.md

قيد معلن: العيّنة من CICIDS2017 بعناوين معاد رسمها (simulate_flows)، فالأرقام
تقيس منطق الكشف على هجمات حقيقية معروفة، لا الأداء على ترافيك منشأة فعلية.
===================================================================
"""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pandas as pd

from ingest.store import LogStore
from netdetect.detect import process_flows
from netdetect.store import NetStore
from netdetect.validate import validate
from simulate_flows import ATTACKERS, ATTACKS, generate

ROOT = Path(__file__).resolve().parent.parent
SEEDS = (1, 2, 3, 4, 5)
START = 1_800_000_000.0
LOW_VOLUME = 25
BEHAVIOURAL = {"net_scan", "net_sweep", "net_brute", "net_flood", "net_ddos"}


def _run(act, res, rng, attack, minutes, per_minute=150, attack_at=4):
    with tempfile.TemporaryDirectory() as d:
        net, logs = NetStore(Path(d) / "t.db"), LogStore(Path(d) / "t.db")
        for b in generate(act, minutes, START, rng, attack=attack, attack_at=attack_at, attack_minutes=2,
                          attack_per_minute=per_minute):
            process_flows(net, logs, res, validate(json.dumps(b), now=b["window_end"]), received_at=b["window_end"])
        return [a for i in logs.incidents() for a in logs.alerts(i["id"])]


def evaluate(act, res):
    rows = []
    for seed in SEEDS:
        for (name, family), volume in [(item, v) for item in ATTACKS.items() for v in (150, LOW_VOLUME)]:
            alerts = _run(act, res, np.random.default_rng(seed), family, minutes=8, per_minute=volume)
            mine = [a for a in alerts if a["ip"] == ATTACKERS[family]]
            model = [a for a in mine if a["type"] == "net_model"]
            rows.append({"seed": seed, "attack": name, "volume": volume, "family": family, "caught": bool(mine),
                         "behavioural": sorted({a["type"] for a in mine if a["type"] in BEHAVIOURAL}),
                         "model": bool(model), "model_family_ok": any(a["details"]["family"] == family for a in model),
                         "false_alerts": [(a["type"], a["ip"]) for a in alerts if a["ip"] != ATTACKERS[family]]})
        benign = _run(act, res, np.random.default_rng(seed), None, minutes=60)
        rows.append({"seed": seed, "attack": "benign", "false_alerts": [(a["type"], a["ip"]) for a in benign]})
    return rows


def summarize(rows):
    out = {}
    for (name, family), volume in [(item, v) for item in ATTACKS.items() for v in (150, LOW_VOLUME)]:
        r = [x for x in rows if x["attack"] == name and x["volume"] == volume]
        layers = sorted({t for x in r for t in x["behavioural"]})
        out[f"{name}/{volume}"] = {"volume": volume, "family": family, "caught": np.mean([x["caught"] for x in r]),
                     "behavioural": np.mean([bool(x["behavioural"]) for x in r]), "behavioural_types": layers,
                     "model": np.mean([x["model"] for x in r]), "model_family_ok": np.mean([x["model_family_ok"] for x in r]),
                     "false_alerts": sum(len(x["false_alerts"]) for x in r)}
    benign = [x for x in rows if x["attack"] == "benign"]
    out["benign_false_alerts"] = sum(len(x["false_alerts"]) for x in benign)
    out["benign_minutes"] = 60 * len(benign)
    return out


def to_markdown(s):
    pct = lambda v: f"{v:.0%}"
    lines = [f"# تقييم الكشف الشبكي ({len(SEEDS)} بذور، إعادة تشغيل CICIDS2017)", "",
             "| الهجوم | تدفقات/دقيقة | رُصد المهاجم | الطبقة السلوكية | أنماطها | النموذج (بعد الحاجز) | نوع النموذج صحيح | تنبيهات على أبرياء |",
             "|---|---|---|---|---|---|---|---|"]
    for key in [k for k in s if "/" in k]:
        r = s[key]
        lines.append(f"| {r['family']} | {r['volume']} | {pct(r['caught'])} | {pct(r['behavioural'])} | "
                     f"{'، '.join(r['behavioural_types']) or '—'} | {pct(r['model'])} | {pct(r['model_family_ok'])} | "
                     f"{r['false_alerts']} |")
    lines += ["", f"- ترافيك طبيعي فقط ({s['benign_minutes']} دقيقة عبر البذور): **{s['benign_false_alerts']} تنبيه**.",
              "- كل هجوم دقيقتان من عنوان واحد، وسط 200 تدفق طبيعي في الدقيقة من 2000 عميل.",
              "- بحجم 150 تدفقًا في الدقيقة تلتقط قاعدة الإغراق السلوكية (≥ 60 اتصالًا لمنفذ واحد) أي هجوم بسبب حجمه، "
              "والنموذج هو من يميّز النوع؛ الصف المنخفض (25) يُظهر ما يبقى حين لا يكفي الحجم.",
              "- «النموذج» يعني أن المصدر عبر حاجز الأدلة: ≥ 20 تدفقًا، ثقة ≥ 0.80، ونسبة هجوم ≥ 50%.", "",
              "قيد: العيّنة من CICIDS2017 بعناوين معاد رسمها وبروتوكول TCP مفترض؛ الأرقام تقيس منطق الكشف على "
              "هجمات حقيقية معروفة، لا الأداء على ترافيك منشأة فعلية حيث بعض الخصائص (Bulk وActive/Idle) مصفّرة."]
    return "\n".join(lines) + "\n"


def main():
    act = pd.read_parquet(ROOT / "dashboard_cache" / "act_sample.parquet")
    tm = joblib.load(ROOT / "attack_type_model.joblib")
    rows = evaluate(act, SimpleNamespace(model=tm["model"], feature_names=tm["feature_names"]))
    summary = summarize(rows)
    (ROOT / "eval_results").mkdir(exist_ok=True)
    (ROOT / "eval_results" / "network_detection.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2, default=float), encoding="utf-8")
    (ROOT / "docs" / "results" / "network_detection.md").write_text(to_markdown(summary), encoding="utf-8")
    print(to_markdown(summary))


if __name__ == "__main__":
    main()
