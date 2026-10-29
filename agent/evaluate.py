"""
===================================================================
التقييم العلمي للمحلل الذكي — مقارنة الوكيل بالقواعد الثابتة
===================================================================
كل سيناريو يُشغَّل على نظامين بنفس البيانات:
  القواعد  decide_action على كل مصدر مشبوه (سلوك /api/respond)
  الوكيل   مقترحاته، بافتراض موافقة صاحب المنشأة عليها كلها
المصدر «مهاجم» إذا كانت نسبة اتصالاته الهجومية الحقيقية ≥ 50%.

الاستخدام (من مجلد المشروع، يستهلك رصيد API):
  python -m agent.evaluate --limit 6 --no-stability   تجربة لقياس الزمن والتكلفة
  python -m agent.evaluate                            60 سيناريو + الثبات
النتائج: eval_results/agent_eval.json و eval_results/agent_eval.md
===================================================================
"""

import argparse
import json
import re

import numpy as np
import pandas as pd

from agent.scenarios import evaluation_suite
from agent.store import ROOT, Run
from agent.tools import ENFORCING, Workspace, make_resources, rules_proposals

OUT_DIR = ROOT / "eval_results"
CACHE = ROOT / "dashboard_cache"
ATTACKER_RATIO = 0.5
STABILITY_N, STABILITY_REPEATS = 10, 3
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩٫٬", "0123456789.,")


# ===================================================================
# المقاييس
# ===================================================================
def score_decisions(truth, enforced):
    attackers = {ip for ip, t in truth.items() if t["attack_ratio"] >= ATTACKER_RATIO}
    benign = set(truth) - attackers
    return {"tp": len(enforced & attackers), "fp": len(enforced & benign),
            "fn": len(attackers - enforced), "benign_sources": len(benign)}


def types_correct(types, family):
    return family in types if family != "BENIGN" else len(types) == 0


def _numbers(text):
    text = IP_RE.sub(" ", text.translate(ARABIC_DIGITS))
    return [float(n.replace(",", "")) for n in NUM_RE.findall(text)]


def hallucinated_ips(report, tool_text):
    return sorted(set(IP_RE.findall(json.dumps(report, ensure_ascii=False))) - set(IP_RE.findall(tool_text)))


def unsupported_numbers(report, tool_text):
    """أرقام في الأدلة لا تظهر في نتائج الأدوات. فحص تقريبي: يقبل التقريب
    وتحويل النسبة إلى مئوية، ويتجاهل الأعداد ≤ 10 (عدّ مثل «3 مصادر»)."""
    known = _numbers(tool_text)
    out = []
    for finding in report.get("findings", []):
        for ev in finding.get("evidence", []):
            for n in _numbers(ev):
                if n <= 10:
                    continue
                if not any(abs(n - k) <= 0.01 * max(1, abs(k)) or abs(n - 100 * k) <= 0.5 for k in known):
                    out.append(n)
    return out


def _rate(a, b):
    return round(a / b, 3) if b else None


def summarize(rows, key):
    tp, fp, fn = (sum(r[key][k] for r in rows) for k in ("tp", "fp", "fn"))
    benign = sum(r[key]["benign_sources"] for r in rows)
    precision, recall = _rate(tp, tp + fp), _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "false_block_rate": _rate(fp, benign),
            "type_accuracy": _rate(sum(r[key]["types_ok"] for r in rows), len(rows)),
            "tp": tp, "fp": fp, "fn": fn}


# ===================================================================
# التشغيل
# ===================================================================
def evaluate_incident(client, res, inc, model):
    from agent.analyst import run_investigation
    ws = Workspace(inc, res)
    run = Run(inc, ws)
    run_investigation(client, ws, run, model=model)
    report = run.report or {}
    agent_enf = {p.source_ip for p in ws.proposals.values() if p.action in ENFORCING}
    tool_text = " ".join(json.dumps(e["result"], ensure_ascii=False, default=str)
                         for e in run.events if e["type"] == "step")
    ws_rules = Workspace(inc, res)
    rules_enf = {p.source_ip for p in rules_proposals(ws_rules) if p.action in ENFORCING}
    rules_types = {s["attack_type"] for s in ws_rules.sources.values()}
    return {
        "incident_id": inc.id, "kind": inc.kind, "family": inc.family, "status": run.status,
        "agent": {**score_decisions(inc.truth, agent_enf), "enforced": sorted(agent_enf),
                  "types_ok": run.status == "done" and types_correct(report.get("attack_types", []), inc.family)},
        "rules": {**score_decisions(inc.truth, rules_enf), "enforced": sorted(rules_enf),
                  "types_ok": types_correct(rules_types, inc.family)},
        "hallucinated_ips": hallucinated_ips(report, tool_text),
        "unsupported_numbers": unsupported_numbers(report, tool_text),
        "seconds": run.seconds, "usage": run.usage,
    }


def stability(client, res, incidents, model):
    from agent.analyst import run_investigation
    agree = []
    for inc in incidents[:STABILITY_N]:
        decisions = set()
        for _ in range(STABILITY_REPEATS):
            ws = Workspace(inc, res)
            run_investigation(client, ws, Run(inc, ws), model=model)
            decisions.add(frozenset(p.source_ip for p in ws.proposals.values() if p.action in ENFORCING))
        agree.append(len(decisions) == 1)
    return _rate(sum(agree), len(agree))


def load_eval_inputs():
    import joblib
    from explain_decision import compute_baseline_stats
    from train_attack_type_model import normalize_label
    from train_final_lstm import ensemble_predict, load_final_ensemble
    tm = joblib.load(ROOT / "attack_type_model.joblib")
    bs = pd.read_parquet(CACHE / "baseline_sample.parquet")
    benign = bs[bs["Label"].map(normalize_label) == "BENIGN"]
    models, meta = load_final_ensemble()
    res = make_resources(tm, compute_baseline_stats(benign, tm["feature_names"]), models, meta, ensemble_predict)
    return res, pd.read_parquet(CACHE / "act_sample.parquet"), pd.read_parquet(CACHE / "lstm_windows.parquet")


def to_markdown(s):
    a, r = s["agent"], s["rules"]

    def fmt(v):
        return "—" if v is None else f"{v:.1%}"

    lines = [f"# تقييم المحلل الذكي ({s['model']}، {s['incidents']} سيناريو)", "",
             "| المقياس | القواعد الثابتة | الوكيل |", "|---|---|---|"]
    for key, label in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"),
                       ("false_block_rate", "نسبة حظر المصادر السليمة"), ("type_accuracy", "صحة نوع الهجوم")]:
        lines.append(f"| {label} | {fmt(r[key])} | {fmt(a[key])} |")
    lines += ["",
              f"- تحقيقات فشلت وعُرض فيها بديل القواعد: {s['agent_failures']}",
              f"- تحقيقات فيها عنوان IP مختلق: {s['incidents_with_hallucinated_ip']}",
              f"- أرقام غير مسندة في الأدلة (تُراجع يدويًا): {s['unsupported_numbers_total']}",
              f"- متوسط الزمن: {s['mean_seconds']} ثانية · متوسط التوكنز لكل حادثة: "
              f"{s['mean_input_tokens']} إدخال، {s['mean_cache_read_tokens']} من الكاش، {s['mean_output_tokens']} إخراج",
              f"- ثبات القرار ({STABILITY_N} سيناريوهات × {STABILITY_REPEATS}): {fmt(s['stability'])}"]
    return "\n".join(lines) + "\n"


def main():
    import anthropic
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    from agent.analyst import MODEL

    ap = argparse.ArgumentParser(description="تقييم المحلل الذكي مقابل القواعد الثابتة")
    ap.add_argument("--limit", type=int, help="عدد السيناريوهات (للتجربة)")
    ap.add_argument("--no-stability", action="store_true", help="تخطي اختبار الثبات")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    res, act, windows = load_eval_inputs()
    suite = evaluation_suite(act, windows)
    order = np.random.default_rng(0).permutation(len(suite))     # خلط ثابت حتى تشمل --limit أنواعًا مختلفة
    incidents = [suite[i] for i in order][:args.limit or len(suite)]
    client = anthropic.Anthropic(timeout=60.0)

    rows = []
    for i, inc in enumerate(incidents, 1):
        rows.append(evaluate_incident(client, res, inc, args.model))
        print(f"[{i}/{len(incidents)}] {inc.id}: {rows[-1]['status']} — {rows[-1]['seconds']} ث")

    def mean(k):
        return int(np.mean([r["usage"][k] for r in rows]))

    summary = {
        "model": args.model, "incidents": len(rows),
        "agent": summarize(rows, "agent"), "rules": summarize(rows, "rules"),
        "agent_failures": sum(r["status"] != "done" for r in rows),
        "incidents_with_hallucinated_ip": sum(bool(r["hallucinated_ips"]) for r in rows),
        "unsupported_numbers_total": sum(len(r["unsupported_numbers"]) for r in rows),
        "mean_seconds": round(float(np.mean([r["seconds"] for r in rows])), 1),
        "mean_input_tokens": mean("input_tokens"), "mean_cache_read_tokens": mean("cache_read_input_tokens"),
        "mean_output_tokens": mean("output_tokens"),
        "stability": None if args.no_stability else stability(client, res, incidents, args.model),
    }
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "agent_eval.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (OUT_DIR / "agent_eval.md").write_text(to_markdown(summary), encoding="utf-8")
    print(to_markdown(summary))


if __name__ == "__main__":
    main()
