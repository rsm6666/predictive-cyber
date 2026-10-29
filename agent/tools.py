"""
===================================================================
أدوات المحلل الذكي — تغليف طبقات النظام الحالية كأدوات للوكيل
===================================================================
الوكيل لا يملك نماذج خاصة به: كل أداة تستدعي طبقة موجودة
(Random Forest، التفسير، مجموعة LSTM، سياسة الجدار المحاكى) وترجع
JSON مختصرًا. الأدوات ترى جزء observed من الحادثة فقط.

حاجز عدم التصعيد: لا يُقبل مقترح أشد من ناتج decide_action، ويُعاد
التحقق عند التنفيذ. الوكيل يقترح فقط؛ التنفيذ عبر decide() بقرار بشري.
===================================================================
"""

import math
from dataclasses import dataclass
from typing import Callable

from act_demo import aggregate_by_source
from explain_decision import explain_row
from sandbox_firewall import Proposal, SimulatedFirewall, decide_action

from agent.scenarios import ATTACK_FAMILIES, SEQ_LEN

MAX_SOURCES = 10
SEVERITY = {"none": 0, "monitor": 1, "rate_limit_target": 2, "block_ip": 3, "quarantine_host": 4}
ENFORCING = ("rate_limit_target", "block_ip", "quarantine_host")
ACTION_AR = {"none": "لا إجراء", "monitor": "مراقبة", "rate_limit_target": "تحديد معدل الهدف",
             "block_ip": "حظر العنوان", "quarantine_host": "عزل الجهاز"}


class ToolError(Exception):
    """خطأ متوقع في أداة؛ يُرجع للوكيل نصًا ليصحح نفسه."""


@dataclass
class Resources:
    model: object
    feature_names: list
    baseline: dict
    forecast_fn: Callable
    forecast_cols: list
    threshold: float


def make_resources(type_model, baseline, lstm_models, lstm_meta, ensemble_predict):
    if lstm_models is None or ensemble_predict is None:
        def forecast_fn(_values):
            raise ToolError("نماذج التنبؤ غير محمّلة على هذا الخادم")
        cols, thr = [], 0.0
    else:
        def forecast_fn(values):
            return ensemble_predict(lstm_models, lstm_meta, values)
        cols, thr = lstm_meta["feature_cols"], float(lstm_meta["threshold_recall"])
    return Resources(type_model["model"], type_model["feature_names"], baseline, forecast_fn, cols, thr)


class Workspace:
    """حادثة واحدة: تنبؤات النموذج محسوبة مرة واحدة + المقترحات + الجدار المحاكى."""

    def __init__(self, incident, res, firewall=None):
        self.incident, self.res = incident, res
        obs = incident.observed
        proba = res.model.predict_proba(obs[res.feature_names])
        self.flows = obs.assign(pred=res.model.classes_[proba.argmax(axis=1)], conf=proba.max(axis=1))
        self.sources = {s["source_ip"]: s for s in aggregate_by_source(self.flows)}
        self.firewall = firewall or SimulatedFirewall()
        self.proposals = {}

    # واجهة الـ Workspace التي تقرأ منها حلقة المحلل (agent/analyst.py)
    system_prompt = None            # None = رسالة المحلل الافتراضية

    @property
    def tool_specs(self):
        return TOOL_SPECS

    @property
    def read_tools(self):
        return READ_TOOLS

    def run_tool(self, name, args):
        return run_tool(self, name, args)

    def describe(self, name, args, result):
        return describe(name, args, result)

    def rules_proposals(self):
        return rules_proposals(self)

    def max_action(self, source_ip):
        return check_policy(self, source_ip)["max_action"]


# ===================================================================
# الأدوات
# ===================================================================
def incident_overview(ws):
    f = ws.flows
    return {
        "total_flows": len(f),
        "unique_sources": int(f["source_ip"].nunique()),
        "unique_destinations": int(f["destination_ip"].nunique()),
        "flows_flagged_as_attack": int((f["pred"] != "BENIGN").sum()),
        "predicted_classes": {str(k): int(v) for k, v in f["pred"].value_counts().items()},
    }


def suspicious_sources(ws):
    return {"sources": [{
        "source_ip": s["source_ip"],
        "predicted_type": s["attack_type"],
        "flagged_flows": int(s["n_flows"]),
        "attack_ratio": round(float(s["attack_ratio"]), 2),
        "mean_confidence": round(float(s["mean_confidence"]), 2),
        "top_target": s["top_target"],
    } for s in list(ws.sources.values())[:MAX_SOURCES]]}


def _known_source(ws, source_ip):
    if source_ip not in set(ws.flows["source_ip"]):
        raise ToolError(f"العنوان {source_ip} غير موجود في هذه الحادثة")


def explain_source(ws, source_ip):
    _known_source(ws, source_ip)
    rows = ws.flows[(ws.flows["source_ip"] == source_ip) & (ws.flows["pred"] != "BENIGN")]
    if rows.empty:
        raise ToolError(f"النموذج لم يصنّف أي اتصال من {source_ip} كهجوم")
    mean_row = rows[ws.res.feature_names].astype(float).mean()
    expl = explain_row(ws.res.model, mean_row, ws.res.feature_names, ws.res.baseline, top_n=5)
    return {"source_ip": source_ip, "flows_explained": len(rows), "top_features": [{
        "feature": e["feature"],
        "mean_z": round(e["z_score"], 2) if math.isfinite(e["z_score"]) else None,
        "direction": e["direction"],
    } for e in expl]}


def forecast_next_minute(ws):
    w = ws.incident.windows
    if len(w) < SEQ_LEN:      # حادثة حقيقية في أول دقائق الوكيل
        raise ToolError(f"التنبؤ غير متاح بعد: {len(w)} من {SEQ_LEN} نوافذ")
    p = float(ws.res.forecast_fn(w[ws.res.forecast_cols].values))
    return {"probability": round(p, 3), "threshold": round(ws.res.threshold, 3),
            "alert": p >= ws.res.threshold,
            "total_flows_per_minute": [int(v) for v in w["total_flows"]]}


def check_policy(ws, source_ip):
    _known_source(ws, source_ip)
    s = ws.sources.get(source_ip)
    if s is None:
        return {"source_ip": source_ip, "max_action": "monitor", "duration_min": 0,
                "reasons": ["النموذج لم يصنّف هذا المصدر مشبوهًا"]}
    p = decide_action(s, 0, tuple(ws.firewall.allowlist))
    return {"source_ip": source_ip, "predicted_type": p.attack_type, "max_action": p.action,
            "duration_min": p.duration_min, "reasons": p.reasons}


def _register(ws, source_ip, action, duration, reasons):
    s = ws.sources.get(source_ip, {})
    p = Proposal(id=len(ws.proposals) + 1, source_ip=source_ip,
                 attack_type=s.get("attack_type", "BENIGN"), action=action, duration_min=duration,
                 n_flows=int(s.get("n_flows", 0)), attack_ratio=float(s.get("attack_ratio", 0.0)),
                 mean_confidence=float(s.get("mean_confidence", 0.0)),
                 target=s.get("top_target", ""), reasons=reasons)
    ws.proposals[p.id] = p
    return p


def propose_action(ws, source_ip, action, justification):
    if action not in SEVERITY:
        raise ToolError(f"إجراء غير معروف: {action}")
    for p in ws.proposals.values():
        if p.source_ip == source_ip and p.status == "pending":
            return {"accepted": False, "proposal_id": p.id, "reason": "يوجد مقترح معلّق لنفس المصدر"}
    policy = check_policy(ws, source_ip)
    if SEVERITY[action] > SEVERITY[policy["max_action"]]:
        return {"accepted": False,
                "reason": f"الإجراء {action} أشد من الحد المسموح ({policy['max_action']})",
                "policy_reasons": policy["reasons"]}
    duration = 0 if action in ("none", "monitor") else policy["duration_min"]
    p = _register(ws, source_ip, action, duration, [justification])
    return {"accepted": True, "proposal_id": p.id, "status": p.status}


def rules_proposals(ws):
    """سلوك القواعد الثابتة (/api/respond): بديل عند فشل الوكيل، وخط أساس للتقييم."""
    taken = {p.source_ip for p in ws.proposals.values()}
    out = []
    for s in ws.sources.values():
        if s["source_ip"] in taken:
            continue
        d = decide_action(s, 0, tuple(ws.firewall.allowlist))
        out.append(_register(ws, s["source_ip"], d.action, d.duration_min, d.reasons))
    return out


def decide(ws, proposal_id, decision, approver="owner"):
    """قرار صاحب المنشأة على مقترح. يعيد فحص الحاجز قبل التنفيذ."""
    p = ws.proposals.get(proposal_id)
    if p is None:
        raise ToolError(f"لا يوجد مقترح رقم {proposal_id}")
    if p.status != "pending":
        return {"proposal_id": p.id, "status": p.status, "note": "تم البت في هذا المقترح مسبقًا"}
    if decision == "reject":
        ws.firewall.reject(p, approver)
    elif SEVERITY[p.action] > SEVERITY[ws.max_action(p.source_ip)]:
        p.status = "refused"
        return {"proposal_id": p.id, "status": p.status, "note": "مرفوض: الإجراء أشد مما تسمح به السياسة الآن"}
    elif ws.firewall.is_covered(p):
        ws.firewall.mark_covered(p)
    else:
        ws.firewall.apply(p, approver)
    return {"proposal_id": p.id, "status": p.status, "note": ws.firewall.log[-1]["note"]}


# ===================================================================
# تعريفات الأدوات لـ Claude
# ===================================================================
def _obj(props, required):
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


_IP = {"type": "string", "description": "عنوان IP للمصدر كما ورد في نتائج الأدوات"}

def report_schema(attack_types):
    """مخطط submit_report؛ أنواع الهجمات تختلف بين CICIDS والسجلات."""
    return _obj({
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
        "summary_owner": {"type": "string", "description": "ملخص عربي من 3 إلى 5 جمل بلا مصطلحات تقنية"},
        "attack_types": {"type": "array", "items": {"type": "string", "enum": list(attack_types)}},
        "findings": {"type": "array", "items": _obj({
            "source_ip": {"type": "string"},
            "assessment": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
        }, ["source_ip", "assessment", "evidence"])},
        "proposal_ids": {"type": "array", "items": {"type": "integer"}},
        "watch_next": {"type": "string"},
        "confidence": {"type": "number", "description": "بين 0 و1"},
    }, ["severity", "summary_owner", "attack_types", "findings", "proposal_ids", "watch_next", "confidence"])


REPORT_SCHEMA = report_schema(ATTACK_FAMILIES)

TOOL_SPECS = [
    {"name": "incident_overview",
     "description": "نظرة عامة على نافذة المراقبة: عدد الاتصالات والمصادر وتوزيع تصنيفات نموذج الكشف.",
     "input_schema": _obj({}, [])},
    {"name": "suspicious_sources",
     "description": "المصادر التي صنّف النموذج بعض اتصالاتها هجومًا، مرتبة بعدد الاتصالات الهجومية.",
     "input_schema": _obj({}, [])},
    {"name": "explain_source",
     "description": "أبرز الخصائص الشبكية التي تنحرف فيها اتصالات مصدر مشبوه عن السلوك الطبيعي (متوسط z).",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "forecast_next_minute",
     "description": "احتمال بداية هجوم في الدقيقة التالية من ترافيك آخر 10 دقائق (مجموعة نماذج LSTM).",
     "input_schema": _obj({}, [])},
    {"name": "check_policy",
     "description": "أقصى إجراء تسمح به سياسة الأمان لهذا المصدر، وأسباب أي تخفيف (ضعف الدليل، قائمة السماح).",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "propose_action",
     "description": "يسجّل مقترح إجراء معلّقًا ينتظر موافقة صاحب المنشأة. لا ينفّذ شيئًا. يُرفض أي إجراء أشد من check_policy.",
     "input_schema": _obj({
         "source_ip": _IP,
         "action": {"type": "string", "enum": list(SEVERITY)},
         "justification": {"type": "string", "description": "سبب مختصر بالعربية"},
     }, ["source_ip", "action", "justification"])},
    {"name": "submit_report",
     "description": "ينهي التحقيق بتقرير لصاحب المنشأة. استدعِه مرة واحدة في النهاية.",
     "input_schema": REPORT_SCHEMA},
]
for _spec in TOOL_SPECS:
    _spec["strict"] = True

READ_TOOLS = ("incident_overview", "suspicious_sources", "explain_source",
              "forecast_next_minute", "check_policy")
_FUNCS = {
    "incident_overview": incident_overview, "suspicious_sources": suspicious_sources,
    "explain_source": explain_source, "forecast_next_minute": forecast_next_minute,
    "check_policy": check_policy, "propose_action": propose_action,
}


def run_tool(ws, name, args):
    fn = _FUNCS.get(name)
    if fn is None:
        raise ToolError(f"أداة غير معروفة: {name}")
    return fn(ws, **args)


def describe(name, args, result):
    """جملة عربية قصيرة للخط الزمني في الواجهة."""
    if "error" in result:
        return f"تعذّر تنفيذ {name}: {result['error']}"
    if name == "incident_overview":
        return (f"فحصتُ {result['total_flows']:,} اتصالًا من {result['unique_sources']} مصدرًا؛ "
                f"النموذج علّم {result['flows_flagged_as_attack']:,} منها كهجوم")
    if name == "suspicious_sources":
        src = result["sources"]
        return "لم أجد مصادر مشبوهة" if not src else f"وجدتُ {len(src)} من المصادر المشبوهة، أبرزها {src[0]['source_ip']}"
    if name == "explain_source":
        top = result["top_features"][0]
        return f"حلّلتُ سلوك {result['source_ip']}: أبرز مؤشر {top['feature']} ({top['direction']})"
    if name == "forecast_next_minute":
        return f"احتمال هجوم في الدقيقة التالية {result['probability']:.0%} مقابل عتبة {result['threshold']:.0%}"
    if name == "check_policy":
        return f"السياسة تسمح لـ {result['source_ip']} بحد أقصى: {ACTION_AR[result['max_action']]}"
    if name == "propose_action":
        if result["accepted"]:
            return f"اقترحتُ {ACTION_AR[args['action']]} على {args['source_ip']} — بانتظار موافقتك"
        return f"لم يُقبل مقترحي على {args['source_ip']}: {result['reason']}"
    return name
