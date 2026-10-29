"""
===================================================================
أدوات المحلل لحوادث السجلات الحقيقية (الجزء 2)
===================================================================
LogWorkspace يربط الوكيل بقاعدة منشأة واحدة ونافذة حادثة واحدة: كل أداة
تقرأ من سجلات هذه المنشأة فقط، وضمن عناوين تنبيهات الحادثة فقط.

السياسة: تنبيه قاعدة ← حظر العنوان بمدة حسب النوع؛ شذوذ وحده ← مراقبة
(ليس دليلًا كافيًا)؛ قائمة السماح ← لا إجراء. نفس حاجز عدم التصعيد.
===================================================================
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sandbox_firewall import Proposal, SimulatedFirewall

from agent.tools import ACTION_AR, ENFORCING, SEVERITY, ToolError, _obj, report_schema

LOG_TYPES = ["brute_force", "path_scan", "flood", "injection", "fw_port_scan", "fw_flood", "anomaly"]
RULE_DURATION = {"brute_force": 60, "path_scan": 30, "flood": 30, "injection": 120,
                 "fw_port_scan": 30, "fw_flood": 30}
TYPE_AR = {"brute_force": "تخمين كلمات المرور", "path_scan": "فحص مسارات الموقع", "flood": "إغراق بالطلبات",
           "injection": "محاولة حقن (SQL/XSS)", "fw_port_scan": "فحص منافذ الخادم",
           "fw_flood": "اتصالات محظورة متكررة", "anomaly": "سلوك غير معتاد"}
FEATURE_AR = {"requests": "عدد الطلبات", "paths": "عدد المسارات المختلفة", "ratio_4xx": "نسبة أخطاء 4xx",
              "ratio_5xx": "نسبة أخطاء 5xx", "ratio_post": "نسبة طلبات POST", "mean_bytes": "متوسط حجم الرد",
              "agents": "عدد وكلاء المستخدم"}
WINDOW_PAD = 300
MAX_SAMPLES = 10

SYSTEM_LOG = """أنت محلل أمن سيبراني يعمل لدى منشأة صغيرة لا تملك فريقًا أمنيًا. فُتحت حادثة من سجلات موقعها أو جدارها الناري، ومهمتك التحقيق فيها بالأدوات المتاحة ثم كتابة تقرير لصاحب المنشأة.

طريقة العمل:
- ابدأ بـ incident_overview لترى التنبيهات.
- لكل عنوان في التنبيهات استخدم source_activity، وsample_requests عند الحاجة لرؤية الطلبات نفسها.
- إذا وُجد تنبيه anomaly فاستخدم anomaly_context. الشذوذ ليس دليل هجوم بذاته.
- قبل أي اقتراح، استدعِ check_policy للعنوان، ثم اقترح عبر propose_action إجراءً لكل عنوان يستحقه. يمكنك اختيار إجراء أخف من الحد الأقصى إذا كان الدليل ضعيفًا.
- أنهِ دائمًا باستدعاء submit_report مرة واحدة.

قواعد التقرير:
- استند إلى نتائج الأدوات فقط. لا تذكر عنوانًا أو رقمًا لم يرد فيها.
- summary_owner لصاحب منشأة غير تقني: ماذا حدث، وهل الخطر قائم، وماذا ينتظر منه.
- attack_types من أنواع التنبيهات كما وردت.
- evidence أرقام ووقائع من نتائج الأدوات."""


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class LogIncident:
    id: str
    kind: str = "log"
    family: str | None = None     # لا «حقيقة» معروفة لحادثة حقيقية


_IP = {"type": "string", "description": "عنوان IP كما ورد في تنبيهات الحادثة"}
LOG_TOOL_SPECS = [
    {"name": "incident_overview", "description": "تنبيهات الحادثة: الأنواع والعناوين والأعداد والخطورة والنافذة الزمنية.",
     "input_schema": _obj({}, [])},
    {"name": "source_activity", "description": "نشاط عنوان من عناوين الحادثة في نافذتها: الطلبات وأكثر المسارات والحالات ووكلاء المستخدم، أو حظر الجدار.",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "sample_requests", "description": "حتى 10 سطور مختصرة من سجلات عنوان في نافذة الحادثة.",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "anomaly_context", "description": "حالة نموذج الشذوذ الخاص بالمنشأة، وتفاصيل تنبيهات الشذوذ في الحادثة (النتيجة والخصائص المنحرفة).",
     "input_schema": _obj({}, [])},
    {"name": "check_policy", "description": "أقصى إجراء تسمح به السياسة لهذا العنوان وأسبابه: قاعدة ← حظر، شذوذ وحده ← مراقبة، قائمة السماح ← لا شيء.",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "propose_action", "description": "يسجّل مقترح إجراء معلّقًا ينتظر موافقة صاحب المنشأة. لا ينفّذ شيئًا. يُرفض أي إجراء أشد من check_policy.",
     "input_schema": _obj({"source_ip": _IP, "action": {"type": "string", "enum": list(SEVERITY)},
                           "justification": {"type": "string", "description": "سبب مختصر بالعربية"}},
                          ["source_ip", "action", "justification"])},
    {"name": "submit_report", "description": "ينهي التحقيق بتقرير لصاحب المنشأة. استدعِه مرة واحدة في النهاية.",
     "input_schema": report_schema(LOG_TYPES)},
]
for _spec in LOG_TOOL_SPECS:
    _spec["strict"] = True
LOG_READ_TOOLS = ("incident_overview", "source_activity", "sample_requests", "anomaly_context", "check_policy")


class LogWorkspace:
    system_prompt = SYSTEM_LOG
    read_tools = LOG_READ_TOOLS

    def __init__(self, store, incident_id, allowlist=(), detector=None, firewall=None):
        self.store, self.detector = store, detector
        self.incident = LogIncident(incident_id)
        self.alerts = store.alerts(incident_id)
        if not self.alerts:
            raise ToolError(f"لا توجد تنبيهات للحادثة {incident_id}")
        self.start = min(a["first_ts"] for a in self.alerts) - WINDOW_PAD
        self.end = max(a["last_ts"] for a in self.alerts) + 60
        self.ips = list(dict.fromkeys(a["ip"] for a in self.alerts))
        self.firewall = firewall or SimulatedFirewall(allowlist=list(allowlist))
        self.proposals = {}

    @property
    def tool_specs(self):
        return LOG_TOOL_SPECS

    @staticmethod
    def tool_specs_static():
        return LOG_TOOL_SPECS

    # ---------------- الأدوات ----------------
    def _known(self, ip):
        if ip not in self.ips:
            raise ToolError(f"العنوان {ip} ليس من عناوين هذه الحادثة")

    def incident_overview(self):
        return {"incident_id": self.incident.id, "window": {"from": _iso(self.start), "to": _iso(self.end)},
                "alerts": [{"type": a["type"], "ip": a["ip"], "source": a["source"], "count": a["count"],
                            "severity": a["severity"], "from": _iso(a["first_ts"]), "to": _iso(a["last_ts"])}
                           for a in self.alerts]}

    def source_activity(self, source_ip):
        self._known(source_ip)
        web = self.store.web_between(self.start, self.end, ip=source_ip)
        fw = self.store.fw_between(self.start, self.end, ip=source_ip)
        out = {"ip": source_ip, "web": None, "firewall": None}
        if web:
            paths = Counter(urlsplit(e["path"]).path for e in web).most_common(5)
            out["web"] = {"requests": len(web), "first": _iso(web[0]["ts"]), "last": _iso(web[-1]["ts"]),
                          "top_paths": [{"path": p[:200], "count": n} for p, n in paths],
                          "statuses": {str(k): v for k, v in sorted(Counter(e["status"] for e in web).items())},
                          "user_agents": [ua[:120] for ua, _ in Counter(e["ua"] for e in web).most_common(3)]}
        if fw:
            ports = Counter(e["dport"] for e in fw if e["dport"] is not None)
            out["firewall"] = {"events": len(fw), "blocked": sum(e["action"] == "BLOCK" for e in fw),
                               "distinct_ports": len(ports), "top_ports": [p for p, _ in ports.most_common(5)],
                               "first": _iso(fw[0]["ts"]), "last": _iso(fw[-1]["ts"])}
        return out

    def sample_requests(self, source_ip):
        self._known(source_ip)
        web = self.store.web_between(self.start, self.end, ip=source_ip)
        if web:
            lines = [f"{e['method']} {e['path'][:200]} → {e['status']}" for e in web[:MAX_SAMPLES]]
        else:
            lines = [f"{e['action']} {e['proto']} → {e['dst']}:{e['dport']}"
                     for e in self.store.fw_between(self.start, self.end, ip=source_ip)[:MAX_SAMPLES]]
        return {"ip": source_ip, "lines": lines}

    def anomaly_context(self):
        model = self.detector.status(self.store) if self.detector else {"state": "unavailable"}
        return {"model": model, "anomalies": [
            {"ip": a["ip"], "score": a["details"].get("score"), "threshold": a["details"].get("threshold"),
             "features": a["details"].get("features", [])} for a in self.alerts if a["type"] == "anomaly"]}

    def check_policy(self, source_ip):
        self._known(source_ip)
        if source_ip in self.firewall.allowlist:
            return {"source_ip": source_ip, "max_action": "none", "duration_min": 0,
                    "reasons": ["العنوان ضمن قائمة السماح"]}
        rules = sorted({a["type"] for a in self.alerts if a["ip"] == source_ip and a["type"] != "anomaly"})
        if rules:
            return {"source_ip": source_ip, "max_action": "block_ip",
                    "duration_min": max(RULE_DURATION[t] for t in rules),
                    "reasons": [f"تنبيه قاعدة: {TYPE_AR[t]}" for t in rules]}
        return {"source_ip": source_ip, "max_action": "monitor", "duration_min": 0,
                "reasons": ["شذوذ فقط: ليس دليلًا كافيًا للحظر"]}

    def _register(self, source_ip, action, duration, reasons):
        own = [a for a in self.alerts if a["ip"] == source_ip]
        p = Proposal(id=len(self.proposals) + 1, source_ip=source_ip, attack_type=own[0]["type"], action=action,
                     duration_min=duration, n_flows=sum(a["count"] for a in own), attack_ratio=0.0,
                     mean_confidence=0.0, reasons=reasons)
        self.proposals[p.id] = p
        return p

    def propose_action(self, source_ip, action, justification):
        if action not in SEVERITY:
            raise ToolError(f"إجراء غير معروف: {action}")
        for p in self.proposals.values():
            if p.source_ip == source_ip and p.status == "pending":
                return {"accepted": False, "proposal_id": p.id, "reason": "يوجد مقترح معلّق لنفس العنوان"}
        policy = self.check_policy(source_ip)
        if SEVERITY[action] > SEVERITY[policy["max_action"]]:
            return {"accepted": False, "reason": f"الإجراء {action} أشد من الحد المسموح ({policy['max_action']})",
                    "policy_reasons": policy["reasons"]}
        duration = 0 if action in ("none", "monitor") else policy["duration_min"]
        p = self._register(source_ip, action, duration, [justification])
        return {"accepted": True, "proposal_id": p.id, "status": p.status}

    # ---------------- واجهة الـ Workspace للحلقة ----------------
    def run_tool(self, name, args):
        fn = getattr(self, name, None) if name in LOG_READ_TOOLS + ("propose_action",) else None
        if fn is None:
            raise ToolError(f"أداة غير معروفة: {name}")
        return fn(**args)

    def max_action(self, source_ip):
        return self.check_policy(source_ip)["max_action"]

    def rules_proposals(self):
        taken = {p.source_ip for p in self.proposals.values()}
        out = []
        for ip in self.ips:
            if ip not in taken:
                policy = self.check_policy(ip)
                out.append(self._register(ip, policy["max_action"], policy["duration_min"], policy["reasons"]))
        return out

    def sync_incident_status(self):
        pending = any(p.status == "pending" and p.action in ENFORCING for p in self.proposals.values())
        self.store.set_incident_status(self.incident.id, "investigating" if pending else "closed")

    def describe(self, name, args, result):
        if "error" in result:
            return f"تعذّر تنفيذ {name}: {result['error']}"
        if name == "incident_overview":
            kinds = "، ".join(sorted({TYPE_AR[a["type"]] for a in result["alerts"]}))
            return f"الحادثة فيها {len(result['alerts'])} من التنبيهات: {kinds}"
        if name == "source_activity":
            web, fw = result["web"], result["firewall"]
            parts = []
            if web:
                parts.append(f"{web['requests']:,} طلبًا، أكثرها على {web['top_paths'][0]['path']}")
            if fw:
                parts.append(f"{fw['blocked']:,} محاولة محظورة على {fw['distinct_ports']} منفذًا")
            return f"نشاط {result['ip']}: " + "؛ ".join(parts or ["لا أحداث في النافذة"])
        if name == "sample_requests":
            return f"راجعتُ {len(result['lines'])} من طلبات {result['ip']}"
        if name == "anomaly_context":
            state = "جاهز" if result["model"].get("state") == "ready" else "ما زال يتعلم"
            return f"نموذج الشذوذ {state}؛ تنبيهات الشذوذ في الحادثة: {len(result['anomalies'])}"
        if name == "check_policy":
            return f"السياسة تسمح لـ {result['source_ip']} بحد أقصى: {ACTION_AR[result['max_action']]}"
        if name == "propose_action":
            if result["accepted"]:
                return f"اقترحتُ {ACTION_AR[args['action']]} على {args['source_ip']} — بانتظار موافقتك"
            return f"لم يُقبل مقترحي على {args['source_ip']}: {result['reason']}"
        return name
