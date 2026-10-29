"""
===================================================================
المنسّق — مساحة عمل حملة (الجزء 6)
===================================================================
المتخصصون (محلل السجلات ومحلل الشبكة) حققوا في الحوادث الأعضاء. المنسّق
يقرأ تقاريرهم وأدلة الربط من المخزّن فقط، ويكتب تقرير حملة بمراحل، ويقترح
إجراءً واحدًا لكل مهاجم:
  - مقترحه يجعل معلّقات المتخصصين لنفس العنوان «merged» (لا تُعتمد بعدها)
  - الحد الأقصى = أشد ما تسمح به سياسة أي عضو لهذا العنوان، لا أكثر
  - لا مقترح لعنوان طُبّق عليه حظر في أي عضو
عند فشل المنسّق: بديل القواعد = أشد مقترح معلّق للمتخصصين لكل مهاجم.
===================================================================
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from sandbox_firewall import Proposal, SimulatedFirewall

from agent.log_tools import _iso
from agent.tools import ACTION_AR, ENFORCING, SEVERITY, ToolError, _obj, report_schema
from campaign.linker import ATTACKER_KINDS, KIND_AR, TYPE_AR, attacker_ips

STAGE_AR = {"weakness": "ثغرة مكشوفة", "recon": "استطلاع", "access": "محاولة دخول",
            "exploit": "استغلال أو تسريب", "disruption": "تعطيل"}
TYPE_STAGE = {"exposed_file": "weakness", "path_scan": "recon", "fw_port_scan": "recon", "net_scan": "recon",
              "net_sweep": "recon", "anomaly": "recon", "brute_force": "access", "net_brute": "access",
              "injection": "exploit", "flood": "disruption", "fw_flood": "disruption", "net_flood": "disruption",
              "net_ddos": "disruption", "site_down": "disruption"}
FAMILY_STAGE = {"PortScan": "recon", "Brute Force (FTP/SSH)": "access", "Web Attack": "exploit",
                "Botnet": "exploit", "DoS": "disruption", "DDoS": "disruption"}
CAMPAIGN_TYPES = list(TYPE_AR)
MAX_STAGES = 20
DEFAULT_DURATION = 60
BLOCKING = ("block_ip", "quarantine_host")

SYSTEM_CAMPAIGN = """أنت المنسّق الأمني لمنشأة صغيرة لا تملك فريقًا أمنيًا. ربط النظام عدة حوادث في «حملة» واحدة لأنها تشترك في مهاجم أو في ملف مكشوف، وحقق في كل حادثة وكيل متخصص (السجلات أو الشبكة). مهمتك قراءة تقاريرهم وأدلة الربط، ثم كتابة تقرير واحد يحكي الهجوم كقصة واحدة، واقتراح إجراء واحد لكل مهاجم.

طريقة العمل:
- ابدأ بـ campaign_overview لترى الأعضاء وأسباب الربط والمراحل.
- اقرأ تقرير كل عضو بـ specialist_report.
- لكل مهاجم استخدم attacker_profile ثم check_policy.
- اقترح عبر propose_action إجراءً واحدًا لكل مهاجم يستحقه. لك أن تختار إجراءً أشد مما اختاره متخصص إذا كانت الأدلة عبر المصادر أقوى، ضمن الحد الأقصى فقط. لا تقترح شيئًا لعنوان مطبّق عليه حظر مسبقًا، واذكر ذلك في التقرير.
- أنهِ دائمًا باستدعاء submit_report مرة واحدة.

قواعد التقرير:
- استند إلى نتائج الأدوات فقط. لا تذكر عنوانًا أو رقمًا أو وقتًا لم يرد فيها.
- summary_owner لصاحب منشأة غير تقني: احكِ تسلسل الهجوم (مثل: فحص المهاجم منافذ خادمك، ثم بحث في موقعك عن ملفات حساسة، ثم حمّل ملفًا مكشوفًا)، وهل الخطر قائم، وماذا ينتظر منه.
- إذا حُمّل ملف حساس فعلًا، فاطلب في watch_next تغيير كلمات المرور والمفاتيح التي فيه.
- stages المراحل بالترتيب الزمني كما وردت في campaign_overview.
- attack_types من أنواع التنبيهات كما وردت."""


def _stage(alert):
    if alert["type"] == "net_model":
        return FAMILY_STAGE.get(alert["details"].get("family"), "exploit")
    return TYPE_STAGE.get(alert["type"], "recon")


def campaign_view(store, cid):
    """الأعضاء وأسباب الربط والمراحل مرتبة زمنيًا (للأداة ولصفحة الحملة)."""
    camp = store.incident(cid)
    members, links = store.campaign_members(cid), store.links(cid)
    stages, attackers = [], []
    for m in members:
        alerts = store.alerts(m["id"])
        if m["kind"] in ATTACKER_KINDS:
            attackers += [a["ip"] for a in alerts]
        groups = {}
        for a in alerts:
            groups.setdefault((_stage(a), a["type"]), []).append(a)
        for (stage, type_), group in groups.items():
            ips = list(dict.fromkeys(a["ip"] for a in group))
            who = "" if m["kind"] == "monitor" else " من " + "، ".join(ips[:3]) + ("…" if len(ips) > 3 else "")
            stages.append({"stage": stage, "incident_id": m["id"], "kind": m["kind"], "type": type_,
                           "ts": min(a["first_ts"] for a in group), "description":
                           f"{KIND_AR[m['kind']]}: {TYPE_AR.get(type_, type_)}{who}"})
    kinds = {m["id"]: m["kind"] for m in members}
    for l in {(l["ip"], l["reason"]): l for l in links}.values():      # نفس التحميل قد يربط عدة حوادث
        if l["downloaded"]:
            monitor = l["a"] if kinds.get(l["a"]) == "monitor" else l["b"]
            stages.append({"stage": "exploit", "incident_id": monitor, "kind": "monitor", "type": "exposed_file",
                           "ts": l["at"], "description": l["reason"]})
    stages = sorted(stages, key=lambda s: s["ts"])[:MAX_STAGES]
    for s in stages:
        s["time"] = _iso(s["ts"])
    return {"campaign_id": cid, "status": camp["status"], "severity": camp["severity"],
            "members": [{"incident_id": m["id"], "kind": m["kind"], "status": m["status"], "severity": m["severity"],
                         "opened": _iso(m["opened_at"]),
                         "types": sorted({a["type"] for a in store.alerts(m["id"])})} for m in members],
            "links": [{"a": l["a"], "b": l["b"], "rule": l["rule"], "ip": l["ip"], "reason": l["reason"],
                       "downloaded": l["downloaded"], "time": _iso(l["at"])} for l in links],
            "attackers": list(dict.fromkeys(attackers)), "stages": stages}


@dataclass
class CampaignIncident:
    id: str
    kind: str = "campaign"
    family: str | None = None
    truth: dict = field(default_factory=dict)


_IP = {"type": "string", "description": "عنوان مهاجم كما ورد في campaign_overview"}
_REPORT = report_schema(CAMPAIGN_TYPES)
_REPORT["properties"]["stages"] = {"type": "array", "items": _obj({
    "stage": {"type": "string", "enum": list(STAGE_AR)},
    "incident_id": {"type": "string"},
    "time": {"type": "string"},
    "description": {"type": "string"},
}, ["stage", "incident_id", "time", "description"])}
_REPORT["required"].append("stages")

CAMPAIGN_TOOL_SPECS = [
    {"name": "campaign_overview", "description": "أعضاء الحملة (الحوادث وأنواعها وحالاتها)، وأسباب ربطها، والمهاجمون، ومراحل الهجوم مرتبة زمنيًا.",
     "input_schema": _obj({}, [])},
    {"name": "specialist_report", "description": "تقرير الوكيل المتخصص الذي حقق في حادثة عضو، ومقترحاته بحالاتها. لحادثة المراقبة: الثغرة المكشوفة.",
     "input_schema": _obj({"incident_id": {"type": "string", "description": "معرّف حادثة عضو مثل log-3"}}, ["incident_id"])},
    {"name": "attacker_profile", "description": "كل ما عن مهاجم عبر أعضاء الحملة: التنبيهات وأوقاتها، ونتيجة النموذج الشبكي، والملفات المكشوفة التي طلبها، والقرارات القائمة عليه.",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "check_policy", "description": "أقصى إجراء تسمح به سياسات الأعضاء لهذا العنوان، ومدته، وهل طُبّق عليه حظر مسبقًا (enforced_in).",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "propose_action", "description": "مقترح واحد للمهاجم على مستوى الحملة، ينتظر موافقة صاحب المنشأة ويحل محل مقترحات المتخصصين المعلّقة لنفس العنوان. لا ينفّذ شيئًا.",
     "input_schema": _obj({"source_ip": _IP, "action": {"type": "string", "enum": list(SEVERITY)},
                           "justification": {"type": "string", "description": "سبب مختصر بالعربية"}},
                          ["source_ip", "action", "justification"])},
    {"name": "submit_report", "description": "ينهي عمل المنسّق بتقرير الحملة لصاحب المنشأة. استدعِه مرة واحدة في النهاية.",
     "input_schema": _REPORT},
]
for _spec in CAMPAIGN_TOOL_SPECS:
    _spec["strict"] = True
CAMPAIGN_READ_TOOLS = ("campaign_overview", "specialist_report", "attacker_profile", "check_policy")


class CampaignWorkspace:
    system_prompt = SYSTEM_CAMPAIGN
    read_tools = CAMPAIGN_READ_TOOLS
    tool_specs = CAMPAIGN_TOOL_SPECS

    def __init__(self, store, campaign_id, runs, runs_dir, allowlist=(), previous=None):
        self.store, self.runs, self.runs_dir = store, runs, Path(runs_dir)
        self.allowlist = set(allowlist)
        self.incident = CampaignIncident(campaign_id)
        self.task = (f"ربط النظام حوادث مترابطة في الحملة {campaign_id}، وحقق فيها المتخصصون. "
                     "اقرأ تقاريرهم واكتب تقرير الحملة.")
        self.firewall = previous.firewall if previous else SimulatedFirewall(allowlist=list(allowlist))
        self.firewall.allowlist = set(allowlist)
        saved = [] if previous else (self._saved(campaign_id) or {}).get("proposals", [])     # بعد إعادة التشغيل
        self.proposals = dict(previous.proposals) if previous else {d["id"]: Proposal(**d) for d in saved}
        # أرقام المقترحات تستمر (فلا يصيب رابط موافقة قديم مقترحًا جديدًا) والقرارات المطبّقة تبقى
        for p in self.proposals.values():
            if p.status == "pending":
                p.status, p.rationale = "superseded", "استُبدل بتقرير الحملة الأحدث"
        self.members = store.campaign_members(campaign_id)
        self.view = campaign_view(store, campaign_id)
        self.member_ips = {m["id"]: attacker_ips(store, m["id"], allowlist)
                           for m in self.members if m["kind"] in ATTACKER_KINDS}
        self.ips = list(dict.fromkeys(ip for ips in self.member_ips.values() for ip in ips))

    # ---------------- بيانات الأعضاء ----------------
    def _member(self, incident_id):
        m = next((m for m in self.members if m["id"] == incident_id), None)
        if m is None:
            raise ToolError(f"{incident_id} ليست من أعضاء هذه الحملة")
        return m

    def _known(self, ip):
        if ip not in self.ips:
            raise ToolError(f"العنوان {ip} ليس من مهاجمي هذه الحملة")

    def _saved(self, incident_id):
        path = self.runs_dir / f"{incident_id}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def _member_proposals(self, incident_id):
        """[(المقترح كقاموس، كائن المقترح الحي أو None)] من الـ Run الحي أو السجل المحفوظ."""
        run = self.runs(incident_id)
        if run is not None:
            return [(_public(p), p) for p in run.ws.proposals.values()]
        saved = self._saved(incident_id) or {}
        return [(p, None) for p in saved.get("proposals", [])]

    def _specialist_proposals(self, ip):
        return [(mid, d, p) for mid, ips in self.member_ips.items() if ip in ips
                for d, p in self._member_proposals(mid) if d["source_ip"] == ip]

    # ---------------- الأدوات ----------------
    def campaign_overview(self):
        return {**self.view, "stages": [{k: s[k] for k in ("stage", "type", "incident_id", "time", "description")}
                                        for s in self.view["stages"]]}

    def specialist_report(self, incident_id):
        m = self._member(incident_id)
        if m["kind"] == "monitor":
            a = self.store.alerts(incident_id)[0]
            return {"incident_id": incident_id, "kind": "monitor", "specialist": None, "status": m["status"],
                    "finding": a["details"].get("detail"), "path": a["details"].get("path")}
        run = self.runs(incident_id)
        if run is not None and run.status == "running":
            raise ToolError(f"ما زال المتخصص يحقق في {incident_id}")
        report = run.report if run is not None else (self._saved(incident_id) or {}).get("report")
        if not report:
            raise ToolError(f"لا يوجد تقرير للمتخصص في {incident_id}")
        return {"incident_id": incident_id, "kind": m["kind"],
                "report": {k: report.get(k) for k in ("severity", "summary_owner", "attack_types", "findings", "watch_next")},
                "proposals": [{k: d[k] for k in ("id", "source_ip", "action", "duration_min", "status")}
                              for d, _ in self._member_proposals(incident_id)]}

    def attacker_profile(self, source_ip):
        self._known(source_ip)
        alerts = []
        for mid in self.member_ips:
            kind = self._member(mid)["kind"]
            for a in self.store.alerts(mid):
                if a["ip"] != source_ip:
                    continue
                row = {"incident_id": mid, "kind": kind, "type": a["type"], "count": a["count"],
                       "severity": a["severity"], "from": _iso(a["first_ts"]), "to": _iso(a["last_ts"])}
                model = a["details"].get("model") or {}
                if a["details"].get("family") or model.get("verdict") not in (None, "BENIGN"):
                    row["model"] = {"family": a["details"].get("family") or model.get("verdict"),
                                    "confidence": model.get("confidence")}
                alerts.append(row)
        return {"source_ip": source_ip, "linking_ip": source_ip in {l["ip"] for l in self.view["links"]},
                "alerts": alerts,
                "exposed_files": list({l["reason"]: {"reason": l["reason"], "downloaded": l["downloaded"], "time": l["time"]}
                                       for l in self.view["links"]
                                       if l["rule"] == "exposed_file" and l["ip"] == source_ip}.values()),
                "decisions": [{"incident_id": mid, "action": d["action"], "status": d["status"]}
                              for mid, d, _ in self._specialist_proposals(source_ip)]}

    def check_policy(self, source_ip):
        self._known(source_ip)
        if source_ip in self.allowlist:
            return {"source_ip": source_ip, "max_action": "none", "duration_min": 0,
                    "reasons": ["العنوان ضمن قائمة السماح"], "enforced_in": []}
        best, reasons = "monitor", []
        for mid, ips in self.member_ips.items():
            if source_ip not in ips:
                continue
            run = self.runs(mid)
            try:
                allowed = run.ws.max_action(source_ip) if run is not None else max(
                    (d["action"] for d, _ in self._member_proposals(mid) if d["source_ip"] == source_ip),
                    key=SEVERITY.get, default="monitor")
            except ToolError:
                continue
            reasons.append(f"أشد ما تسمح به سياسة {mid}: {ACTION_AR[allowed]}")
            best = max(best, allowed, key=SEVERITY.get)
        specialist = self._specialist_proposals(source_ip)
        durations = [d["duration_min"] for _, d, _ in specialist if d["action"] in ENFORCING and d["duration_min"]]
        enforced = [mid for mid, d, _ in specialist if d["status"] == "applied" and d["action"] in BLOCKING]
        if any(p.source_ip == source_ip and p.status == "applied" and p.action in BLOCKING
               for p in self.proposals.values()):
            enforced.append(self.incident.id)
        return {"source_ip": source_ip, "max_action": best,
                "duration_min": max(durations, default=DEFAULT_DURATION) if best in ENFORCING else 0,
                "reasons": reasons, "enforced_in": enforced}

    def _register(self, source_ip, action, duration, reasons):
        own = [a for mid in self.member_ips for a in self.store.alerts(mid) if a["ip"] == source_ip]
        p = Proposal(id=max(self.proposals, default=0) + 1, source_ip=source_ip,
                     attack_type=own[0]["type"] if own else "campaign", action=action, duration_min=duration,
                     n_flows=sum(a["count"] for a in own), attack_ratio=0.0, mean_confidence=0.0, reasons=reasons)
        self.proposals[p.id] = p
        self._merge(source_ip)
        return p

    def _merge(self, source_ip):
        """معلّقات المتخصصين لنفس العنوان ← merged (لا تُعتمد بعدها، فيبطل رابط موافقتها)."""
        for mid, _, p in self._specialist_proposals(source_ip):
            if p is not None and p.status == "pending":
                p.status, p.rationale = "merged", f"دُمج في الحملة {self.incident.id}"
        for mid in self.member_ips:
            run = self.runs(mid)
            if run is not None:
                run.save()

    def propose_action(self, source_ip, action, justification):
        if action not in SEVERITY:
            raise ToolError(f"إجراء غير معروف: {action}")
        self._known(source_ip)
        for p in self.proposals.values():
            if p.source_ip == source_ip and p.status == "pending":
                return {"accepted": False, "proposal_id": p.id, "reason": "يوجد مقترح معلّق لنفس العنوان في الحملة"}
        policy = self.check_policy(source_ip)
        if action in ENFORCING and policy["enforced_in"]:
            return {"accepted": False, "reason": f"مطبّق مسبقًا في {'، '.join(policy['enforced_in'])}"}
        if SEVERITY[action] > SEVERITY[policy["max_action"]]:
            return {"accepted": False, "reason": f"الإجراء {action} أشد من الحد المسموح ({policy['max_action']})",
                    "policy_reasons": policy["reasons"]}
        duration = policy["duration_min"] if action in ENFORCING else 0
        p = self._register(source_ip, action, duration, [justification])
        return {"accepted": True, "proposal_id": p.id, "status": p.status}

    # ---------------- واجهة الـ Workspace للحلقة ----------------
    def run_tool(self, name, args):
        fn = getattr(self, name, None) if name in CAMPAIGN_READ_TOOLS + ("propose_action",) else None
        if fn is None:
            raise ToolError(f"أداة غير معروفة: {name}")
        return fn(**args)

    def max_action(self, source_ip):
        return self.check_policy(source_ip)["max_action"]

    def rules_proposals(self):
        """البديل: أشد مقترح معلّق للمتخصصين لكل مهاجم، بنفس المدة والأسباب."""
        taken = {p.source_ip for p in self.proposals.values() if p.status != "merged"}
        out = []
        for ip in self.ips:
            pending = [d for _, d, p in self._specialist_proposals(ip) if p is not None and p.status == "pending"]
            if ip in taken or not pending:
                continue
            best = max(pending, key=lambda d: SEVERITY[d["action"]])
            out.append(self._register(ip, best["action"], best["duration_min"], list(best["reasons"])))
        return out

    def sync_incident_status(self):
        pending = any(p.status == "pending" and p.action in ENFORCING for p in self.proposals.values())
        self.store.set_incident_status(self.incident.id, "investigating" if pending else "closed")
        if pending:
            return
        for mid in self.member_ips:          # حوادث المراقبة تبقى حتى إصلاح الموقع
            own = [p for _, p in self._member_proposals(mid) if p is not None]
            if not any(p.status == "pending" and p.action in ENFORCING for p in own):
                self.store.set_incident_status(mid, "closed")

    def describe(self, name, args, result):
        if "error" in result:
            return f"تعذّر تنفيذ {name}: {result['error']}"
        if name == "campaign_overview":
            return (f"الحملة تضم {len(result['members'])} حوادث من "
                    f"{'، '.join(dict.fromkeys(KIND_AR[m['kind']] for m in result['members']))}، "
                    f"و{len(result['stages'])} مراحل")
        if name == "specialist_report":
            if result["kind"] == "monitor":
                return f"حادثة المراقبة {result['incident_id']}: {result['finding']}"
            return f"قرأتُ تقرير متخصص {KIND_AR[result['kind']]} في {result['incident_id']}"
        if name == "attacker_profile":
            sources = "، ".join(dict.fromkeys(KIND_AR[a["kind"]] for a in result["alerts"]))
            return f"{result['source_ip']} ظهر في {sources}" + ("، وحمّل ملفًا مكشوفًا" if any(
                f["downloaded"] for f in result["exposed_files"]) else "")
        if name == "check_policy":
            if result["enforced_in"]:
                return f"{result['source_ip']} محظور مسبقًا في {'، '.join(result['enforced_in'])}"
            return f"السياسة تسمح لـ {result['source_ip']} بحد أقصى: {ACTION_AR[result['max_action']]}"
        if name == "propose_action":
            if result["accepted"]:
                return f"اقترحتُ {ACTION_AR[args['action']]} على {args['source_ip']} للحملة كلها — بانتظار موافقتك"
            return f"لم يُقبل مقترحي على {args['source_ip']}: {result['reason']}"
        return name


def _public(p):
    return {"id": p.id, "source_ip": p.source_ip, "action": p.action, "duration_min": p.duration_min,
            "status": p.status, "reasons": p.reasons}
