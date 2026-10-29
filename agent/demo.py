"""
===================================================================
وضع العرض التجريبي — محلل بلا نموذج لغوي (حتى يُربط مفتاح Claude)
===================================================================
DemoClient يحاكي واجهة عميل Claude (beta.messages.create) فتعمل حلقة
الوكيل والخادم والواجهة كما هي. لكنه لا «يفكر»: يتبع خطوات ثابتة
(نظرة عامة ← المصادر ← التفسير ← التنبؤ ← السياسة ← المقترح ← التقرير)
فوق نتائج الأدوات الحقيقية، ويكتب التقرير والإجابات من قوالب.
كل رقم في التقرير مأخوذ من نتائج الأدوات. الواجهة تعلن هذا الوضع صراحة.
===================================================================
"""

import itertools
import json
import time
from types import SimpleNamespace

from sandbox_firewall import MIN_ATTACK_RATIO, MIN_FLOWS

from agent.analyst import SYSTEM_CHAT
from agent.log_tools import FEATURE_AR, TYPE_AR
from agent.tools import ENFORCING
from campaign.linker import TYPE_AR as LOG_TYPE_AR_ALL

MAX_TARGETS = 2
FAMILY_AR = {
    "PortScan": "فحص المنافذ", "DoS": "حجب الخدمة", "DDoS": "حجب الخدمة الموزّع",
    "Brute Force (FTP/SSH)": "تخمين كلمات المرور", "Web Attack": "هجوم على تطبيق الويب",
    "Botnet": "جهاز ضمن شبكة بوتات",
}
FAMILY_PLAIN = {
    "PortScan": "جهازًا يفحص أجهزتك واحدًا تلو الآخر بحثًا عن منفذ مفتوح",
    "DoS": "جهازًا يغرق أحد خوادمك بطلبات كثيرة ليوقفه عن العمل",
    "DDoS": "سيلًا من الطلبات يستهدف خدمة لديك لإيقافها",
    "Brute Force (FTP/SSH)": "محاولات متكررة لتخمين كلمات مرور الدخول إلى خوادمك",
    "Web Attack": "محاولات لاختراق موقعك أو تطبيق الويب لديك",
    "Botnet": "جهازًا يتواصل مع خادم تحكم خارجي وقد يكون مخترقًا",
}
SEVERITY = {"DoS": "critical", "DDoS": "critical", "Botnet": "critical",
            "Brute Force (FTP/SSH)": "high", "Web Attack": "high", "PortScan": "medium"}
_RANK = ["none", "low", "medium", "high", "critical"]
_ids = itertools.count(1)


def _flows(n):
    """عدد الاتصالات بصيغة عربية صحيحة."""
    if n == 1:
        return "اتصالًا واحدًا"
    if n == 2:
        return "اتصالين"
    return f"{n:,} اتصالات" if 3 <= n <= 10 else f"{n:,} اتصالًا"


def _action_phrase(action, ip):
    if action == "rate_limit_target":
        return f"تقييد الطلبات على الخدمة التي يستهدفها {ip}"
    if action == "quarantine_host":
        return f"عزل الجهاز {ip}"
    return f"حظر العنوان {ip}"


def _response(*blocks):
    stop = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
    usage = SimpleNamespace(input_tokens=0, output_tokens=0,
                            cache_read_input_tokens=0, cache_creation_input_tokens=0)
    return SimpleNamespace(content=list(blocks), stop_reason=stop, usage=usage)


def _call(name, **args):
    return _response(SimpleNamespace(type="tool_use", name=name, input=args, id=f"demo_{next(_ids)}"))


def _history(messages):
    """[(اسم الأداة، المدخلات، النتيجة)] من سجل المحادثة."""
    uses, calls = {}, []
    for m in messages:
        if not isinstance(m["content"], list):
            continue
        for b in m["content"]:
            if getattr(b, "type", None) == "tool_use":
                uses[b.id] = (b.name, b.input)
            elif isinstance(b, dict) and b.get("type") == "tool_result":
                name, args = uses[b["tool_use_id"]]
                calls.append((name, args, json.loads(b["content"])))
    return calls


class DemoClient:
    def __init__(self, delay=0.0):
        self.delay = delay      # إبطاء بسيط حتى تظهر الخطوات واحدة تلو الأخرى في العرض
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        time.sleep(self.delay)
        if kw["system"] == SYSTEM_CHAT:
            return _response(SimpleNamespace(type="text", text=_chat_answer(kw["messages"][-1]["content"])))
        if any(t["name"] == "campaign_overview" for t in kw["tools"]):   # المنسّق على حملة
            return _next_campaign_step(_history(kw["messages"]))
        if any(t["name"] == "source_activity" for t in kw["tools"]):     # حادثة من سجلات المنشأة
            return _next_log_step(_history(kw["messages"]))
        return _next_step(_history(kw["messages"]))


# ===================================================================
# التحقيق: الخطوة التالية من نتائج ما سبق
# ===================================================================
def _next_step(calls):
    done = {(name, args.get("source_ip")) for name, args, _ in calls}
    results = {name: res for name, _, res in calls}
    if ("incident_overview", None) not in done:
        return _call("incident_overview")
    if ("suspicious_sources", None) not in done:
        return _call("suspicious_sources")

    targets = [s for s in results["suspicious_sources"]["sources"]
               if s["flagged_flows"] >= MIN_FLOWS and s["attack_ratio"] >= MIN_ATTACK_RATIO][:MAX_TARGETS]
    for s in targets:
        if ("explain_source", s["source_ip"]) not in done:
            return _call("explain_source", source_ip=s["source_ip"])
    if ("forecast_next_minute", None) not in done:
        return _call("forecast_next_minute")
    for s in targets:
        if ("check_policy", s["source_ip"]) not in done:
            return _call("check_policy", source_ip=s["source_ip"])
    policies = {args["source_ip"]: res for name, args, res in calls if name == "check_policy"}
    for s in targets:
        policy = policies[s["source_ip"]]
        if policy.get("max_action") in ENFORCING and ("propose_action", s["source_ip"]) not in done:
            return _call("propose_action", source_ip=s["source_ip"], action=policy["max_action"],
                         justification=f"{_flows(s['flagged_flows'])} صنّفها النموذج «{FAMILY_AR[s['predicted_type']]}» "
                                       f"بنسبة {s['attack_ratio']:.0%} وثقة {s['mean_confidence']:.0%}")
    return _call("submit_report", **_report(calls, targets))


def _report(calls, targets):
    overview = next(res for name, _, res in calls if name == "incident_overview")
    forecast = next(res for name, _, res in calls if name == "forecast_next_minute")
    explained = {args["source_ip"]: res for name, args, res in calls if name == "explain_source"}
    proposed = [(args, res) for name, args, res in calls if name == "propose_action" and res.get("accepted")]
    soon = (f"احتمال هجوم في الدقيقة التالية {forecast['probability']:.0%}"
            if "probability" in forecast else "التنبؤ غير متاح")

    if not targets:
        flagged = overview["flows_flagged_as_attack"]
        return {
            "severity": "low" if flagged else "none",
            "summary_owner": (f"راجعنا {_flows(overview['total_flows'])} في شبكتك. "
                              + (f"النموذج علّم {_flows(flagged)} بشكل متفرق من مصادر مختلفة، ولا يوجد مصدر بنمط هجومي واضح؛ "
                                 "هذه غالبًا أخطاء تصنيف فردية. " if flagged else "لم نجد أي اتصال مشبوه. ")
                              + "لا حاجة لأي إجراء الآن."),
            "attack_types": [], "findings": [], "proposal_ids": [],
            "watch_next": f"{soon}؛ استمر في المراقبة المعتادة",
            "confidence": 0.8,
        }

    findings = []
    for s in targets:
        evidence = [f"{_flows(s['flagged_flows'])} صنّفها النموذج «{FAMILY_AR[s['predicted_type']]}»",
                    f"نسبة الاتصالات الهجومية {s['attack_ratio']:.0%} بمتوسط ثقة {s['mean_confidence']:.0%}"]
        top = explained.get(s["source_ip"], {}).get("top_features")
        if top:
            evidence.append(f"أبرز مؤشر: {top[0]['feature']} ({top[0]['direction']})")
        findings.append({"source_ip": s["source_ip"], "assessment": FAMILY_AR[s["predicted_type"]],
                         "evidence": evidence})

    main = targets[0]
    action_text = ("واقترحنا " + "، و".join(_action_phrase(a["action"], a["source_ip"]) for a, _ in proposed)
                   + "، وينتظر ذلك موافقتك.") if proposed else "ولم نقترح حظرًا لأن الدليل غير كافٍ؛ نكتفي بالمراقبة."
    severity = max((SEVERITY[s["predicted_type"]] for s in targets), key=_RANK.index)
    if not proposed:
        severity = "medium" if _RANK.index(severity) > _RANK.index("medium") else severity
    return {
        "severity": severity,
        "summary_owner": (f"رصدنا {FAMILY_PLAIN[main['predicted_type']]}، مصدره العنوان {main['source_ip']}. "
                          + ("ونتوقع استمرار النشاط في الدقيقة القادمة. " if forecast.get("alert") else "")
                          + action_text),
        "attack_types": sorted({s["predicted_type"] for s in targets}),
        "findings": findings,
        "proposal_ids": [r["proposal_id"] for _, r in proposed],
        "watch_next": f"{soon}؛ راقب أي اتصالات جديدة من نفس المصدر",
        "confidence": round(sum(s["mean_confidence"] for s in targets) / len(targets), 2),
    }


# ===================================================================
# التحقيق في حوادث السجلات الحقيقية
# ===================================================================
LOG_PLAIN = {
    "brute_force": "محاولات متكررة لتخمين كلمة المرور على صفحة الدخول",
    "path_scan": "فحصًا لمسارات موقعك بحثًا عن ملفات حساسة",
    "flood": "سيلًا من الطلبات يحاول إبطاء موقعك أو إيقافه",
    "injection": "محاولات لحقن أوامر خبيثة في موقعك",
    "fw_port_scan": "فحصًا لمنافذ خادمك بحثًا عن خدمة مفتوحة",
    "fw_flood": "محاولات اتصال متكررة صدّها جدارك الناري",
}
LOG_TARGETS = 3


def _events(n):
    if n == 1:
        return "حدثًا واحدًا"
    if n == 2:
        return "حدثين"
    return f"{n:,} أحداث" if 3 <= n <= 10 else f"{n:,} حدثًا"


def _next_log_step(calls):
    done = {(name, args.get("source_ip")) for name, args, _ in calls}
    results = {name: res for name, _, res in calls}
    if ("incident_overview", None) not in done:
        return _call("incident_overview")
    alerts = results["incident_overview"]["alerts"]
    ips = list(dict.fromkeys(a["ip"] for a in alerts))[:LOG_TARGETS]
    for ip in ips:
        if ("source_activity", ip) not in done:
            return _call("source_activity", source_ip=ip)
    if any(a["type"] == "anomaly" for a in alerts) and ("anomaly_context", None) not in done:
        return _call("anomaly_context")
    for ip in ips:
        if ("check_policy", ip) not in done:
            return _call("check_policy", source_ip=ip)
    policies = {args["source_ip"]: res for name, args, res in calls if name == "check_policy"}
    for ip in ips:
        policy = policies[ip]
        if policy.get("max_action") in ENFORCING and ("propose_action", ip) not in done:
            kinds = "، ".join(TYPE_AR[a["type"]] for a in alerts if a["ip"] == ip)
            return _call("propose_action", source_ip=ip, action=policy["max_action"],
                         justification=f"تنبيه قاعدة على هذا العنوان: {kinds}")
    return _call("submit_report", **_log_report(calls, alerts, ips))


def _log_report(calls, alerts, ips):
    activity = {args["source_ip"]: res for name, args, res in calls if name == "source_activity"}
    anomalies = next((res["anomalies"] for name, _, res in calls if name == "anomaly_context"), [])
    proposed = [(args, res) for name, args, res in calls if name == "propose_action" and res.get("accepted")]

    findings = []
    for ip in ips:
        own = [a for a in alerts if a["ip"] == ip]
        evidence = [f"تنبيه «{TYPE_AR[a['type']]}»: {_events(a['count'])}" for a in own]
        web = (activity.get(ip) or {}).get("web")
        if web:
            top = web["top_paths"][0]
            evidence.append(f"أكثر مسار طلبه: {top['path']} ({top['count']} مرة)")
        for an in (x for x in anomalies if x["ip"] == ip):
            evidence += [f"انحراف عن المعتاد في: {FEATURE_AR[f['feature']]} (z={f['z']:+})" for f in an["features"][:2]]
        findings.append({"source_ip": ip, "assessment": "، ".join(TYPE_AR[a["type"]] for a in own),
                         "evidence": evidence})

    rule_alerts = [a for a in alerts if a["type"] != "anomaly"]
    severity = max((a["severity"] for a in alerts), key=_RANK.index)
    if rule_alerts:
        main = rule_alerts[0]
        action_text = ("واقترحنا " + "، و".join(_action_phrase(a["action"], a["source_ip"]) for a, _ in proposed)
                       + "، وينتظر ذلك موافقتك.") if proposed else "ولم نقترح حظرًا لأن العنوان محمي أو الدليل غير كافٍ."
        summary = f"رصدنا {LOG_PLAIN[main['type']]}، مصدره العنوان {main['ip']}. " + action_text
        watch = "راقب أي نشاط جديد من نفس العنوان أو عناوين قريبة منه خلال الساعة القادمة"
    else:
        severity = "low"
        summary = (f"لاحظنا سلوكًا غير معتاد من العنوان {ips[0]} مقارنة بزوار موقعك المعتادين. "
                   "هذا ليس دليلًا كافيًا على هجوم، فنكتفي بمراقبته دون حظر.")
        watch = "إذا تكرر هذا السلوك أو ظهر معه تنبيه قاعدة، فسيُقترح إجراء أشد"
    return {
        "severity": severity, "summary_owner": summary,
        "attack_types": sorted({a["type"] for a in alerts}), "findings": findings,
        "proposal_ids": [r["proposal_id"] for _, r in proposed], "watch_next": watch,
        "confidence": 0.85 if rule_alerts else 0.5,
    }


# ===================================================================
# المنسّق: الحملة (الجزء 6)
# ===================================================================
STAGE_PLAIN = {
    "weakness": "كان في موقعك ملف حساس مكشوف للعامة",
    "recon": "استطلع المهاجم خادمك أو موقعك بحثًا عن ثغرة",
    "access": "حاول الدخول بتخمين كلمات المرور",
    "exploit": "استغل ثغرة أو سرّب بيانات",
    "disruption": "حاول تعطيل خدمتك",
}
CAMPAIGN_TARGETS = 4


def _next_campaign_step(calls):
    done = {(name, args.get("source_ip") or args.get("incident_id")) for name, args, _ in calls}
    if ("campaign_overview", None) not in done:
        return _call("campaign_overview")
    overview = next(res for name, _, res in calls if name == "campaign_overview")
    for m in overview["members"][:CAMPAIGN_TARGETS]:
        if ("specialist_report", m["incident_id"]) not in done:
            return _call("specialist_report", incident_id=m["incident_id"])
    ips = overview["attackers"][:CAMPAIGN_TARGETS]
    for tool in ("attacker_profile", "check_policy"):
        for ip in ips:
            if (tool, ip) not in done:
                return _call(tool, source_ip=ip)
    profiles = {args["source_ip"]: res for name, args, res in calls if name == "attacker_profile"}
    policies = {args["source_ip"]: res for name, args, res in calls if name == "check_policy"}
    for ip in ips:
        policy, profile = policies[ip], profiles[ip]
        if (policy.get("max_action") in ENFORCING and not policy.get("enforced_in")
                and ("propose_action", ip) not in done):
            seen = "، ".join(dict.fromkeys(a["incident_id"] for a in profile.get("alerts", [])))
            return _call("propose_action", source_ip=ip, action=policy["max_action"],
                         justification=f"ظهر في حوادث الحملة {seen}؛ إجراء واحد يغني عن موافقة لكل حادثة")
    return _call("submit_report", **_campaign_report(calls, overview, ips, policies, profiles))


def _campaign_report(calls, overview, ips, policies, profiles):
    proposed = [(args, res) for name, args, res in calls if name == "propose_action" and res.get("accepted")]
    stages = overview["stages"]
    story = "، ثم ".join(dict.fromkeys(STAGE_PLAIN[s["stage"]] for s in stages if s["stage"] != "weakness"))
    downloaded = any(l["downloaded"] for l in overview["links"])
    enforced = [ip for ip in ips if policies[ip].get("enforced_in")]
    summary = f"ربطنا {len(overview['members'])} حوادث في هجوم واحد منسّق: {story}. "
    if any(s["stage"] == "weakness" for s in stages):     # سياق لا فعل مهاجم، أيًّا كان وقت اكتشافه
        summary += STAGE_PLAIN["weakness"] + "، وطلبه المهاجم. "
    if proposed:
        summary += ("نقترح " + "، و".join(_action_phrase(a["action"], a["source_ip"]) for a, _ in proposed)
                    + " بموافقة واحدة تغني عن موافقة لكل حادثة.")
    elif enforced:
        summary += "المهاجم محظور مسبقًا، فلا يلزم إجراء جديد."
    if downloaded:
        summary += " حُمّل ملف حساس من موقعك فعلًا."
    findings = []
    for ip in ips:
        p = profiles.get(ip) or {}
        evidence = [f"{a['incident_id']}: {LOG_TYPE_AR_ALL.get(a['type'], a['type'])} ({_events(a['count'])})"
                    for a in p.get("alerts", [])]
        evidence += [f["reason"] for f in p.get("exposed_files", [])]
        findings.append({"source_ip": ip, "assessment": "مهاجم في الحملة" + (" ربط حوادثها" if p.get("linking_ip") else ""),
                         "evidence": evidence})
    watch = ("غيّر فورًا كلمات المرور والمفاتيح الموجودة في الملف المكشوف، واحذفه من موقعك"
             if downloaded else "راقب أي نشاط جديد من نفس المهاجم في أي مصدر خلال الأيام القادمة")
    return {
        "severity": overview["severity"], "summary_owner": summary,
        "attack_types": sorted({s["type"] for s in stages if s["type"] in LOG_TYPE_AR_ALL}), "findings": findings,
        "proposal_ids": [r["proposal_id"] for _, r in proposed], "watch_next": watch, "confidence": 0.9,
        "stages": [{k: s[k] for k in ("stage", "incident_id", "time", "description")} for s in stages],
    }


# ===================================================================
# المحادثة: إجابات من قوالب فوق سياق الحادثة
# ===================================================================
def _chat_answer(content):
    head, _, question = content.partition("\n\nسؤال صاحب المنشأة: ")
    ctx = json.loads(head.split("\n", 1)[1])
    report = ctx.get("report") or {}
    acts = [p for p in ctx.get("proposals", []) if p["action"] in ENFORCING]
    pending = [p for p in acts if p["status"] == "pending"]
    applied = [p for p in acts if p["status"] == "applied"]

    def names(ps):
        return "، و".join(_action_phrase(p["action"], p["source_ip"]) for p in ps)

    if any(w in question for w in ("ليش", "لماذا", "ليه", "السبب")):
        if not acts:
            return "لم أقترح أي حظر في هذه الحادثة، لأن الأدلة لم تصل إلى حد السياسة (عدد الاتصالات أو نسبة الهجوم أو الثقة)."
        return " ".join(f"اقترحت {_action_phrase(p['action'], p['source_ip'])} لأن {'، '.join(p['reasons'])}." for p in acts)
    if any(w in question for w in ("آمن", "امن", "الوضع")):
        if pending:
            return f"ليس بعد: الإجراء المقترح ({names(pending)}) ما زال بانتظار موافقتك. بعد الموافقة يتوقف المصدر عن الوصول لشبكتك."
        if applied:
            return f"بعد تطبيق {names(applied)} لم يبقَ مصدر مشبوه نشط في هذه النافذة، فالوضع تحت السيطرة. {report.get('watch_next', '')}"
        return report.get("summary_owner", "لا يوجد تقرير بعد.")
    if any(w in question for w in ("أسوي", "اسوي", "أفعل", "افعل", "المفروض", "أعمل")):
        if pending:
            return f"وافق على المقترح ({names(pending)}) من قائمة الإجراءات، ثم راقب الوضع. {report.get('watch_next', '')}"
        return f"لا يلزمك إجراء الآن. {report.get('watch_next', '')}"
    return (f"{report.get('summary_owner', '')} (وضع العرض التجريبي يجيب على أسئلة محددة فقط، "
            "مثل: هل شبكتي آمنة؟ ليش اقترحت الحظر؟ وش المفروض أسوي؟ وعند ربط Claude يجيب على أي سؤال.)")
