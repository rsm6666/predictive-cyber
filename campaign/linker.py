"""
===================================================================
رابط الحوادث في حملات (الجزء 6) — قواعد ثابتة قابلة للتفسير، بلا نموذج
===================================================================
  القاعدة 1 (same_ip): نفس عنوان المهاجم في حادثتي سجلات/شبكة خلال 24 ساعة
  القاعدة 2 (exposed_file): مهاجم حادثة سجلات/شبكة طلب مسارًا كشفته المراقبة
            خلال 24 ساعة من فتح حادثتها؛ الرد 200 = «حُمّل الملف فعلًا» ← critical

العناوين في القائمة البيضاء لا تربط شيئًا. لكل ربط سبب نصي يُعرض كما هو.
الحملة حادثة بنوع campaign؛ إذا امتدت الروابط عبر حملتين تُدمج الأحدث في الأقدم.
===================================================================
"""

from dataclasses import dataclass, field

from agent.log_tools import TYPE_AR as LOG_TYPE_AR
from ingest.store import SEVERITY_RANK, _incident_n

WINDOW = 24 * 3600
KIND_AR = {"log": "السجلات", "network": "الشبكة", "monitor": "المراقبة"}
TYPE_AR = {**LOG_TYPE_AR, "site_down": "الموقع متعطل", "exposed_file": "ملف حساس مكشوف",
           "net_scan": "فحص منافذ", "net_sweep": "مسح أجهزة الشبكة", "net_brute": "تخمين على خدمة دخول",
           "net_flood": "إغراق بالاتصالات", "net_ddos": "هجوم موزّع", "net_model": "هجوم رصده النموذج"}
ATTACKER_KINDS = ("log", "network")


@dataclass
class LinkResult:
    campaign: str | None
    changed: bool = False
    merged: list = field(default_factory=list)


def attacker_ips(store, incident_id, allowlist=()):
    """عناوين تنبيهات الحادثة بالترتيب، خارج القائمة البيضاء."""
    return [ip for ip in dict.fromkeys(a["ip"] for a in store.alerts(incident_id)) if ip not in set(allowlist)]


def _types(store, incident_id, ip):
    return "، ".join(dict.fromkeys(TYPE_AR.get(a["type"], a["type"])
                                   for a in store.alerts(incident_id) if a["ip"] == ip))


def _exposed_path(store, incident_id):
    a = next((a for a in store.alerts(incident_id) if a["type"] == "exposed_file"), None)
    return a and a["details"].get("path")


def _exposed_link(store, ip, monitor_inc, other):
    """← (rule، ip، السبب، حُمّل؟، الوقت) إن طلب ip مسار حادثة المراقبة في نافذتها."""
    path = _exposed_path(store, monitor_inc["id"])
    if not path:
        return None
    hits = store.path_requests(path, monitor_inc["opened_at"] - WINDOW, monitor_inc["opened_at"] + WINDOW, ip=ip)
    if not hits:
        return None
    ok = [h for h in hits if h["status"] == 200]
    first = (ok or hits)[0]
    shown = f"\u2066{path}\u2069"          # عزل المسار عن اتجاه النص العربي
    reason = (f"{ip} حمّل {shown} الذي كشفته المراقبة (HTTP 200)" if ok
              else f"{ip} طلب {shown} الذي كشفته المراقبة (HTTP {first['status']})")
    return other, "exposed_file", ip, reason, bool(ok), first["ts"]


def _exposed_incidents(store, start, end):
    return [i for i in store.incidents(limit=500)
            if i["kind"] == "monitor" and start <= i["opened_at"] <= end and _exposed_path(store, i["id"])]


def _found(store, inc, allowlist):
    """كل الروابط المكتشفة: [(الحادثة الأخرى، القاعدة، العنوان، السبب، حُمّل؟، الوقت)]."""
    start, end = inc["opened_at"] - WINDOW, inc["updated_at"] + WINDOW
    out = []
    if inc["kind"] in ATTACKER_KINDS:
        ips = attacker_ips(store, inc["id"], allowlist)
        for ip in ips:
            for other in store.incidents_with_ip(ip, start, end):
                if other != inc["id"]:
                    o = store.incident(other)
                    reason = (f"نفس العنوان {ip} في {KIND_AR[inc['kind']]} ({_types(store, inc['id'], ip)}) "
                              f"و{KIND_AR[o['kind']]} ({_types(store, other, ip)})")
                    out.append((other, "same_ip", ip, reason, False, min(inc["opened_at"], o["opened_at"])))
        for m in _exposed_incidents(store, start, end):
            out += [x for x in (_exposed_link(store, ip, m, m["id"]) for ip in ips) if x]
    elif inc["kind"] == "monitor" and _exposed_path(store, inc["id"]):
        hits = store.path_requests(_exposed_path(store, inc["id"]), start, inc["opened_at"] + WINDOW)
        for ip in dict.fromkeys(h["ip"] for h in hits):
            if ip in set(allowlist):
                continue
            for other in store.incidents_with_ip(ip, inc["opened_at"] - WINDOW, inc["opened_at"] + WINDOW):
                x = _exposed_link(store, ip, inc, other)
                if x:
                    out.append(x)
    return out


def _refresh(store, cid, changed):
    members = store.campaign_members(cid)
    severity = max((m["severity"] for m in members), key=SEVERITY_RANK.get)
    if any(l["downloaded"] for l in store.links(cid)):
        severity = "critical"
    fields = {"severity": severity, "updated_at": max(m["updated_at"] for m in members)}
    if changed and store.incident(cid)["status"] == "closed":
        fields["status"] = "open"
    store.update_incident(cid, **fields)


def link(store, incident_id, allowlist=()):
    """يربط الحادثة بما يرتبط بها، وينشئ الحملة أو يضمها أو يدمج حملتين. ← LinkResult"""
    inc = store.incident(incident_id)
    if inc is None or inc["kind"] == "campaign":
        return LinkResult(None)
    found = _found(store, inc, allowlist)
    if not found:
        return LinkResult(inc["campaign"])

    members = list(dict.fromkeys([incident_id] + [f[0] for f in found]))
    rows = {m: store.incident(m) for m in members}
    camps = sorted({r["campaign"] for r in rows.values() if r["campaign"]}, key=_incident_n)
    changed = False
    if camps:
        cid, merged = camps[0], camps[1:]
    else:
        cid, merged = store.new_campaign(min(r["opened_at"] for r in rows.values()), inc["severity"]), []
    for c in merged:
        store.move_campaign(c, cid)
        store.update_incident(c, status="merged")
        changed = True
    for m in members:
        if store.incident(m)["campaign"] != cid:
            store.set_campaign(m, cid)
            changed = True
    for other, rule, ip, reason, downloaded, at in found:
        a, b = sorted((incident_id, other), key=_incident_n)
        changed |= store.add_link(cid, a, b, rule, ip, reason, downloaded, at)
    _refresh(store, cid, changed)
    return LinkResult(cid, changed, merged)
