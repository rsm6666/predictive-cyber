"""
بناء طلبات القنوات (بلا إرسال): Webhook موقّع، ورسالة Telegram عربية.
كل دالة ترجع (الرابط، الترويسات، الجسم) ليرسلها المرسِل بأي نقل.
"""

import html
import ipaddress
import json
from urllib.parse import urlsplit

from agent.tools import ACTION_AR
from notify.signing import sign

SEV_AR = {"critical": "حرجة", "high": "مرتفعة", "medium": "متوسطة", "low": "منخفضة", "none": "لا خطر"}
STATUS_AR = {"applied": "طُبّق", "rejected": "رُفض", "refused": "رفضه الحاجز", "covered": "مغطّى بقاعدة سابقة",
             "no_enforcement": "مراقبة فقط"}


def is_local_url(url):
    host = urlsplit(url).hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def webhook_request(url, secret, delivery_id, event, tenant_id, data, now):
    body = json.dumps({"event": event, "delivery_id": delivery_id, "tenant_id": tenant_id,
                       "created_at": int(now), "data": data}, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "X-PC-Event": event, "X-PC-Delivery": delivery_id,
               "X-PC-Timestamp": str(int(now)), "X-PC-Signature": sign(secret, int(now), body)}
    return url, headers, body


def _report_text(d, local):
    e = html.escape
    title = {"campaign": "حملة هجوم منسّقة"}.get(d.get("kind")) or (
        "تنبيه أمني" if d.get("kind") in (None, "log", "network") else "تنبيه أمني (محاكاة)")
    lines = [f"<b>{title} — {e(d.get('tenant_name', ''))}</b>",
             f"الخطورة: <b>{SEV_AR.get(d.get('severity'), e(str(d.get('severity'))))}</b> · الحادثة {e(d['incident_id'])}",
             "", e(d.get("summary", ""))]
    if d.get("stages"):
        lines += ["", "<b>المراحل:</b>"] + [f"{i}. {e(st['description'])}" for i, st in enumerate(d["stages"], 1)]
    if d.get("proposals"):
        lines += ["", "<b>إجراءات بانتظار قرارك:</b>"]
        for p in d["proposals"]:
            line = f"• {ACTION_AR.get(p['action'], e(p['action']))} على <code>{e(p['source_ip'])}</code>"
            if p.get("duration_min"):
                line += f" ({p['duration_min']} دقيقة)"
            lines.append(line)
            if local:
                lines.append(f"  للقرار (من نفس الجهاز): {e(p['approve_url'])}")
    return "\n".join(lines)


def _text(event, d, local):
    e = html.escape
    if event == "incident.report":
        return _report_text(d, local)
    if event == "monitor.alert":
        return _monitor_text(d)
    if event == "action.result":
        status = STATUS_AR.get(d.get("status"), e(str(d.get("status"))))
        return (f"{ACTION_AR.get(d['action'], e(d['action']))} على <code>{e(d['source_ip'])}</code>: <b>{status}</b>"
                + (f"\n{e(d['note'])}" if d.get("note") else ""))
    return f"رسالة تجربة من منصة التنبؤ بالهجمات ({e(d.get('tenant_name', ''))}): الربط يعمل."


MONITOR_AR = {"down": "الموقع متعطل", "recovered": "عاد الموقع للعمل", "slow": "الموقع بطيء",
              "exposed_file": "ملف حساس مكشوف"}


def _monitor_text(d):
    e = html.escape
    lines = [f"<b>مراقبة الموقع: {MONITOR_AR.get(d['kind'], e(d['kind']))}</b>",
             f"<code>{e(d['site'])}</code> · الخطورة: <b>{SEV_AR.get(d['severity'], e(d['severity']))}</b>", "",
             e(d.get("detail", ""))]
    if d.get("fix"):
        lines += ["", "<b>الإصلاح (Nginx):</b>", f"<code>{e(d['fix']['nginx'])}</code>"]
    return "\n".join(lines)


def telegram_request(token, chat_id, event, data):
    proposals = data.get("proposals") or []
    local = any(is_local_url(p["approve_url"]) for p in proposals)
    msg = {"chat_id": chat_id, "text": _text(event, data, local), "parse_mode": "HTML",
           "disable_web_page_preview": True}
    if event == "incident.report" and proposals and not local:   # Telegram يرفض أزرار URL لعناوين محلية
        msg["reply_markup"] = {"inline_keyboard": [[
            {"text": f"وافق: {ACTION_AR.get(p['action'], p['action'])} {p['source_ip']}", "url": p["approve_url"] + "?d=approve"},
            {"text": "ارفض", "url": p["approve_url"] + "?d=reject"}] for p in proposals]}
    return (f"https://api.telegram.org/bot{token}/sendMessage", {"Content-Type": "application/json"},
            json.dumps(msg, ensure_ascii=False).encode())
