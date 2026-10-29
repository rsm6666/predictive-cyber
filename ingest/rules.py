"""
===================================================================
قواعد كشف هجمات الويب والجدار الناري — شفافة وقابلة للضبط
===================================================================
تعمل على دلاء ثابتة (5 دقائق، ودقيقة للإغراق) لكل عنوان مصدر، فيُفحص
التاريخ المُعاد كاملًا لا آخر دقائقه فقط. هجوم يقع على حدّ دلوين قد
ينقسم بينهما؛ قيد معلن في التقييم.
===================================================================
"""

import re
from collections import defaultdict
from urllib.parse import unquote_plus, urlsplit

BUCKET = 300
MINUTE = 60
BRUTE_MIN = 20              # طلبات دخول فاشلة (401/403)
SCAN_404_MIN = 30           # مسارات مختلفة بحالة 404
SENSITIVE_MIN = 3           # مسارات حساسة مختلفة
FLOOD_PER_MINUTE = 300
FW_PORTS_MIN = 20
FW_FLOOD_MIN = 100
MAX_EVIDENCE = 5

LOGIN_RE = re.compile(r"(^|/)(login|signin|wp-login\.php|admin|user/login|api/auth[\w/-]*)/?$", re.I)
SENSITIVE_RE = re.compile(
    r"(^|/)(\.env|\.git(/|$)|\.htaccess|\.htpasswd|phpmyadmin|wp-config\.php|server-status|\.aws|\.ssh"
    r"|backup\.(zip|sql|tar\.gz))", re.I)
INJECTION_RE = re.compile(
    r"union(\s|/\*.*?\*/)+(all\s+)?select|'\s*or\s+'?\d+'?\s*=\s*'?\d+|;\s*drop\s+table|sleep\(\d+\)"
    r"|information_schema|<script|javascript:|onerror\s*=|\.\./|\x00", re.I)


def _route(path):
    return urlsplit(path).path


def _decoded(path):
    return unquote_plus(unquote_plus(path))


def _groups(events, key, size):
    groups = defaultdict(list)
    for e in events:
        groups[(e[key], int(e["ts"] // size))].append(e)
    return groups.items()


def _web_line(e):
    return f"{e['method']} {e['path'][:120]} → {e['status']}"


def _fw_line(e):
    return f"{e['proto']} → {e['dst']}:{e['dport'] if e['dport'] is not None else '-'}"


def _alert(type_, source, ip, evs, severity, line, count=None, details=None):
    return {"type": type_, "source": source, "ip": ip, "first_ts": evs[0]["ts"], "last_ts": evs[-1]["ts"],
            "count": count if count is not None else len(evs), "severity": severity,
            "evidence": [line(e) for e in evs[:MAX_EVIDENCE]], "details": details or {}}


def web_rules(events):
    alerts = []
    for (ip, _), evs in _groups(events, "ip", BUCKET):
        login = [e for e in evs if e["status"] in (401, 403) and LOGIN_RE.search(_route(e["path"]))]
        if len(login) >= BRUTE_MIN:
            alerts.append(_alert("brute_force", "web", ip, login, "high", _web_line))

        not_found = [e for e in evs if e["status"] == 404]
        sensitive = [e for e in evs if SENSITIVE_RE.search(_route(e["path"]))]
        distinct_404 = {e["path"] for e in not_found}
        distinct_sensitive = sorted({_route(e["path"]) for e in sensitive})
        if len(distinct_404) >= SCAN_404_MIN or len(distinct_sensitive) >= SENSITIVE_MIN:
            hits = sorted({id(e): e for e in not_found + sensitive}.values(), key=lambda e: e["ts"])
            alerts.append(_alert("path_scan", "web", ip, hits, "medium", _web_line, details={
                "distinct_404": len(distinct_404), "sensitive": distinct_sensitive[:MAX_EVIDENCE]}))

        injected = [e for e in evs if INJECTION_RE.search(_decoded(e["path"]))]
        if injected:
            alerts.append(_alert("injection", "web", ip, injected, "high", _web_line))

    for (ip, _), evs in _groups(events, "ip", MINUTE):
        if len(evs) >= FLOOD_PER_MINUTE:
            alerts.append(_alert("flood", "web", ip, evs, "critical", _web_line))
    return alerts


def firewall_rules(events):
    alerts = []
    blocked = [e for e in events if e["action"] == "BLOCK"]
    for (src, _), evs in _groups(blocked, "src", BUCKET):
        ports = {e["dport"] for e in evs if e["dport"] is not None}
        if len(ports) >= FW_PORTS_MIN:
            alerts.append(_alert("fw_port_scan", "firewall", src, evs, "medium", _fw_line,
                                 details={"distinct_ports": len(ports)}))
        if len(evs) >= FW_FLOOD_MIN:
            alerts.append(_alert("fw_flood", "firewall", src, evs, "high", _fw_line))
    return alerts
