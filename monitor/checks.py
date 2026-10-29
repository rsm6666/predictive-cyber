"""
فحوص الموقع من رد HTTP: التوفر، وترويسات الأمان، والملفات الحساسة المكشوفة، والدرجة.
كل ملاحظة تحمل شرح الخطر بالعربية وسطر إصلاح جاهزًا لـ Nginx وApache.
"""

import re
import secrets

SLOW_MS = 3000

# المفتاح: (الخصم، الخطورة، العنوان، الخطر، إصلاح Nginx، إصلاح Apache)
CATALOG = {
    "csp": (15, "medium", "لا توجد سياسة أمان المحتوى (CSP)",
            "بدونها يسهل حقن سكربتات خبيثة في صفحاتك (XSS) وسرقة جلسات العملاء.",
            "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always;",
            "Header always set Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\""),
    "hsts": (10, "medium", "لا يُفرض HTTPS على المتصفح (HSTS)",
             "يمكن لمهاجم في نفس الشبكة إنزال الاتصال إلى HTTP غير مشفّر واعتراض البيانات.",
             "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
             "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""),
    "xfo": (10, "medium", "الموقع قابل للتضمين في إطار (Clickjacking)",
            "يمكن تضمين موقعك في صفحة مزيفة وخداع العميل للنقر على أزرار لا يراها.",
            "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "Header always set X-Frame-Options \"SAMEORIGIN\""),
    "cookies": (10, "medium", "ملفات تعريف ارتباط بلا حماية (Secure/HttpOnly)",
                "ملف الجلسة بلا HttpOnly تقرؤه السكربتات المحقونة، وبلا Secure قد يُرسل بلا تشفير.",
                "proxy_cookie_flags ~ secure httponly;",
                "Header always edit Set-Cookie ^(.*)$ \"$1; Secure; HttpOnly\""),
    "nosniff": (5, "low", "لا يُمنع تخمين نوع المحتوى (nosniff)",
                "قد يفسّر المتصفح ملفًا مرفوعًا كسكربت وينفّذه.",
                "add_header X-Content-Type-Options \"nosniff\" always;",
                "Header always set X-Content-Type-Options \"nosniff\""),
    "referrer": (5, "low", "لا توجد سياسة للمُحيل (Referrer-Policy)",
                 "قد تتسرب روابط داخلية فيها معلومات حساسة إلى المواقع الخارجية.",
                 "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
                 "Header always set Referrer-Policy \"strict-origin-when-cross-origin\""),
    "permissions": (5, "low", "لا تُقيَّد صلاحيات المتصفح (Permissions-Policy)",
                    "يمكن لسكربت محقون طلب الكاميرا أو الموقع الجغرافي باسم موقعك.",
                    "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
                    "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""),
    "server_version": (5, "low", "الخادم يكشف رقم إصداره",
                       "رقم الإصدار يدل المهاجم مباشرة على الثغرات المعروفة لهذا الإصدار.",
                       "server_tokens off;",
                       "ServerTokens Prod\nServerSignature Off"),
    "powered_by": (5, "low", "الموقع يكشف تقنيته (X-Powered-By)",
                   "معرفة اللغة وإصدارها تختصر على المهاجم البحث عن ثغرة مناسبة.",
                   "proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;",
                   "Header always unset X-Powered-By"),
}

# المسار، الخطورة، بصمة المحتوى (None = ملف ثنائي/نسخة احتياطية: غير HTML ويختلف عن خط الأساس)
EXPOSED = [
    ("/.env", "critical", re.compile(rb"^[A-Z][A-Z0-9_]*=", re.M)),
    ("/.git/config", "critical", re.compile(rb"\[core\]")),
    ("/.git/HEAD", "critical", re.compile(rb"\Aref: refs/")),
    ("/backup.zip", "high", None),
    ("/db.sql", "high", None),
    ("/phpinfo.php", "high", re.compile(rb"phpinfo\(\)")),
    ("/server-status", "high", re.compile(rb"Server Status")),
    ("/wp-config.php.bak", "high", None),
    ("/.DS_Store", "high", None),
]
EXPOSED_DEDUCTION = 40


def _finding(key, detail=""):
    deduction, severity, title, risk, nginx, apache = CATALOG[key]
    return {"key": key, "severity": severity, "deduction": deduction, "title": title, "risk": risk,
            "detail": detail, "fix": {"nginx": nginx, "apache": apache}}


def availability(r):
    ok = r.error is None and r.status < 500
    return {"ok": ok, "slow": ok and r.ms > SLOW_MS, "status": r.status, "ms": r.ms,
            "detail": r.error or f"HTTP {r.status}"}


def header_findings(r, https):
    h = r.headers
    csp = h.get("content-security-policy", "")
    found = []
    if not csp:
        found.append(_finding("csp"))
    if https and "strict-transport-security" not in h:
        found.append(_finding("hsts"))
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        found.append(_finding("xfo"))
    weak = []
    for cookie in r.cookies:
        flags = {p.strip().lower() for p in cookie.split(";")[1:]}
        if "httponly" not in flags or (https and "secure" not in flags):
            weak.append(cookie.split("=")[0].strip())
    if weak:
        found.append(_finding("cookies", "، ".join(weak)))
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        found.append(_finding("nosniff"))
    if "referrer-policy" not in h:
        found.append(_finding("referrer"))
    if "permissions-policy" not in h:
        found.append(_finding("permissions"))
    if re.search(r"\d", h.get("server", "")):
        found.append(_finding("server_version", h["server"]))
    if "x-powered-by" in h:
        found.append(_finding("powered_by", h["x-powered-by"]))
    return found


def _exposed_finding(path, severity):
    block = "location ^~ /.git/ { deny all; }" if path.startswith("/.git/") else f"location = {path} {{ deny all; }}"
    match = '<LocationMatch "^/\\.git/">' if path.startswith("/.git/") else f'<Location "{path}">'
    close = "</LocationMatch>" if path.startswith("/.git/") else "</Location>"
    return {"key": f"exposed:{path}", "severity": severity, "deduction": EXPOSED_DEDUCTION,
            "title": f"ملف حساس مكشوف للعامة: {path}",
            "risk": "أي شخص يستطيع تنزيله الآن، وقد يحوي كلمات مرور أو مفاتيح أو بيانات عملاء. "
                    "احذفه من مجلد الموقع، وغيّر أي سر ظهر فيه.",
            "detail": path, "fix": {"nginx": block, "apache": f"{match}\n  Require all denied\n{close}"}}


def exposed_files(get, base):
    """get(url) ← Response. يقارن بمسار عشوائي غير موجود حتى لا تخدعه مواقع SPA."""
    baseline = get(f"{base}/pc-{secrets.token_hex(8)}")
    found = []
    for path, severity, signature in EXPOSED:
        r = get(base + path)
        if r.error or r.status != 200 or not r.body or r.body == baseline.body:
            continue
        hit = signature.search(r.body) if signature else r.content_type != "text/html"
        if hit:
            found.append(_exposed_finding(path, severity))
    return found


def score(findings):
    value = max(0, 100 - sum(f["deduction"] for f in findings))
    grade = next((g for g, floor in (("A", 90), ("B", 80), ("C", 70), ("D", 60)) if value >= floor), "F")
    return value, grade
