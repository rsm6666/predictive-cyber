"""
===================================================================
المراقب: من رابط موقع إلى درجة أمان وتنبيهات
===================================================================
add_site   يطبّع الرابط إلى الأصل، ويرفض الداخلي عند منعه، ويعطي رمز تحقق
verify     يجرّب ملف التحقق ثم DNS، وعند النجاح يشغّل فحصًا عميقًا فورًا
run_site   فحص توفر وانتقالات التعطل/البطء/العودة، وفحص عميق إن استحق
check_now  فحص كامل فوري، بحد مرة كل دقيقة لكل موقع
start      مجدول كل 15 ثانية يرسل المستحق إلى 4 عمّال

الحوادث (site_down وexposed_file) تُسجَّل في قائمة حوادث المنشأة بنوع
monitor، وتُغلق تلقائيًا عند العودة أو الإصلاح. لا تحقيق للمحلل فيها.
===================================================================
"""

import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from monitor.checks import SLOW_MS, availability, exposed_files, header_findings, score
from monitor.fetch import BLOCKED, fetch, is_private_host
from monitor.store import SiteStore
from monitor.verify import FILE_PATH, dns_name, verify_dns, verify_file
from tenancy.registry import TENANT_ID_RE

MAX_SITES = 5
AVAIL_EVERY = 5 * 60
DEEP_EVERY = 86400
MANUAL_EVERY = 60
DOWN_AFTER = 2
SLOW_AFTER = 3


class MonitorError(Exception):
    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status, self.retry_after = status, retry_after


def normalize(url):
    """رابط كامل ← الأصل فقط: scheme://host[:port] بلا مسار."""
    parts = urlsplit(url.strip())
    try:
        port = parts.port
    except ValueError:
        port = -1
    if parts.scheme not in ("http", "https") or not parts.hostname or port == -1:
        raise MonitorError(422, "أدخل رابطًا كاملًا يبدأ بـ http:// أو https://")
    if parts.username or parts.password:
        raise MonitorError(422, "الرابط لا يقبل اسم مستخدم أو كلمة مرور")
    host = parts.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")


def _port(origin):
    parts = urlsplit(origin)
    return parts.port or (443 if parts.scheme == "https" else 80)


class Monitor:
    def __init__(self, store, notifier=None, allow_private=True, fetcher=fetch, resolve_txt=None,
                 clock=time.time, workers=4):
        self.store, self.notifier, self.allow_private = store, notifier, allow_private
        self.fetcher, self.resolve_txt, self.clock = fetcher, resolve_txt, clock
        self._busy, self._lock = set(), threading.Lock()
        self._pool = ThreadPoolExecutor(workers)
        self.on_incident = None     # (tenant_id، incident_id) بعد فتح حادثة ملف مكشوف: ربط الحملات (الجزء 6)

    def sites(self, tenant_id):
        return SiteStore(self.store.dir(tenant_id) / "tenant.db")

    def _get(self, url):
        return self.fetcher(url, allow_private=self.allow_private)

    def _site(self, tenant_id, site_id):
        site = self.sites(tenant_id).get(site_id)
        if site is None:
            raise MonitorError(404, "الموقع غير موجود")
        return site

    # ---------------- الإدارة ----------------
    def add_site(self, tenant_id, url, now=None):
        origin = normalize(url)
        sites = self.sites(tenant_id)
        existing = sites.all()
        if any(s["url"] == origin for s in existing):
            raise MonitorError(409, "الموقع مضاف من قبل")
        if len(existing) >= MAX_SITES:
            raise MonitorError(409, f"الحد {MAX_SITES} مواقع لكل منشأة")
        if not self.allow_private and is_private_host(urlsplit(origin).hostname, _port(origin)):
            raise MonitorError(422, BLOCKED)
        return sites.add(origin, "pc-verify-" + secrets.token_hex(16), now or self.clock())

    def delete(self, tenant_id, site_id):
        site = self._site(tenant_id, site_id)
        sites, logs = self.sites(tenant_id), self.store.logs(tenant_id)
        for incident in [site["incident_id"]] + [f["incident_id"] for f in sites.open_findings(site_id)]:
            if incident:
                logs.set_incident_status(incident, "closed")   # لا مراقبة بعد الحذف، فلا حادثة معلّقة
        sites.delete(site_id)

    def verify(self, tenant_id, site_id, now=None):
        now = now or self.clock()
        site = self._site(tenant_id, site_id)
        dns = None
        method = "file" if verify_file(site["url"], site["token"], self._get) else None
        if method is None:
            dns = verify_dns(urlsplit(site["url"]).hostname, site["token"], self.resolve_txt)
            method = "dns" if dns else None
        if method:
            self.sites(tenant_id).update(site_id, verified_at=now, verify_method=method)
            self.run_site(tenant_id, site_id, now, deep=True)
        return {"verified": method is not None, "method": method, "dns_unavailable": method is None and dns is None}

    def check_now(self, tenant_id, site_id, now=None):
        now = now or self.clock()
        site = self._site(tenant_id, site_id)
        if site["last_manual_at"] and now - site["last_manual_at"] < MANUAL_EVERY:
            wait = int(MANUAL_EVERY - (now - site["last_manual_at"])) + 1
            raise MonitorError(429, f"انتظر {wait} ثانية قبل الفحص التالي", retry_after=wait)
        self.sites(tenant_id).update(site_id, last_manual_at=now)
        self.run_site(tenant_id, site_id, now, deep=bool(site["verified_at"]))

    # ---------------- الفحص ----------------
    def run_site(self, tenant_id, site_id, now=None, deep=None):
        key = (tenant_id, site_id)
        with self._lock:
            if key in self._busy:
                return False
            self._busy.add(key)
        try:
            self._run(tenant_id, site_id, now or self.clock(), deep)
            return True
        finally:
            with self._lock:
                self._busy.discard(key)

    def _run(self, tenant_id, site_id, now, deep):
        sites, logs = self.sites(tenant_id), self.store.logs(tenant_id)
        site = sites.get(site_id)
        if site is None:
            return
        origin, host = site["url"], urlsplit(site["url"]).hostname
        r = self._get(origin + "/")
        av = availability(r)
        sites.add_check(site_id, now, "avail", av["ok"], av["status"], av["ms"], av["detail"])
        fields = {"last_avail_at": now}

        if not av["ok"]:
            down = site["down_streak"] + 1
            fields.update(down_streak=down, slow_streak=0)
            if down >= DOWN_AFTER and not site["incident_id"]:
                detail = f"الموقع لا يستجيب في {DOWN_AFTER} فحوص متتالية ({av['detail']})"
                incident = logs.open_incident(_alert("site_down", host, "critical", now, origin, detail))
                fields["incident_id"] = incident
                self._emit(tenant_id, origin, "down", "critical", detail, incident)
        else:
            if site["incident_id"]:
                logs.set_incident_status(site["incident_id"], "closed")
                self._emit(tenant_id, origin, "recovered", "low",
                           f"عاد الموقع للعمل (HTTP {av['status']}، {av['ms']} ms)", site["incident_id"])
                fields["incident_id"] = None
            slow = site["slow_streak"] + 1 if av["slow"] else 0
            fields.update(down_streak=0, slow_streak=slow)
            if slow == SLOW_AFTER:
                self._emit(tenant_id, origin, "slow", "medium",
                           f"الموقع بطيء: أكثر من {SLOW_MS // 1000} ثوانٍ في {SLOW_AFTER} فحوص متتالية ({av['ms']} ms)")

        if deep is None:
            deep = site["last_deep_at"] is None or now - site["last_deep_at"] >= DEEP_EVERY
        if deep and site["verified_at"] and av["ok"]:
            self._deep(tenant_id, sites, logs, site, r, now)
            fields["last_deep_at"] = now
        sites.update(site_id, **fields)

    def _deep(self, tenant_id, sites, logs, site, r, now):
        origin, host = site["url"], urlsplit(site["url"]).hostname
        findings = header_findings(r, origin.startswith("https://")) + exposed_files(self._get, origin)
        new, resolved = sites.sync_findings(site["id"], findings, now)
        for f in new:
            if f["key"].startswith("exposed:"):
                detail = f"{f['title']} — {origin}{f['detail']}"
                incident = logs.open_incident(_alert("exposed_file", host, f["severity"], now, origin, detail,
                                                     path=f["detail"]))
                sites.set_finding_incident(site["id"], f["key"], incident)
                self._emit(tenant_id, origin, "exposed_file", f["severity"], detail, incident, f["fix"])
                if self.on_incident:
                    self.on_incident(tenant_id, incident)
        for f in resolved:
            if f["incident_id"]:
                logs.set_incident_status(f["incident_id"], "closed")

    def _emit(self, tenant_id, origin, kind, severity, detail, incident_id=None, fix=None):
        if self.notifier:
            self.notifier.emit(tenant_id, "monitor.alert", {"site": origin, "kind": kind, "severity": severity,
                                                            "detail": detail, "fix": fix, "incident_id": incident_id})

    # ---------------- العرض ----------------
    def summary(self, tenant_id, now=None):
        now = now or self.clock()
        sites = self.sites(tenant_id)
        out = []
        for s in sites.all():
            last = sites.last_check(s["id"])
            findings = sites.open_findings(s["id"]) if s["last_deep_at"] else []
            value, grade = score(findings) if s["last_deep_at"] else (None, None)
            state = None if last is None else "down" if not last["ok"] else "slow" if last["ms"] > SLOW_MS else "up"
            out.append({
                "id": s["id"], "url": s["url"], "created_at": s["created_at"],
                "verified": s["verified_at"] is not None, "verify_method": s["verify_method"],
                "verification": {"token": s["token"], "file_url": s["url"] + FILE_PATH,
                                 "dns_name": dns_name(urlsplit(s["url"]).hostname)},
                "state": state, "status": last and last["status"], "ms": last and last["ms"],
                "detail": last and last["detail"], "checked_at": last and last["ts"],
                "uptime_24h": sites.uptime(s["id"], now - 86400), "incident_id": s["incident_id"],
                "score": value, "grade": grade, "deep_at": s["last_deep_at"], "findings": findings,
            })
        return out

    # ---------------- المجدول ----------------
    def _due(self, site, now):
        avail = site["last_avail_at"] is None or now - site["last_avail_at"] >= AVAIL_EVERY
        deep = site["verified_at"] is not None and (site["last_deep_at"] is None
                                                    or now - site["last_deep_at"] >= DEEP_EVERY)
        return avail or deep

    def tick(self, now=None):
        now = now or self.clock()
        if not self.store.root.exists():
            return
        for path in self.store.root.iterdir():
            if TENANT_ID_RE.fullmatch(path.name) and (path / "tenant.db").exists():
                for site in self.sites(path.name).all():
                    if self._due(site, now):
                        self.submit(path.name, site["id"])

    def submit(self, tenant_id, site_id):
        self._pool.submit(self._safe_run, tenant_id, site_id)

    def _safe_run(self, tenant_id, site_id):
        try:
            self.run_site(tenant_id, site_id)
        except Exception as e:      # موقع واحد لا يوقف المراقبة
            print(f"تحذير: خطأ في مراقبة الموقع {site_id} للمنشأة {tenant_id} ({e})")

    def start(self, interval=15.0):
        def loop():
            while True:
                try:
                    self.tick()
                except Exception as e:
                    print(f"تحذير: خطأ في مجدول المراقبة ({e})")
                time.sleep(interval)

        threading.Thread(target=loop, daemon=True).start()


def _alert(type_, host, severity, now, origin, detail, path=None):
    details = {"url": origin, "detail": detail, **({"path": path} if path else {})}
    return {"type": type_, "source": "monitor", "ip": host, "first_ts": now, "last_ts": now, "count": 1,
            "severity": severity, "evidence": [detail], "details": details}
