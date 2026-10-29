"""
===================================================================
المرسِل: من حدث إلى رسالة مسلَّمة
===================================================================
emit          يسجّل الحدث في صندوق المنشأة الصادر لكل قناة مفعّلة
dispatch_once يرسل المستحق، ويعيد المحاولة عند الفشل (notify/outbox.py)
start         خيط خلفي يستدعي dispatch_once كل ثانيتين

رد مستقبل action.execute (المنفّذ على خادم المنشأة) يُمرَّر إلى on_result
ليُحدِّث ملاحظة المقترح: «نُفّذ على خادمك» أو «تجربة» أو سبب الرفض.
===================================================================
"""

import json
import threading
import time
import urllib.error
import urllib.request

from notify.channels import telegram_request, webhook_request
from notify.outbox import Outbox
from tenancy.registry import TENANT_ID_RE

TIMEOUT = 5


def urllib_transport(url, headers, body, timeout):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def enabled_channels(settings):
    out = []
    if settings.get("webhook_url") and settings.get("webhook_secret"):
        out.append("webhook")
    if settings.get("telegram_token") and settings.get("telegram_chat_id"):
        out.append("telegram")
    return out


class Notifier:
    def __init__(self, store, transport=None, clock=time.time):
        self.store, self.transport, self.clock = store, transport or urllib_transport, clock
        self.on_result = None
        self._pending, self._lock = set(), threading.Lock()

    def _outbox(self, tenant_id):
        return Outbox(self.store.dir(tenant_id) / "tenant.db")

    def emit(self, tenant_id, event, data, only=None):
        channels = [c for c in enabled_channels(self.store.settings(tenant_id)) if only in (None, c)]
        ids = [self._outbox(tenant_id).enqueue(event, c, data, now=self.clock()) for c in channels]
        if ids:
            with self._lock:
                self._pending.add(tenant_id)
        return ids

    def recent(self, tenant_id, limit=20):
        return self._outbox(tenant_id).recent(limit)

    def dispatch_once(self):
        with self._lock:
            tenants = list(self._pending)
        for tenant_id in tenants:
            outbox = self._outbox(tenant_id)
            for d in outbox.due(self.clock()):
                self._send(tenant_id, outbox, d)
            if outbox.pending_count() == 0:
                with self._lock:
                    self._pending.discard(tenant_id)

    def _send(self, tenant_id, outbox, d):
        settings = self.store.settings(tenant_id)
        if d["channel"] not in enabled_channels(settings):
            outbox.attempt_failed(d["id"], "القناة لم تعد مضبوطة في الإعدادات", self.clock())
            return
        if d["channel"] == "webhook":
            req = webhook_request(settings["webhook_url"], settings["webhook_secret"], d["id"], d["event"],
                                  tenant_id, d["payload"], now=self.clock())
        else:
            req = telegram_request(settings["telegram_token"], settings["telegram_chat_id"], d["event"], d["payload"])
        try:
            status, text = self.transport(*req, timeout=TIMEOUT)
        except Exception as e:      # انقطاع أو مهلة: يُعاد لاحقًا
            outbox.attempt_failed(d["id"], f"{type(e).__name__}: {e}", self.clock())
            return
        if not 200 <= status < 300:
            outbox.attempt_failed(d["id"], f"HTTP {status}: {text[:200]}", self.clock())
            return
        outbox.delivered(d["id"], text)
        if d["event"] == "action.execute" and self.on_result:
            try:
                response = json.loads(text)
            except ValueError:
                return
            if isinstance(response, dict) and "status" in response:
                self.on_result(tenant_id, d["payload"], response)

    def rebuild(self):
        """عند الإقلاع: المنشآت التي لها تسليمات معلّقة من قبل."""
        if not self.store.root.exists():
            return
        for path in self.store.root.iterdir():
            if TENANT_ID_RE.fullmatch(path.name) and (path / "tenant.db").exists():
                if self._outbox(path.name).pending_count():
                    with self._lock:
                        self._pending.add(path.name)

    def start(self, interval=2.0):
        self.rebuild()

        def loop():
            while True:
                try:
                    self.dispatch_once()
                except Exception as e:      # المرسِل لا يتوقف بسبب منشأة واحدة
                    print(f"تحذير: خطأ في المرسِل ({e})")
                time.sleep(interval)

        threading.Thread(target=loop, daemon=True).start()
