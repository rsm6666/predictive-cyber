"""
مصادقة المنصة:
  dashboard_tenant  اعتمادية FastAPI: مفتاح اللوحة في الترويسة ← المنشأة
  StreamTokens      رمز بث لمرة واحدة (EventSource لا يرسل ترويسات)
  RateLimiter       حد بسيط في الذاكرة للتسجيل المفتوح
"""

import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from tenancy.registry import DASHBOARD, INGEST


def _bearer(request):
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def _tenant(request, kind, denied):
    found = request.app.state.platform.registry.resolve(_bearer(request))
    if found is None:
        raise HTTPException(401, "مفتاح غير صالح")
    tenant, key_kind = found
    if key_kind != kind:
        raise HTTPException(403, denied)
    return tenant


def dashboard_tenant(request: Request):
    """المنشأة تُستنتج من المفتاح فقط؛ لا يُقبل المفتاح ولا معرّف المنشأة من الرابط."""
    return _tenant(request, DASHBOARD, "هذا المفتاح لا يملك صلاحية اللوحة")


def ingest_tenant(request: Request):
    """مفتاح الاستقبال: إرسال السجلات فقط."""
    return _tenant(request, INGEST, "استخدم مفتاح الاستقبال لإرسال السجلات")


class StreamTokens:
    """رمز لمرة واحدة، مرتبط بمنشأة وحادثة، صالح TTL ثانية."""
    TTL = 60

    def __init__(self, clock=time.monotonic):
        self._clock, self._tokens, self._lock = clock, {}, threading.Lock()

    def issue(self, tenant_id, incident_id):
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = (tenant_id, incident_id, self._clock() + self.TTL)
        return token

    def consume(self, token, incident_id):
        """يرجع معرّف المنشأة أو None. الرمز يُحرق في كل الأحوال."""
        with self._lock:
            entry = self._tokens.pop(token, None)
        if entry is None or entry[1] != incident_id or self._clock() > entry[2]:
            return None
        return entry[0]


class RateLimiter:
    def __init__(self, limit=10, window=3600, clock=time.monotonic):
        self.limit, self.window, self._clock = limit, window, clock
        self._hits, self._lock = defaultdict(deque), threading.Lock()

    def allow(self, key):
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True
