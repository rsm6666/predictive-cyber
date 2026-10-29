"""
جلب صفحة من الخارج بحدود صارمة: مهلة، وحد للجسم، وحد للتحويلات،
ورفض العناوين الداخلية (لكل تحويل أيضًا) عند منعها.
"""

import http.client
import ipaddress
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

UA = "PredictiveCyber-Monitor/1.0"
MAX_BODY = 256 * 1024
MAX_REDIRECTS = 5
BLOCKED = "العنوان داخلي أو محلي، والمراقبة الخارجية لا تفحصه"


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)   # أسماء بحروف صغيرة
    cookies: list = field(default_factory=list)   # قيم Set-Cookie كما هي
    body: bytes = b""
    ms: int = 0
    error: str | None = None

    @property
    def content_type(self):
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


class _Blocked(Exception):
    pass


def is_private_host(host, port=80, resolver=socket.getaddrinfo):
    """صحيح إن حُلّ المضيف (أو كان) إلى أي عنوان غير عام."""
    try:
        infos = resolver(host, port)
    except OSError:
        return False   # لا يُحل: سيفشل الطلب نفسه
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return True
    return False


def fetch(url, allow_private=True, resolver=socket.getaddrinfo, timeout=10):
    def check(u):
        parts = urlsplit(u)
        if parts.scheme not in ("http", "https"):
            raise _Blocked("بروتوكول غير مدعوم")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if not allow_private and is_private_host(parts.hostname or "", port, resolver):
            raise _Blocked(BLOCKED)

    class Redirects(urllib.request.HTTPRedirectHandler):
        max_redirections = MAX_REDIRECTS

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            check(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects)
    start = time.monotonic()
    elapsed = lambda: int((time.monotonic() - start) * 1000)
    try:
        check(url)
        try:
            resp = opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e   # 4xx/5xx رد طبيعي بالنسبة للفحص
        with resp:
            body = resp.read(MAX_BODY)
            msg = resp.headers
            return Response(resp.status,
                            {k.lower(): v for k, v in msg.items()}, msg.get_all("Set-Cookie") or [],
                            body, elapsed())
    except _Blocked as e:
        return Response(ms=elapsed(), error=str(e))
    except (TimeoutError, socket.timeout):
        return Response(ms=elapsed(), error="انتهت المهلة")
    except urllib.error.URLError as e:
        reason = "انتهت المهلة" if isinstance(e.reason, (TimeoutError, socket.timeout)) else f"تعذّر الاتصال: {e.reason}"
        return Response(ms=elapsed(), error=reason)
    except (OSError, http.client.HTTPException, ValueError) as e:
        return Response(ms=elapsed(), error=f"تعذّر الاتصال: {e}")
