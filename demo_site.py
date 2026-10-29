"""
===================================================================
موقع العرض للمراقبة الخارجية: متجر صغير بثغرات مقصودة
===================================================================
  - بلا ترويسات أمان، وServer: nginx/1.18.0، وX-Powered-By، وملف /.env وهمي مكشوف
  - يرد 200 بالصفحة الرئيسية لأي مسار آخر (مثل مواقع SPA) ليظهر أن الفحص لا ينخدع
  - ملف التحقق /.well-known/pc-verification.txt من --token أو /__token/<الرمز>

نقاط تحكم للعرض (من نفس الجهاز فقط):
  /__down  يعطّل الموقع (503)      /__up     يعيده للعمل
  /__fix   يصلح الثغرات             /__break  يعيدها

التشغيل:
  python demo_site.py --port 8090
ثم أضف http://127.0.0.1:8090 في صفحة «المراقبة»، وانسخ رمز التحقق:
  curl http://127.0.0.1:8090/__token/<الرمز>
===================================================================
"""

import argparse
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = """<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><title>متجر التمور</title>
<body style="font-family:system-ui;max-width:640px;margin:40px auto"><h1>متجر التمور</h1>
<p>سكري، خلاص، عجوة — توصيل لكل المدن.</p></body></html>""".encode()
FAKE_ENV = b"APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD=demo-not-a-real-secret\nSTRIPE_KEY=sk_demo_123\n"
SECURE = [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
          ("X-Frame-Options", "SAMEORIGIN"), ("X-Content-Type-Options", "nosniff"),
          ("Referrer-Policy", "strict-origin-when-cross-origin"),
          ("Permissions-Policy", "camera=(), microphone=(), geolocation=()")]

state = {"down": False, "fixed": False, "token": None}


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "nginx" if state["fixed"] else "nginx/1.18.0"

    def _send(self, status, body, ctype="text/html; charset=utf-8", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _control(self, path):
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            return self._send(403, b"local only", "text/plain")
        if path.startswith("/__token/"):
            state["token"] = path[len("/__token/"):]
        else:
            state.update({"/__down": {"down": True}, "/__up": {"down": False},
                          "/__fix": {"fixed": True}, "/__break": {"fixed": False}}.get(path, {}))
        self._send(200, f"{state}\n".encode(), "text/plain")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/__"):
            return self._control(path)
        if state["down"]:
            return self._send(503, b"Service Unavailable", "text/plain")
        if path == "/.well-known/pc-verification.txt" and state["token"]:
            return self._send(200, state["token"].encode(), "text/plain")
        if path == "/.env" and not state["fixed"]:
            return self._send(200, FAKE_ENV, "text/plain")
        if state["fixed"]:
            headers = SECURE + [("Set-Cookie", "session=demo; Path=/; HttpOnly; SameSite=Lax")]
        else:
            headers = [("X-Powered-By", "PHP/7.4.3"), ("Set-Cookie", "session=demo; Path=/")]
        self._send(200, HOME, headers=headers)   # أي مسار آخر يرجع الرئيسية (SPA)

    def log_message(self, fmt, *args):
        print(f"[demo_site] {self.address_string()} {fmt % args}")


def main():
    ap = argparse.ArgumentParser(description="موقع عرض بثغرات مقصودة للمراقبة الخارجية")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--token", help="رمز التحقق من صفحة «المراقبة»")
    args = ap.parse_args()
    state["token"] = args.token
    print(f"موقع العرض يعمل على http://{args.host}:{args.port} (تحكم: /__down /__up /__fix /__break /__token/<رمز>)")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
