"""موقع HTTP حقيقي محلي للاختبارات، بمسارات وسلوك قابلين للضبط أثناء الاختبار."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTML = {"Content-Type": "text/html; charset=utf-8"}


class LocalSite:
    """routes: مسار ← (حالة، [(ترويسة، قيمة)]، جسم). fallback لأي مسار آخر (SPA = 200 للكل)."""

    def __init__(self, routes=None, fallback=(404, list(HTML.items()), b"not found")):
        self.routes, self.fallback, self.delay, self.down = dict(routes or {}), fallback, 0.0, False
        self.hits = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                site.hits.append(self.path)
                time.sleep(site.delay)
                if site.down:
                    self.send_response(503)
                    self.end_headers()
                    return
                status, headers, body = site.routes.get(self.path.split("?")[0], site.fallback)
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def page(headers=(), body=b"<html>shop</html>", status=200):
    return status, list(HTML.items()) + list(headers), body


SECURE_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'"), ("Strict-Transport-Security", "max-age=31536000"),
    ("X-Frame-Options", "SAMEORIGIN"), ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"), ("Permissions-Policy", "camera=()"),
    ("Server", "nginx"), ("Set-Cookie", "sid=1; Secure; HttpOnly"),
]
