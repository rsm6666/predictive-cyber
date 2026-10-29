#!/usr/bin/env python3
"""
===================================================================
المنفّذ المرجعي — يعمل على خادم المنشأة، وهو وحده من يلمس الجدار الناري
===================================================================
يستقبل أوامر action.execute الموقّعة من المنصة ويطبّقها بـ ufw. مكتبة Python
القياسية فقط ولا يستورد شيئًا من المشروع: انسخ هذا الملف إلى خادمك وشغّله.

  # تجريبي (افتراضي): يطبع الأمر ولا ينفّذه
  python3 receiver.py --secret <سرّ التوقيع من الإعدادات> --port 9000
  # تنفيذ فعلي (يحتاج root)، مع قائمة سماح محلية
  sudo python3 receiver.py --secret ... --apply --allowlist allow.txt

ثم ضع http://<خادمك>:9000/ رابطًا للـ Webhook في إعدادات المنشأة.

حواجزه مستقلة عن المنصة: توقيع HMAC وطابع زمني، تجاهل التسليم المكرر،
قائمة سماح محلية، حماية العناوين الداخلية افتراضيًا، أوامر بلا shell،
وسقف للقواعد النشطة. كل قاعدة تُزال تلقائيًا عند انتهاء مدتها.
===================================================================
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_AGE = 300
MAX_FUTURE = 60
MAX_BODY = 64 * 1024
SEEN_MAX = 1000
BLOCKING = ("block_ip", "quarantine_host")


def verify(secret, timestamp, body, signature, now):
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if now - ts > MAX_AGE or ts - now > MAX_FUTURE:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def _timer(delay, fn):
    t = threading.Timer(delay, fn)
    t.daemon = True
    t.start()


class Enforcer:
    def __init__(self, secret, apply=False, allowlist=(), protect_private=True, max_rules=50,
                 runner=subprocess.run, clock=time.time, schedule=_timer):
        self.secret, self.apply, self.protect_private, self.max_rules = secret, apply, protect_private, max_rules
        self.allowlist = {ipaddress.ip_address(a.strip()) for a in allowlist if a.strip()}
        self.runner, self.clock, self.schedule = runner, clock, schedule
        self.active, self.seen, self.lock = {}, OrderedDict(), threading.Lock()

    def handle(self, headers, body):
        """← (رمز HTTP، رد JSON)"""
        h = {k.lower(): v for k, v in headers.items()}
        if not verify(self.secret, h.get("x-pc-timestamp"), body, h.get("x-pc-signature"), self.clock()):
            return 401, {"status": "refused", "detail": "توقيع غير صالح أو رسالة قديمة"}
        event, delivery = h.get("x-pc-event"), h.get("x-pc-delivery", "")
        if event in ("incident.report", "action.result", "monitor.alert"):     # المنفّذ هو رابط الـ Webhook، فتصله كل الأحداث
            return 200, {"status": "ignored", "detail": "المنفّذ يطبّق أوامر action.execute فقط"}
        if event not in ("action.execute", "test"):
            return 400, {"status": "refused", "detail": f"حدث غير مدعوم: {event}"}
        with self.lock:
            if delivery in self.seen:
                return 200, {"status": "duplicate", "detail": "وصل هذا التسليم مسبقًا"}
            self.seen[delivery] = True
            while len(self.seen) > SEEN_MAX:
                self.seen.popitem(last=False)
        if event == "test":
            return 200, {"status": "ok", "detail": "المنفّذ يعمل ويتحقق من التوقيع"}
        return 200, self.execute(json.loads(body)["data"])

    def execute(self, data):
        action, minutes = data.get("action"), int(data.get("duration_min") or 0)
        if action not in BLOCKING:
            return {"status": "refused", "detail": f"الإجراء {action} غير مدعوم في المنفّذ المرجعي"}
        try:
            ip = ipaddress.ip_address(str(data.get("ip")))
        except ValueError:
            return {"status": "refused", "detail": "عنوان IP غير صالح"}
        internal = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        if ip in self.allowlist or (self.protect_private and internal):
            return {"status": "refused", "detail": f"العنوان {ip} محمي في المنفّذ (قائمة سماح أو عنوان داخلي)"}
        with self.lock:
            if len(self.active) >= self.max_rules and ip not in self.active:
                return {"status": "refused", "detail": f"بلغ سقف القواعد النشطة ({self.max_rules})"}
        cmd = ["ufw", "insert", "1", "deny", "from", str(ip), "to", "any"]
        if not self.apply:
            print("تجريبي:", " ".join(cmd))
            return {"status": "dry_run", "detail": " ".join(cmd)}
        result = self.runner(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return {"status": "refused", "detail": f"فشل ufw: {(result.stderr or '').strip()[:200]}"}
        with self.lock:
            self.active[ip] = self.clock() + minutes * 60
        if minutes:
            self.schedule(minutes * 60, lambda: self._remove(ip))
        return {"status": "applied", "detail": f"{' '.join(cmd)} (يُزال بعد {minutes} دقيقة)"}

    def _remove(self, ip):
        self.runner(["ufw", "delete", "deny", "from", str(ip), "to", "any"], capture_output=True, text=True, check=False)
        with self.lock:
            self.active.pop(ip, None)


def serve(enforcer, host, port):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                code, out = 413, {"status": "refused", "detail": "رسالة كبيرة"}
            else:
                code, out = enforcer.handle(dict(self.headers), self.rfile.read(length))
            body = json.dumps(out, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} {fmt % args}")

    print(f"المنفّذ يستمع على {host}:{port} ({'تنفيذ فعلي' if enforcer.apply else 'تجريبي'})")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


def main():
    ap = argparse.ArgumentParser(description="المنفّذ المرجعي لأوامر المنصة (ufw)")
    ap.add_argument("--secret", default=os.environ.get("PC_WEBHOOK_SECRET"), help="سرّ التوقيع من إعدادات المنشأة")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--apply", action="store_true", help="تنفيذ فعلي بدل الوضع التجريبي (يحتاج root)")
    ap.add_argument("--allowlist", help="ملف عناوين لا تُحظر أبدًا، عنوان في كل سطر")
    ap.add_argument("--allow-private-targets", action="store_true", help="السماح بحظر عناوين داخلية")
    args = ap.parse_args()
    if not args.secret:
        ap.error("--secret مطلوب (أو PC_WEBHOOK_SECRET)")
    allowlist = open(args.allowlist).read().splitlines() if args.allowlist else []
    serve(Enforcer(args.secret, apply=args.apply, allowlist=allowlist,
                   protect_private=not args.allow_private_targets), args.host, args.port)


if __name__ == "__main__":
    main()
