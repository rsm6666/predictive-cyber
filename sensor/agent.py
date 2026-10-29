#!/usr/bin/env python3
"""
===================================================================
وكيل الخادم — يعمل على خادم المنشأة ويرسل ملخصات التدفقات للمنصة
===================================================================
يلتقط الترافيك (أو يقرأ ملف pcap)، ويقسمه نوافذ دقيقة واحدة، ويحسب لكل
تدفق الخصائص الـ77 (sensor/flows.py)، ويرسل كل نافذة بمفتاح الاستقبال.

  # التقاط حي (يكفيه CAP_NET_RAW بدل root):
  sudo setcap cap_net_raw+eip "$(readlink -f "$(which python3)")"
  python3 -m sensor.agent --url https://platform.example --key $INGEST_KEY --iface eth0
  # ملف pcap (بلا صلاحية): يُعاد بتوقيته النسبي منتهيًا «الآن»
  python3 -m sensor.agent --url ... --key ... --pcap capture.pcap

حواجزه: قراءة فقط (لا يغيّر شيئًا في الخادم ولا يستقبل أوامر)، ولا يخرج منه
محتوى الحزم، وحد 5000 تدفق لكل نافذة، ويستثني اتصاله بالمنصة، والدفعات
التي فشل إرسالها تُحفظ محليًا (24 ساعة أو 50MB) وتُعاد بالترتيب.
===================================================================
"""

import argparse
import gzip
import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from sensor.flows import FlowTable, from_scapy

VERSION = "1.0"
WINDOW = 60
MAX_FLOWS = 5000
MAX_BUFFER_BYTES = 50 * 1024 * 1024
MAX_BUFFER_AGE = 86400
DROP = (400, 413, 422)          # رفض نهائي: إعادة الدفعة لن تنجح


def make_batch(start, rows, host, window=WINDOW):
    return {"agent": {"host": host, "version": VERSION}, "window_start": start, "window_end": start + window,
            "truncated": len(rows) > MAX_FLOWS, "flows": rows[:MAX_FLOWS]}


def encode(batch):
    return gzip.compress(json.dumps(batch, separators=(",", ":")).encode())


def decode(body):
    return json.loads(gzip.decompress(body))


class Windower:
    """الحزم ← نوافذ دقيقة بوقت الحزمة. tick في الالتقاط الحي يغلق النافذة ولو بلا حزم (نبضة حياة)."""

    def __init__(self, on_window, window=WINDOW, exclude=(), start=None):
        self.on_window, self.window, self.exclude = on_window, window, set(exclude)
        self.start, self.table = start, FlowTable()

    def _emit(self):
        self.on_window(self.start, self.table.rows())
        self.table = FlowTable()

    def add(self, p):
        if p is None or (p.dst, p.dport) in self.exclude or (p.src, p.sport) in self.exclude:
            return
        w = p.ts // self.window * self.window
        if self.start is None:
            self.start = w
        elif w > self.start:
            self._emit()
            self.start = w
        self.table.add(p)

    def tick(self, now):
        while self.start is not None and now >= self.start + self.window:
            self._emit()
            self.start += self.window

    def close(self):
        if self.start is not None and len(self.table):
            self._emit()


def urllib_transport(url, headers, body):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


class Sender:
    """كل دفعة تُكتب في المخزن أولًا، ثم يُرسل المخزن من الأقدم حتى أول فشل."""

    def __init__(self, url, key, buffer_dir, transport=None, clock=time.time,
                 max_bytes=MAX_BUFFER_BYTES, max_age=MAX_BUFFER_AGE):
        self.url = url.rstrip("/") + "/api/v1/ingest/flows"
        self.headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                        "Content-Encoding": "gzip"}
        self.dir = Path(buffer_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.transport, self.clock = transport or urllib_transport, clock
        self.max_bytes, self.max_age = max_bytes, max_age

    def _files(self):
        return sorted(self.dir.glob("*.json.gz"))

    def send(self, batch):
        (self.dir / f"{int(batch['window_start']):012d}-{uuid.uuid4().hex[:8]}.json.gz").write_bytes(encode(batch))
        self._prune()
        self.flush()

    def flush(self):
        for path in self._files():
            try:
                status = self.transport(self.url, self.headers, path.read_bytes())
            except OSError as e:
                print(f"تعذّر الإرسال ({e})؛ الدفعة محفوظة وستُعاد")
                return
            if status < 300 or status in DROP:
                if status in DROP:
                    print(f"رفضت المنصة الدفعة {path.name} نهائيًا (HTTP {status})")
                path.unlink()
            else:     # 401/403 مفتاح، 429 معدل، 5xx خادم: نعيد لاحقًا
                print(f"المنصة ردت HTTP {status}؛ الدفعات محفوظة وستُعاد")
                return

    def _prune(self):
        files = self._files()
        for path in files:
            if int(path.name.split("-")[0]) < self.clock() - self.max_age:
                path.unlink()
        files = self._files()
        while len(files) > 1 and sum(f.stat().st_size for f in files) > self.max_bytes:
            files.pop(0).unlink()


def run_pcap(path, emit, host, now=None):
    """ملف pcap بتوقيته النسبي، منتهيًا «الآن» حتى تقبله المنصة كنوافذ حديثة."""
    from scapy.utils import PcapReader
    with PcapReader(path) as reader:
        last = max((float(p.time) for p in reader), default=None)
    if last is None:
        return
    shift = (now or time.time()) - last - 0.001     # قبل «الآن» بقليل حتى لا تقع آخر حزمة على حد نافذة جديدة
    windower = Windower(lambda start, rows: emit(make_batch(start, rows, host)))
    with PcapReader(path) as reader:
        for raw in reader:
            p = from_scapy(raw)
            if p is not None:
                p.ts += shift
                windower.add(p)
    windower.close()


def run_live(iface, sender, host, exclude):
    """الالتقاط في خيط scapy، والنوافذ تُغلق بالساعة كل ثانية، والإرسال في الخيط الرئيسي."""
    from scapy.sendrecv import AsyncSniffer
    ready, lock = queue.Queue(), threading.Lock()
    now = time.time()
    windower = Windower(lambda start, rows: ready.put(make_batch(start, rows, host)),
                        exclude=exclude, start=now // WINDOW * WINDOW)

    def on_packet(raw):
        p = from_scapy(raw)
        if p is not None:
            p.ts = min(p.ts, time.time())
            with lock:
                windower.add(p)

    sniffer = AsyncSniffer(iface=iface, filter="ip", prn=on_packet, store=False)
    sniffer.start()
    print(f"الوكيل يلتقط على {iface}؛ نافذة كل {WINDOW} ثانية. أوقفه بـ Ctrl+C")
    try:
        while True:
            time.sleep(1)
            with lock:
                windower.tick(time.time())
            while not ready.empty():
                batch = ready.get()
                sender.send(batch)
                print(f"نافذة {time.strftime('%H:%M', time.localtime(batch['window_start']))}: "
                      f"{len(batch['flows'])} تدفقًا" + (" (مقتطعة)" if batch["truncated"] else ""))
    finally:
        sniffer.stop()


def platform_endpoints(url):
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        return {(info[4][0], port) for info in socket.getaddrinfo(parts.hostname, port)}
    except OSError:
        return set()


def main():
    ap = argparse.ArgumentParser(description="وكيل الخادم: يرسل ملخصات التدفقات لمنصة التنبؤ بالهجمات")
    ap.add_argument("--url", required=True, help="عنوان المنصة، مثل https://platform.example")
    ap.add_argument("--key", default=os.environ.get("PC_INGEST_KEY"), help="مفتاح الاستقبال pc_ing_...")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="واجهة الالتقاط الحي، مثل eth0")
    src.add_argument("--pcap", help="ملف pcap بدل الالتقاط الحي")
    ap.add_argument("--host", default=socket.gethostname(), help="اسم هذا الخادم كما يظهر في المنصة")
    ap.add_argument("--buffer", default=str(Path.home() / ".pc-sensor"), help="مجلد المخزن المحلي")
    args = ap.parse_args()
    if not args.key:
        ap.error("--key أو PC_INGEST_KEY مطلوب")
    sender = Sender(args.url, args.key, args.buffer)
    if args.pcap:
        run_pcap(args.pcap, sender.send, args.host)
        left = len(sender._files())
        print("أُرسلت كل النوافذ" if not left else f"بقيت {left} نافذة في المخزن وستُعاد في التشغيل التالي")
    else:
        run_live(args.iface, sender, args.host, platform_endpoints(args.url))


if __name__ == "__main__":
    main()
