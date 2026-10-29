"""
===================================================================
بيانات العرض: منشأة «متجر التمور» جاهزة للعرض أمام اللجنة
===================================================================
كل شيء عبر واجهات المنصة الحقيقية، كما يرسله عميل حقيقي:
  1. التسجيل، وWebhook إلى المنفّذ المرجعي (تجريبي على 9000)
  2. يومان من سجلات متجر طبيعية (ليتعلم نموذج الشذوذ)
  3. 14 دقيقة ترافيك طبيعي من وكيل الخادم (ليجهز مؤشر LSTM)
  4. مراقبة demo_site بملف /.env مكشوف (تحقق الملكية بالملف)
  5. الحملة: فحص منافذ ← فحص مسارات حمّل /.env ← تخمين، وطُعم منفصل
ثم يحفظ المفاتيح في demo_video/out/demo_keys.json (مستثنى من git)،
ويبقي وكيل الخادم «متصلًا» بنافذة طبيعية كل دقيقة مع --keepalive.

المتطلبات: الخادم على 8001، وdemo_site على 8091، والمنفّذ على 9000:
  python demo_site.py --port 8091
  PC_WEBHOOK_SECRET=<من demo_keys.json> python enforcer/receiver.py --port 9000
  python demo_video/seed_demo.py --keepalive
===================================================================
"""

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sensor.agent import WINDOW, Sender  # noqa: E402
from simulate_campaign import build  # noqa: E402
from simulate_flows import generate  # noqa: E402
from simulate_logs import send  # noqa: E402

OUT = ROOT / "demo_video" / "out"


def call(url, method="GET", key=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        **({"Authorization": f"Bearer {key}"} if key else {}), "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"null")


def wait(what, check, timeout=180):
    for _ in range(timeout):
        out = check()
        if out:
            return out
        time.sleep(1)
    sys.exit(f"انتهت المهلة: {what}")


def send_flows(base, key, batches):
    with tempfile.TemporaryDirectory() as buffer:
        sender = Sender(base, key, buffer)
        for b in batches:
            sender.send(b)


def main():
    ap = argparse.ArgumentParser(description="منشأة عرض جاهزة للتصوير")
    ap.add_argument("--url", default="http://localhost:8001")
    ap.add_argument("--site", default="http://127.0.0.1:8091")
    ap.add_argument("--enforcer", default="http://127.0.0.1:9000/")
    ap.add_argument("--keepalive", action="store_true", help="نافذة طبيعية كل دقيقة بعد التجهيز")
    args = ap.parse_args()
    base, api = args.url, args.url + "/api/v1"
    act = pd.read_parquet(ROOT / "dashboard_cache" / "act_sample.parquet")
    rng = np.random.default_rng(2026)

    t = call(api + "/tenants", "POST", body={"name": "متجر التمور"})
    dk, ik = t["dashboard_key"], t["ingest_key"]
    secret = call(api + "/settings", "PUT", dk, {"webhook_url": args.enforcer, "allowlist": []})["webhook_secret"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "demo_keys.json").write_text(json.dumps({"tenant_id": t["tenant_id"], "dashboard_key": dk,
                                                    "ingest_key": ik, "webhook_secret": secret}, indent=2))
    print(f"1) المنشأة {t['tenant_id']} — المفاتيح في {OUT / 'demo_keys.json'}")

    print("2) يومان من سجلات المتجر الطبيعية…")
    subprocess.run([sys.executable, str(ROOT / "simulate_logs.py"), "--url", base, "--key", ik,
                    "--history-days", "2"], check=True, stdout=subprocess.DEVNULL)

    now = time.time()
    print("3) 14 دقيقة من وكيل الخادم…")
    send_flows(base, ik, generate(act, 14, (now // WINDOW - 22) * WINDOW, rng))

    print("4) مراقبة الموقع…")
    site = call(api + "/monitor/sites", "POST", dk, {"url": args.site})
    urllib.request.urlopen(f"{args.site}/__token/{site['verification']['token']}", timeout=10).read()
    call(f"{api}/monitor/sites/{site['id']}/verify", "POST", dk)
    wait("حادثة الملف المكشوف", lambda: any(i["kind"] == "monitor" for i in call(api + "/incidents", key=dk)["incidents"]))

    print("5) الحملة والطُعم…")
    plan = build(act, time.time(), rng)
    send(base, ik, "web", plan["decoy"])
    send_flows(base, ik, plan["flows"])
    send(base, ik, "web", plan["web"])

    def settled():
        rows = call(api + "/incidents", key=dk)["incidents"]
        camp = [i for i in rows if i["kind"] == "campaign" and i["status"] == "investigating"]
        return camp and not call(api + "/agent/status", key=dk)["running"] and camp[0]
    camp = wait("تحقيق المنسّق", settled)
    print(f"جاهز: الحملة {camp['id']} بانتظار قرارك. لوحة التحكم: {base}/app/")

    while args.keepalive:       # وكيل الخادم «متصل» أثناء التصوير
        time.sleep(WINDOW - time.time() % WINDOW + 1)
        start = (time.time() // WINDOW - 1) * WINDOW
        send_flows(base, ik, generate(act, 1, start, rng))


if __name__ == "__main__":
    main()
