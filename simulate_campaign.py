"""
===================================================================
محاكي حملة متعددة المراحل (الجزء 6) — عبر الواجهات الحقيقية
===================================================================
مهاجم واحد (45.155.205.12) عبر مصدرين، وطُعم لا يجب ربطه:
  1. وكيل الخادم: 8 دقائق ترافيك CICIDS فيها PortScan من المهاجم (simulate_flows)
  2. سجلات الموقع: فحص مسارات يطلب /.env (200 إن كان مكشوفًا)، ثم تخمين كلمات المرور
  3. طُعم: إغراق من 103.75.190.9 قبل ساعتين ← حادثة سجلات منفصلة بلا ربط

إن كان demo_site مراقبًا و/.env مكشوفًا فيه، تربط القاعدة 2 حادثة المراقبة أيضًا.

  python simulate_campaign.py --key $INGEST_KEY
  python simulate_campaign.py --key $INGEST_KEY --env-status 404   # الملف لم يُحمّل
===================================================================
"""

import argparse
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sensor.agent import WINDOW, Sender
from simulate_flows import ATTACKERS, generate
from simulate_logs import ATTACKERS as LOG_ATTACKERS, SCAN_WORDS, send, web_line

HERE = Path(__file__).resolve().parent
ATTACKER = ATTACKERS["PortScan"]
DECOY = LOG_ATTACKERS["flood"]
SCANNER_UA = "Mozilla/5.0 zgrab/0.x"
assert LOG_ATTACKERS["scan"] == ATTACKER     # نفس العنوان في المحاكيين


def _scan(t, env_status):
    paths = SCAN_WORDS + [f"/old{i}" for i in range(30)]
    return [web_line(t + i, ATTACKER, "GET", p, env_status if p == "/.env" else 404,
                     90 if p == "/.env" and env_status == 200 else 150, SCANNER_UA) for i, p in enumerate(paths)]


def _brute(t):
    return [web_line(t + i * 2, ATTACKER, "POST", "/wp-login.php", 401, 230, "python-requests/2.31.0")
            for i in range(40)]


def _flood(t):
    return [web_line(t + i * 0.1, DECOY, "GET", "/", 200, 4000, "Mozilla/5.0") for i in range(600)]


def build(act, now, rng, env_status=200):
    """← {flows: دفعات الوكيل، web: سطور المهاجم، decoy: سطور الطُعم، attacker، decoy_ip}"""
    start = (now // WINDOW - 8) * WINDOW
    flows = generate(act, 8, start, rng, attack="PortScan", attack_at=3, attack_minutes=2)
    return {"flows": flows, "web": _scan(now - 180, env_status) + _brute(now - 100),
            "decoy": _flood(now - 2 * 3600), "attacker": ATTACKER, "decoy_ip": DECOY}


def main():
    ap = argparse.ArgumentParser(description="حملة متعددة المراحل: وكيل الخادم + سجلات الموقع + طُعم")
    ap.add_argument("--url", default="http://localhost:8001")
    ap.add_argument("--key", required=True, help="مفتاح الاستقبال pc_ing_...")
    ap.add_argument("--env-status", type=int, default=200, choices=(200, 404), help="رد /.env على المهاجم")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    act = pd.read_parquet(HERE / "dashboard_cache" / "act_sample.parquet")
    plan = build(act, time.time(), np.random.default_rng(args.seed), args.env_status)
    print(f"1) طُعم: إغراق من {DECOY} قبل ساعتين")
    send(args.url, args.key, "web", plan["decoy"])
    print(f"2) وكيل الخادم: {len(plan['flows'])} نوافذ فيها فحص منافذ من {ATTACKER}")
    with tempfile.TemporaryDirectory() as buffer:
        sender = Sender(args.url, args.key, buffer)
        for b in plan["flows"]:
            sender.send(b)
    print(f"3) سجلات الموقع: فحص مسارات (/.env ← {args.env_status}) ثم تخمين كلمات المرور من {ATTACKER}")
    send(args.url, args.key, "web", plan["web"])
    print("تابع «منشأتي»: حادثتان تُربطان في حملة بعد تحقيق المتخصصين، والطُعم يبقى منفصلًا.")


if __name__ == "__main__":
    main()
