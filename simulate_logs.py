"""
===================================================================
مولّد سجلات متجر إلكتروني — للعرض والتقييم (بلا موقع حقيقي)
===================================================================
ترافيك طبيعي (زوار يتصفحون ويشترون، وزواحف بحث، وضجيج إنترنت على الجدار)
بكثافة تتغير حسب ساعة اليوم، مع هجمات اختيارية من عناوين منفصلة.

  # يومان من التاريخ الطبيعي (ليتعلم نموذج الشذوذ) ثم 30 دقيقة فيها هجمات
  python simulate_logs.py --key pc_ing_... --history-days 2
  python simulate_logs.py --key pc_ing_... --minutes 30 --attack brute sqli

  # بث مباشر للعرض: دفعة كل 5 ثوانٍ، والهجوم بعد 30 ثانية
  python simulate_logs.py --key pc_ing_... --live 5 --attack brute --attack-at 30

  # حفظ في ملفات بدل الإرسال
  python simulate_logs.py --minutes 60 --attack scan --out /tmp/shop
===================================================================
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import numpy as np

ATTACKS = ("brute", "scan", "sqli", "flood", "fw_scan", "scrape")
# scrape بلا قاعدة عمدًا: سحب الكتالوج كاملًا بإيقاع تحت عتبة الإغراق، ليظهر دور نموذج الشذوذ
EXPECTED_RULE = {"brute": "brute_force", "scan": "path_scan", "sqli": "injection",
                 "flood": "flood", "fw_scan": "fw_port_scan", "scrape": "anomaly"}
ATTACKERS = {"brute": "185.220.101.7", "scan": "45.155.205.12", "sqli": "91.240.118.33",
             "flood": "103.75.190.9", "fw_scan": "80.94.95.115", "scrape": "152.32.128.40"}
SERVER = "10.0.0.5"
SESSIONS_PER_MINUTE = 2.0
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SEARCH_WORDS = ["qahwa", "dates", "perfume", "abaya", "oud", "gift", "honey", "tea"]
SCAN_WORDS = ["/.env", "/.git/config", "/phpmyadmin/", "/wp-config.php", "/server-status", "/backup.zip",
              "/admin.php", "/config.json", "/.aws/credentials", "/debug", "/test.php", "/old", "/db.sql"]
SQLI = ["1' UNION SELECT username,password FROM users--", "1' OR '1'='1", "1; DROP TABLE orders",
        "1 AND SLEEP(5)", "<script>alert(1)</script>", "../../../../etc/passwd"]


def web_line(ts, ip, method, path, status, size, ua, referer="-"):
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def fw_line(ts, src, dport, rng, proto="TCP"):
    t = datetime.fromtimestamp(ts, tz=timezone.utc)
    return (f"{t:%b} {t.day:2d} {t:%H:%M:%S} shop kernel: [{int(ts) % 100000}.{int(rng.integers(1000))}] "
            f"[UFW BLOCK] IN=eth0 OUT= SRC={src} DST={SERVER} PROTO={proto} SPT={int(rng.integers(1024, 65535))} "
            f"DPT={dport} WINDOW=1024 SYN URGP=0")


def _visitor_pool(rng, n=400):
    firsts = [5, 31, 37, 46, 51, 62, 77, 78, 80, 82, 85, 86, 87, 89, 94, 95, 176, 178, 188, 212, 213]
    return [f"{firsts[int(rng.integers(len(firsts)))]}.{int(rng.integers(1, 255))}."
            f"{int(rng.integers(1, 255))}.{int(rng.integers(1, 255))}" for _ in range(n)]


def _page_view(rng, ts, ip, ua, path, status=200):
    out = [(ts, web_line(ts, ip, "GET", path, status, int(rng.integers(3000, 40000)), ua))]
    for asset in ("/static/app.css", "/static/app.js"):
        ts += float(rng.uniform(0.05, 0.4))
        out.append((ts, web_line(ts, ip, "GET", asset, 304 if rng.random() < 0.5 else 200,
                                 int(rng.integers(200, 90000)), ua, "https://shop.example/")))
    return out


def _session(rng, ts, ip, ua):
    lines = _page_view(rng, ts, ip, ua, "/")
    for _ in range(int(rng.integers(1, 6))):
        ts += float(rng.uniform(3, 25))
        r = rng.random()
        if r < 0.6:
            lines += _page_view(rng, ts, ip, ua, f"/products/{int(rng.integers(1, 120))}")
        elif r < 0.75:
            lines += _page_view(rng, ts, ip, ua, f"/search?q={SEARCH_WORDS[int(rng.integers(len(SEARCH_WORDS)))]}")
        elif r < 0.9:
            lines.append((ts, web_line(ts, ip, "POST", "/cart/add", 302, 120, ua)))
            lines += _page_view(rng, ts + 0.5, ip, ua, "/cart")
        elif r < 0.97:
            lines += _page_view(rng, ts, ip, ua, "/checkout")
            lines.append((ts + 20, web_line(ts + 20, ip, "POST", "/checkout", 303, 90, ua)))
        else:
            lines += _page_view(rng, ts, ip, ua, f"/products/{int(rng.integers(500, 900))}", status=404)
    return lines


def _normal(start, minutes, rng, pool):
    web, fw = [], []
    for m in range(minutes):
        t = start + m * 60
        hour = datetime.fromtimestamp(t, tz=timezone.utc).hour
        rate = SESSIONS_PER_MINUTE * (0.35 + 0.65 * (1 + np.cos((hour - 20) / 24 * 2 * np.pi)) / 2)
        for _ in range(int(rng.poisson(rate))):
            ip = pool[int(rng.integers(len(pool)))]
            web += _session(rng, t + float(rng.uniform(0, 60)), ip, BROWSER_UAS[int(rng.integers(len(BROWSER_UAS)))])
        if rng.random() < 0.15:
            bot = f"66.249.66.{int(rng.integers(1, 255))}"
            ts = t + float(rng.uniform(0, 60))
            web += [(ts + k, web_line(ts + k, bot, "GET", f"/products/{int(rng.integers(1, 120))}", 200, 15000, BOT_UA))
                    for k in range(3)]
        for _ in range(int(rng.poisson(0.6))):      # ضجيج الإنترنت على المنافذ الشائعة
            ts = t + float(rng.uniform(0, 60))
            src = f"{int(rng.integers(1, 223))}.{int(rng.integers(256))}.{int(rng.integers(256))}.{int(rng.integers(1, 255))}"
            fw.append((ts, fw_line(ts, src, [22, 23, 445, 3389][int(rng.integers(4))], rng)))
    return web, fw


def _attack(kind, t, rng):
    ip, bad_ua = ATTACKERS[kind], "python-requests/2.31.0"
    if kind == "brute":
        return [(t + i * 3, web_line(t + i * 3, ip, "POST", "/wp-login.php", 401, 230, bad_ua)) for i in range(80)], []
    if kind == "scan":
        paths = SCAN_WORDS + [f"/{w}{i}" for i in range(140) for w in ("old", "bak")][:140]
        return [(t + i, web_line(t + i, ip, "GET", p, 404, 150, "Mozilla/5.0 zgrab/0.x")) for i, p in enumerate(paths)], []
    if kind == "sqli":
        return [(t + i * 5, web_line(t + i * 5, ip, "GET", "/products?id=" + SQLI[i % len(SQLI)].replace(" ", "%20"),
                                     500 if i % 3 == 0 else 200, 900, bad_ua)) for i in range(12)], []
    if kind == "scrape":       # 240 صفحة منتج مختلفة خلال 5 دقائق (48/دقيقة، تحت عتبة الإغراق)
        return [(t + i * 1.25, web_line(t + i * 1.25, ip, "GET", f"/products/{i % 120 + 1}?page={i // 120}", 200, 15000,
                                        "Mozilla/5.0 (compatible; PriceBot/1.0)")) for i in range(240)], []
    if kind == "flood":
        return [(t + i * 0.08, web_line(t + i * 0.08, ip, "GET", "/", 200, 4000, "Mozilla/5.0")) for i in range(1500)], []
    ports = rng.choice(np.arange(1, 1025), size=200, replace=False)
    return [], [(t + i * 0.3, fw_line(t + i * 0.3, ip, int(p), rng)) for i, p in enumerate(ports)]


def generate(start, minutes, rng, attacks=(), attack_at=None):
    """← (سطور الويب، سطور الجدار، {نوع الهجوم: عنوانه}) مرتبة بالوقت."""
    web, fw = _normal(start, minutes, rng, _visitor_pool(rng))
    t = start + (attack_at if attack_at is not None else minutes * 30)
    for i, kind in enumerate(attacks):
        w, f = _attack(kind, t + i * 20, rng)
        web += w
        fw += f
    return ([line for _, line in sorted(web)], [line for _, line in sorted(fw)],
            {kind: ATTACKERS[kind] for kind in attacks})


# ===================================================================
# الإرسال وواجهة الأوامر
# ===================================================================
def send(url, key, source, lines, batch=5000):
    for i in range(0, len(lines), batch):
        req = urllib.request.Request(f"{url}/api/v1/ingest/{source}", data="\n".join(lines[i:i + batch]).encode(),
                                     headers={"Authorization": f"Bearer {key}", "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                print(f"  {source}: {json.loads(r.read())}")
        except urllib.error.HTTPError as e:
            sys.exit(f"رفض الخادم الدفعة ({e.code}): {e.read().decode()}")


def _emit(args, web, fw, labels):
    if args.out:
        with open(f"{args.out}.web.log", "a") as f:
            f.write("\n".join(web) + "\n")
        with open(f"{args.out}.fw.log", "a") as f:
            f.write("\n".join(fw) + "\n")
    else:
        send(args.url, args.key, "web", web)
        if fw:
            send(args.url, args.key, "firewall", fw)
    if args.labels and labels:
        with open(args.labels, "w") as f:
            json.dump(labels, f, ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(description="مولّد سجلات متجر إلكتروني مع هجمات اختيارية")
    ap.add_argument("--url", default="http://localhost:8001")
    ap.add_argument("--key", help="مفتاح الاستقبال pc_ing_...")
    ap.add_argument("--history-days", type=float, help="أيام من الترافيك الطبيعي بأوقات ماضية")
    ap.add_argument("--minutes", type=int, default=30, help="مدة الترافيك (الوضع العادي)")
    ap.add_argument("--live", type=int, help="بث مباشر: دفعة كل N ثانية حتى الإيقاف")
    ap.add_argument("--attack", nargs="*", choices=ATTACKS, default=[])
    ap.add_argument("--attack-at", type=int, help="ثوانٍ من البداية قبل الهجوم")
    ap.add_argument("--out", help="حفظ في ملفات <out>.web.log و<out>.fw.log بدل الإرسال")
    ap.add_argument("--labels", help="ملف JSON بعنوان كل هجوم")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    if not args.out and not args.key:
        ap.error("--key مطلوب للإرسال (أو استخدم --out)")
    rng = np.random.default_rng(args.seed)
    now = time.time()

    if args.history_days:
        minutes = int(args.history_days * 24 * 60)
        print(f"تاريخ طبيعي: {minutes} دقيقة")
        web, fw, _ = generate(now - minutes * 60 - 600, minutes, rng)
        _emit(args, web, fw, {})
        return
    if args.live:
        print(f"بث مباشر كل {args.live} ثانية (Ctrl+C للإيقاف)")
        pool, attacked = _visitor_pool(rng), False
        while True:
            t = time.time()
            w, f = _normal(t - args.live, 1, rng, pool)        # دقيقة تبدأ قبل N ثانية، نأخذ ما مضى منها فقط
            labels = {}
            if args.attack and not attacked and t - now >= (args.attack_at or 0):
                for i, kind in enumerate(args.attack):
                    aw, af = _attack(kind, t + i * 20, rng)
                    w, f = w + aw, f + af
                labels, attacked = {k: ATTACKERS[k] for k in args.attack}, True
                print(f"هجوم: {labels}")
            web = [line for ts, line in sorted(w) if ts < t or labels]
            fw = [line for ts, line in sorted(f) if ts < t or labels]
            _emit(args, web, fw, labels)
            time.sleep(args.live)
    web, fw, labels = generate(now - args.minutes * 60, args.minutes, rng, attacks=args.attack,
                               attack_at=args.attack_at)
    _emit(args, web, fw, labels)
    print(f"أُرسل {len(web)} سطر ويب و{len(fw)} سطر جدار. الهجمات: {labels or 'لا شيء'}")


if __name__ == "__main__":
    main()
