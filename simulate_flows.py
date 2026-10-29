"""
===================================================================
محاكي وكيل الخادم: يعيد تشغيل تدفقات CICIDS حقيقية موسومة عبر نفس كود الإرسال
===================================================================
عرض مضمون بحقيقة معروفة: ترافيك طبيعي كل دقيقة، وهجوم من نوع يُختار
يبدأ بعد --attack-at دقيقة ويستمر --attack-minutes دقيقة.

خريطة العناوين (العيّنة من شبكة مختبر داخلية، فلا تصلح كما هي لخادم واحد):
  - كل الوجهات ← عنوان الخادم SERVER (الوكيل على هذا الخادم)
  - كل مهاجم ← عنوان عام ثابت حسب نوع الهجوم (ATTACKERS)
  - التدفقات الطبيعية ← مجمع كبير من العملاء بعناوين عامة
البروتوكول TCP لكل التدفقات (العيّنة بلا عمود بروتوكول)، والخصائص الـ77 كما هي.

  python simulate_flows.py --key $INGEST_KEY --minutes 15 --attack scan
===================================================================
"""

import argparse
import ipaddress
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sensor.agent import WINDOW, Sender, make_batch
from sensor.flows import FEATURES

HERE = Path(__file__).resolve().parent
SERVER = "10.0.0.5"
ATTACKS = {"scan": "PortScan", "dos": "DoS", "ddos": "DDoS", "brute": "Brute Force (FTP/SSH)",
           "web": "Web Attack", "botnet": "Botnet"}
ATTACKERS = {"PortScan": "45.155.205.12", "DoS": "103.75.190.9", "DDoS": "193.42.33.14",
             "Brute Force (FTP/SSH)": "185.220.101.7", "Web Attack": "91.240.118.33", "Botnet": "80.94.95.115"}
CLIENTS = 2000
BENIGN_PER_MINUTE = 200
ATTACK_PER_MINUTE = 150


def _clients(rng, n=CLIENTS):
    out = set()
    while len(out) < n:
        ip = ipaddress.ip_address(int(rng.integers(1 << 24, 223 << 24)))
        if ip.is_global and str(ip) not in ATTACKERS.values():
            out.add(str(ip))
    return sorted(out)


def _flows(rows, srcs, window_start, rng):
    feats = rows[FEATURES].replace([np.inf, -np.inf], 0).fillna(0).clip(lower=0).to_numpy(dtype=float)
    out = []
    for i, (src, dport, dur_us) in enumerate(zip(srcs, rows["destination_port"], rows["Flow Duration"])):
        start = window_start + float(rng.uniform(0, WINDOW - 5))
        end = min(start + max(float(dur_us), 0) / 1e6, window_start + WINDOW)
        out.append({"src": src, "dst": SERVER, "sport": int(rng.integers(32768, 61000)), "dport": int(dport),
                    "proto": 6, "start": start, "end": end, "f": feats[i].tolist()})
    return out


def generate(act, minutes, start, rng, attack=None, attack_at=5, attack_minutes=5, attack_per_minute=ATTACK_PER_MINUTE):
    """← دفعات بصيغة الوكيل، نافذة لكل دقيقة. attack اسم العائلة كما في CICIDS."""
    benign = act[act["family"] == "BENIGN"]
    pool = act[act["family"] == attack] if attack else None
    clients = _clients(rng)
    batches = []
    for m in range(minutes):
        ws = start + m * WINDOW
        rows = benign.sample(BENIGN_PER_MINUTE, random_state=int(rng.integers(1 << 31)))
        flows = _flows(rows, rng.choice(clients, len(rows)), ws, rng)
        if attack and attack_at <= m < attack_at + attack_minutes:
            hits = pool.sample(min(attack_per_minute, len(pool)), random_state=int(rng.integers(1 << 31)))
            flows += _flows(hits, [ATTACKERS[attack]] * len(hits), ws, rng)
        rng.shuffle(flows)
        batches.append(make_batch(ws, flows, host="demo-server"))
    return batches


def main():
    ap = argparse.ArgumentParser(description="إعادة تشغيل تدفقات CICIDS كأنها من وكيل خادم")
    ap.add_argument("--url", default="http://localhost:8001")
    ap.add_argument("--key", required=True, help="مفتاح الاستقبال pc_ing_...")
    ap.add_argument("--minutes", type=int, default=15)
    ap.add_argument("--attack", choices=sorted(ATTACKS), help="نوع الهجوم (بلا هجوم إن تُرك)")
    ap.add_argument("--attack-at", type=int, default=10, help="دقيقة بدء الهجوم")
    ap.add_argument("--attack-minutes", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    act = pd.read_parquet(HERE / "dashboard_cache" / "act_sample.parquet")
    start = (time.time() // WINDOW - args.minutes) * WINDOW       # النوافذ تنتهي الآن
    batches = generate(act, args.minutes, start, np.random.default_rng(args.seed),
                       ATTACKS.get(args.attack), args.attack_at, args.attack_minutes)
    with tempfile.TemporaryDirectory() as buffer:
        sender = Sender(args.url, args.key, buffer)
        for b in batches:
            sender.send(b)
        left = len(sender._files())
    print(f"أُرسلت {len(batches) - left} من {len(batches)} نافذة"
          + (f" (هجوم {ATTACKS[args.attack]} من {ATTACKERS[ATTACKS[args.attack]]})" if args.attack else ""))


if __name__ == "__main__":
    main()
