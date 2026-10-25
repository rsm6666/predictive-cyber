"""
===================================================================
خدمة المراقبة المستمرة (الاستباقي الحي)
===================================================================
تبني نوافذ زمنية حقيقية من شبكتك عبر الوقت، تكدّسها، وعند تجمّع
SEQ نافذة يتنبأ نموذج LSTM ببداية هجوم في النافذة التالية — أي
تطبيق القدرة الاستباقية على ترافيكك الحقيقي، لا على الداتاسيت.

كل دورة: تلتقط WINDOW_SECONDS من الترافيك، تحوّلها لتدفقات، تحسب
نفس خصائص النافذة التي دُرّب عليها LSTM (total_flows, unique_dst_ports,
avg_flow_duration, avg_packet_size, total_fwd/bwd_packets)، وتضيفها
لطابور بطول SEQ. ثم تمرّر التسلسل المقيّس للنموذج.

صدق علمي: LSTM مدرّب على شبكة محاكاة (CICIDS2017)؛ التنبؤ على
ترافيك حقيقي يخضع لفجوة المجال، فيُعرض كمؤشر لا كحكم قاطع.

التشغيل المستقل (للاختبار):
  sudo /path/venv/bin/python live_monitor.py --cycles 12 --window 30

الخادم يستدعيه كخدمة تكتب حالتها إلى ملف JSON يقرأه الـ API.
===================================================================
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

STATE_FILE = "/tmp/live_monitor_state.json"
WINDOW_FEATURES = ["total_flows", "unique_dst_ports", "avg_flow_duration",
                   "avg_packet_size", "total_fwd_packets", "total_bwd_packets"]


def _home():
    return (f"/home/{os.environ['SUDO_USER']}"
            if os.environ.get("SUDO_USER") else os.path.expanduser("~"))


def _nudge_traffic():
    """حركة خفيفة تضمن ألا تكون النافذة فارغة على شبكة هادئة (عرض/محاكاة)."""
    import threading
    def gen():
        for host in ("8.8.8.8", "1.1.1.1"):
            subprocess.Popen(["ping", "-c", "6", "-i", "0.3", host],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for url in ("https://www.google.com", "https://www.wikipedia.org"):
            subprocess.Popen(["curl", "-s", "-o", "/dev/null", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    threading.Thread(target=gen, daemon=True).start()


def _default_gateway():
    """يستخرج بوابة eth0 (مضيف ويندوز في WSL) — هدف الاختبار الذاتي."""
    try:
        parts = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True).stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def _simulate_attack_traffic(duration):
    """
    اختبار الصحة (نفس فكرة أزرار الحقن في التبويب اللحظي): يولّد نمط
    فحص منافذ حقيقي على بوابة شبكتك أنت — مئات محاولات اتصال لمنافذ
    مختلفة — فترتفع total_flows و unique_dst_ports بشكل حاد، وهذا هو
    توقيع هجوم PortScan الفعلي. الهدف: نتأكد أن LSTM يشتعل على نمط
    هجومي حقيقي، لا على الطبيعي فقط. كله ضد جهازك/بوابتك، لا طرف خارجي.
    """
    import socket
    import threading
    target = _default_gateway() or "8.8.8.8"
    deadline = time.time() + max(duration - 1, 2)

    def sweep(lo, hi):
        while time.time() < deadline:
            for port in range(lo, hi):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.08)
                    s.connect_ex((target, port))
                    s.close()
                except Exception:
                    pass

    for lo, hi in ((20, 170), (170, 320), (320, 470)):
        threading.Thread(target=sweep, args=(lo, hi), daemon=True).start()


def capture_window(iface, seconds, max_pkts=2000, attack=False):
    """يلتقط نافذة زمنية واحدة إلى pcap مؤقت ويعيد مساره."""
    path = tempfile.mktemp(suffix=".pcap", dir="/tmp")
    if attack:
        _simulate_attack_traffic(seconds)   # حقن نمط هجومي (اختبار الصحة)
    else:
        _nudge_traffic()   # يضمن وجود حركة ليُلتقط شيء دائمًا
    try:
        subprocess.run(["tcpdump", "-i", iface, "-w", path, "-c", str(max_pkts)],
                       timeout=seconds, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    return path if os.path.exists(path) else None


def window_features(pcap_path):
    """يحسب خصائص نافذة واحدة من الحزم الملتقطة (نفس تعريف التدريب)."""
    from live_capture import build_flows, flows_to_df
    try:
        if os.path.getsize(pcap_path) < 50:
            return None
        df = flows_to_df(build_flows(pcap_path))
    except Exception:
        return None
    if len(df) == 0:
        return None
    return {
        "total_flows": float(len(df)),
        "unique_dst_ports": float(df["_dport"].nunique()),
        "avg_flow_duration": float(df["Flow Duration"].mean()),
        "avg_packet_size": float(df["Average Packet Size"].mean()),
        "total_fwd_packets": float(df["Total Fwd Packets"].sum()),
        "total_bwd_packets": float(df["Total Backward Packets"].sum()),
    }


def write_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.chmod(STATE_FILE, 0o644)
    except OSError:
        pass


def _recommend(context, model="qwen2.5:14b"):
    """توصية أمنية عبر Ollama (تُستدعى مرة واحدة لحظة الإنذار)."""
    try:
        import ollama
        r = ollama.chat(model=model, options={"temperature": 0.2}, messages=[{
            "role": "user",
            "content": (f"أنت محلل أمن سيبراني خبير. {context} اكتب توصية "
                        "أمنية عملية موجزة من سطرين إلى ثلاثة، بالعربية الفصحى "
                        "فقط ودون أي كلمة أجنبية إطلاقًا، تبدأ بالإجراء الأهم "
                        "وتكون محدّدة لنوع النشاط المرصود. بدون مقدمات ولا عناوين."),
        }])
        return r["message"]["content"].strip()
    except Exception:
        return None


def run(iface, window_s, cycles, model_dir, attack=False):
    import numpy as np
    import joblib
    from train_final_lstm import load_final_ensemble, SEQUENCE_LENGTH, ensemble_predict

    # نحمّل المجموعة من مجلد النماذج
    os.chdir(model_dir)
    models, meta = load_final_ensemble()
    seq_len = meta["sequence_length"]
    thr = meta["threshold_recall"]
    feats = meta["feature_cols"]

    history = deque(maxlen=seq_len)
    state = {"running": True, "collected": 0, "need": seq_len,
             "windows": [], "prediction": None, "advice": None,
             "started": time.time(), "mode": "attack-test" if attack else "live"}
    write_state(state)

    advised = False
    i = 0
    while cycles <= 0 or i < cycles:
        i += 1
        pcap = capture_window(iface, window_s, attack=attack)
        feat = window_features(pcap) if pcap else None
        if pcap:
            try: os.remove(pcap)
            except OSError: pass
        if feat is None:
            feat = {k: 0.0 for k in WINDOW_FEATURES}

        history.append(feat)
        state["collected"] = len(history)
        state["windows"] = [
            {"total_flows": round(w["total_flows"], 0),
             "unique_dst_ports": round(w["unique_dst_ports"], 0)}
            for w in history]

        # عند اكتمال التسلسل: نتنبأ
        if len(history) >= seq_len:
            seq = np.array([[w[c] for c in feats] for w in history])
            prob = ensemble_predict(models, meta, seq)
            alert = bool(prob >= thr)
            state["prediction"] = {
                "probability": round(float(prob), 3),
                "threshold": round(float(thr), 3),
                "alert": alert,
            }
            # توصية أمنية مرة واحدة لحظة أول إنذار
            if alert and not advised:
                advised = True
                last = history[-1]
                ctx = (f"رصد نظام التنبؤ نمطًا ينذر بهجوم وشيك: ارتفاع حاد في "
                       f"عدد الاتصالات (~{int(last['total_flows'])}) وعدد المنافذ "
                       f"الفريدة (~{int(last['unique_dst_ports'])}) من مصدر واحد — "
                       f"نمط يشبه فحص المنافذ أو استطلاع الشبكة. بلغت احتمالية "
                       f"بدء الهجوم {prob*100:.0f}% متجاوزةً عتبة الإنذار.")
                adv = _recommend(ctx)
                if adv:
                    state["advice"] = adv
                    print("\n" + "=" * 60)
                    print("🛡️  التوصية الأمنية (استباقية):")
                    print("=" * 60)
                    print(adv + "\n")
                else:
                    print("\n🛡️  (التوصية غير متاحة — تأكد أن Ollama يعمل)\n")
        write_state(state)

    state["running"] = False
    write_state(state)
    return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--window", type=int, default=30, help="ثواني لكل نافذة")
    ap.add_argument("--cycles", type=int, default=0, help="0 = مستمر")
    ap.add_argument("--model-dir", default=_home())
    ap.add_argument("--simulate-attack", action="store_true",
                    help="يحقن نمط فحص منافذ حقيقي لاختبار صحة التنبؤ")
    args = ap.parse_args()
    run(args.iface, args.window, args.cycles, args.model_dir,
        attack=args.simulate_attack)


if __name__ == "__main__":
    main()
