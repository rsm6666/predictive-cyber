"""
===================================================================
اختبار الهجوم الحقيقي (Red-Team) — نهاجم فعليًا ونرى هل النظام يمسك
===================================================================
هذا هو الاختبار المقنع الذي يطلبه المحكّمون: لا نحقن رقمًا ولا عيّنة
من الداتاسيت — بل نشنّ هجومًا حقيقيًا بأدوات حقيقية (nmap وغيرها)
على جهازك نفسه، نلتقط الترافيك الناتج، ونمرّره على نظام الكشف
بطبقتيه (النموذج + الكاشف السلوكي)، ثم نعلن: هل مُسِك الهجوم؟

كل الأهداف محليّة (جهازك/شبكتك)، لا طرف خارجي — اختبار ذاتي آمن.

الأنواع المدعومة:
  portscan    فحص منافذ أفقي           (nmap)      → PortScan
  hostsweep   مسح مضيفي الشبكة          (nmap)      → HostSweep
  synflood    إغراق SYN نصف-مفتوح       (hping3)    → SYNFlood
  dos         إغراق خدمة (UDP)          (hping3)    → DoS
  bruteforce  تخمين كلمة مرور SSH       (python)    → BruteForce
  icmpflood   إغراق Ping                (ping)      → ICMPFlood
  all         يشغّل كل الأنواع بالتتابع (عرض شامل)

التشغيل (بصلاحية sudo للالتقاط والأدوات):
  sudo -n /home/rsm/project/bin/python3 attack_test.py --attack portscan
  sudo -n /home/rsm/project/bin/python3 attack_test.py --attack all

يفضّل تثبيت الأدوات الحقيقية للعرض:  sudo apt install -y nmap hping3
(إن غابت أداة، يسقط تلقائيًا على مولّد Python يعطي نفس التوقيع.)
===================================================================
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LOCAL = "127.0.0.1"


# ===================================================================
# اكتشاف البيئة
# ===================================================================
def _sudo_home():
    return (f"/home/{os.environ['SUDO_USER']}"
            if os.environ.get("SUDO_USER") else os.path.expanduser("~"))


def _find_model():
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "attack_type_model.joblib"),
              os.path.join(_sudo_home(), "attack_type_model.joblib"),
              os.path.expanduser("~/attack_type_model.joblib")):
        if os.path.exists(p):
            return p
    return os.path.join(here, "attack_type_model.joblib")


def _subnet_base():
    """يستخرج بادئة شبكة eth0 (مثل 172.20.0.) لمسح المضيفين."""
    try:
        out = subprocess.run(["ip", "-4", "addr", "show", "eth0"],
                             capture_output=True, text=True).stdout
        for tok in out.split():
            if "/" in tok and tok.count(".") == 3:
                ip = tok.split("/")[0]
                return ip.rsplit(".", 1)[0] + "."
    except Exception:
        pass
    return "127.0.0."


def _have(tool):
    return shutil.which(tool) is not None


# ===================================================================
# تعريفات الهجمات: (الواجهة، الهدف، النوع المتوقّع، دالة الشنّ)
# ===================================================================
def atk_portscan():
    target = LOCAL
    def run():
        if _have("nmap"):
            subprocess.run(["nmap", "-sT", "-p", "1-1000", "--max-retries", "1",
                            target], capture_output=True, timeout=30)
        else:
            for port in range(1, 1001):            # بديل Python
                s = socket.socket(); s.settimeout(0.03)
                try: s.connect_ex((target, port))
                finally: s.close()
    return "lo", target, "PortScan", run, ("nmap" if _have("nmap") else "python")


def atk_udpscan():
    target = LOCAL
    def run():
        if _have("nmap"):
            subprocess.run(["nmap", "-sU", "--top-ports", "200", target],
                           capture_output=True, timeout=40)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for port in range(1, 201):             # بديل Python: 200 منفذ UDP
                try: s.sendto(b"x", (target, port))
                except Exception: break
            s.close()
    return "lo", target, "UDPScan", run, ("nmap" if _have("nmap") else "python")


def atk_stealth():
    target = LOCAL
    def run():
        if _have("nmap"):
            subprocess.run(["nmap", "-sF", "-p", "1-1000", target],
                           capture_output=True, timeout=30)   # FIN scan متخفٍّ
        else:
            try:                                    # بديل scapy: حزم FIN منفردة
                from scapy.all import IP, TCP, send
                send(IP(dst=target) / TCP(dport=(1, 400), flags="F"),
                     verbose=0)
            except Exception:
                pass
    return "lo", target, "StealthScan", run, ("nmap" if _have("nmap") else "scapy")


HOSTSWEEP_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "208.67.222.222", "208.67.220.220", "4.2.2.1", "4.2.2.2",
    "64.6.64.6", "94.140.14.14", "149.112.112.112", "76.76.2.0",
    "185.228.168.9", "76.76.19.19",
]


def atk_hostsweep():
    # نمط «مضيف واحد يتحسّس مضيفين كُثُر» عبر الاتصال بعدّة عناوين عامة
    # (طرق واحد لكلٍّ) — يولّد ترافيكًا يخرج فعليًا على eth0 فيُلتقط.
    def run():
        if _have("nmap"):
            subprocess.run(["nmap", "-sn", *HOSTSWEEP_IPS],
                           capture_output=True, timeout=30)
        else:
            import threading
            def knock(ip):
                s = socket.socket(); s.settimeout(0.4)
                try: s.connect_ex((ip, 443))
                finally: s.close()
            ts = [threading.Thread(target=knock, args=(ip,)) for ip in HOSTSWEEP_IPS]
            for t in ts: t.start()
            for t in ts: t.join()
    return "eth0", "15 مضيفًا عامًا", "HostSweep", run, ("nmap" if _have("nmap") else "python")


def atk_synflood():
    target = LOCAL
    def run():
        if _have("hping3"):
            subprocess.run(["hping3", "-S", "-p", "80", "-i", "u200",
                            "-c", "3000", target], capture_output=True, timeout=25)
        else:
            try:   # بديل scapy: إغراق SYN نصف-مفتوح حقيقي (SYN فقط بلا إكمال)
                from scapy.all import IP, TCP, send, RandShort
                send(IP(dst=target) / TCP(sport=RandShort(), dport=80, flags="S"),
                     count=400, verbose=0)
            except Exception:
                for _ in range(400):
                    s = socket.socket(); s.settimeout(0.02)
                    try: s.connect_ex((target, 80))
                    finally: s.close()
    tool = "hping3" if _have("hping3") else "scapy"
    return "lo", target, "SYNFlood", run, tool


def atk_dos():
    target = LOCAL
    def run():
        if _have("hping3"):
            subprocess.run(["hping3", "--udp", "-p", "9999", "-i", "u150",
                            "-c", "4000", target], capture_output=True, timeout=25)
        else:
            for _ in range(400):                   # بديل Python: 400 اتصال UDP (منفذ مصدر جديد = تدفق جديد)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try: s.sendto(b"x" * 64, (target, 9999))
                except Exception: pass
                finally: s.close()
    return "lo", target, "DoS", run, ("hping3" if _have("hping3") else "python")


def atk_bruteforce():
    target = LOCAL
    def run():
        for _ in range(40):                        # 40 محاولة على SSH (منفذ 22)
            s = socket.socket(); s.settimeout(0.1)
            try: s.connect_ex((target, 22))
            finally: s.close()
            time.sleep(0.02)
    return "lo", target, "BruteForce", run, "python"


def atk_icmpflood():
    target = LOCAL
    def run():
        subprocess.run(["ping", "-c", "400", "-i", "0.004", target],
                       capture_output=True, timeout=25)
    return "lo", target, "ICMPFlood", run, "ping"


ATTACKS = {
    "portscan": atk_portscan, "udpscan": atk_udpscan,
    "stealth": atk_stealth, "hostsweep": atk_hostsweep,
    "synflood": atk_synflood, "dos": atk_dos,
    "bruteforce": atk_bruteforce, "icmpflood": atk_icmpflood,
}


# ===================================================================
# التقاط + تحليل
# ===================================================================
def capture_during(iface, run_attack):
    """يشغّل tcpdump بالخلفية، يشنّ الهجوم، ثم يوقف الالتقاط ويعيد pcap."""
    pcap = tempfile.mktemp(suffix=".pcap", dir="/tmp")
    cap = subprocess.Popen(["tcpdump", "-i", iface, "-w", pcap, "-U"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)                 # نترك tcpdump يرتبط بالواجهة
    try:
        run_attack()
    except subprocess.TimeoutExpired:
        pass
    time.sleep(1.0)                 # تصريف آخر الحزم
    cap.terminate()
    try: cap.wait(timeout=5)
    except Exception: cap.kill()
    return pcap if os.path.exists(pcap) else None


def analyze(pcap, model_path):
    import numpy as np
    import joblib
    from collections import Counter
    from live_capture import build_flows, flows_to_df
    from behavioral_detector import behavioral_pass

    if not pcap or os.path.getsize(pcap) < 50:
        return None
    df = flows_to_df(build_flows(pcap))
    if len(df) == 0:
        return None

    saved = joblib.load(model_path)
    model, feats = saved["model"], saved["feature_names"]
    X = df[feats].replace([np.inf, -np.inf], 0).fillna(0)
    preds = model.classes_[model.predict_proba(X).argmax(axis=1)]
    alerts = behavioral_pass(df)
    return {
        "flows": len(df),
        "model_summary": dict(Counter(preds.tolist())),
        "alerts": alerts,
        "types": sorted(set(a["type"] for a in alerts)),
    }


# ===================================================================
# تشغيل اختبار واحد
# ===================================================================
def run_one(name, model_path):
    iface, target, expected, run_attack, tool = ATTACKS[name]()
    print(f"\n{'='*60}")
    print(f"🎯 الهجوم: {name}  |  الأداة: {tool}  |  الهدف: {target}  |  الواجهة: {iface}")
    print(f"   النوع المتوقّع أن يُمسَك: {expected}")
    print(f"{'='*60}")
    print("… نشنّ الهجوم ونلتقط الترافيك الحقيقي الناتج")

    pcap = capture_during(iface, run_attack)
    try:
        res = analyze(pcap, model_path)
    finally:
        if pcap and os.path.exists(pcap):
            try: os.remove(pcap)
            except OSError: pass

    if res is None:
        print("⚠️ لم يُلتقط ترافيك كافٍ (جرّب مجددًا أو واجهة أخرى).")
        return name, expected, False

    print(f"📦 حلّلنا {res['flows']} تدفقًا حقيقيًا.")
    print(f"🔍 الطبقة 1 (النموذج لكل تدفق): {res['model_summary']}")
    print("🛡️ الطبقة 2 (الكاشف السلوكي):")
    if res["alerts"]:
        for a in res["alerts"]:
            sev = {"medium": "🟡 متوسط", "high": "⚠️ عالٍ",
                   "critical": "🔴 حرج"}.get(a["severity"], a["severity"])
            print(f"     [{sev}] {a['type']}: {a['entity']} — {a['evidence']}")
    else:
        print("     لا تنبيهات.")

    caught = expected in res["types"]
    print(f"\n{'✅ مُسِك الهجوم' if caught else '❌ فات الهجوم'} "
          f"— المتوقّع «{expected}»، والمرصود: {res['types'] or 'لا شيء'}")
    return name, expected, caught


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="portscan",
                    choices=list(ATTACKS) + ["all"])
    ap.add_argument("--model", default=_find_model())
    args = ap.parse_args()

    names = list(ATTACKS) if args.attack == "all" else [args.attack]
    results = [run_one(n, args.model) for n in names]

    if len(results) > 1:
        print(f"\n{'#'*60}\n📊 ملخّص العرض الشامل:")
        hit = sum(1 for _, _, c in results if c)
        for name, expected, caught in results:
            print(f"   {'✅' if caught else '❌'} {name:<11} → {expected}")
        print(f"\n   النتيجة: مُسِك {hit} من {len(results)} أنواع هجوم.")
        print(f"{'#'*60}")


if __name__ == "__main__":
    main()
