"""
===================================================================
مساعد الالتقاط (يُشغّل بصلاحية sudo من الخادم)
===================================================================
يلتقط عددًا من الحزم من الواجهة الحقيقية، يحوّلها لتدفقات، يفحصها
بالطبقتين (النموذج + الكاشف السلوكي)، ويطبع النتيجة كـ JSON على
المخرج القياسي — ليقرأها الخادم.

يُستدعى هكذا (الخادم يفعل هذا داخليًا):
  sudo /path/to/venv/bin/python capture_helper.py --count 600 --iface any

لماذا منفصل؟ الالتقاط يحتاج root، والخادم يعمل كمستخدم عادي. فصلُه
يبقي الخادم آمنًا ويعزل الصلاحية العالية في خطوة واحدة محدودة.
===================================================================
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

# نضمن أن مجلد هذا الملف ضمن مسار الاستيراد (مهم تحت sudo)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _generate_traffic():
    """يولّد ترافيكًا كافيًا أثناء الالتقاط حتى لا يعتمد على وجوده صدفة."""
    import threading, time
    def gen():
        time.sleep(0.5)
        # ping سريع متوازٍ + عدة طلبات ويب = عشرات التدفقات مضمونة
        for host in ("8.8.8.8", "1.1.1.1"):
            subprocess.Popen(["ping", "-c", "15", "-i", "0.2", host],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for url in ("https://www.google.com", "https://www.github.com",
                    "https://www.wikipedia.org", "https://www.cloudflare.com"):
            subprocess.Popen(["curl", "-s", "-o", "/dev/null", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    threading.Thread(target=gen, daemon=True).start()


def capture(iface, count, timeout):
    """يلتقط حزمًا إلى ملف pcap مؤقت ويعيد مساره."""
    path = tempfile.mktemp(suffix=".pcap", dir="/tmp")
    cmd = ["tcpdump", "-i", iface, "-w", path, "-c", str(count)]
    _generate_traffic()   # نضمن وجود حركة ليُلتقط شيء دائمًا
    try:
        subprocess.run(cmd, timeout=timeout, capture_output=True)
    except subprocess.TimeoutExpired:
        pass  # انتهى الوقت المحدد — نستخدم ما التُقط
    return path if os.path.exists(path) else None


def analyze(pcap_path, model_path):
    import numpy as np
    import joblib
    from live_capture import build_flows, flows_to_df
    from behavioral_detector import behavioral_pass

    # الملف قد يكون فارغًا (شبكة هادئة أو انتهى الوقت قبل أي حزمة)
    try:
        if os.path.getsize(pcap_path) < 50:   # أصغر من ترويسة pcap = لا حزم
            return {"flows": 0, "model": {}, "alerts": [], "verdict": "no_traffic"}
        flows = build_flows(pcap_path)
    except Exception:
        return {"flows": 0, "model": {}, "alerts": [], "verdict": "no_traffic"}
    df = flows_to_df(flows)
    if len(df) == 0:
        return {"flows": 0, "model": {}, "alerts": [], "verdict": "no_traffic"}

    saved = joblib.load(model_path)
    model, feats = saved["model"], saved["feature_names"]
    X = df[feats].replace([np.inf, -np.inf], 0).fillna(0)
    preds = model.classes_[model.predict_proba(X).argmax(axis=1)]

    from collections import Counter
    model_summary = {k: int(v) for k, v in Counter(preds.tolist()).items()}
    alerts = behavioral_pass(df)

    # عيّنة اتصالات للعرض
    sample = []
    for i in range(min(len(df), 12)):
        sample.append({
            "src": str(df.iloc[i]["_src"]), "dst": str(df.iloc[i]["_dst"]),
            "dport": int(df.iloc[i]["_dport"]), "pred": str(preds[i]),
        })

    verdict = "attack" if alerts else "benign"
    return {
        "flows": int(len(df)), "model": model_summary,
        "alerts": alerts, "sample": sample, "verdict": verdict,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--count", type=int, default=120)
    ap.add_argument("--timeout", type=int, default=15)
    # تحت sudo تصبح ~ هي /root؛ لذلك نحدد المسار بجانب هذا الملف،
    # ثم مجلد المستخدم الأصلي الذي استدعى sudo (SUDO_USER)، كبدائل.
    _here = os.path.dirname(os.path.abspath(__file__))
    _sudo_home = (f"/home/{os.environ['SUDO_USER']}"
                  if os.environ.get("SUDO_USER") else os.path.expanduser("~"))
    _default_model = next(
        (p for p in (os.path.join(_here, "attack_type_model.joblib"),
                     os.path.join(_sudo_home, "attack_type_model.joblib"),
                     os.path.expanduser("~/attack_type_model.joblib"))
         if os.path.exists(p)), os.path.join(_here, "attack_type_model.joblib"))
    ap.add_argument("--model", default=_default_model)
    args = ap.parse_args()

    pcap = capture(args.iface, args.count, args.timeout)
    if not pcap:
        print(json.dumps({"error": "capture_failed"})); return
    try:
        result = analyze(pcap, args.model)
    finally:
        try: os.remove(pcap)
        except OSError: pass
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
