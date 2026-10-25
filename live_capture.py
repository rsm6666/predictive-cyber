"""
===================================================================
محوّل الالتقاط الحي → خصائص النموذج (بديل مستقل عن أدوات خارجية)
===================================================================
يقرأ ملف pcap حقيقي (أو يلتقط لحظيًا)، يجمّع الحزم في تدفقات ثنائية
الاتجاه (Bi-flows) بمفتاح (src,sport,dst,dport,proto)، ويحسب نفس الـ77
خاصية التي يتوقّعها نموذج المشروع — بأسمائها الدقيقة.

صدق علمي: الخصائص اللحظية الدقيقة (مدة، أحجام، توقيت، أعلام TCP) تُحسب
فعليًا من الحزم. أما الخصائص المتقدمة (Bulk/Subflow/Active-Idle) فتُقرّب
أو تُصفّر لأنها تتطلب منطق CICFlowMeter الكامل. نذكر هذا بوضوح كـ«إثبات
مفهوم للربط الحي مع فجوة المجال المتوقّعة».

الاستخدام:
  # من ملف pcap (يحوّل LINUX_SLL تلقائيًا)
  python live_capture.py --pcap /tmp/cap.pcap --csv /tmp/flows.csv

  # ثم افحصها بنموذج المشروع:
  python live_capture.py --pcap /tmp/cap.pcap --predict
===================================================================
"""

import argparse
from collections import defaultdict

import numpy as np
import pandas as pd

# الأعمدة الـ77 بالترتيب الذي يتوقّعه النموذج
FEATURES = [
    "Flow Duration","Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets",
    "Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
    "Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
    "Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s",
    "Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std","Packet Length Variance",
    "FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count",
    "URG Flag Count","CWE Flag Count","ECE Flag Count","Down/Up Ratio","Average Packet Size",
    "Avg Fwd Segment Size","Avg Bwd Segment Size","Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate",
    "Subflow Fwd Packets","Subflow Fwd Bytes","Subflow Bwd Packets","Subflow Bwd Bytes",
    "Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd","min_seg_size_forward",
    "Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min",
]
# الخصائص التي تتطلب منطق CICFlowMeter الكامل؛ نتركها صفرًا بأمانة
ZERO_FEATURES = {
    "Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate",
    "Active Mean","Active Std","Active Max","Active Min",
    "Idle Mean","Idle Std","Idle Max","Idle Min",
}


def _stats(vals):
    """(max,min,mean,std) بأمان لقائمة قد تكون فارغة."""
    if not vals:
        return 0.0, 0.0, 0.0, 0.0
    a = np.array(vals, dtype=float)
    return float(a.max()), float(a.min()), float(a.mean()), float(a.std())


def _iat(times):
    """الفجوات بين الطوابع الزمنية (Inter-Arrival Times)."""
    if len(times) < 2:
        return []
    t = sorted(times)
    return [t[i + 1] - t[i] for i in range(len(t) - 1)]


def build_flows(pcap_path):
    from scapy.utils import rdpcap
    from scapy.layers.inet import IP, TCP, UDP

    pkts = rdpcap(pcap_path)
    flows = defaultdict(lambda: {
        "fwd": [], "bwd": [], "ftime": [], "btime": [], "t0": None, "t1": None,
        "key_src": None, "init_ep": None, "resp_ep": None,
        "fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0,
        "urg": 0, "cwe": 0, "ece": 0, "fwd_psh": 0, "bwd_psh": 0,
        "fwd_urg": 0, "bwd_urg": 0, "fwd_hdr": 0, "bwd_hdr": 0,
        "init_win_f": -1, "init_win_b": -1, "act_data_f": 0, "min_seg_f": 0,
        "proto": 0,
    })

    for p in pkts:
        if not p.haslayer(IP):
            continue
        ip = p[IP]
        proto = ip.proto
        sport = dport = 0
        l4 = None
        if p.haslayer(TCP):
            l4 = p[TCP]; sport, dport = int(l4.sport), int(l4.dport)
        elif p.haslayer(UDP):
            l4 = p[UDP]; sport, dport = int(l4.sport), int(l4.dport)

        # مفتاح اتجاهي موحّد: نرتّب الطرفين حتى يجتمع الاتجاهان بتدفق واحد
        a = (ip.src, sport); b = (ip.dst, dport)
        key = (a, b, proto) if a <= b else (b, a, proto)
        f = flows[key]
        if f["key_src"] is None:
            # البادئ = مُرسِل أول حزمة (العميل)؛ المستقبِل = الخدمة.
            # نعتمد هذا بدل ترتيب المنافذ حتى لا يختلّ الاتجاه على 127.0.0.1
            f["key_src"] = ip.src
            f["proto"] = proto
            f["init_ep"] = (ip.src, sport)   # العميل (منفذ عشوائي)
            f["resp_ep"] = (ip.dst, dport)   # الخدمة (منفذ الوجهة الحقيقي)
        is_fwd = (ip.src == f["key_src"])

        t = float(p.time)
        f["t0"] = t if f["t0"] is None else min(f["t0"], t)
        f["t1"] = t if f["t1"] is None else max(f["t1"], t)
        plen = len(ip.payload) if l4 is not None else len(ip)
        size = len(p)
        hdr = (ip.ihl * 4) + (l4.dataofs * 4 if p.haslayer(TCP) else (8 if p.haslayer(UDP) else 0))

        if is_fwd:
            f["fwd"].append(size); f["ftime"].append(t); f["fwd_hdr"] += hdr
            if plen > 0: f["act_data_f"] += 1
            if f["min_seg_f"] == 0 or hdr < f["min_seg_f"]: f["min_seg_f"] = hdr
        else:
            f["bwd"].append(size); f["btime"].append(t); f["bwd_hdr"] += hdr

        if p.haslayer(TCP):
            fl = int(l4.flags)
            if fl & 0x01: f["fin"] += 1
            if fl & 0x02: f["syn"] += 1
            if fl & 0x04: f["rst"] += 1
            if fl & 0x08: f["psh"] += 1; (f.__setitem__("fwd_psh", f["fwd_psh"]+1) if is_fwd else f.__setitem__("bwd_psh", f["bwd_psh"]+1))
            if fl & 0x10: f["ack"] += 1
            if fl & 0x20: f["urg"] += 1; (f.__setitem__("fwd_urg", f["fwd_urg"]+1) if is_fwd else f.__setitem__("bwd_urg", f["bwd_urg"]+1))
            if fl & 0x40: f["ece"] += 1
            if fl & 0x80: f["cwe"] += 1
            win = int(l4.window)
            if is_fwd and f["init_win_f"] == -1: f["init_win_f"] = win
            if (not is_fwd) and f["init_win_b"] == -1: f["init_win_b"] = win

    return flows


def flows_to_df(flows):
    rows = []
    for key, f in flows.items():
        fwd, bwd = f["fwd"], f["bwd"]
        dur = (f["t1"] - f["t0"]) if (f["t0"] is not None and f["t1"] > f["t0"]) else 0.0
        dur_s = dur if dur > 0 else 1e-6
        allpk = fwd + bwd
        n_f, n_b, n_all = len(fwd), len(bwd), len(allpk)

        fmax, fmin, fmean, fstd = _stats(fwd)
        bmax, bmin, bmean, bstd = _stats(bwd)
        pmax, pmin, pmean, pstd = _stats(allpk)
        f_iat = _iat(f["ftime"]); b_iat = _iat(f["btime"]); all_iat = _iat(f["ftime"] + f["btime"])
        fi_max, fi_min, fi_mean, fi_std = _stats(f_iat)
        bi_max, bi_min, bi_mean, bi_std = _stats(b_iat)
        ai_max, ai_min, ai_mean, ai_std = _stats(all_iat)

        r = {name: 0.0 for name in FEATURES}
        r.update({
            "Flow Duration": dur * 1e6,  # بالميكروثانية (مثل الداتاسيت)
            "Total Fwd Packets": n_f, "Total Backward Packets": n_b,
            "Total Length of Fwd Packets": sum(fwd), "Total Length of Bwd Packets": sum(bwd),
            "Fwd Packet Length Max": fmax, "Fwd Packet Length Min": fmin,
            "Fwd Packet Length Mean": fmean, "Fwd Packet Length Std": fstd,
            "Bwd Packet Length Max": bmax, "Bwd Packet Length Min": bmin,
            "Bwd Packet Length Mean": bmean, "Bwd Packet Length Std": bstd,
            "Flow Bytes/s": sum(allpk) / dur_s, "Flow Packets/s": n_all / dur_s,
            "Flow IAT Mean": ai_mean, "Flow IAT Std": ai_std, "Flow IAT Max": ai_max, "Flow IAT Min": ai_min,
            "Fwd IAT Total": sum(f_iat), "Fwd IAT Mean": fi_mean, "Fwd IAT Std": fi_std,
            "Fwd IAT Max": fi_max, "Fwd IAT Min": fi_min,
            "Bwd IAT Total": sum(b_iat), "Bwd IAT Mean": bi_mean, "Bwd IAT Std": bi_std,
            "Bwd IAT Max": bi_max, "Bwd IAT Min": bi_min,
            "Fwd PSH Flags": f["fwd_psh"], "Bwd PSH Flags": f["bwd_psh"],
            "Fwd URG Flags": f["fwd_urg"], "Bwd URG Flags": f["bwd_urg"],
            "Fwd Header Length": f["fwd_hdr"], "Bwd Header Length": f["bwd_hdr"],
            "Fwd Header Length.1": f["fwd_hdr"],
            "Fwd Packets/s": n_f / dur_s, "Bwd Packets/s": n_b / dur_s,
            "Min Packet Length": pmin, "Max Packet Length": pmax,
            "Packet Length Mean": pmean, "Packet Length Std": pstd, "Packet Length Variance": pstd ** 2,
            "FIN Flag Count": f["fin"], "SYN Flag Count": f["syn"], "RST Flag Count": f["rst"],
            "PSH Flag Count": f["psh"], "ACK Flag Count": f["ack"], "URG Flag Count": f["urg"],
            "CWE Flag Count": f["cwe"], "ECE Flag Count": f["ece"],
            "Down/Up Ratio": (n_b / n_f) if n_f else 0.0,
            "Average Packet Size": (sum(allpk) / n_all) if n_all else 0.0,
            "Avg Fwd Segment Size": fmean, "Avg Bwd Segment Size": bmean,
            "Subflow Fwd Packets": n_f, "Subflow Fwd Bytes": sum(fwd),
            "Subflow Bwd Packets": n_b, "Subflow Bwd Bytes": sum(bwd),
            "Init_Win_bytes_forward": f["init_win_f"], "Init_Win_bytes_backward": f["init_win_b"],
            "act_data_pkt_fwd": f["act_data_f"], "min_seg_size_forward": f["min_seg_f"],
        })
        for z in ZERO_FEATURES:
            r[z] = 0.0
        # نرفق معلومات تعريفية (لا تُمرّر للنموذج): العميل والخدمة من البادئ
        init, resp = f.get("init_ep"), f.get("resp_ep")
        if init and resp:
            r["_src"] = init[0]; r["_dst"] = resp[0]; r["_dport"] = resp[1]
        else:
            r["_src"] = key[0][0]; r["_dst"] = key[1][0]; r["_dport"] = key[1][1]
        r["_proto"] = int(f["proto"])   # 6=TCP 17=UDP 1=ICMP
        rows.append(r)

    df = pd.DataFrame(rows)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--csv", default="")
    ap.add_argument("--predict", action="store_true")
    ap.add_argument("--model", default="/home/rsm/attack_type_model.joblib")
    args = ap.parse_args()

    print(f"قراءة الحزم من {args.pcap} ...")
    flows = build_flows(args.pcap)
    df = flows_to_df(flows)
    print(f"عدد التدفقات المستخرجة: {len(df)}")
    if len(df) == 0:
        print("لا توجد تدفقات (تحقق من ملف pcap).")
        return

    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"حُفظت الخصائص في {args.csv}")

    if args.predict:
        import joblib
        saved = joblib.load(args.model)
        model, feats = saved["model"], saved["feature_names"]
        X = df[feats].replace([np.inf, -np.inf], 0).fillna(0)
        proba = model.predict_proba(X)
        preds = model.classes_[proba.argmax(axis=1)]
        conf = proba.max(axis=1)
        print("\n=== نتائج الفحص على ترافيكك الحقيقي ===")
        print(f"{'المصدر':<16}{'→ المنفذ':<10}{'التصنيف':<16}{'الثقة'}")
        for i in range(min(len(df), 25)):
            print(f"{str(df.iloc[i]['_src']):<16}"
                  f"{':'+str(int(df.iloc[i]['_dport'])):<10}"
                  f"{str(preds[i]):<16}{conf[i]*100:.0f}%")
        from collections import Counter
        print("\nملخص:", dict(Counter(preds.tolist())))
        print("\nملاحظة صادقة: بعض الخصائص المتقدمة مُصفّرة (إثبات مفهوم)،"
              " وقد يظهر «فجوة مجال» بين ترافيكك الحقيقي وبيئة التدريب.")


if __name__ == "__main__":
    main()
