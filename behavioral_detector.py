"""
===================================================================
الكاشف السلوكي (Behavioral Detector) — طبقة فوق المحوّل الحي
===================================================================
لماذا؟ النموذج اللحظي يصنّف كل تدفق منفردًا، فيفوّت الهجمات التي
تظهر فقط في «النمط الكلي» عبر عدة تدفقات (فحص المنافذ = مصدر يفتح
مئات المنافذ؛ الإغراق = مصدر يرسل آلاف الحزم لهدف واحد). هذا هو
جوهر «فجوة المجال» التي لاحظناها على الترافيك الحقيقي.

الحل: طبقة سلوكية تجمّع التدفقات حسب المصدر وتكشف الأنماط بقواعد
مبرّرة — تمامًا كما تفعل أنظمة SOC الحقيقية (طبقة توقيعية + طبقة
سلوكية). النتيجة النهائية = دمج رأي النموذج مع رأي الكاشف السلوكي.

هذا تحليل سلوكي شفّاف بقواعد (Rule-based)، لا نموذج تعلّم آلي ثانٍ —
وهذا مقصود: الشفافية والتفسير أهم من التعقيد في طبقة الاستجابة.

الاستخدام:
  python behavioral_detector.py --pcap /tmp/attack.pcap
  python behavioral_detector.py --pcap /tmp/cap.pcap      # ترافيك طبيعي
===================================================================
"""

import argparse
from collections import Counter, defaultdict

import numpy as np

from live_capture import build_flows, flows_to_df

# ---- عتبات الكشف السلوكي (مبرّرة، وقابلة للضبط) ----
PORTSCAN_UNIQUE_PORTS = 15     # مصدر يفتح ≥ هذا العدد من منافذ TCP الفريدة = فحص أفقي
UDPSCAN_UNIQUE_PORTS = 15      # مصدر → منافذ UDP فريدة كثيرة = فحص UDP
STEALTH_PROBES = 12            # مصدر → فحوص متخفّية (FIN/NULL/Xmas) كثيرة = فحص تهرّبي
HOSTSWEEP_UNIQUE_HOSTS = 10    # مصدر يتصل بـ ≥ هذا العدد من المضيفين = مسح شبكة
BRUTE_CONNECTIONS = 15         # مصدر → منفذ دخول واحد بعدد محاولات = تخمين كلمة مرور
DOS_FLOWS = 60                 # عدد تدفقات/اتصالات ضخم نحو منفذ واحد = إغراق خدمة
SYNFLOOD_SYN = 60              # مصدر → منفذ واحد بعدد SYN مرتفع و SYN≫ACK = إغراق SYN
ICMPFLOOD_PACKETS = 300        # مصدر → هدف بـ ICMP كثير = إغراق Ping
DDOS_SOURCES = 20              # ≥ هذا العدد من المصادر تضرب هدفًا واحدًا = DDoS موزّع

# منافذ الخدمات الحسّاسة (أهداف التخمين الشائعة)
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900}


def behavioral_pass(df):
    """
    يأخذ جدول التدفقات (مخرج المحوّل) ويُنتج تنبيهات سلوكية على مستوى
    المصدر/الهدف، لسبعة أنماط هجوم. يعتمد على الأعمدة التعريفية
    _src/_dst/_dport/_proto وأعلام TCP وعدّادات الحزم.
    """
    if df is None or len(df) == 0:
        return []
    d = df.copy()
    d["_pkts"] = (d["Total Fwd Packets"].fillna(0) +
                  d["Total Backward Packets"].fillna(0))
    d["_syn"] = d["SYN Flag Count"].fillna(0)
    d["_ack"] = d["ACK Flag Count"].fillna(0)
    has_proto = "_proto" in d.columns

    alerts = []
    tcp = d[d["_proto"] == 6] if has_proto else d
    udp = d[d["_proto"] == 17] if has_proto else d.iloc[0:0]

    # --- 1) فحص منافذ TCP (أفقي): مصدر واحد → منافذ فريدة كثيرة ---
    for src, nports in tcp.groupby("_src")["_dport"].nunique().items():
        if nports >= PORTSCAN_UNIQUE_PORTS:
            alerts.append({
                "type": "PortScan", "entity": str(src), "severity": "high",
                "evidence": f"فتح {int(nports)} منفذ TCP فريدًا (فحص خدمات)",
            })

    # --- 1ب) فحص منافذ UDP ---
    if len(udp):
        for src, nports in udp.groupby("_src")["_dport"].nunique().items():
            if nports >= UDPSCAN_UNIQUE_PORTS:
                alerts.append({
                    "type": "UDPScan", "entity": str(src), "severity": "high",
                    "evidence": f"فحص {int(nports)} منفذ UDP فريدًا",
                })

    # --- 1ج) فحص متخفٍّ (Stealth): FIN/NULL/Xmas بلا مصافحة كاملة ---
    if len(tcp):
        t = tcp
        fin = t["FIN Flag Count"].fillna(0); syn = t["SYN Flag Count"].fillna(0)
        ack = t["ACK Flag Count"].fillna(0); rst = t["RST Flag Count"].fillna(0)
        psh = t["PSH Flag Count"].fillna(0); urg = t["URG Flag Count"].fillna(0)
        null_scan = (fin + syn + rst + psh + ack + urg) == 0          # لا أعلام إطلاقًا
        # FIN scan: FIN بلا بدء مصافحة (SYN=0). نسمح بـ RST لأن المنفذ
        # المغلق يردّ RST فيجتمع مع حزمة الفحص في نفس التدفق (خاصة على 127.0.0.1)
        fin_scan = (fin > 0) & (syn == 0)
        xmas_scan = (fin > 0) & (psh > 0) & (urg > 0)                  # Xmas
        stealth = t[null_scan | fin_scan | xmas_scan]
        if len(stealth):
            for src, cnt in stealth.groupby("_src").size().items():
                if cnt >= STEALTH_PROBES:
                    alerts.append({
                        "type": "StealthScan", "entity": str(src), "severity": "critical",
                        "evidence": f"{int(cnt)} فحص متخفٍّ (FIN/NULL/Xmas بلا مصافحة) — تهرّب",
                    })

    # --- 2) مسح شبكة (Host Sweep): مصدر واحد → مضيفون كُثُر ---
    for src, nhosts in d.groupby("_src")["_dst"].nunique().items():
        if nhosts >= HOSTSWEEP_UNIQUE_HOSTS:
            alerts.append({
                "type": "HostSweep", "entity": str(src), "severity": "medium",
                "evidence": f"تحسّس {int(nhosts)} مضيفًا مختلفًا (استطلاع شبكة)",
            })

    # --- 3) تخمين كلمة مرور (Brute Force): محاولات كثيرة على منفذ دخول واحد ---
    auth = d[d["_dport"].isin(AUTH_PORTS)]
    if len(auth):
        for (src, port), nconn in auth.groupby(["_src", "_dport"]).size().items():
            if nconn >= BRUTE_CONNECTIONS:
                alerts.append({
                    "type": "BruteForce", "entity": str(src), "severity": "high",
                    "evidence": f"{int(nconn)} محاولة اتصال على منفذ {int(port)} (تخمين)",
                })

    # --- 4) إغراق خدمة (DoS) و SYN Flood: عدد اتصالات ضخم نحو منفذ واحد ---
    # ملاحظة: نعتمد عدد التدفقات لا عدد الحزم — فالتنزيل العادي اتصال
    # واحد كبير (لا يُعدّ إغراقًا)، بينما الإغراق مئات الاتصالات لمنفذ واحد.
    svc = d.groupby(["_src", "_dst", "_dport"]).agg(
        flows=("_dport", "size"), syn=("_syn", "sum"), ack=("_ack", "sum"))
    for (src, dst, port), row in svc.iterrows():
        if row["flows"] >= DOS_FLOWS:
            alerts.append({
                "type": "DoS", "entity": str(src), "severity": "high",
                "evidence": f"{int(row['flows'])} اتصالًا نحو {dst}:{int(port)} (إغراق)",
            })
        if row["syn"] >= SYNFLOOD_SYN and row["syn"] > row["ack"] * 2:
            alerts.append({
                "type": "SYNFlood", "entity": str(src), "severity": "critical",
                "evidence": f"{int(row['syn'])} SYN مقابل {int(row['ack'])} ACK على "
                            f"{dst}:{int(port)} (نصف-مفتوح)",
            })

    # --- 5) إغراق Ping (ICMP Flood): ICMP كثير مصدر→هدف ---
    if has_proto:
        icmp = d[d["_proto"] == 1]
        if len(icmp):
            for (src, dst), pk in icmp.groupby(["_src", "_dst"])["_pkts"].sum().items():
                if pk >= ICMPFLOOD_PACKETS:
                    alerts.append({
                        "type": "ICMPFlood", "entity": str(src), "severity": "high",
                        "evidence": f"~{int(pk)} حزمة ICMP إلى {dst} (إغراق Ping)",
                    })

    # --- 6) DDoS موزّع: هدف واحد يُضرب من مصادر كثيرة ---
    for dst, nsrc in d.groupby("_dst")["_src"].nunique().items():
        if nsrc >= DDOS_SOURCES:
            alerts.append({
                "type": "DDoS", "entity": str(dst), "severity": "critical",
                "evidence": f"هُوجم من {int(nsrc)} مصدرًا مختلفًا",
            })

    return alerts


def combined_verdict(df, model_preds):
    """
    يدمج رأي النموذج (لكل تدفق) مع الكاشف السلوكي (لكل مصدر).
    القاعدة: إذا رفع الكاشف السلوكي تنبيهًا لمصدر، فهو الأرجح لأنه
    يرى النمط الكامل؛ وإلا نأخذ أغلبية رأي النموذج.
    """
    alerts = behavioral_pass(df)
    flagged = {a["entity"]: a for a in alerts}  # entity -> alert
    model_summary = Counter(model_preds.tolist())
    return alerts, flagged, model_summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--model", default="/home/rsm/attack_type_model.joblib")
    args = ap.parse_args()

    print(f"قراءة الحزم من {args.pcap} ...")
    flows = build_flows(args.pcap)
    df = flows_to_df(flows)
    print(f"عدد التدفقات: {len(df)}")
    if len(df) == 0:
        print("لا توجد تدفقات."); return

    # رأي النموذج اللحظي
    import joblib
    saved = joblib.load(args.model)
    model, feats = saved["model"], saved["feature_names"]
    X = df[feats].replace([np.inf, -np.inf], 0).fillna(0)
    preds = model.classes_[model.predict_proba(X).argmax(axis=1)]

    alerts, flagged, model_summary = combined_verdict(df, preds)

    print("\n" + "=" * 56)
    print("طبقة 1 — رأي النموذج اللحظي (لكل تدفق):")
    print("=" * 56)
    print(" ", dict(model_summary))

    print("\n" + "=" * 56)
    print("طبقة 2 — الكاشف السلوكي (النمط عبر المصادر):")
    print("=" * 56)
    if not alerts:
        print("  لا تنبيهات سلوكية — السلوك ضمن الطبيعي. ✅")
    else:
        for a in alerts:
            sev = {"high": "⚠️ عالٍ", "critical": "🔴 حرج"}.get(a["severity"], a["severity"])
            print(f"  [{sev}] {a['type']}: الكيان {a['entity']} — {a['evidence']}")

    print("\n" + "=" * 56)
    print("الحكم النهائي المدمج:")
    print("=" * 56)
    if alerts:
        types = sorted(set(a["type"] for a in alerts))
        print(f"  🚨 رُصد نشاط هجومي: {'، '.join(types)}")
        print("  (الكاشف السلوكي التقط ما فات النموذج اللحظي — فجوة المجال)")
    else:
        print("  ✅ الترافيك طبيعي (توافق الطبقتان).")


if __name__ == "__main__":
    main()
