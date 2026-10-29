"""
===================================================================
محوّل الالتقاط الحي → خصائص النموذج (بديل مستقل عن أدوات خارجية)
===================================================================
يقرأ ملف pcap حقيقي، ويحوّله إلى تدفقات ثنائية الاتجاه بالخصائص الـ77
التي يتوقّعها نموذج المشروع. الحساب نفسه في sensor/flows.py (التعريف
الوحيد للخصائص، ويستخدمه وكيل الخادم أيضًا)؛ هذا الملف غلاف له.

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

import numpy as np
import pandas as pd

from sensor.flows import FEATURES, FlowTable, from_scapy


def build_flows(pcap_path):
    from scapy.utils import PcapReader
    table = FlowTable()
    with PcapReader(pcap_path) as reader:
        for p in reader:
            table.add(from_scapy(p))
    return table


def flows_to_df(table):
    """جدول الخصائص + أعمدة تعريفية لا تُمرَّر للنموذج: العميل والخدمة والبروتوكول."""
    rows = table.rows()
    df = pd.DataFrame([r["f"] for r in rows], columns=FEATURES)
    df["_src"] = [r["src"] for r in rows]
    df["_dst"] = [r["dst"] for r in rows]
    df["_dport"] = [r["dport"] for r in rows]
    df["_proto"] = [r["proto"] for r in rows]   # 6=TCP 17=UDP 1=ICMP
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
