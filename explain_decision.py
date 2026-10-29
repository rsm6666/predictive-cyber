"""
===================================================================
تفسير قرار النموذج (Built-in Explainability) — بدون مكتبات خارجية
===================================================================
يجاوب على سؤال اللجنة: "النموذج صندوق أسود، كيف نثق فيه؟"

الفكرة: لكل اتصال، نوضّح أي الخصائص دفعت النموذج لقراره. نجمع
إشارتين (كلاهما من Random Forest نفسه، بدون أي مكتبة جديدة):
  1) الأهمية العامة (feature_importances_): أي الخصائص يعتمد عليها
     النموذج عمومًا.
  2) الانحراف المعياري (z-score): كم تبعد قيمة هذه الخاصية في هذا
     الاتصال عن متوسطها الطبيعي (BENIGN).
المساهمة التقريبية = الأهمية × |z|. خاصية مهمة + قيمتها شاذة جدًا
عن الطبيعي = سبب قوي لقرار "هجوم".

تنبيه منهجي صادق (يُذكر بالتقرير): هذا تقريب مبني على إحصاء أحادي
المتغير (كل خاصية لحدها)، وليس قيمة Shapley حقيقية التي توزّع
المساهمة بين الخصائص بشكل نظري أدق. يكفي للعرض والتفسير البصري،
وSHAP الكامل مذكور كتحسين مستقبلي.

يُستورد منه الدوال للداشبورد، ويُشغّل مباشرة لعرض أمثلة:
  python explain_decision.py            # يشرح نموذج نوع الهجوم
  python explain_decision.py --binary   # يشرح نموذج الكشف الثنائي
===================================================================
"""

import argparse

import joblib
import numpy as np
import pandas as pd


# ===================================================================
# حساب "خط الأساس الطبيعي" مرة وحدة (متوسط وانحراف خصائص BENIGN)
# ===================================================================
def compute_baseline_stats(X_benign, feature_names):
    mean = X_benign[feature_names].mean()
    std = X_benign[feature_names].std().replace(0, 1e-9)   # نتفادى القسمة على صفر
    return {"mean": mean, "std": std}


# ===================================================================
# تفسير قرار واحد
# ===================================================================
def explain_row(model, row, feature_names, baseline, top_n=5):
    """
    row: Series فيها قيم خصائص اتصال واحد.
    يرجع قائمة بأهم الخصائص المؤثرة، مع قيمتها واتجاه انحرافها.
    """
    importances = pd.Series(model.feature_importances_, index=feature_names)
    values = row[feature_names].astype(float)
    z = (values - baseline["mean"]) / baseline["std"]
    contribution = importances * z.abs()

    top = contribution.sort_values(ascending=False).head(top_n)
    explanation = []
    for name in top.index:
        direction = "أعلى من الطبيعي" if z[name] > 0 else "أقل من الطبيعي"
        explanation.append({
            "feature": name,
            "value": float(values[name]),
            "z_score": float(z[name]),
            "direction": direction,
            "importance": float(importances[name]),
            "contribution": float(top[name]),
        })
    return explanation


def format_explanation(explanation, prediction, confidence):
    lines = [f"القرار: {prediction}  (ثقة {confidence * 100:.0f}%)",
             "أبرز الأسباب (الخاصية — القيمة — مقارنة بالطبيعي):"]
    for e in explanation:
        lines.append(
            f"  • {e['feature']} = {e['value']:.1f}  ({e['direction']}، "
            f"z={e['z_score']:+.1f})")
    return "\n".join(lines)


# ===================================================================
# تشغيل مباشر: أمثلة تفسير حقيقية
# ===================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", action="store_true",
                        help="يشرح نموذج الكشف الثنائي بدل نموذج النوع")
    parser.add_argument("--n-examples", type=int, default=6)
    args = parser.parse_args()

    from train_baseline_model import DATA_FOLDER, clean_dataset, load_dataset
    from train_attack_type_model import normalize_label

    model_path = "./baseline_rf_model.joblib" if args.binary else "./attack_type_model.joblib"
    saved = joblib.load(model_path)
    model, feature_names = saved["model"], saved["feature_names"]
    print(f"النموذج: {model_path}")

    df = clean_dataset(load_dataset(DATA_FOLDER))
    df["Family"] = df["Label"].map(normalize_label)
    X_benign = df[df["Family"] == "BENIGN"]
    baseline = compute_baseline_stats(X_benign, feature_names)

    # نختار أمثلة هجوم متنوعة
    rng = np.random.default_rng(0)
    attacks = df[df["Family"] != "BENIGN"]
    sample = attacks.sample(min(args.n_examples, len(attacks)),
                            random_state=int(rng.integers(1_000_000)))

    for _, row in sample.iterrows():
        proba = model.predict_proba(row[feature_names].to_frame().T)[0]
        pred = model.classes_[proba.argmax()]
        conf = proba.max()
        explanation = explain_row(model, row, feature_names, baseline)
        print("\n" + "=" * 60)
        print(f"النوع الحقيقي: {row['Family']}")
        print(format_explanation(explanation, pred, conf))


if __name__ == "__main__":
    main()
