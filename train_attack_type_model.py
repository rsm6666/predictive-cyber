"""
===================================================================
نموذج تحديد نوع الهجوم (Multi-class) — Random Forest
===================================================================
بدل "هجوم / لا"، يصنّف الاتصال إلى: BENIGN, DoS, DDoS, PortScan,
Brute Force (FTP/SSH), Web Attack, Botnet.

قرارات التصميم (ولماذا):
1) نجمّع الأنواع الفرعية بعائلات (مثلاً 4 أنواع DoS = DoS)، لأن بعض
   الأنواع الفرعية عينات قليلة جدًا بعد حذف المكرر.
2) نستبعد الأنواع اللي عيناتها < 100 (Infiltration, Heartbleed) لأن أي
   رقم عنها غير موثوق، ونطبع أسماءها بدل ما نخفيها.
3) سقف 60,000 صف لكل نوع (مأخوذة بتباعد منتظم مع حفظ ترتيب الالتقاط)،
   حتى ما يطغى BENIGN ويصير التدريب سريعًا.
   ملاحظة: بسبب السقف، Precision لكل فئة نسبي لهذا التوزيع، أما Recall
   فما يتأثر.
4) نستثني Destination Port (نفس قرار نموذج الكشف): هو يفرّق بين الأنواع
   من رقم المنفذ المستخدم بسيناريو الداتاسيت، مو من سلوك الهجوم نفسه.
5) نقيّم بطريقتين:
   - عشوائي: الأسهل، ومتفائل لأن التدفقات المتجاورة بنفس الهجوم شبه
     متطابقة، فتتسرب بين التدريب والاختبار.
   - زمني داخل كل نوع: آخر 20% من كل نوع (حسب ترتيب الالتقاط) للاختبار،
     مع فجوة 1% قبله. هذا الأصدق، والفرق بين الطريقتين نتيجة بحد ذاتها.

التشغيل (من مجلد المشروع، والبيئة مفعّلة):  python train_attack_type_model.py
===================================================================
"""

import joblib
import matplotlib

matplotlib.use("Agg")   # حفظ الصور بدون شاشة
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from train_baseline_model import DATA_FOLDER, clean_dataset, load_dataset

MIN_CLASS_ROWS = 100
CAP_PER_CLASS = 60_000
EXCLUDE_COLS = ("Destination Port",)
MODEL_PATH = "./attack_type_model.joblib"


# ===================================================================
# توحيد أسماء الأنواع إلى عائلات
# ===================================================================
def normalize_label(label):
    text = str(label).strip()
    low = text.lower()
    if low == "benign":
        return "BENIGN"
    if low == "ddos":
        return "DDoS"
    if low.startswith("dos"):
        return "DoS"
    if low == "portscan":
        return "PortScan"
    if low in ("ftp-patator", "ssh-patator"):
        return "Brute Force (FTP/SSH)"
    if low.startswith("web attack"):   # الاسم الأصلي فيه حرف تالف، فنقارن بالبداية
        return "Web Attack"
    if low == "bot":
        return "Botnet"
    return text   # Infiltration, Heartbleed → تُستبعد لاحقًا لقلتها


# ===================================================================
# تجهيز البيانات
# ===================================================================
def build_dataset():
    df = clean_dataset(load_dataset(DATA_FOLDER))   # يحذف NaN والمكرر
    df["Family"] = df["Label"].map(normalize_label)

    counts = df["Family"].value_counts()
    print("\nتوزيع الأنواع بعد التنظيف:")
    print(counts.to_string())
    too_small = counts[counts < MIN_CLASS_ROWS]
    if len(too_small):
        print(f"\nاستُبعدت لقلة العينات (< {MIN_CLASS_ROWS}): {dict(too_small)}")
    df = df[df["Family"].isin(counts[counts >= MIN_CLASS_ROWS].index)]

    parts = []
    for _, group in df.groupby("Family"):
        group = group.sort_index()   # الفهرس الأصلي = ترتيب الالتقاط
        if len(group) > CAP_PER_CLASS:
            positions = np.linspace(0, len(group) - 1, CAP_PER_CLASS).astype(int)
            group = group.iloc[positions]
        parts.append(group)
    data = pd.concat(parts).sort_index()

    feature_cols = [
        c for c in data.select_dtypes(include=[np.number]).columns
        if c != "Label_Binary" and c not in EXCLUDE_COLS
    ]
    print(f"\nحجم البيانات للتدريب والتقييم: {len(data):,} صف | {len(feature_cols)} خاصية")
    return data[feature_cols], data["Family"], feature_cols


# ===================================================================
# طريقتا التقسيم
# ===================================================================
def random_split(X, y):
    train_idx, test_idx = train_test_split(
        X.index.values, test_size=0.2, random_state=42, stratify=y.values)
    return train_idx, test_idx


def blocked_split(y, test_frac=0.2, gap_frac=0.01):
    train_idx, test_idx = [], []
    for _, group in y.groupby(y):
        idx = np.sort(group.index.values)
        n = len(idx)
        n_test, gap = int(n * test_frac), int(n * gap_frac)
        train_idx.extend(idx[: n - n_test - gap])
        test_idx.extend(idx[n - n_test:])
    return np.array(train_idx), np.array(test_idx)


# ===================================================================
# التدريب والتقييم
# ===================================================================
def fit_and_report(X, y, train_idx, test_idx, name):
    model = RandomForestClassifier(
        n_estimators=150, class_weight="balanced_subsample",
        n_jobs=-1, random_state=42)
    model.fit(X.loc[train_idx], y.loc[train_idx])
    pred = model.predict(X.loc[test_idx])

    print(f"\n===== [{name}] تدريب={len(train_idx):,} | اختبار={len(test_idx):,} =====")
    print(classification_report(y.loc[test_idx], pred, zero_division=0))
    report = classification_report(
        y.loc[test_idx], pred, output_dict=True, zero_division=0)

    labels = sorted(y.unique())
    cm = confusion_matrix(y.loc[test_idx], pred, labels=labels, normalize="true")
    fig, ax = plt.subplots(figsize=(9, 8))
    ConfusionMatrixDisplay(cm, display_labels=labels).plot(
        ax=ax, cmap="Blues", xticks_rotation=45, values_format=".2f")
    ax.set_title(f"Attack type confusion matrix (row-normalized) - {name}")
    fig.savefig(f"confusion_matrix_attack_type_{name}.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    return model, report


def main():
    X, y, feature_cols = build_dataset()

    tr_r, te_r = random_split(X, y)
    _, report_random = fit_and_report(X, y, tr_r, te_r, "random")

    tr_b, te_b = blocked_split(y)
    model_blocked, report_blocked = fit_and_report(X, y, tr_b, te_b, "blocked")

    labels = sorted(y.unique())
    rows = []
    for cls in labels:
        rows.append({
            "class": cls,
            "test_rows": int(report_blocked[cls]["support"]),
            "recall_random": report_random[cls]["recall"],
            "recall_blocked": report_blocked[cls]["recall"],
            "f1_random": report_random[cls]["f1-score"],
            "f1_blocked": report_blocked[cls]["f1-score"],
        })
    summary = pd.DataFrame(rows).round(3)
    summary.to_csv("attack_type_summary.csv", index=False)

    print("\n" + "=" * 70)
    print("المقارنة: تقسيم عشوائي مقابل تقسيم زمني داخل كل نوع")
    print("=" * 70)
    print(summary.to_string(index=False))
    print(f"\nMacro-F1  عشوائي = {report_random['macro avg']['f1-score']:.3f} "
          f"| زمني = {report_blocked['macro avg']['f1-score']:.3f}")

    # أمثلة: الحقيقي مقابل المتوقع (من الاختبار الزمني)
    sample_idx = np.random.default_rng(0).choice(te_b, size=min(8, len(te_b)), replace=False)
    probs = model_blocked.predict_proba(X.loc[sample_idx])
    preds = model_blocked.classes_[probs.argmax(axis=1)]
    print("\nأمثلة (الحقيقي → المتوقع | الثقة):")
    for true, pred, p in zip(y.loc[sample_idx], preds, probs.max(axis=1)):
        mark = "✅" if true == pred else "❌"
        print(f"  {mark} {true}  →  {pred}  | {p:.2f}")

    # نحفظ النموذج المدرّب بالتقسيم الزمني (الأصدق)
    joblib.dump({
        "model": model_blocked,
        "feature_names": feature_cols,
        "classes": list(model_blocked.classes_),
    }, MODEL_PATH)
    print(f"\n✅ حفظنا النموذج: {MODEL_PATH}  و attack_type_summary.csv "
          "وصور confusion_matrix_attack_type_*.png")


if __name__ == "__main__":
    main()
