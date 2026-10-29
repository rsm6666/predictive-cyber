"""
===================================================================
سكربت تدريب نموذج Baseline لمشروع التنبؤ بالهجمات السيبرانية
===================================================================
الهدف: تدريب نموذج Random Forest على بيانات CICIDS2017 للتمييز بين
حركة الشبكة الطبيعية (BENIGN) والهجمات (ATTACK).

كيف تشغّلونه:
1) حمّلوا CICIDS2017 من: https://www.unb.ca/cic/datasets/ids-2017.html
2) حطوا ملفات الـ CSV كلها بمجلد واحد
3) عدّلوا متغير DATA_FOLDER تحت لمسار المجلد عندكم
4) شغّلوا: python train_baseline_model.py

المكتبات المطلوبة (تنصيب مرة وحدة):
pip install pandas numpy scikit-learn joblib matplotlib
===================================================================
"""

import glob
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

# ===================================================================
# 1) الإعدادات — عدّلوا هذا الجزء بس حسب جهازكم
# ===================================================================
DATA_FOLDER = os.path.expanduser("~/.cache/kagglehub/datasets/chethuhn/network-intrusion-dataset/versions/1")   # مسار مجلد ملفات CSV
TEST_SIZE = 0.2                     # 20% اختبار / 80% تدريب
RANDOM_STATE = 42                   # يثبّت النتائج تكون قابلة للتكرار
MODEL_OUTPUT_PATH = "./baseline_rf_model.joblib"


# ===================================================================
# 2) تحميل ودمج كل ملفات CSV بمجلد واحد
# ===================================================================
def load_dataset(folder_path: str) -> pd.DataFrame:
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"ما لقيت أي ملف CSV بمجلد: {folder_path}\n"
            "تأكدوا من مسار DATA_FOLDER وإن ملفات CICIDS2017 موجودة فيه."
        )

    print(f"لقيت {len(csv_files)} ملف CSV. جاري التحميل والدمج...")
    dataframes = [pd.read_csv(f, low_memory=False) for f in csv_files]
    df = pd.concat(dataframes, ignore_index=True)

    # أعمدة CICIDS2017 فيها مسافات زايدة بالأسماء (مشكلة معروفة بالداتاسيت)
    df.columns = df.columns.str.strip()

    print(f"إجمالي الصفوف بعد الدمج: {len(df):,}")
    return df


# ===================================================================
# 3) تنظيف البيانات
# ===================================================================
def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    # استبدال القيم اللانهائية (شائعة بهذا الداتاسيت) بـ NaN ثم حذفها
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    print(f"حذفنا {before - len(df):,} صف فيها قيم ناقصة/لانهائية")

    # حذف الصفوف المكررة بالكامل — CICIDS2017 معروف بوجود صفوف مكررة
    # كثيرة، ولو تركناها ممكن نفس الصف يطلع بالتدريب والاختبار بنفس
    # الوقت، فيحفظ النموذج الإجابة بدل ما يتعلم نمط حقيقي (Overfitting)
    before_dup = len(df)
    df = df.drop_duplicates()
    print(f"حذفنا {before_dup - len(df):,} صف مكرر بالكامل")

    # تحويل عمود Label لتصنيف ثنائي: BENIGN = 0, أي هجوم = 1
    # (بدأنا بمشكلة Binary Classification أبسط؛ التصنيف متعدد الفئات
    #  خطوة لاحقة بعد ما يثبت النموذج الأساسي يشتغل صح)
    df["Label_Binary"] = df["Label"].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    print("توزيع الفئات بعد التحويل:")
    print(df["Label_Binary"].value_counts())
    return df


# ===================================================================
# 4) تجهيز X (الخصائص) و y (الإجابة الصحيحة)
# ===================================================================
def prepare_features(df: pd.DataFrame):
    drop_cols = ["Label", "Label_Binary"]
    X = df.drop(columns=drop_cols)
    y = df["Label_Binary"]

    # نستخدم بس الأعمدة الرقمية (لو فيه أعمدة نصية زيادة تتجاهل هنا)
    X = X.select_dtypes(include=[np.number])
    print(f"عدد الـ Features المستخدمة: {X.shape[1]}")
    return X, y


# ===================================================================
# 5) التدريب والتقييم
# ===================================================================
def train_and_evaluate(X, y, run_name="baseline", drop_features=None):
    """
    run_name: اسم التجربة (يُستخدم بأسماء الملفات المحفوظة حتى ما تنكتب
              فوق بعض لو شغّلنا أكثر من تجربة).
    drop_features: قائمة أسماء أعمدة نبيها تُستثنى من هذي التجربة بالذات
                   (نستخدمها لاختبار تأثير عمود Destination Port).
    """
    if drop_features:
        existing = [c for c in drop_features if c in X.columns]
        X = X.drop(columns=existing)
        print(f"\n[{run_name}] استبعدنا الأعمدة: {existing}")

    print(f"[{run_name}] عدد الـ Features المستخدمة فعليًا: {X.shape[1]}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # تحجيم القيم (بعض الخصائص بمقاييس مختلفة جدًا عن بعض)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(f"\n[{run_name}] جاري تدريب نموذج Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight="balanced",  # يعالج مشكلة Class Imbalance
        random_state=RANDOM_STATE,
        n_jobs=-1,                # يستخدم كل أنوية المعالج لتسريع التدريب
    )
    model.fit(X_train_scaled, y_train)

    print(f"[{run_name}] جاري التقييم على بيانات الاختبار...")
    y_pred = model.predict(X_test_scaled)

    print(f"\n===== [{run_name}] تقرير الأداء =====")
    report = classification_report(
        y_test, y_pred, target_names=["Normal", "Attack"], output_dict=True
    )
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    # مصفوفة الالتباس (Confusion Matrix) — تبين الأخطاء بالتفصيل
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Attack"])
    disp.plot(cmap="Blues")
    plt.title(f"Confusion Matrix - {run_name}")
    plt.savefig(f"confusion_matrix_{run_name}.png", dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[{run_name}] حفظنا مصفوفة الالتباس بملف: confusion_matrix_{run_name}.png")

    # أهم 10 خصائص أثّرت على قرار النموذج (مفيدة جدًا للتقرير والمناقشة)
    importances = pd.Series(model.feature_importances_, index=X.columns)
    top_features = importances.sort_values(ascending=False).head(10)
    print(f"\n===== [{run_name}] أهم 10 خصائص أثّرت على النموذج =====")
    print(top_features)

    return model, scaler, report


# ===================================================================
# 6) التشغيل الرئيسي
# ===================================================================
if __name__ == "__main__":
    df = load_dataset(DATA_FOLDER)
    df = clean_dataset(df)
    X, y = prepare_features(df)

    # ===== التجربة 1: كل الـ Features (تحتوي Destination Port) =====
    model_full, scaler_full, report_full = train_and_evaluate(
        X, y, run_name="with_port"
    )

    # ===== التجربة 2: بدون Destination Port =====
    # لو الأداء انخفض كثير هنا، يأكد إن العمود كان "اختصار مصطنع"
    # للمشكلة (Data Leakage) مو تعلم حقيقي لسلوك الهجوم
    model_no_port, scaler_no_port, report_no_port = train_and_evaluate(
        X, y, run_name="without_port", drop_features=["Destination Port"]
    )

    # ===== المقارنة النهائية بين التجربتين =====
    print("\n" + "=" * 60)
    print("مقارنة الأداء: مع Destination Port  مقابل  بدونه")
    print("=" * 60)
    print(f"{'المقياس':<20}{'مع العمود':<15}{'بدون العمود':<15}")
    for metric in ["precision", "recall", "f1-score"]:
        with_val = report_full["Attack"][metric]
        without_val = report_no_port["Attack"][metric]
        print(f"{metric:<20}{with_val:<15.4f}{without_val:<15.4f}")
    print("=" * 60)
    print(
        "لو الفرق كبير (مثلاً أكثر من 3-5%)، هذا دليل قوي إن Destination "
        "Port كان يسبب نتيجة مضللة، والرقم الأدق للاعتماد عليه هو نتيجة "
        "'بدون العمود' — وثّقوا هالمقارنة بالتقرير كدليل على منهجية علمية."
    )

    # نحفظ النموذج الأكثر واقعية (بدون العمود المشبوه) كنموذج نهائي
    joblib.dump(
        {
            "model": model_no_port,
            "scaler": scaler_no_port,
            "feature_names": [c for c in X.columns if c != "Destination Port"],
        },
        MODEL_OUTPUT_PATH,
    )
    print(f"\n✅ تم حفظ النموذج (بدون Destination Port) بملف: {MODEL_OUTPUT_PATH}")
    print("جاهز تستخدمونه بالخطوة الجاية: بناء الـ Dashboard أو نموذج LSTM.")
