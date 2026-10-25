"""
===================================================================
سكربت بناء النوافذ الزمنية وتدريب نموذج LSTM
===================================================================
الفكرة: نحوّل بيانات CICIDS2017 (صفوف منفردة) لنوافذ زمنية مجمّعة
(كل نافذة = دقيقة واحدة من نشاط الشبكة)، وندرّب LSTM يتنبأ هل
بيصير هجوم بالنافذة الجاية بناءً على تسلسل آخر N نافذة.

قبل التشغيل تأكد:
pip install pandas numpy scikit-learn tensorflow joblib matplotlib

شغّله بـ: python train_lstm_model.py

ملاحظة: هذا السكربت أبطأ من الـ Baseline لأنه يبني تسلسلات زمنية
ويدرّب شبكة عصبية — توقع وقت أطول، وخصوصًا لو ما عندك GPU مفعّل
مع TensorFlow.
===================================================================
"""

import glob
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.models import Sequential
import matplotlib.pyplot as plt

# ===================================================================
# 1) الإعدادات
# ===================================================================
# عدّل هذا المسار حسب مكان ملف CICIDS_Flow.parquet عندك (طلع لك بعد
# تشغيل download_flows.py — استخدم أمر find لو ما تتذكره بالضبط)
PARQUET_PATH = "./CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet"
WINDOW_SIZE = "1min"     # حجم كل نافذة زمنية (تقدر تجرب "30s" أو "5min")
SEQUENCE_LENGTH = 10     # كم نافذة سابقة نستخدم للتنبؤ بالنافذة الجاية
TEST_SIZE = 0.2
RANDOM_STATE = 42
MODEL_OUTPUT_PATH = "./lstm_model.keras"
SCALER_OUTPUT_PATH = "./lstm_scaler.joblib"


# ===================================================================
# 2) تحميل البيانات مع الحفاظ على عمود الوقت
# ===================================================================
def load_dataset_with_time(parquet_path: str) -> pd.DataFrame:
    print(f"جاري تحميل البيانات من: {parquet_path}")
    df = pd.read_parquet(parquet_path)
    df.columns = df.columns.str.strip()

    # هذي النسخة تسمي عمود التصنيف "attack_label" بدل "Label"
    label_col = "attack_label" if "attack_label" in df.columns else "Label"

    # تحويل عمود الوقت — CICIDS2017 معروف بوجود صيغ تاريخ مختلفة بين
    # الأيام المسجّلة (بعضها بثواني، بعضها بدون، وبعضها ترتيب يوم/شهر
    # معكوس). نجرب عدة صيغ بالتتابع بدل الاعتماد على صيغة وحدة، عشان
    # ما نفقد أيام كاملة (وأهمها الأيام اللي فيها هجمات فعلية).
    candidate_formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ]
    parsed = pd.Series(pd.NaT, index=df.index)
    raw_timestamps = df["Timestamp"].astype(str)
    for fmt in candidate_formats:
        still_missing = parsed.isna()
        if not still_missing.any():
            break
        attempt = pd.to_datetime(
            raw_timestamps[still_missing], format=fmt, errors="coerce"
        )
        parsed.loc[still_missing] = attempt
        print(f"  بعد تجربة الصيغة {fmt}: {parsed.notna().sum():,} صف صالح تراكميًا")

    df["Timestamp"] = parsed
    before = len(df)
    df = df.dropna(subset=["Timestamp"])
    print(f"حذفنا {before - len(df):,} صف بسبب مشاكل بصيغة الوقت (تعذّر تحليلها بأي صيغة)")

    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()

    df["Label_Binary"] = df[label_col].apply(
        lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
    )

    print(f"إجمالي الصفوف الصالحة: {len(df):,}")
    return df


# ===================================================================
# 3) تجميع البيانات لنوافذ زمنية (أهم خطوة بالسكربت كله)
# ===================================================================
def build_time_windows(df: pd.DataFrame) -> pd.DataFrame:
    df = df.set_index("Timestamp").sort_index()

    # لكل نافذة زمنية، نحسب مؤشرات مجمّعة تصف "سلوك الشبكة" بتلك الفترة
    # ملاحظة: جربنا سابقًا إضافة syn_flag_count و rst_flag_count، لكنها
    # طلعت مرتبطة بشكل شبه مباشر بـ total_flows (تكرار معلومة مو إضافة
    # حقيقية)، فأثّرت سلبًا على الأداء. أبقينا فقط unique_src_ips لأنها
    # تقيس بُعدًا مختلفًا فعليًا (تنوّع المصادر، مو عدد الاتصالات).
    windows = df.resample(WINDOW_SIZE).agg(
        total_flows=("Label_Binary", "count"),
        attack_flows=("Label_Binary", "sum"),
        unique_dst_ports=("destination_port", "nunique"),
        unique_src_ips=("source_ip", "nunique"),
        avg_flow_duration=("Flow Duration", "mean"),
        avg_packet_size=("Average Packet Size", "mean"),
        total_fwd_packets=("Total Fwd Packets", "sum"),
        total_bwd_packets=("Total Backward Packets", "sum"),
    )

    windows = windows.fillna(0)

    # الهدف: هل بيصير هجوم بالنافذة *الجاية*؟ (نزيح attack_flows خطوة للخلف)
    windows["attack_next_window"] = (windows["attack_flows"].shift(-1) > 0).astype(int)
    windows = windows.dropna()

    print(f"عدد النوافذ الزمنية الناتجة: {len(windows):,}")
    print("توزيع الهدف (هجوم بالنافذة الجاية):")
    print(windows["attack_next_window"].value_counts())

    if windows["attack_next_window"].nunique() < 2:
        raise ValueError(
            "⚠️ كل النوافذ الزمنية بنفس الفئة (كلها هجوم أو كلها لا)! "
            "هذا يعني على الأغلب فقدنا بيانات أيام فيها هجمات بسبب "
            "مشاكل بتحليل صيغة الوقت. راجع رسائل تحليل الوقت بالأعلى "
            "وتأكد إن أغلب الصفوف نجحت (نسبة قريبة من 100%، مو 20%)."
        )

    return windows


# ===================================================================
# 4) بناء التسلسلات (Sequences) اللي يحتاجها LSTM
# ===================================================================
def build_sequences(windows: pd.DataFrame):
    feature_cols = [
        "total_flows", "attack_flows", "unique_dst_ports", "unique_src_ips",
        "avg_flow_duration", "avg_packet_size",
        "total_fwd_packets", "total_bwd_packets",
    ]

    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(windows[feature_cols])

    X, y = [], []
    targets = windows["attack_next_window"].values

    for i in range(len(scaled_features) - SEQUENCE_LENGTH):
        X.append(scaled_features[i:i + SEQUENCE_LENGTH])
        y.append(targets[i + SEQUENCE_LENGTH - 1])

    X = np.array(X)
    y = np.array(y)
    print(f"شكل بيانات التسلسلات: {X.shape}  (عينات, خطوات زمنية, خصائص)")
    return X, y, scaler, feature_cols


# ===================================================================
# 5) بناء وتدريب نموذج LSTM
# ===================================================================
def train_lstm(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    model = Sequential([
        LSTM(64, input_shape=(X.shape[1], X.shape[2]), return_sequences=False),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(1, activation="sigmoid"),
    ])

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    print("\nجاري تدريب نموذج LSTM...")
    model.fit(
        X_train, y_train,
        epochs=30,
        batch_size=64,
        validation_split=0.1,
        callbacks=[EarlyStopping(patience=5, restore_best_weights=True)],
        verbose=1,
    )

    print("\nجاري التقييم على بيانات الاختبار...")
    y_pred_proba = model.predict(X_test)
    y_pred = (y_pred_proba > 0.5).astype(int)

    print("\n===== تقرير أداء LSTM =====")
    print(classification_report(y_test, y_pred, target_names=["No Attack Next", "Attack Next"]))

    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack Next", "Attack Next"])
    disp.plot(cmap="Purples")
    plt.title("Confusion Matrix - LSTM Model")
    plt.savefig("confusion_matrix_lstm.png", dpi=150, bbox_inches="tight")
    print("حفظنا مصفوفة الالتباس بملف: confusion_matrix_lstm.png")

    return model


# ===================================================================
# 6) التشغيل الرئيسي
# ===================================================================
if __name__ == "__main__":
    df = load_dataset_with_time(PARQUET_PATH)
    windows = build_time_windows(df)
    X, y, scaler, feature_cols = build_sequences(windows)
    model = train_lstm(X, y)

    model.save(MODEL_OUTPUT_PATH)
    joblib.dump({"scaler": scaler, "feature_cols": feature_cols}, SCALER_OUTPUT_PATH)
    print(f"\n✅ تم حفظ نموذج LSTM بملف: {MODEL_OUTPUT_PATH}")
    print(f"✅ تم حفظ الـ Scaler بملف: {SCALER_OUTPUT_PATH}")
