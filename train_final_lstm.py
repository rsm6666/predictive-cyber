"""
===================================================================
النموذج النهائي: مجموعة (Ensemble) من 5 نماذج LSTM
===================================================================
ما الجديد مقارنة بـ train_lstm_model.py؟
1) المدخلات: سلوك الشبكة فقط (بدون attack_flows لأنها محسوبة من
   التصنيفات الحقيقية وغير متاحة بنظام فعلي)
2) تقسيم زمني (تدريب/تحقق/اختبار) مع فجوة بين المجموعات
3) التحجيم (Scaler) من بيانات التدريب فقط
4) 5 نماذج بـ seeds مختلفة، والقرار من متوسط احتمالاتها (يقلل التذبذب)
5) العتبة تُضبط على بيانات التحقق (Recall >= 0.80)، وتُحفظ مع النموذج

يحفظ: lstm_final_seed1..5.keras  +  lstm_final_meta.joblib

التشغيل:  python train_final_lstm.py
هذا الملف يحتوي أيضًا دوال مساعدة يستوردها الداشبورد وسكربت التوصيات.
===================================================================
"""

import random

import joblib
import numpy as np
import tensorflow as tf
from sklearn.metrics import precision_recall_curve, precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from tensorflow.keras.models import Sequential, load_model

from train_lstm_model import (
    PARQUET_PATH,
    SEQUENCE_LENGTH,
    build_time_windows,
    load_dataset_with_time,
)

ALL_COLS = [
    "total_flows", "attack_flows", "unique_dst_ports",
    "avg_flow_duration", "avg_packet_size",
    "total_fwd_packets", "total_bwd_packets",
]
ATTACK_IDX = ALL_COLS.index("attack_flows")
FEATURE_COLS = [c for c in ALL_COLS if c != "attack_flows"]   # مدخلات النموذج
SEEDS = [1, 2, 3, 4, 5]
TARGET_RECALL = 0.80
MODEL_PREFIX = "./lstm_final_seed"
META_PATH = "./lstm_final_meta.joblib"


# ===================================================================
# بناء التسلسلات والتقسيم الزمني
# ===================================================================
def make_sequences(windows):
    values = windows[ALL_COLS].values.astype("float32")
    targets = windows["attack_next_window"].values
    count = len(values) - SEQUENCE_LENGTH
    X = np.stack([values[i:i + SEQUENCE_LENGTH] for i in range(count)])
    y = np.array([targets[i + SEQUENCE_LENGTH - 1] for i in range(count)])
    return X, y


def chronological_split(X, y):
    n = len(X)
    gap = SEQUENCE_LENGTH   # فجوة حتى ما تتشارك التسلسلات نوافذ بين المجموعات
    n_test = int(0.2 * n)
    n_val = int(0.15 * (n - n_test))
    te_start = n - n_test
    va_start = te_start - gap - n_val
    tr_end = va_start - gap
    return (X[:tr_end], y[:tr_end],
            X[va_start:va_start + n_val], y[va_start:va_start + n_val],
            X[te_start:], y[te_start:])


def build_model(n_features):
    model = Sequential([
        Input(shape=(SEQUENCE_LENGTH, n_features)),
        LSTM(64),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(1, activation="sigmoid"),
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy")
    return model


def pick_thresholds(y_val, p_val):
    """أعلى F1، وأعلى عتبة تحقق Recall >= TARGET_RECALL (على التحقق فقط)."""
    if y_val.sum() == 0:
        return 0.5, 0.5
    precision, recall, thresholds = precision_recall_curve(y_val, p_val)
    f1 = 2 * precision * recall / (precision + recall + 1e-9)
    t_f1 = thresholds[np.argmax(f1[:-1])]
    reachable = np.where(recall[:-1] >= TARGET_RECALL)[0]
    t_recall = thresholds[reachable[-1]] if len(reachable) else t_f1
    return float(t_f1), float(t_recall)


def metrics_at(y, p, threshold, X_raw):
    pred = (p >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred, average="binary", zero_division=0)
    onset_mask = (X_raw[:, -1, ATTACK_IDX] == 0) & (y == 1)
    onset = float(pred[onset_mask].mean()) if onset_mask.any() else float("nan")
    return {
        "threshold": float(threshold), "precision": float(precision),
        "recall": float(recall), "f1": float(f1), "onset_recall": onset,
        "alert_rate": float(pred.mean()), "n_onset": int(onset_mask.sum()),
    }


# ===================================================================
# دوال مساعدة للداشبورد وسكربت التوصيات
# ===================================================================
def load_final_ensemble():
    meta = joblib.load(META_PATH)
    models = [load_model(f"{MODEL_PREFIX}{s}.keras") for s in meta["seeds"]]
    return models, meta


def ensemble_predict(models, meta, window_values):
    """window_values: مصفوفة (SEQUENCE_LENGTH, عدد الخصائص) غير محجّمة."""
    seq = meta["scaler"].transform(np.asarray(window_values)).astype("float32")
    X = np.expand_dims(seq, 0)
    return float(np.mean([m.predict(X, verbose=0)[0][0] for m in models]))


def pick_demo_end(windows, mode="onset", rng=random):
    """
    يختار نهاية تسلسل للعرض: التسلسل = windows.iloc[end-SEQUENCE_LENGTH:end]،
    والهدف الحقيقي = windows.iloc[end-1]["attack_next_window"].
    mode: onset   = بداية هجوم جديد (آخر نافذة بدون هجوم والتالية فيها هجوم)
          ongoing = هجوم مستمر
          random  = نافذة عشوائية فيها نشاط
    """
    n = len(windows)
    ends = np.arange(SEQUENCE_LENGTH, n)
    last = ends - 1
    attack = windows["attack_flows"].values[last]
    target = windows["attack_next_window"].values[last]
    flows = windows["total_flows"].values[last]
    if mode == "onset":
        ok = (attack == 0) & (target == 1)
    elif mode == "ongoing":
        ok = (attack > 0) & (target == 1)
    else:
        ok = flows > 0
    candidates = ends[ok]
    if len(candidates) == 0:
        candidates = ends
    return int(rng.choice(list(candidates)))


# ===================================================================
# التدريب
# ===================================================================
if __name__ == "__main__":
    df = load_dataset_with_time(PARQUET_PATH)
    windows = build_time_windows(df)
    X_all, y = make_sequences(windows)
    Xtr, ytr, Xva, yva, Xte, yte = chronological_split(X_all, y)
    print(f"\nتدريب={len(Xtr):,} (هجوم {ytr.sum()}) | تحقق={len(Xva):,} "
          f"(هجوم {yva.sum()}) | اختبار={len(Xte):,} (هجوم {yte.sum()})")

    in_idx = [ALL_COLS.index(c) for c in FEATURE_COLS]
    k = len(in_idx)
    scaler = StandardScaler().fit(Xtr[:, :, in_idx].reshape(-1, k))

    def prep(X):
        flat = scaler.transform(X[:, :, in_idx].reshape(-1, k))
        return flat.reshape(len(X), SEQUENCE_LENGTH, k).astype("float32")

    Xtr_s, Xva_s, Xte_s = prep(Xtr), prep(Xva), prep(Xte)

    p_val_all, p_test_all = [], []
    for seed in SEEDS:
        tf.keras.utils.set_random_seed(seed)
        model = build_model(k)
        model.fit(
            Xtr_s, ytr, validation_data=(Xva_s, yva),
            epochs=40, batch_size=64, verbose=0,
            callbacks=[EarlyStopping(monitor="val_loss", patience=6,
                                     restore_best_weights=True)],
        )
        model.save(f"{MODEL_PREFIX}{seed}.keras")
        p_val_all.append(model.predict(Xva_s, verbose=0).ravel())
        p_test_all.append(model.predict(Xte_s, verbose=0).ravel())
        print(f"  تم تدريب النموذج seed={seed}")

    p_val = np.mean(p_val_all, axis=0)
    p_test = np.mean(p_test_all, axis=0)
    t_f1, t_recall = pick_thresholds(yva, p_val)

    results = {
        "recall_mode": metrics_at(yte, p_test, t_recall, Xte),
        "f1_mode": metrics_at(yte, p_test, t_f1, Xte),
        "default_0.5": metrics_at(yte, p_test, 0.5, Xte),
    }
    persistence_pred = (Xte[:, -1, ATTACK_IDX] > 0).astype(int)
    pr, rc, f1, _ = precision_recall_fscore_support(
        yte, persistence_pred, average="binary", zero_division=0)

    print("\n" + "=" * 64)
    print("نتائج المجموعة النهائية على الاختبار الزمني (مجموعة 5 نماذج)")
    print("=" * 64)
    for name, m in results.items():
        chance = m["alert_rate"]
        print(f"[{name}] عتبة={m['threshold']:.3f} | Precision={m['precision']:.3f} "
              f"| Recall={m['recall']:.3f} | F1={m['f1']:.3f}")
        print(f"    Onset Recall={m['onset_recall']:.3f} من {m['n_onset']} حدث "
              f"| معدل الإنذارات={chance:.3f} (الصدفة تعطي Onset ≈ {chance:.2f})")
    print(f"[Persistence (oracle)] Precision={pr:.3f} | Recall={rc:.3f} | F1={f1:.3f}")

    joblib.dump({
        "scaler": scaler, "feature_cols": FEATURE_COLS, "seeds": SEEDS,
        "sequence_length": SEQUENCE_LENGTH,
        "threshold_recall": t_recall, "threshold_f1": t_f1,
        "target_recall": TARGET_RECALL, "test_metrics": results,
        "persistence": {"precision": float(pr), "recall": float(rc), "f1": float(f1)},
    }, META_PATH)
    print(f"\n✅ حفظنا {len(SEEDS)} نماذج ({MODEL_PREFIX}1..{len(SEEDS)}.keras) "
          f"و {META_PATH}")
