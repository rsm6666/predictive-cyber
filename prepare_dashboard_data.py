"""
===================================================================
تجهيز بيانات خفيفة للداشبورد (يُشغّل مرة وحدة)
===================================================================
المشكلة: الداشبورد كان يحمّل 2.8 مليون صف في كل تشغيل، فيستنزف
الذاكرة وينهار WSL. الحل: نحضّر عيّنات صغيرة مرة وحدة ونحفظها،
فيفتح الداشبورد فورًا وبذاكرة قليلة.

ينتج ثلاثة ملفات صغيرة في مجلد dashboard_cache/:
  1) baseline_sample.parquet  — عينة اتصالات للكشف اللحظي (مع التصنيف)
  2) lstm_windows.parquet      — جدول النوافذ الزمنية الجاهز (6480 صف فقط)
  3) act_sample.parquet        — عينة تدفقات لطبقة Act (مع IP)

التشغيل (مرة وحدة، ومن مجلد المشروع):
    python prepare_dashboard_data.py
===================================================================
"""

import os

import numpy as np
import pandas as pd

OUT_DIR = "./dashboard_cache"
BASELINE_SAMPLE_PER_CLASS = 400   # عينة لكل نوع للكشف اللحظي
ACT_SAMPLE_BENIGN = 4000
ACT_SAMPLE_PER_ATTACK = 1500
SEED = 42


def prepare_baseline_sample():
    """عينة صغيرة متوازنة من اتصالات الكشف اللحظي، مع أعمدة الخصائص والتصنيف."""
    from train_baseline_model import DATA_FOLDER, clean_dataset, load_dataset

    df = clean_dataset(load_dataset(DATA_FOLDER))
    rng = np.random.default_rng(SEED)
    parts = []
    for label, group in df.groupby("Label"):
        n = min(BASELINE_SAMPLE_PER_CLASS, len(group))
        parts.append(group.sample(n, random_state=int(rng.integers(1_000_000))))
    sample = pd.concat(parts).sample(frac=1, random_state=SEED).reset_index(drop=True)
    sample.to_parquet(f"{OUT_DIR}/baseline_sample.parquet")
    print(f"✅ baseline_sample.parquet — {len(sample):,} صف، "
          f"{sample['Label'].nunique()} نوع")


def prepare_lstm_windows():
    """جدول النوافذ الزمنية الجاهز (صغير أصلًا: ~6480 صف)."""
    from train_lstm_model import PARQUET_PATH, build_time_windows, load_dataset_with_time

    windows = build_time_windows(load_dataset_with_time(PARQUET_PATH))
    windows.to_parquet(f"{OUT_DIR}/lstm_windows.parquet")
    print(f"✅ lstm_windows.parquet — {len(windows):,} نافذة زمنية")


def prepare_act_sample():
    """عينة تدفقات لطبقة Act، تحتفظ بأعمدة IP اللازمة للحظر."""
    from train_attack_type_model import normalize_label
    from act_demo import DEFAULT_PARQUET, META_COLS

    import joblib
    feature_names = joblib.load("./attack_type_model.joblib")["feature_names"]
    wanted = sorted(set(feature_names) | set(META_COLS) |
                    ({"Fwd Header Length"} if "Fwd Header Length.1" in feature_names else set()))
    try:
        import pyarrow.parquet as pq
        cols = sorted(set(wanted) & set(pq.ParquetFile(DEFAULT_PARQUET).schema.names))
    except Exception:
        cols = None
    df = pd.read_parquet(DEFAULT_PARQUET, columns=cols)
    if "Fwd Header Length.1" in feature_names and "Fwd Header Length.1" not in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=feature_names)
    df["family"] = df["attack_label"].map(normalize_label)

    rng = np.random.default_rng(SEED)
    parts = []
    for family, group in df.groupby("family"):
        n = ACT_SAMPLE_BENIGN if family == "BENIGN" else ACT_SAMPLE_PER_ATTACK
        parts.append(group.sample(min(n, len(group)),
                                  random_state=int(rng.integers(1_000_000))))
    sample = pd.concat(parts).sample(frac=1, random_state=SEED).reset_index(drop=True)
    sample.to_parquet(f"{OUT_DIR}/act_sample.parquet")
    print(f"✅ act_sample.parquet — {len(sample):,} تدفق")


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    print("جاري تجهيز بيانات الداشبورد (مرة وحدة)...\n")
    prepare_baseline_sample()
    prepare_lstm_windows()
    prepare_act_sample()
    print(f"\n✅ خلص. الملفات في {OUT_DIR}/ — الداشبورد الآن يفتح بسرعة وذاكرة قليلة.")
