"""
===================================================================
نموذج شذوذ لكل منشأة — يتعلم السلوك الطبيعي لزوار موقعها
===================================================================
كل (عنوان، نافذة 5 دقائق) يصبح متجه خصائص، وIsolation Forest يتدرب على
تاريخ المنشأة نفسها بعد استبعاد النوافذ التي علّمتها القواعد. يبدأ بعد
MIN_WINDOWS نافذة، ويُعاد تدريبه عند تضاعفها.

قرار هجين (z في فضاء النموذج اللوغاريتمي، بأرضية للانحراف المعياري):
  - انحراف قوي: خاصية تبعد Z_STRONG أو أكثر عن الطبيعي، أو
  - إشارة مركّبة: نتيجة Isolation Forest فوق المئين 99 لنوافذ التدريب، مع
    خاصية تبعد Z_MIN أو أكثر.
لماذا؟ الغابة تقسّم داخل مدى بيانات التدريب فقط، فتتشبع نتيجة النقطة البعيدة
جدًا في خاصية أو اثنتين (سحب كتالوج: 0.599 مقابل عتبة 0.630 في التقييم).
والأرضية تمنع خصائص شبه ثابتة (وكيل مستخدم واحد غالبًا) من إنتاج z ضخم
لاختلاف بسيط كزائرين خلف عنوان واحد.
الشذوذ ليس دليل هجوم: سياسته لا تتجاوز المراقبة.
===================================================================
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ingest.rules import BUCKET

FEATURES = ["requests", "paths", "ratio_4xx", "ratio_5xx", "ratio_post", "mean_bytes", "agents"]
_LOG_FEATURES = ("requests", "paths", "mean_bytes", "agents")
MIN_WINDOWS = 200
MIN_REQUESTS = 5            # نافذة بطلبات أقل لا تُقيَّم (ضجيج)
TOP_FEATURES = 3
QUANTILE = 0.99
Z_MIN = 4.0
Z_STRONG = 6.0
# أرضية الانحراف المعياري في فضاء النموذج: log1p للعدّادات، والنسب كما هي
STD_FLOOR = np.array([0.3 if f in _LOG_FEATURES else 0.1 for f in FEATURES])
STATE_KEY = "anomaly"


def window_features(events):
    if not events:
        return pd.DataFrame(columns=["ip", "bucket", *FEATURES])
    df = pd.DataFrame(events)
    df["bucket"] = (df["ts"] // BUCKET).astype(int) * BUCKET
    df["is4"] = df["status"].between(400, 499)
    df["is5"] = df["status"] >= 500
    df["post"] = df["method"] == "POST"
    return df.groupby(["ip", "bucket"]).agg(
        requests=("ts", "size"), paths=("path", "nunique"), ratio_4xx=("is4", "mean"),
        ratio_5xx=("is5", "mean"), ratio_post=("post", "mean"), mean_bytes=("bytes", "mean"),
        agents=("ua", "nunique")).reset_index()


def _matrix(df):
    return np.column_stack([np.log1p(df[f]) if f in _LOG_FEATURES else df[f] for f in FEATURES]).astype(float)


def _flagged(spans):
    out = set()
    for ip, first, last in spans:
        b = int(first // BUCKET) * BUCKET
        while b <= last:
            out.add((ip, b))
            b += BUCKET
    return out


class AnomalyDetector:
    def __init__(self, path):
        self.path = Path(path)

    def status(self, store):
        st = store.state_get(STATE_KEY, {})
        return {"state": "ready" if st.get("trained_n") else "learning",
                "windows": st.get("windows", 0), "needed": MIN_WINDOWS}

    def update(self, store, start, end):
        """يحدّث التعلم بتاريخ المنشأة ويرجع تنبيهات الشذوذ لنوافذ [start, end] الجديدة."""
        history = window_features(store.web_between(0, end))
        flagged = _flagged(store.rule_alert_spans())
        is_flagged = np.array([(ip, b) in flagged for ip, b in zip(history["ip"], history["bucket"])], dtype=bool)
        clean = history[~is_flagged]
        st = store.state_get(STATE_KEY, {})
        if len(clean) >= MIN_WINDOWS and (not st.get("trained_n") or len(clean) >= 2 * st["trained_n"]):
            self._train(clean)
            st.update(trained_n=len(clean), trained_until=int(clean["bucket"].max()))
        st["windows"] = len(clean)
        store.state_set(STATE_KEY, st)
        if not st.get("trained_n"):
            return []

        candidates = clean[(clean["bucket"] > st["trained_until"]) &
                           (clean["bucket"] >= int(start // BUCKET) * BUCKET) &
                           (clean["requests"] >= MIN_REQUESTS)]
        if candidates.empty:
            return []
        saved = joblib.load(self.path)
        scores = -saved["model"].score_samples(_matrix(candidates))
        z = (_matrix(candidates) - saved["mean"]) / saved["std"]
        alerts = []
        for (_, row), score, zrow in zip(candidates.iterrows(), scores, z):
            peak = np.abs(zrow).max()
            if peak >= Z_STRONG or (score > saved["threshold"] and peak >= Z_MIN):
                alerts.append(self._alert(row, score, zrow, saved))
        return alerts

    def _train(self, clean):
        model = IsolationForest(n_estimators=150, random_state=0).fit(_matrix(clean))
        X = _matrix(clean)
        scores = -model.score_samples(X)
        joblib.dump({"model": model, "threshold": float(np.quantile(scores, QUANTILE)),
                     "mean": X.mean(axis=0), "std": np.maximum(X.std(axis=0), STD_FLOOR)}, self.path)

    @staticmethod
    def _alert(row, score, zrow, saved):
        top = np.argsort(-np.abs(zrow))[:TOP_FEATURES]
        features = [{"feature": FEATURES[i], "value": round(float(row[FEATURES[i]]), 3), "z": round(float(zrow[i]), 1)}
                    for i in top]
        return {"type": "anomaly", "source": "web", "ip": row["ip"], "first_ts": float(row["bucket"]),
                "last_ts": float(row["bucket"] + BUCKET - 1), "count": int(row["requests"]), "severity": "medium",
                "evidence": [f"{f['feature']} = {f['value']} (z={f['z']:+})" for f in features],
                "details": {"score": round(float(score), 4), "threshold": round(saved["threshold"], 4),
                            "features": features}}
