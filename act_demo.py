"""
===================================================================
عرض طبقة Act: من تصنيف نوع الهجوم إلى إجراء على جدار ناري محاكى
===================================================================
الخطوات:
  1) يحمّل نموذج نوع الهجوم (attack_type_model.joblib) وعينة من تدفقات الـ parquet
     (النسخة اللي فيها source_ip).
  2) يتحقق أولًا: هل النموذج (المدرّب على نسخة Kaggle) يعمّم على نسخة الـ parquet؟
     يطبع الدقة، ويحذّر لو أقل من 90%.
  3) نافذة المراقبة (نصف التدفقات): يصنّف، ويجمّع القرائن حسب source_ip،
     ويطبّق السياسة + حواجز الأمان لإنتاج مقترحات.
  4) موافقة بشرية لكل مقترح تنفيذي (أو --auto-approve داخل الـ Sandbox فقط).
  5) نافذة الإعادة (النصف الثاني): يقيس أثر القواعد المطبّقة:
     كم هجوم كان سيُمنع، وكم تدفق طبيعي كان سيتضرر (Collateral).

تنبيه عن التفسير: عناوين المهاجمين بهذا الداتاسيت قليلة وثابتة (محاكاة)،
فحظر المصدر أسهل من الواقع. الأرقام تبرهن آلية القرار، لا أداء إنتاجي.

التشغيل:
  python act_demo.py                  # موافقة يدوية لكل مقترح
  python act_demo.py --auto-approve   # موافقة آلية (Sandbox فقط)
  python act_demo.py --ollama         # مع شرح نصي لكل مقترح من Ollama
===================================================================
"""

import argparse

import joblib
import numpy as np
import pandas as pd

from sandbox_firewall import SimulatedFirewall, decide_action
from train_attack_type_model import normalize_label

DEFAULT_PARQUET = "./CIC-IDS2017/Network-Flows/CICIDS_Flow.parquet"
DEFAULT_MODEL = "./attack_type_model.joblib"
META_COLS = ["source_ip", "destination_ip", "destination_port", "attack_label"]
OLLAMA_MODEL = "qwen2.5:14b"


# ===================================================================
# تحميل عينة التدفقات وتجهيز الخصائص
# ===================================================================
def load_flows(path, feature_names):
    wanted = set(feature_names) | set(META_COLS)
    if "Fwd Header Length.1" in wanted:     # عمود مكرر موجود بنسخة Kaggle فقط
        wanted.discard("Fwd Header Length.1")
        wanted.add("Fwd Header Length")
    try:
        import pyarrow.parquet as pq
        columns = sorted(wanted & set(pq.ParquetFile(path).schema.names))
    except Exception:
        columns = None
    df = pd.read_parquet(path, columns=columns)

    if "Fwd Header Length.1" in feature_names and "Fwd Header Length.1" not in df.columns:
        df["Fwd Header Length.1"] = df["Fwd Header Length"]
    missing = [c for c in feature_names if c not in df.columns]
    if missing:
        raise SystemExit(f"أعمدة ناقصة بملف الـ parquet: {missing}")

    feats = df[feature_names].replace([np.inf, -np.inf], np.nan)
    df = df.loc[feats.notna().all(axis=1)].copy()
    mapping = {label: normalize_label(label) for label in df["attack_label"].unique()}
    df["family"] = df["attack_label"].map(mapping)
    return df


def build_stream(df, classes, n_benign, per_family, rng):
    parts = []
    for family, group in df.groupby("family"):
        if family not in classes:
            continue   # أنواع نادرة ما درّبنا عليها
        n = n_benign if family == "BENIGN" else per_family
        parts.append(group.sample(min(n, len(group)),
                                  random_state=int(rng.integers(1_000_000_000))))
    stream = pd.concat(parts)
    return stream.sample(frac=1, random_state=int(rng.integers(1_000_000_000))
                         ).reset_index(drop=True)


# ===================================================================
# تجميع القرائن حسب المصدر (الـ Agent يتصرف على كيان، مو على تدفق منفرد)
# ===================================================================
def aggregate_by_source(obs):
    totals = obs.groupby("source_ip").size()
    stats = []
    for ip, group in obs[obs["pred"] != "BENIGN"].groupby("source_ip"):
        counts = group["pred"].value_counts()
        target = (group["destination_ip"].astype(str) + ":" +
                  group["destination_port"].astype(str)).value_counts().index[0]
        stats.append({
            "source_ip": ip, "attack_type": counts.index[0],
            "n_flows": len(group), "attack_ratio": len(group) / totals[ip],
            "mean_confidence": float(group["conf"].mean()), "top_target": target,
        })
    return sorted(stats, key=lambda s: -s["n_flows"])


def ollama_rationale(p):
    import ollama
    prompt = (
        f"You are a security analyst. A detector flagged source {p.source_ip} as "
        f"'{p.attack_type}' over {p.n_flows} flows (mean confidence "
        f"{p.mean_confidence:.2f}). Proposed action: {p.action} for "
        f"{p.duration_min} minutes. In at most 2 sentences, explain why this "
        "action fits this attack type and mention one risk of false positives. "
        "No preamble.")
    reply = ollama.chat(model=OLLAMA_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        options={"temperature": 0.3})
    return reply["message"]["content"].strip()


def ask_approval(p):
    print(f"\n--- مقترح #{p.id} ---")
    print(f"المصدر: {p.source_ip} | النوع: {p.attack_type} | تدفقات: {p.n_flows} | "
          f"ثقة: {p.mean_confidence:.2f} | نسبة هجوم: {p.attack_ratio:.2f}")
    print(f"الإجراء المقترح: {p.action} لمدة {p.duration_min} دقيقة"
          + (f" على الهدف {p.target}" if p.action == "rate_limit_target" else ""))
    if p.rationale:
        print(f"الشرح: {p.rationale}")
    return input("وافق على التنفيذ؟ [y/N]: ").strip().lower() == "y"


# ===================================================================
# التشغيل
# ===================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parquet", default=DEFAULT_PARQUET)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--n-benign", type=int, default=6000)
    parser.add_argument("--per-family", type=int, default=2000)
    parser.add_argument("--auto-approve", action="store_true")
    parser.add_argument("--ollama", action="store_true")
    args = parser.parse_args()
    rng = np.random.default_rng(args.seed)

    saved = joblib.load(args.model)
    model, feature_names = saved["model"], saved["feature_names"]
    print(f"تم تحميل نموذج نوع الهجوم | الأنواع: {list(model.classes_)}")

    flows = load_flows(args.parquet, feature_names)
    stream = build_stream(flows, set(model.classes_), args.n_benign, args.per_family, rng)
    print(f"حجم العينة: {len(stream):,} تدفق")

    proba = model.predict_proba(stream[feature_names])
    stream["pred"] = model.classes_[proba.argmax(axis=1)]
    stream["conf"] = proba.max(axis=1)

    # ---- فحص التعميم على نسخة الـ parquet ----
    accuracy = (stream["pred"] == stream["family"]).mean()
    print(f"\nفحص التعميم: دقة النموذج على عينة الـ parquet = {accuracy:.3f}")
    correct = stream["pred"] == stream["family"]
    print(correct.groupby(stream["family"]).mean().round(3).to_string())
    if accuracy < 0.90:
        print("⚠️ الدقة أقل من 90%: النموذج مدرّب على نسخة بيانات مختلفة. "
              "الأفضل إعادة تدريبه على الـ parquet قبل الاعتماد على نتائج هذا العرض.")

    half = len(stream) // 2
    observe, replay = stream.iloc[:half], stream.iloc[half:]

    # ---- القرار ----
    firewall = SimulatedFirewall()
    proposals = [decide_action(s, i + 1, firewall.allowlist)
                 for i, s in enumerate(aggregate_by_source(observe))]
    print(f"\nعدد المصادر المشتبه بها بنافذة المراقبة: {len(proposals)}")

    # الحقيقة (للتقييم فقط، الـ Agent ما يشوفها)
    true_attack_ratio = (observe.assign(is_attack=observe["family"] != "BENIGN")
                         .groupby("source_ip")["is_attack"].mean())

    if args.ollama:
        for p in proposals:
            if p.action not in ("monitor", "none"):
                try:
                    p.rationale = ollama_rationale(p)
                except Exception as e:   # Ollama مو شغّال: نكمل بدونه
                    print(f"(تعذّر شرح Ollama: {e})")
                    break

    # ---- الموافقة والتنفيذ ----
    for p in proposals:
        if p.action in ("monitor", "none"):
            firewall.apply(p, "system")
            continue
        if firewall.is_covered(p):     # نفس المصدر محظور/معزول بقاعدة سابقة
            firewall.mark_covered(p)
            continue
        if args.auto_approve:
            ok, approver = True, "auto(sandbox)"
        else:
            ok, approver = ask_approval(p), "human"
        firewall.apply(p, approver) if ok else firewall.reject(p, approver)

    # ---- ملخص المقترحات (مع الحقيقة للمقارنة) ----
    table = pd.DataFrame([{
        "المصدر": p.source_ip, "النوع المتوقع": p.attack_type, "الإجراء": p.action,
        "تدفقات": p.n_flows, "الثقة": round(p.mean_confidence, 2),
        "نسبة هجوم حقيقية": round(float(true_attack_ratio.get(p.source_ip, np.nan)), 2),
        "الحالة": p.status,
    } for p in proposals])
    print("\n===== المقترحات والنتائج =====")
    print(table.to_string(index=False) if len(table) else "لا مقترحات")

    # ---- أثر القواعد على نافذة الإعادة ----
    dropped = firewall.would_drop_mask(replay, rng)
    is_attack = (replay["family"] != "BENIGN").to_numpy()
    attack_total, benign_total = is_attack.sum(), (~is_attack).sum()
    print("\n===== أثر القواعد على نافذة الإعادة (محاكاة) =====")
    print(f"قواعد نشطة: {len(firewall.rules)}")
    if attack_total:
        print(f"تدفقات هجوم كانت ستُمنع: {(dropped & is_attack).sum():,} "
              f"من {attack_total:,} ({(dropped & is_attack).sum() / attack_total:.1%})")
    if benign_total:
        print(f"تدفقات طبيعية كانت ستتضرر (Collateral): {(dropped & ~is_attack).sum():,} "
              f"من {benign_total:,} ({(dropped & ~is_attack).sum() / benign_total:.1%})")
    per_type = (replay.assign(dropped=dropped)[is_attack]
                .groupby("family")["dropped"].mean().round(3))
    print("نسبة المنع لكل نوع هجوم:")
    print(per_type.to_string())

    firewall.save_log("action_log.json")
    print("\n✅ سجل الإجراءات محفوظ: action_log.json")


if __name__ == "__main__":
    main()
