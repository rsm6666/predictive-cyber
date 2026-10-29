"""
===================================================================
خادم API للمشروع (FastAPI) — عقل النظام
===================================================================
يغلّف النماذج الخمسة كواجهة برمجية (API) تخدمها واجهة HTML احترافية
منفصلة. هذي بنية الأنظمة الحقيقية: Frontend (الشكل) + Backend (العقل).

يحمّل النماذج مرة واحدة عند الإقلاع (لا في كل طلب)، ويخدم:
  GET  /                      فحص صحة الخادم
  GET  /api/stats             إحصاءات المشروع (للوحة)
  POST /api/detect            كشف + نوع + تفسير لاتصال (أو عينة عشوائية)
  POST /api/forecast          إنذار مبكر (نافذة زمنية)
  POST /api/respond           اقتراح إجراءات لنافذة مراقبة (Sandbox)
  POST /api/recommend         توصية نصية عبر Ollama (اختياري)
  GET  /api/stream/flow       تدفق حي واحد (طبيعي أو هجوم محدّد)
  /api/v1/...                 المنصة متعددة المنشآت والمحلل الذكي (tenancy/api.py)
  /approve/{token}            صفحة الموافقة من رابط التنبيه (tenancy/pages.py)

التشغيل:
  pip install fastapi uvicorn
  uvicorn api_server:app --reload --port 8000
  ثم افتح الواجهة (index.html) التي تتصل بهذا الخادم.

كل النماذج تُحمّل من نفس ملفات المشروع الموجودة.
===================================================================
"""

import os
import random
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")       # مفتاح Claude للمحلل الذكي (اختياري)
# بعد load_dotenv: agent.analyst يقرأ ANTHROPIC_MODEL عند الاستيراد
from tenancy.api import Platform, router as platform_router  # noqa: E402
from tenancy.pages import pages as approval_pages  # noqa: E402
from monitor.api import router as monitor_router  # noqa: E402

CACHE = HERE / "dashboard_cache"
DATA = HERE / "data"             # سجل المنشآت ومجلداتها المعزولة (مستثنى من git)
OLLAMA_MODEL = "qwen2.5:14b"

# مخزن النماذج والبيانات (يُملأ عند الإقلاع)
STATE = {}


# ===================================================================
# الإقلاع: تحميل كل شيء مرة واحدة
# ===================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("تحميل النماذج والبيانات (مرة واحدة)...")
    sys.path.insert(0, str(HERE))

    # نماذج Random Forest
    STATE["type_model"] = joblib.load(HERE / "attack_type_model.joblib")
    STATE["detector"] = joblib.load(HERE / "baseline_rf_model.joblib")

    # عيّنات خفيفة من الكاش
    STATE["baseline_sample"] = pd.read_parquet(CACHE / "baseline_sample.parquet")
    STATE["lstm_windows"] = pd.read_parquet(CACHE / "lstm_windows.parquet")
    STATE["act_sample"] = pd.read_parquet(CACHE / "act_sample.parquet")

    # إحصاء خط الأساس للتفسير
    from explain_decision import compute_baseline_stats
    from train_attack_type_model import normalize_label
    bs = STATE["baseline_sample"]
    bs = bs.copy()
    bs["family"] = bs["Label"].map(normalize_label)
    benign = bs[bs["family"] == "BENIGN"]
    feats = STATE["type_model"]["feature_names"]
    STATE["expl_baseline"] = compute_baseline_stats(benign, feats)
    STATE["normalize_label"] = normalize_label

    # الإنذار المبكر (مجموعة LSTM) — قد لا يكون موجودًا
    try:
        from train_final_lstm import load_final_ensemble
        STATE["lstm_models"], STATE["lstm_meta"] = load_final_ensemble()
    except Exception as e:
        print(f"تحذير: نماذج LSTM غير متاحة ({e})")
        STATE["lstm_models"] = None

    # المنصة: سجل المنشآت ومجلداتها المعزولة + المحلل الذكي
    from tenancy.registry import Registry
    from tenancy.store import TenantStore
    app.state.platform = Platform(
        registry=Registry(DATA / "registry.db"), store=TenantStore(DATA / "tenants"),
        resources=_agent_resources, act_sample=STATE["act_sample"], windows=STATE["lstm_windows"],
        client=_agent_client, live=_agent_live,
        public_url=os.environ.get("PUBLIC_BASE_URL", "http://localhost:8001").rstrip("/"),
        allow_private_webhooks=os.environ.get("ALLOW_PRIVATE_WEBHOOKS", "true").lower() == "true",
        allow_private_targets=os.environ.get("ALLOW_PRIVATE_TARGETS", "true").lower() == "true")
    app.state.platform.notifier.start()     # مرسِل التنبيهات في الخلفية (مع إعادة المحاولة)
    app.state.platform.monitor.start()      # مجدول المراقبة الخارجية للمواقع

    print("جاهز. الخادم يعمل.")
    yield
    STATE.clear()


app = FastAPI(title="Predictive Cyber API", lifespan=lifespan)
# نسمح للواجهة بالاتصال (أثناء التطوير)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# ===================================================================
# نماذج الطلبات
# ===================================================================
class RecommendReq(BaseModel):
    context: str   # نص يصف الحالة، يُمرر لـ Ollama


# ===================================================================
# أدوات مساعدة
# ===================================================================
def _ollama(prompt):
    import ollama
    r = ollama.chat(model=OLLAMA_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    options={"temperature": 0.3})
    return r["message"]["content"].strip()


# ===================================================================
# نقاط الوصول
# ===================================================================
@app.get("/")
def health():
    return {"status": "ok", "models_loaded": "type_model" in STATE,
            "lstm_ready": STATE.get("lstm_models") is not None}


@app.get("/api/stats")
def stats():
    """إحصاءات ثابتة للوحة العرض (من نتائج التدريب الموثّقة)."""
    out = {
        "detector_recall": 0.948, "attack_type_f1": 0.952,
        "onset_recall": 0.41, "collateral": 0.005,
        "attack_types": 7, "dataset_rows": 2827677,
    }
    if STATE.get("lstm_meta"):
        m = STATE["lstm_meta"].get("test_metrics", {}).get("recall_mode", {})
        if m:
            out["onset_recall"] = round(m.get("onset_recall", 0.41), 3)
    return out


@app.post("/api/detect")
def detect(index: int = -1):
    """
    يأخذ اتصالًا (عشوائيًا إن index=-1) ويرجع: النوع، الثقة، التصنيف
    الحقيقي، والتفسير (أبرز الخصائص المؤثرة).
    """
    from explain_decision import explain_row
    model = STATE["type_model"]["model"]
    feats = STATE["type_model"]["feature_names"]
    df = STATE["baseline_sample"]

    i = random.randrange(len(df)) if index < 0 else index % len(df)
    row = df.iloc[i]
    proba = model.predict_proba(row[feats].to_frame().T)[0]
    pred = str(model.classes_[proba.argmax()])
    conf = float(proba.max())
    expl = explain_row(model, row, feats, STATE["expl_baseline"], top_n=5)

    return {
        "prediction": pred, "confidence": round(conf, 3),
        "true_label": str(row["Label"]).strip(),
        "is_attack": pred != "BENIGN",
        "explanation": [{
            "feature": e["feature"], "value": round(e["value"], 2),
            "direction": e["direction"], "z": round(e["z_score"], 2),
        } for e in expl],
    }


@app.post("/api/forecast")
def forecast(mode: str = "onset"):
    """إنذار مبكر: يختار نافذة ويتنبأ ببداية هجوم بالدقيقة التالية."""
    if STATE.get("lstm_models") is None:
        return {"error": "نماذج الإنذار المبكر غير محمّلة"}
    from train_final_lstm import ensemble_predict, pick_demo_end
    meta = STATE["lstm_meta"]
    windows = STATE["lstm_windows"]
    seq = meta["sequence_length"]
    end = pick_demo_end(windows, mode if mode in ("onset", "ongoing", "random") else "onset")
    wslice = windows.iloc[end - seq:end]
    prob = ensemble_predict(STATE["lstm_models"], meta, wslice[meta["feature_cols"]].values)
    thr = meta["threshold_recall"]
    trend = {c: [round(float(v), 1) for v in wslice[c].values]
             for c in ["total_flows", "unique_dst_ports", "avg_packet_size"]}
    return {
        "probability": round(float(prob), 3), "threshold": round(float(thr), 3),
        "alert": bool(prob >= thr),
        "true_label": int(windows.iloc[end - 1]["attack_next_window"]),
        "trend": trend,
    }


@app.post("/api/validate")
def validate(n_examples: int = 6):
    """
    اختبار موثّق: نمرّر النموذج على مجموعة الاختبار الزمنية (آخر 20% من
    النوافذ — لم يرها أثناء التدريب)، ونقارن تنبؤه بالحقيقة الأرضية
    المُسمّاة. نعيد: Onset Recall (كم بداية هجوم مسك)، معدل الإنذار
    الكاذب على النوافذ الهادئة، وأمثلة ملموسة بحقيقتها الأرضية.
    """
    if STATE.get("lstm_models") is None:
        return {"error": "نماذج LSTM غير محمّلة"}
    import numpy as np
    meta = STATE["lstm_meta"]
    w = STATE["lstm_windows"]
    seq = meta["sequence_length"]
    feats = meta["feature_cols"]
    thr = float(meta["threshold_recall"])

    vals = w[feats].values.astype("float32")
    attack_flows = w["attack_flows"].values
    targets = w["attack_next_window"].values
    n = len(w) - seq
    if n <= 10:
        return {"error": "نوافذ غير كافية للتقييم"}

    # آخر 20% = مجموعة الاختبار الزمنية (نفس حدّ التدريب بالضبط)
    te_start = n - int(0.2 * n)
    idx = list(range(te_start, n))
    X = np.stack([vals[i:i + seq] for i in idx])
    y = np.array([targets[i + seq - 1] for i in idx])
    last_attack = np.array([attack_flows[i + seq - 1] for i in idx])

    # تقييس + تنبؤ دفعة واحدة (سريع)
    flat = meta["scaler"].transform(X.reshape(-1, len(feats)))
    Xs = flat.reshape(len(X), seq, len(feats)).astype("float32")
    probs = np.mean([m.predict(Xs, verbose=0).ravel()
                     for m in STATE["lstm_models"]], axis=0)
    pred = (probs >= thr).astype(int)

    onset = (last_attack == 0) & (y == 1)   # بداية هجوم جديدة (الأصعب)
    benign = (y == 0)
    tf_idx = feats.index("total_flows")

    examples = []
    half = max(1, n_examples // 2)
    for mask, kind in ((onset, "onset"), (benign, "benign")):
        pool = list(np.where(mask)[0])
        for j in random.sample(pool, min(half, len(pool))):
            examples.append({
                "kind": kind,
                "probability": round(float(probs[j]), 3),
                "alert": bool(pred[j]),
                "true_label": int(y[j]),
                "correct": bool(pred[j] == y[j]),
                "trend": [round(float(v), 1) for v in X[j][:, tf_idx]],
            })

    return {
        "threshold": round(thr, 3),
        "n_test_sequences": int(len(X)),
        "n_onset": int(onset.sum()),
        "onset_caught": int(pred[onset].sum()),
        "onset_recall": round(float(pred[onset].mean()), 3) if onset.any() else None,
        "n_benign": int(benign.sum()),
        "false_alarms": int(pred[benign].sum()),
        "false_alarm_rate": round(float(pred[benign].mean()), 3) if benign.any() else None,
        "persistence": meta.get("persistence"),
        "examples": examples,
    }


@app.post("/api/respond")
def respond(n_sources: int = 8):
    """يحلل نافذة مراقبة ويقترح إجراءات مع حواجز الأمان."""
    from act_demo import aggregate_by_source
    from sandbox_firewall import decide_action, DEFAULT_ALLOWLIST
    model = STATE["type_model"]["model"]
    feats = STATE["type_model"]["feature_names"]
    df = STATE["act_sample"].sample(min(5000, len(STATE["act_sample"])),
                                    random_state=random.randrange(9999))
    proba = model.predict_proba(df[feats])
    df = df.assign(pred=model.classes_[proba.argmax(axis=1)], conf=proba.max(axis=1))
    true_ratio = (df.assign(a=df["family"] != "BENIGN")
                  .groupby("source_ip")["a"].mean())

    proposals = []
    for i, s in enumerate(aggregate_by_source(df)[:n_sources]):
        p = decide_action(s, i + 1, DEFAULT_ALLOWLIST)
        enforced = p.action in ("block_ip", "quarantine_host", "rate_limit_target")
        proposals.append({
            "source_ip": p.source_ip, "attack_type": p.attack_type,
            "action": p.action, "n_flows": p.n_flows,
            "confidence": round(p.mean_confidence, 2),
            "true_ratio": round(float(true_ratio.get(p.source_ip, 0)), 2),
            "enforced": enforced, "duration_min": p.duration_min,
        })
    return {"proposals": proposals}


@app.post("/api/livescan")
def livescan(count: int = 1500, iface: str = "any"):
    """
    فحص حي للشبكة الحقيقية: يلتقط حزمًا فعلية عبر مساعد يعمل بصلاحية
    sudo، يحوّلها لتدفقات، ويفحصها بطبقتين (النموذج + الكاشف السلوكي).
    يتطلب إعداد sudoers مرة واحدة (انظر README) ليعمل بلا كلمة مرور.
    """
    import json as _json
    import subprocess
    helper = str(HERE / "capture_helper.py")
    py = sys.executable
    try:
        proc = subprocess.run(
            ["sudo", "-n", py, helper, "--count", str(count), "--iface", iface],
            capture_output=True, text=True, timeout=40)
        if proc.returncode != 0:
            return {"error": "capture_failed",
                    "detail": (proc.stderr or "")[-400:],
                    "hint": "يتطلب صلاحية sudo بلا كلمة مرور لـ tcpdump/المساعد"}
        line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
        return _json.loads(line)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "hint": "لم يكتمل الالتقاط في الوقت المحدد"}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/monitor/start")
def monitor_start(window: int = 20, cycles: int = 15, iface: str = "eth0",
                  attack: int = 0):
    """
    يبدأ المراقبة المستمرة الاستباقية في الخلفية: يبني نوافذ زمنية
    حقيقية من الشبكة، وعند تجمّع تسلسل كافٍ يتنبأ LSTM ببداية هجوم.
    يكتب تقدّمه إلى ملف حالة يقرأه /api/monitor/status.
    attack=1: وضع اختبار الصحة — يحقن نمط فحص منافذ حقيقي لنرى هل
    يشتعل التنبؤ على نمط هجومي (نظير أزرار الحقن في التبويب اللحظي).
    """
    import subprocess
    monitor = str(HERE / "live_monitor.py")
    cmd = ["sudo", "-n", sys.executable, monitor,
           "--window", str(window), "--cycles", str(cycles), "--iface", iface]
    if attack:
        cmd.append("--simulate-attack")
    try:
        # نشغّلها منفصلة بالخلفية (sudo للالتقاط)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"started": True, "window": window, "cycles": cycles,
                "attack": bool(attack)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/monitor/status")
def monitor_status():
    """يقرأ حالة المراقبة الحالية (تقدّم النوافذ + تنبؤ LSTM)."""
    import json as _json
    try:
        with open("/tmp/live_monitor_state.json", encoding="utf-8") as f:
            return _json.load(f)
    except FileNotFoundError:
        return {"running": False, "collected": 0, "need": 10,
                "windows": [], "prediction": None, "idle": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/ids/start")
def ids_start(window: int = 6, iface: str = "any"):
    """يبدأ شاشة الكشف الحيّة بالخلفية (التقاط متتالٍ + كشف لحظي)."""
    import subprocess
    svc = str(HERE / "live_ids_service.py")
    try:
        subprocess.Popen(
            ["sudo", "-n", sys.executable, svc,
             "--window", str(window), "--iface", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"started": True, "window": window, "iface": iface}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/ids/status")
def ids_status():
    """يقرأ حالة شاشة الكشف الحيّة (اللحظة الحالية + السجلّ الدوّار)."""
    import json as _json
    try:
        with open("/tmp/live_ids_state.json", encoding="utf-8") as f:
            return _json.load(f)
    except FileNotFoundError:
        return {"running": False, "current": None, "log": [], "idle": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/ids/stop")
def ids_stop():
    """يوقف شاشة الكشف الحيّة عبر ملف إيقاف تتحقق منه الخدمة كل نافذة."""
    try:
        open("/tmp/live_ids_stop", "w").close()
        return {"stopping": True}
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/recommend")
def recommend(req: RecommendReq):
    """توصية نصية عبر Ollama (اختياري — يحتاج ollama serve)."""
    try:
        text = _ollama(
            f"أنت محلل أمن سيبراني خبير. {req.context} "
            "اكتب توصية أمنية عملية موجزة من سطرين إلى ثلاثة، بالعربية الفصحى "
            "فقط ودون أي كلمة أجنبية إطلاقًا، تبدأ بالإجراء الأهم وتكون محدّدة "
            "لنوع النشاط المرصود. بدون مقدمات ولا عناوين.")
        return {"recommendation": text}
    except Exception as e:
        return {"error": f"Ollama غير متاح: {e}"}


@app.get("/api/stream/flow")
def stream_flow(attack: str = ""):
    """
    يرجّع تدفقًا واحدًا للعرض الحي: إن حُدّد attack (مثل DDoS, PortScan)
    نختار منه، وإلا نختار طبيعيًا غالبًا. يحاكي 'وصول اتصال جديد'.
    """
    df = STATE["act_sample"]
    model = STATE["type_model"]["model"]
    feats = STATE["type_model"]["feature_names"]

    if attack and attack.upper() != "BENIGN":
        pool = df[df["family"].str.contains(attack, case=False, na=False)]
    else:
        pool = df[df["family"] == "BENIGN"]
    if len(pool) == 0:
        pool = df
    row = pool.sample(1).iloc[0]

    proba = model.predict_proba(row[feats].to_frame().T)[0]
    pred = str(model.classes_[proba.argmax()])
    return {
        "source_ip": str(row.get("source_ip", "—")),
        "dest_port": int(row.get("destination_port", 0)),
        "prediction": pred, "confidence": round(float(proba.max()), 3),
        "true_label": str(row["family"]),
        "is_attack": pred != "BENIGN",
    }


# ===================================================================
# المنصة متعددة المنشآت + المحلل الذكي — انظر tenancy/ و agent/
# ===================================================================
_AGENT = {}


def _agent_live():
    """بمفتاح Claude يعمل الوكيل الحقيقي، وبدونه وضع العرض التجريبي (agent/demo.py)."""
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def _agent_client():
    if "client" not in _AGENT:
        if _agent_live():
            import anthropic
            _AGENT["client"] = anthropic.Anthropic(timeout=60.0)
        else:
            from agent.demo import DemoClient
            _AGENT["client"] = DemoClient(delay=0.8)
    return _AGENT["client"]


def _agent_resources():
    if "res" not in _AGENT:
        from agent.tools import make_resources
        try:
            from train_final_lstm import ensemble_predict
        except Exception:
            ensemble_predict = None
        _AGENT["res"] = make_resources(STATE["type_model"], STATE["expl_baseline"],
                                       STATE.get("lstm_models"), STATE.get("lstm_meta"), ensemble_predict)
    return _AGENT["res"]


app.include_router(platform_router)
app.include_router(approval_pages)
app.include_router(monitor_router)


# خدمة الواجهة الساكنة (توضع لاحقًا بمجلد web/)
WEB = HERE / "web"
if WEB.is_dir():
    app.mount("/app", StaticFiles(directory=str(WEB), html=True), name="web")
