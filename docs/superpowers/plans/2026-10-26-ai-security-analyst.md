# خطة تنفيذ: المحلل الأمني الذكي

> **لمن ينفّذ:** نفّذ المهام بالترتيب، وخطوة خطوة. كل خطوة عليها مربع `- [ ]` تُعلَّم عند إنجازها. لا تنتقل لمهمة قبل أن تنجح اختباراتها.

- **الهدف:** وكيل Claude يحقق في الحادثة باستخدام طبقات النظام الحالية كأدوات، ويكتب تقريرًا عربيًا لصاحب المنشأة، ويقترح إجراءات تنتظر موافقته، ويجيب على أسئلته، مع تقييم علمي مقابل القواعد الثابتة.
- **مستند التصميم:** [2026-10-26-ai-security-analyst-design.md](../specs/2026-10-26-ai-security-analyst-design.md)
- **البنية:** مجلد `agent/` جديد يستورد الملفات الحالية ولا يغيّرها: `scenarios.py` (حوادث بحقيقة مخفية) ← `tools.py` (أدوات فوق الحادثة) ← `store.py` (حالة التحقيق وأحداثه) ← `analyst.py` (حلقة Claude) ← `evaluate.py` (التقييم). ثم نقاط وصول في `api_server.py` وصفحة في `web/`.
- **التقنيات:** Python 3.11، FastAPI، مكتبة `anthropic` (Messages API مع Tool Use)، pytest، JavaScript بلا مكتبات.

## قرارات تقنية ثابتة (من مرجع Claude API)

- **النموذج:** `claude-opus-5-5` افتراضيًا، قابل للتغيير بـ `ANTHROPIC_MODEL`. الجهد `medium` بـ `ANTHROPIC_EFFORT`. التفكير التكيفي يعمل تلقائيًا على Opus 5.5، فلا نرسل `thinking`.
- **إجبار أداة ممنوع:** `tool_choice` من نوع `any` أو `tool` يرجع 400 على Opus 5.5. نوجّه بالتعليمات، ونستخدم `strict: true` على كل الأدوات.
- **الرفض والبديل:** كل طلب يرسل `betas=["server-side-fallback-2026-07-01"]` و`fallbacks="default"` عبر `client.beta.messages.create`. ونتعامل مع `stop_reason == "refusal"` كخطأ.
- **سجل الرسائل إضافة فقط:** نضيف `response.content` كاملًا (بما فيه كتل التفكير) ولا نعدّل الرسائل السابقة أبدًا. السياق المتغير في المحادثة يُرسل داخل رسالة المستخدم الجديدة، لا في `system`.
- **حلقة يدوية لا Tool Runner:** نحتاج حدّ خطوات ووقت، وحدث خط زمني لكل خطوة، وعميلًا وهميًا في الاختبارات.
- **التخزين المؤقت:** `cache_control={"type": "ephemeral"}` على مستوى الطلب لتقليل تكلفة الجولات المتكررة.

## خريطة الملفات

| الملف | جديد/تعديل | المسؤولية |
|---|---|---|
| `agent/__init__.py` | جديد | فارغ |
| `agent/scenarios.py` | جديد | بناء الحوادث وفصل الحقيقة، ومجموعة التقييم (60) |
| `agent/tools.py` | جديد | `Resources` و`Workspace` والأدوات السبع وتعريفاتها، `decide`، `rules_proposals` |
| `agent/store.py` | جديد | `Run`: الأحداث والاستهلاك والحفظ في `agent_runs/` |
| `agent/analyst.py` | جديد | `investigate` و`run_investigation` و`chat` |
| `agent/evaluate.py` | جديد | المقاييس وتشغيل التقييم وكتابة النتائج |
| `tests/fakes.py` | جديد | عميل Claude وهمي وكتل الردود |
| `tests/conftest.py` | جديد | تحميل البيانات والنموذج مرة واحدة |
| `tests/test_scenarios.py` و`test_tools.py` و`test_analyst.py` و`test_evaluate.py` | جديد | الاختبارات |
| `api_server.py` | تعديل | تحميل `.env` ونقاط `/api/agent/*` |
| `web/index.html` و`style.css` و`app.js` | تعديل | صفحة «المحلل الذكي» |
| `.gitignore` و`.env.example` و`run.py` و`README.md` | تعديل/جديد | الإعداد والتوثيق |

## المتطلبات قبل البدء

- [ ] **التأكد من الفرع:**

```bash
cd /Users/S/Downloads/cyber/predictive-cyber && git branch --show-current
```

المتوقع: `ai-analyst`

- [ ] **التأكد من وجود النماذج وبيانات الكاش** (تُنتج بسكربتات التدريب و`prepare_dashboard_data.py`):

```bash
ls attack_type_model.joblib lstm_final_meta.joblib dashboard_cache/
```

المتوقع: الملفان، وداخل `dashboard_cache/` الملفات `act_sample.parquet` و`baseline_sample.parquet` و`lstm_windows.parquet`.

- [ ] **هوية git:** الـ commits أدناه تفترض أن `git config user.name` و`user.email` مضبوطان على الجهاز.

---

## المهمة 1: المكتبات والإعداد وأدوات الاختبار

**الملفات:** تعديل `.gitignore` و`run.py`، إنشاء `.env.example` و`agent/__init__.py` و`tests/fakes.py` و`tests/conftest.py`

- [ ] **الخطوة 1: تثبيت المكتبات**

```bash
project/bin/pip install anthropic python-dotenv pytest
project/bin/python -c "import anthropic, dotenv, pytest; print(anthropic.__version__)"
```

المتوقع: رقم إصدار بلا أخطاء.

- [ ] **الخطوة 2: إضافة المكتبات لأمر الإعداد في `run.py`**

في قاموس `COMMANDS` تحت `"setup"`، أضف إلى نهاية قائمة الحزم بعد `"kagglehub", "nids_datasets"`:

```python
                         "kagglehub", "nids_datasets",
                         "anthropic", "python-dotenv", "pytest"]]),
```

- [ ] **الخطوة 3: استثناء مخرجات الوكيل من git** بإضافة سطرين إلى نهاية `.gitignore`:

```
agent_runs/
eval_results/
```

- [ ] **الخطوة 4: إنشاء `.env.example`**

```
# انسخ هذا الملف إلى .env وضع مفتاحك. ملف .env مستثنى من git.
ANTHROPIC_API_KEY=
# ANTHROPIC_MODEL=claude-opus-5-5
# ANTHROPIC_EFFORT=medium
```

- [ ] **الخطوة 5: إنشاء `agent/__init__.py`** فارغًا.

- [ ] **الخطوة 6: إنشاء `tests/fakes.py`**

```python
"""عميل Claude وهمي للاختبارات: يرجّع ردودًا مكتوبة مسبقًا ويسجّل الطلبات."""

import itertools
from types import SimpleNamespace

_ids = itertools.count(1)


def block(type_, **fields):
    return SimpleNamespace(type=type_, **fields)


def tool_use(name, input=None):
    return block("tool_use", name=name, input=input or {}, id=f"toolu_{next(_ids)}")


def reply(*blocks, stop=None):
    if stop is None:
        stop = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
    usage = SimpleNamespace(input_tokens=100, output_tokens=20,
                            cache_read_input_tokens=0, cache_creation_input_tokens=0)
    return SimpleNamespace(content=list(blocks), stop_reason=stop, usage=usage)


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self.replies.pop(0)


REPORT = {
    "severity": "high",
    "summary_owner": "رصدنا جهازًا خارجيًا يفحص منافذ أجهزتك بحثًا عن ثغرة.",
    "attack_types": ["PortScan"],
    "findings": [{"source_ip": "172.16.0.1", "assessment": "فحص منافذ",
                  "evidence": ["301 اتصال مصنّف فحص منافذ"]}],
    "proposal_ids": [1],
    "watch_next": "راقب محاولات الدخول على المنافذ المفتوحة",
    "confidence": 0.9,
}
```

- [ ] **الخطوة 7: إنشاء `tests/conftest.py`**

```python
import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CACHE = ROOT / "dashboard_cache"


@pytest.fixture(scope="session")
def data():
    if not (CACHE / "act_sample.parquet").exists():
        pytest.skip("شغّل prepare_dashboard_data.py أولًا")
    return (pd.read_parquet(CACHE / "act_sample.parquet"),
            pd.read_parquet(CACHE / "lstm_windows.parquet"))


@pytest.fixture(scope="session")
def resources(data):
    """موارد حقيقية لنموذج الكشف، وتنبؤ ثابت بدل LSTM (حتى لا تحمّل الاختبارات TensorFlow)."""
    from explain_decision import compute_baseline_stats
    from agent.tools import Resources
    tm = joblib.load(ROOT / "attack_type_model.joblib")
    act, windows = data
    benign = act[act["family"] == "BENIGN"]
    cols = [c for c in windows.columns if c not in ("attack_flows", "attack_next_window")]
    return Resources(model=tm["model"], feature_names=tm["feature_names"],
                     baseline=compute_baseline_stats(benign, tm["feature_names"]),
                     forecast_fn=lambda values: 0.5, forecast_cols=cols, threshold=0.1)


@pytest.fixture
def portscan(data):
    from agent.scenarios import build_incident
    return build_incident(*data, "PortScan", seed=1)
```

- [ ] **الخطوة 8: Commit**

```bash
git add .gitignore run.py .env.example agent/__init__.py tests/fakes.py tests/conftest.py
git commit -m "Set up agent package, dependencies, and test helpers"
```

---

## المهمة 2: السيناريوهات وفصل الحقيقة (`agent/scenarios.py`)

**الملفات:** إنشاء `agent/scenarios.py` و`tests/test_scenarios.py`

- [ ] **الخطوة 1: كتابة الاختبارات الفاشلة** في `tests/test_scenarios.py`

```python
import pandas as pd

from agent.scenarios import (N_ATTACK, N_ATTACK_LOW, N_BENIGN, SEQ_LEN, TRUTH_COLS,
                             WINDOW_TRUTH_COLS, build_incident, evaluation_suite)


def test_same_seed_same_incident(data):
    a = build_incident(*data, "DoS", seed=5)
    b = build_incident(*data, "DoS", seed=5)
    assert a.id == b.id and a.truth == b.truth
    pd.testing.assert_frame_equal(a.observed, b.observed)
    pd.testing.assert_frame_equal(a.windows, b.windows)


def test_observed_and_windows_hide_truth(portscan):
    assert not set(TRUTH_COLS) & set(portscan.observed.columns)
    assert not set(WINDOW_TRUTH_COLS) & set(portscan.windows.columns)
    assert len(portscan.windows) == SEQ_LEN


def test_attack_incident_truth(portscan):
    attackers = {ip: t for ip, t in portscan.truth.items() if t["attack_ratio"] >= 0.5}
    assert attackers and all(t["family"] == "PortScan" for t in attackers.values())
    assert len(portscan.observed) == N_BENIGN + N_ATTACK
    assert portscan.kind == "attack"


def test_benign_incident_has_no_attackers(data):
    inc = build_incident(*data, "BENIGN", seed=3)
    assert inc.kind == "benign"
    assert all(t["attack_ratio"] == 0 for t in inc.truth.values())


def test_low_volume_incident(data):
    inc = build_incident(*data, "DDoS", seed=2, low_volume=True)
    assert inc.kind == "attack_low" and len(inc.observed) == N_BENIGN + N_ATTACK_LOW


def test_evaluation_suite_composition(data):
    suite = evaluation_suite(*data)
    kinds = [i.kind for i in suite]
    assert len(suite) == 60 and len({i.id for i in suite}) == 60
    assert kinds.count("attack") == 36 and kinds.count("attack_low") == 12
    assert kinds.count("benign") == 12
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_scenarios.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'agent.scenarios'`

- [ ] **الخطوة 3: كتابة `agent/scenarios.py`**

```python
"""
===================================================================
سيناريوهات المحلل الذكي — حوادث من بيانات CICIDS بحقيقة معروفة
===================================================================
الحادثة = نافذة مراقبة (~1500 اتصال): ترافيك طبيعي + هجوم من نوع واحد
(أو بلا هجوم). لكل حادثة جزآن:
  observed / windows  ما تراه أدوات الوكيل (حُذفت منها أعمدة الحقيقة)
  truth               نوع كل مصدر ونسبة اتصالاته الهجومية — للتقييم فقط
سياق التنبؤ (10 نوافذ زمنية) مطابق لنوع السيناريو، لكنه ليس من نفس
الاتصالات زمنيًا؛ هذا قيد معلن في مستند التصميم.
===================================================================
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

ATTACK_FAMILIES = ["PortScan", "DoS", "DDoS", "Brute Force (FTP/SSH)", "Web Attack", "Botnet"]
TRUTH_COLS = ["family", "attack_label", "Label"]
WINDOW_TRUTH_COLS = ["attack_flows", "attack_next_window"]
N_BENIGN = 1200
N_ATTACK = 300
N_ATTACK_LOW = 20       # حالة صعبة: هجوم بحجم صغير
SEQ_LEN = 10


@dataclass
class Incident:
    id: str
    kind: str               # attack | attack_low | benign
    family: str             # النوع الحقيقي، أو BENIGN
    observed: pd.DataFrame
    windows: pd.DataFrame
    truth: dict             # source_ip -> {"attack_ratio": float, "family": str}


def _source_truth(flows):
    is_attack = flows["family"] != "BENIGN"
    ratio = is_attack.groupby(flows["source_ip"]).mean()
    fam = flows[is_attack].groupby("source_ip")["family"].agg(lambda s: s.value_counts().index[0])
    return {ip: {"attack_ratio": round(float(r), 3), "family": fam.get(ip, "BENIGN")}
            for ip, r in ratio.items()}


def _pick_windows(windows, attack_next, rng):
    ends = np.arange(SEQ_LEN, len(windows))
    last = ends - 1
    target = windows["attack_next_window"].values[last]
    if attack_next:
        ok = target == 1
    else:
        ok = (target == 0) & (windows["attack_flows"].values[last] == 0)
    end = int(rng.choice(ends[ok]))
    return windows.iloc[end - SEQ_LEN:end].drop(columns=WINDOW_TRUTH_COLS)


def build_incident(act_sample, windows, family, seed, low_volume=False):
    rng = np.random.default_rng(seed)
    parts = [act_sample[act_sample["family"] == "BENIGN"].sample(N_BENIGN, random_state=seed)]
    if family != "BENIGN":
        pool = act_sample[act_sample["family"] == family]
        n = N_ATTACK_LOW if low_volume else N_ATTACK
        parts.append(pool.sample(min(n, len(pool)), random_state=seed))
    flows = pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)
    kind = "benign" if family == "BENIGN" else ("attack_low" if low_volume else "attack")
    return Incident(
        id=f"{kind}-{family.split()[0].lower()}-{seed}",
        kind=kind,
        family=family,
        observed=flows.drop(columns=[c for c in TRUTH_COLS if c in flows.columns]),
        windows=_pick_windows(windows, family != "BENIGN", rng),
        truth=_source_truth(flows),
    )


def evaluation_suite(act_sample, windows, seed=2026):
    """60 سيناريو ثابتًا: لكل نوع 6 عادية + 2 منخفضة الحجم، ثم 12 طبيعيًا."""
    incidents, s = [], seed
    for fam in ATTACK_FAMILIES:
        for i in range(8):
            incidents.append(build_incident(act_sample, windows, fam, s, low_volume=i >= 6))
            s += 1
    for _ in range(12):
        incidents.append(build_incident(act_sample, windows, "BENIGN", s))
        s += 1
    return incidents
```

- [ ] **الخطوة 4: التأكد من النجاح**

```bash
project/bin/python -m pytest tests/test_scenarios.py -q
```

المتوقع: `6 passed`

- [ ] **الخطوة 5: Commit**

```bash
git add agent/scenarios.py tests/test_scenarios.py
git commit -m "Add agent scenarios with hidden ground truth"
```

---

## المهمة 3: الأدوات والحواجز (`agent/tools.py`)

**الملفات:** إنشاء `agent/tools.py` و`tests/test_tools.py`

- [ ] **الخطوة 1: كتابة الاختبارات الفاشلة** في `tests/test_tools.py`

```python
import json

import pytest

from agent.tools import (TOOL_SPECS, ToolError, Workspace, check_policy, decide,
                         rules_proposals, run_tool)

TRUTH_KEYS = {"family", "attack_label", "Label", "attack_flows", "attack_next_window"}


def _keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _keys(v)


@pytest.fixture
def ws(resources, portscan):
    return Workspace(portscan, resources)


def attacker(ws):
    return next(iter(ws.sources))      # المصدر الأكثر اتصالات هجومية (172.16.0.1)


def test_read_tools_return_plain_json_without_truth(ws):
    ip = attacker(ws)
    for name, args in [("incident_overview", {}), ("suspicious_sources", {}),
                       ("explain_source", {"source_ip": ip}), ("forecast_next_minute", {}),
                       ("check_policy", {"source_ip": ip})]:
        out = run_tool(ws, name, args)
        json.dumps(out)                                  # يفشل لو بقيت أنواع numpy
        assert not TRUTH_KEYS & set(_keys(out)), name


def test_all_tools_are_strict():
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in TOOL_SPECS)


def test_unknown_source_is_tool_error(ws):
    with pytest.raises(ToolError):
        run_tool(ws, "explain_source", {"source_ip": "1.2.3.4"})


def test_non_suspicious_source_is_capped_at_monitor(ws):
    ip = next(i for i in ws.flows["source_ip"].unique() if i not in ws.sources)
    assert check_policy(ws, ip)["max_action"] == "monitor"


def test_propose_cannot_escalate_beyond_policy(ws):
    ip = attacker(ws)
    assert check_policy(ws, ip)["max_action"] == "block_ip"
    out = run_tool(ws, "propose_action", {"source_ip": ip, "action": "quarantine_host", "justification": "x"})
    assert out["accepted"] is False and ws.proposals == {}


def test_propose_registers_pending_without_applying(ws):
    out = run_tool(ws, "propose_action", {"source_ip": attacker(ws), "action": "block_ip", "justification": "x"})
    assert out["accepted"] and ws.proposals[out["proposal_id"]].status == "pending"
    assert ws.firewall.rules == []


def test_duplicate_pending_proposal_is_refused(ws):
    args = {"source_ip": attacker(ws), "action": "block_ip", "justification": "x"}
    run_tool(ws, "propose_action", args)
    assert run_tool(ws, "propose_action", args)["accepted"] is False


def test_approve_applies_and_reject_rejects(ws):
    ip = attacker(ws)
    pid = run_tool(ws, "propose_action", {"source_ip": ip, "action": "block_ip", "justification": "x"})["proposal_id"]
    assert decide(ws, pid, "approve")["status"] == "applied" and len(ws.firewall.rules) == 1
    assert decide(ws, pid, "approve")["status"] == "applied"          # لا تنفيذ مزدوج
    other = run_tool(ws, "propose_action", {"source_ip": ip, "action": "monitor", "justification": "y"})
    assert other["accepted"] is True
    assert decide(ws, other["proposal_id"], "reject")["status"] == "rejected"


def test_allowlist_is_enforced_at_execution(ws):
    ip = attacker(ws)
    pid = run_tool(ws, "propose_action", {"source_ip": ip, "action": "block_ip", "justification": "x"})["proposal_id"]
    ws.firewall.allowlist.add(ip)
    assert decide(ws, pid, "approve")["status"] == "refused"
    assert ws.firewall.rules == []


def test_rules_proposals_match_static_policy(ws):
    props = rules_proposals(ws)
    assert props and all(p.status == "pending" for p in props)
    assert next(p for p in props if p.source_ip == attacker(ws)).action == "block_ip"
```

ملاحظة: في `test_approve_applies_and_reject_rejects` المقترح الثاني لنفس المصدر يُقبل لأن الأول لم يعد معلّقًا (طُبّق).

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_tools.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'agent.tools'`

- [ ] **الخطوة 3: كتابة `agent/tools.py`**

```python
"""
===================================================================
أدوات المحلل الذكي — تغليف طبقات النظام الحالية كأدوات للوكيل
===================================================================
الوكيل لا يملك نماذج خاصة به: كل أداة تستدعي طبقة موجودة
(Random Forest، التفسير، مجموعة LSTM، سياسة الجدار المحاكى) وترجع
JSON مختصرًا. الأدوات ترى جزء observed من الحادثة فقط.

حاجز عدم التصعيد: لا يُقبل مقترح أشد من ناتج decide_action، ويُعاد
التحقق عند التنفيذ. الوكيل يقترح فقط؛ التنفيذ عبر decide() بقرار بشري.
===================================================================
"""

import math
from dataclasses import dataclass
from typing import Callable

from act_demo import aggregate_by_source
from explain_decision import explain_row
from sandbox_firewall import Proposal, SimulatedFirewall, decide_action

from agent.scenarios import ATTACK_FAMILIES

MAX_SOURCES = 10
SEVERITY = {"none": 0, "monitor": 1, "rate_limit_target": 2, "block_ip": 3, "quarantine_host": 4}
ENFORCING = ("rate_limit_target", "block_ip", "quarantine_host")
ACTION_AR = {"none": "لا إجراء", "monitor": "مراقبة", "rate_limit_target": "تحديد معدل الهدف",
             "block_ip": "حظر العنوان", "quarantine_host": "عزل الجهاز"}


class ToolError(Exception):
    """خطأ متوقع في أداة؛ يُرجع للوكيل نصًا ليصحح نفسه."""


@dataclass
class Resources:
    model: object
    feature_names: list
    baseline: dict
    forecast_fn: Callable
    forecast_cols: list
    threshold: float


def make_resources(type_model, baseline, lstm_models, lstm_meta, ensemble_predict):
    if lstm_models is None or ensemble_predict is None:
        def forecast_fn(_values):
            raise ToolError("نماذج التنبؤ غير محمّلة على هذا الخادم")
        cols, thr = [], 0.0
    else:
        def forecast_fn(values):
            return ensemble_predict(lstm_models, lstm_meta, values)
        cols, thr = lstm_meta["feature_cols"], float(lstm_meta["threshold_recall"])
    return Resources(type_model["model"], type_model["feature_names"], baseline, forecast_fn, cols, thr)


class Workspace:
    """حادثة واحدة: تنبؤات النموذج محسوبة مرة واحدة + المقترحات + الجدار المحاكى."""

    def __init__(self, incident, res, firewall=None):
        self.incident, self.res = incident, res
        obs = incident.observed
        proba = res.model.predict_proba(obs[res.feature_names])
        self.flows = obs.assign(pred=res.model.classes_[proba.argmax(axis=1)], conf=proba.max(axis=1))
        self.sources = {s["source_ip"]: s for s in aggregate_by_source(self.flows)}
        self.firewall = firewall or SimulatedFirewall()
        self.proposals = {}


# ===================================================================
# الأدوات
# ===================================================================
def incident_overview(ws):
    f = ws.flows
    return {
        "total_flows": len(f),
        "unique_sources": int(f["source_ip"].nunique()),
        "unique_destinations": int(f["destination_ip"].nunique()),
        "flows_flagged_as_attack": int((f["pred"] != "BENIGN").sum()),
        "predicted_classes": {str(k): int(v) for k, v in f["pred"].value_counts().items()},
    }


def suspicious_sources(ws):
    return {"sources": [{
        "source_ip": s["source_ip"],
        "predicted_type": s["attack_type"],
        "flagged_flows": int(s["n_flows"]),
        "attack_ratio": round(float(s["attack_ratio"]), 2),
        "mean_confidence": round(float(s["mean_confidence"]), 2),
        "top_target": s["top_target"],
    } for s in list(ws.sources.values())[:MAX_SOURCES]]}


def _known_source(ws, source_ip):
    if source_ip not in set(ws.flows["source_ip"]):
        raise ToolError(f"العنوان {source_ip} غير موجود في هذه الحادثة")


def explain_source(ws, source_ip):
    _known_source(ws, source_ip)
    rows = ws.flows[(ws.flows["source_ip"] == source_ip) & (ws.flows["pred"] != "BENIGN")]
    if rows.empty:
        raise ToolError(f"النموذج لم يصنّف أي اتصال من {source_ip} كهجوم")
    mean_row = rows[ws.res.feature_names].astype(float).mean()
    expl = explain_row(ws.res.model, mean_row, ws.res.feature_names, ws.res.baseline, top_n=5)
    return {"source_ip": source_ip, "flows_explained": len(rows), "top_features": [{
        "feature": e["feature"],
        "mean_z": round(e["z_score"], 2) if math.isfinite(e["z_score"]) else None,
        "direction": e["direction"],
    } for e in expl]}


def forecast_next_minute(ws):
    w = ws.incident.windows
    p = float(ws.res.forecast_fn(w[ws.res.forecast_cols].values))
    return {"probability": round(p, 3), "threshold": round(ws.res.threshold, 3),
            "alert": p >= ws.res.threshold,
            "total_flows_per_minute": [int(v) for v in w["total_flows"]]}


def check_policy(ws, source_ip):
    _known_source(ws, source_ip)
    s = ws.sources.get(source_ip)
    if s is None:
        return {"source_ip": source_ip, "max_action": "monitor", "duration_min": 0,
                "reasons": ["النموذج لم يصنّف هذا المصدر مشبوهًا"]}
    p = decide_action(s, 0, tuple(ws.firewall.allowlist))
    return {"source_ip": source_ip, "predicted_type": p.attack_type, "max_action": p.action,
            "duration_min": p.duration_min, "reasons": p.reasons}


def _register(ws, source_ip, action, duration, reasons):
    s = ws.sources.get(source_ip, {})
    p = Proposal(id=len(ws.proposals) + 1, source_ip=source_ip,
                 attack_type=s.get("attack_type", "BENIGN"), action=action, duration_min=duration,
                 n_flows=int(s.get("n_flows", 0)), attack_ratio=float(s.get("attack_ratio", 0.0)),
                 mean_confidence=float(s.get("mean_confidence", 0.0)),
                 target=s.get("top_target", ""), reasons=reasons)
    ws.proposals[p.id] = p
    return p


def propose_action(ws, source_ip, action, justification):
    if action not in SEVERITY:
        raise ToolError(f"إجراء غير معروف: {action}")
    for p in ws.proposals.values():
        if p.source_ip == source_ip and p.status == "pending":
            return {"accepted": False, "proposal_id": p.id, "reason": "يوجد مقترح معلّق لنفس المصدر"}
    policy = check_policy(ws, source_ip)
    if SEVERITY[action] > SEVERITY[policy["max_action"]]:
        return {"accepted": False,
                "reason": f"الإجراء {action} أشد من الحد المسموح ({policy['max_action']})",
                "policy_reasons": policy["reasons"]}
    duration = 0 if action in ("none", "monitor") else policy["duration_min"]
    p = _register(ws, source_ip, action, duration, [justification])
    return {"accepted": True, "proposal_id": p.id, "status": p.status}


def rules_proposals(ws):
    """سلوك القواعد الثابتة (/api/respond): بديل عند فشل الوكيل، وخط أساس للتقييم."""
    taken = {p.source_ip for p in ws.proposals.values()}
    out = []
    for s in ws.sources.values():
        if s["source_ip"] in taken:
            continue
        d = decide_action(s, 0, tuple(ws.firewall.allowlist))
        out.append(_register(ws, s["source_ip"], d.action, d.duration_min, d.reasons))
    return out


def decide(ws, proposal_id, decision):
    """قرار صاحب المنشأة على مقترح. يعيد فحص الحاجز قبل التنفيذ."""
    p = ws.proposals.get(proposal_id)
    if p is None:
        raise ToolError(f"لا يوجد مقترح رقم {proposal_id}")
    if p.status != "pending":
        return {"proposal_id": p.id, "status": p.status, "note": "تم البت في هذا المقترح مسبقًا"}
    if decision == "reject":
        ws.firewall.reject(p, "owner")
    elif SEVERITY[p.action] > SEVERITY[check_policy(ws, p.source_ip)["max_action"]]:
        p.status = "refused"
        return {"proposal_id": p.id, "status": p.status, "note": "مرفوض: الإجراء أشد مما تسمح به السياسة الآن"}
    elif ws.firewall.is_covered(p):
        ws.firewall.mark_covered(p)
    else:
        ws.firewall.apply(p, "owner")
    return {"proposal_id": p.id, "status": p.status, "note": ws.firewall.log[-1]["note"]}


# ===================================================================
# تعريفات الأدوات لـ Claude
# ===================================================================
def _obj(props, required):
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


_IP = {"type": "string", "description": "عنوان IP للمصدر كما ورد في نتائج الأدوات"}

REPORT_SCHEMA = _obj({
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
    "summary_owner": {"type": "string", "description": "ملخص عربي من 3 إلى 5 جمل بلا مصطلحات تقنية"},
    "attack_types": {"type": "array", "items": {"type": "string", "enum": ATTACK_FAMILIES}},
    "findings": {"type": "array", "items": _obj({
        "source_ip": {"type": "string"},
        "assessment": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
    }, ["source_ip", "assessment", "evidence"])},
    "proposal_ids": {"type": "array", "items": {"type": "integer"}},
    "watch_next": {"type": "string"},
    "confidence": {"type": "number", "description": "بين 0 و1"},
}, ["severity", "summary_owner", "attack_types", "findings", "proposal_ids", "watch_next", "confidence"])

TOOL_SPECS = [
    {"name": "incident_overview",
     "description": "نظرة عامة على نافذة المراقبة: عدد الاتصالات والمصادر وتوزيع تصنيفات نموذج الكشف.",
     "input_schema": _obj({}, [])},
    {"name": "suspicious_sources",
     "description": "المصادر التي صنّف النموذج بعض اتصالاتها هجومًا، مرتبة بعدد الاتصالات الهجومية.",
     "input_schema": _obj({}, [])},
    {"name": "explain_source",
     "description": "أبرز الخصائص الشبكية التي تنحرف فيها اتصالات مصدر مشبوه عن السلوك الطبيعي (متوسط z).",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "forecast_next_minute",
     "description": "احتمال بداية هجوم في الدقيقة التالية من ترافيك آخر 10 دقائق (مجموعة نماذج LSTM).",
     "input_schema": _obj({}, [])},
    {"name": "check_policy",
     "description": "أقصى إجراء تسمح به سياسة الأمان لهذا المصدر، وأسباب أي تخفيف (ضعف الدليل، قائمة السماح).",
     "input_schema": _obj({"source_ip": _IP}, ["source_ip"])},
    {"name": "propose_action",
     "description": "يسجّل مقترح إجراء معلّقًا ينتظر موافقة صاحب المنشأة. لا ينفّذ شيئًا. يُرفض أي إجراء أشد من check_policy.",
     "input_schema": _obj({
         "source_ip": _IP,
         "action": {"type": "string", "enum": list(SEVERITY)},
         "justification": {"type": "string", "description": "سبب مختصر بالعربية"},
     }, ["source_ip", "action", "justification"])},
    {"name": "submit_report",
     "description": "ينهي التحقيق بتقرير لصاحب المنشأة. استدعِه مرة واحدة في النهاية.",
     "input_schema": REPORT_SCHEMA},
]
for _spec in TOOL_SPECS:
    _spec["strict"] = True

READ_TOOLS = ("incident_overview", "suspicious_sources", "explain_source",
              "forecast_next_minute", "check_policy")
_FUNCS = {
    "incident_overview": incident_overview, "suspicious_sources": suspicious_sources,
    "explain_source": explain_source, "forecast_next_minute": forecast_next_minute,
    "check_policy": check_policy, "propose_action": propose_action,
}


def run_tool(ws, name, args):
    fn = _FUNCS.get(name)
    if fn is None:
        raise ToolError(f"أداة غير معروفة: {name}")
    return fn(ws, **args)


def describe(name, args, result):
    """جملة عربية قصيرة للخط الزمني في الواجهة."""
    if "error" in result:
        return f"تعذّر تنفيذ {name}: {result['error']}"
    if name == "incident_overview":
        return (f"فحصتُ {result['total_flows']:,} اتصالًا من {result['unique_sources']} مصدرًا؛ "
                f"النموذج علّم {result['flows_flagged_as_attack']:,} منها كهجوم")
    if name == "suspicious_sources":
        src = result["sources"]
        return "لم أجد مصادر مشبوهة" if not src else f"وجدتُ {len(src)} من المصادر المشبوهة، أبرزها {src[0]['source_ip']}"
    if name == "explain_source":
        top = result["top_features"][0]
        return f"حلّلتُ سلوك {result['source_ip']}: أبرز مؤشر {top['feature']} ({top['direction']})"
    if name == "forecast_next_minute":
        return f"احتمال هجوم في الدقيقة التالية {result['probability']:.0%} مقابل عتبة {result['threshold']:.0%}"
    if name == "check_policy":
        return f"السياسة تسمح لـ {result['source_ip']} بحد أقصى: {ACTION_AR[result['max_action']]}"
    if name == "propose_action":
        if result["accepted"]:
            return f"اقترحتُ {ACTION_AR[args['action']]} على {args['source_ip']} — بانتظار موافقتك"
        return f"لم يُقبل مقترحي على {args['source_ip']}: {result['reason']}"
    return name
```

- [ ] **الخطوة 4: التأكد من النجاح**

```bash
project/bin/python -m pytest tests/test_tools.py -q
```

المتوقع: `10 passed`

- [ ] **الخطوة 5: Commit**

```bash
git add agent/tools.py tests/test_tools.py
git commit -m "Add agent tools over existing detection, forecast, and policy layers"
```

---

## المهمة 4: حالة التحقيق وحلقة الوكيل (`agent/store.py` و`agent/analyst.py`)

**الملفات:** إنشاء `agent/store.py` و`agent/analyst.py` و`tests/test_analyst.py`

- [ ] **الخطوة 1: كتابة اختبارات التحقيق الفاشلة** في `tests/test_analyst.py`

```python
import pytest
from fakes import REPORT, FakeClient, block, reply, tool_use

from agent.analyst import FALLBACK_BETA, MAX_STEPS, MODEL, run_investigation
from agent.store import Run
from agent.tools import Workspace


@pytest.fixture
def setup(resources, portscan, tmp_path):
    ws = Workspace(portscan, resources)
    return ws, Run(portscan, ws, save_dir=tmp_path)


def test_investigation_streams_steps_then_report(setup, tmp_path):
    ws, run = setup
    client = FakeClient([reply(tool_use("incident_overview")),
                         reply(tool_use("suspicious_sources")),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert [e["type"] for e in run.events] == ["step", "step", "report", "done"]
    assert run.status == "done" and run.report["severity"] == "high"
    assert run.events[-1]["truth_family"] == "PortScan"
    assert (tmp_path / f"{run.incident.id}.json").exists()


def test_request_shape(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    kw = client.calls[0]
    assert kw["model"] == MODEL and kw["fallbacks"] == "default" and FALLBACK_BETA in kw["betas"]
    assert "tool_choice" not in kw and "thinking" not in kw
    assert all(t["strict"] for t in kw["tools"])


def test_tool_error_does_not_stop_investigation(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("explain_source", {"source_ip": "1.2.3.4"})),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert run.events[0]["is_error"] and "غير موجود" in run.events[0]["result"]["error"]
    assert run.status == "done"


def test_step_limit_turns_tools_into_errors(setup):
    ws, run = setup
    client = FakeClient([reply(tool_use("incident_overview")) for _ in range(MAX_STEPS + 1)]
                        + [reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert sum(e["type"] == "step" for e in run.events) == MAX_STEPS
    results = [m["content"][0] for m in client.calls[-1]["messages"]
               if m["role"] == "user" and isinstance(m["content"], list)]
    assert results[MAX_STEPS - 1]["is_error"] is False
    assert results[MAX_STEPS]["is_error"] is True
    assert run.status == "done"


def test_text_only_reply_is_reprompted(setup):
    ws, run = setup
    client = FakeClient([reply(block("text", text="انتهيت")),
                         reply(tool_use("submit_report", REPORT))])
    run_investigation(client, ws, run)
    assert "submit_report" in client.calls[-1]["messages"][2]["content"]
    assert run.status == "done"


def test_refusal_falls_back_to_rules(setup):
    ws, run = setup
    run_investigation(FakeClient([reply(stop="refusal")]), ws, run)
    err = next(e for e in run.events if e["type"] == "agent_error")
    assert run.status == "failed" and err["proposals"]
    assert run.events[-1]["type"] == "done"
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_analyst.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'agent.analyst'`

- [ ] **الخطوة 3: كتابة `agent/store.py`**

```python
"""
حالة تحقيق واحد: أحداث الخط الزمني (step/report/agent_error/done)،
الاستهلاك، والحفظ في agent_runs/ كسجل تدقيق. آمنة بين الخيوط: خيط
التحقيق يكتب الأحداث، وطلب SSE ينتظرها بـ wait_events.
"""

import json
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "agent_runs"


class Run:
    def __init__(self, incident, ws, save_dir=RUNS_DIR):
        self.incident, self.ws, self.save_dir = incident, ws, Path(save_dir)
        self.events, self.report, self.status = [], None, "running"
        self.usage = {"input_tokens": 0, "output_tokens": 0,
                      "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
        self.started, self.seconds = time.time(), None
        self.chat_messages, self.chat_log = [], []
        self._cond = threading.Condition()

    def emit(self, type_, **data):
        with self._cond:
            self.events.append({"type": type_, **data})
            self._cond.notify_all()

    def wait_events(self, start, timeout):
        with self._cond:
            self._cond.wait_for(lambda: len(self.events) > start, timeout=timeout)
            return self.events[start:]

    def add_usage(self, usage):
        for k in self.usage:
            self.usage[k] += getattr(usage, k, 0) or 0

    def finish(self, status):
        self.status = status
        self.seconds = round(time.time() - self.started, 1)

    def to_dict(self):
        from dataclasses import asdict
        return {
            "incident_id": self.incident.id, "kind": self.incident.kind, "family": self.incident.family,
            "status": self.status, "seconds": self.seconds, "usage": self.usage,
            "events": self.events, "report": self.report,
            "proposals": [asdict(p) for p in self.ws.proposals.values()],
            "decisions": self.ws.firewall.log, "chat": self.chat_log,
        }

    def save(self):
        self.save_dir.mkdir(parents=True, exist_ok=True)
        path = self.save_dir / f"{self.incident.id}.json"
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8")
```

- [ ] **الخطوة 4: كتابة `agent/analyst.py`** (التحقيق والمحادثة معًا؛ اختبارات المحادثة في المهمة 5)

```python
"""
===================================================================
المحلل الأمني الذكي — حلقة وكيل Claude (Tool Use)
===================================================================
  investigate / run_investigation  تحقيق تلقائي ينتهي بـ submit_report
  chat                             أسئلة صاحب المنشأة، بأدوات القراءة فقط

حلقة يدوية لا Tool Runner: نحتاج حد خطوات ووقت، حدثًا لكل خطوة، وعميلًا
وهميًا في الاختبارات. لا نجبر أداة عبر tool_choice (غير مدعوم على
Opus 5.5)؛ بعد الحد تُرجع الأدوات خطأً يطلب كتابة التقرير.
السجل إضافة فقط: نضيف response.content كاملًا ولا نعدّل ما سبق.
===================================================================
"""

import json
import os
import time

import anthropic

from agent.tools import READ_TOOLS, TOOL_SPECS, ToolError, describe, rules_proposals, run_tool

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")
EFFORT = os.environ.get("ANTHROPIC_EFFORT", "medium")
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_STEPS = 12
MAX_SECONDS = 90
GRACE_TURNS = 2
CHAT_MAX_STEPS = 6
CHAT_TOOLS = [t for t in TOOL_SPECS if t["name"] in READ_TOOLS]

SYSTEM_INVESTIGATE = """أنت محلل أمن سيبراني يعمل لدى منشأة صغيرة لا تملك فريقًا أمنيًا. وصلك تنبيه عن نافذة مراقبة من ترافيك شبكتها، ومهمتك التحقيق فيه بالأدوات المتاحة ثم كتابة تقرير لصاحب المنشأة.

طريقة العمل:
- ابدأ بـ incident_overview ثم suspicious_sources.
- افحص أهم المصادر المشبوهة بـ explain_source، واستخدم forecast_next_minute لتقدير ما سيحدث بعد قليل.
- قبل أي اقتراح، استدعِ check_policy للمصدر. اقترح عبر propose_action إجراءً لكل مصدر يستحقه، ويمكنك اختيار إجراء أخف من الحد الأقصى إذا كان الدليل ضعيفًا (ثقة أو نسبة هجوم منخفضة، أو اتصالات قليلة). المصادر التي علّم النموذج اتصالًا أو اتصالين منها فقط غالبًا أخطاء تصنيف فردية.
- إذا لم تجد ما يستدعي القلق، قل ذلك بوضوح ولا تقترح إجراءات.
- أنهِ دائمًا باستدعاء submit_report مرة واحدة.

قواعد التقرير:
- استند إلى نتائج الأدوات فقط. لا تذكر عنوانًا أو رقمًا لم يرد فيها.
- summary_owner لصاحب منشأة غير تقني: ماذا حدث، وهل الخطر قائم، وماذا ينتظر منه. بلا مصطلحات تقنية.
- attack_types من أسماء predicted_type كما وردت، وتبقى فارغة إذا لم يوجد هجوم.
- evidence أرقام ووقائع من نتائج الأدوات."""

SYSTEM_CHAT = """أنت المحلل الأمني نفسه الذي حقق في الحادثة، وتجيب الآن على أسئلة صاحب المنشأة. أجب بالعربية البسيطة باختصار (من 3 إلى 6 جمل). استند إلى السياق المرفق ونتائج الأدوات فقط، وإذا لم تعرف فقل ذلك. لا تستطيع تنفيذ أي إجراء أو الموافقة عليه: القرار لصاحب المنشأة عبر أزرار الموافقة في الصفحة."""


class AgentError(Exception):
    """فشل لا يُكمل معه التحقيق (رفض، أو انتهاء بلا تقرير)."""


def proposal_public(p):
    return {"id": p.id, "source_ip": p.source_ip, "attack_type": p.attack_type, "action": p.action,
            "duration_min": p.duration_min, "status": p.status, "reasons": p.reasons}


def _call(client, model, system, tools, messages):
    return client.beta.messages.create(
        model=model, max_tokens=16000, system=system, tools=tools, messages=messages,
        output_config={"effort": EFFORT}, cache_control={"type": "ephemeral"},
        betas=[FALLBACK_BETA], fallbacks="default",
    )


def _execute(ws, b):
    try:
        return run_tool(ws, b.name, b.input), False
    except ToolError as e:
        return {"error": str(e)}, True
    except Exception as e:      # خطأ غير متوقع في أداة لا يوقف التحقيق
        return {"error": f"خطأ داخلي في الأداة: {e}"}, True


def _tool_result(b, result, is_error):
    return {"type": "tool_result", "tool_use_id": b.id, "is_error": is_error,
            "content": json.dumps(result, ensure_ascii=False, default=str)}


# ===================================================================
# التحقيق
# ===================================================================
def investigate(client, ws, run, model=MODEL, clock=time.monotonic):
    messages = [{"role": "user",
                 "content": f"تنبيه أمني جديد على الشبكة (الحادثة {ws.incident.id}). حقّق فيه واكتب التقرير."}]
    steps, start = 0, clock()
    for _ in range(MAX_STEPS + GRACE_TURNS + 2):
        response = _call(client, model, SYSTEM_INVESTIGATE, TOOL_SPECS, messages)
        run.add_usage(response.usage)
        if response.stop_reason == "refusal":
            raise AgentError("رفض مصنّف الأمان متابعة التحقيق")
        messages.append({"role": "assistant", "content": response.content})
        uses = [b for b in response.content if b.type == "tool_use"]
        report = next((b for b in uses if b.name == "submit_report"), None)
        if report is not None:
            run.report = dict(report.input)
            return run.report
        if not uses:
            messages.append({"role": "user", "content": "أنهِ التحقيق الآن باستدعاء submit_report."})
            continue
        results = []
        for b in uses:
            if steps >= MAX_STEPS or clock() - start > MAX_SECONDS:
                result, is_error = {"error": "بلغتَ حد الخطوات أو الوقت. استدعِ submit_report الآن بما جمعته."}, True
            else:
                steps += 1
                result, is_error = _execute(ws, b)
                run.emit("step", tool=b.name, input=b.input, summary=describe(b.name, b.input, result),
                         result=result, is_error=is_error)
            results.append(_tool_result(b, result, is_error))
        messages.append({"role": "user", "content": results})
    raise AgentError("انتهى التحقيق دون تقرير")


def _fail(ws, run, message):
    rules_proposals(ws)
    run.emit("agent_error", message=message, proposals=[proposal_public(p) for p in ws.proposals.values()])
    run.finish("failed")


def run_investigation(client, ws, run, model=MODEL):
    """يشغّل التحقيق ويضمن دائمًا: تقرير أو بديل القواعد، ثم حدث done وحفظ السجل."""
    try:
        investigate(client, ws, run, model=model)
        run.emit("report", report=run.report, proposals=[proposal_public(p) for p in ws.proposals.values()])
        run.finish("done")
    except AgentError as e:
        _fail(ws, run, str(e))
    except anthropic.APIConnectionError:
        _fail(ws, run, "تعذّر الوصول إلى خدمة Claude")
    except anthropic.APIStatusError as e:
        _fail(ws, run, f"خطأ من خدمة Claude (رمز {e.status_code})")
    except Exception as e:
        _fail(ws, run, f"خطأ داخلي: {e}")
    finally:
        run.emit("done", status=run.status, truth_family=run.incident.family,
                 seconds=run.seconds, usage=run.usage)
        run.save()


# ===================================================================
# المحادثة
# ===================================================================
def chat(client, ws, run, message, model=MODEL):
    """سؤال من صاحب المنشأة. السياق المتغير يُرسل داخل رسالة المستخدم (السجل إضافة فقط)."""
    context = {
        "incident_id": ws.incident.id, "report": run.report,
        "proposals": [proposal_public(p) for p in ws.proposals.values()],
        "decisions": [{k: e[k] for k in ("source_ip", "action", "status", "note")} for e in ws.firewall.log],
    }
    mark = len(run.chat_messages)
    run.chat_messages.append({"role": "user", "content":
                              f"سياق محدّث:\n{json.dumps(context, ensure_ascii=False, default=str)}\n\n"
                              f"سؤال صاحب المنشأة: {message}"})
    steps = []
    try:
        for _ in range(CHAT_MAX_STEPS + 2):
            response = _call(client, model, SYSTEM_CHAT, CHAT_TOOLS, run.chat_messages)
            run.add_usage(response.usage)
            if response.stop_reason == "refusal":
                raise AgentError("رفض مصنّف الأمان الإجابة")
            run.chat_messages.append({"role": "assistant", "content": response.content})
            uses = [b for b in response.content if b.type == "tool_use"]
            if not uses:
                answer = "\n".join(b.text for b in response.content if b.type == "text").strip()
                run.chat_log += [{"role": "owner", "text": message}, {"role": "agent", "text": answer}]
                return {"reply": answer, "steps": steps}
            results = []
            for b in uses:
                if b.name not in READ_TOOLS:
                    result, is_error = {"error": "هذه الأداة غير متاحة في المحادثة"}, True
                elif len(steps) >= CHAT_MAX_STEPS:
                    result, is_error = {"error": "بلغتَ حد الأدوات؛ أجب الآن بما لديك."}, True
                else:
                    result, is_error = _execute(ws, b)
                    steps.append(describe(b.name, b.input, result))
                results.append(_tool_result(b, result, is_error))
            run.chat_messages.append({"role": "user", "content": results})
        raise AgentError("لم تكتمل الإجابة")
    except Exception:
        del run.chat_messages[mark:]     # لا نترك سجلًا ناقصًا يكسر السؤال التالي
        raise
```

- [ ] **الخطوة 5: التأكد من نجاح اختبارات التحقيق**

```bash
project/bin/python -m pytest tests/test_analyst.py -q
```

المتوقع: `6 passed`

- [ ] **الخطوة 6: Commit**

```bash
git add agent/store.py agent/analyst.py tests/test_analyst.py
git commit -m "Add investigation loop with step limits and rules fallback"
```

---

## المهمة 5: اختبارات المحادثة

**الملفات:** تعديل `tests/test_analyst.py`

- [ ] **الخطوة 1: إضافة الاختبارات** إلى نهاية `tests/test_analyst.py`

```python
from agent.analyst import AgentError, chat
from agent.tools import READ_TOOLS


def test_chat_uses_read_tools_only(setup):
    ws, run = setup
    run.report = REPORT
    client = FakeClient([
        reply(tool_use("propose_action", {"source_ip": "172.16.0.1", "action": "block_ip", "justification": "x"})),
        reply(tool_use("check_policy", {"source_ip": "172.16.0.1"})),
        reply(block("text", text="الوضع تحت السيطرة بعد الحظر.")),
    ])
    out = chat(client, ws, run, "هل شبكتي آمنة؟")
    assert out["reply"] == "الوضع تحت السيطرة بعد الحظر." and len(out["steps"]) == 1
    assert ws.proposals == {}
    assert {t["name"] for t in client.calls[0]["tools"]} == set(READ_TOOLS)
    assert run.chat_log[-1] == {"role": "agent", "text": "الوضع تحت السيطرة بعد الحظر."}


def test_chat_keeps_history_append_only(setup):
    ws, run = setup
    client = FakeClient([reply(block("text", text="أ")), reply(block("text", text="ب"))])
    chat(client, ws, run, "سؤال 1")
    first_turns = list(run.chat_messages)
    chat(client, ws, run, "سؤال 2")
    assert run.chat_messages[:len(first_turns)] == first_turns


def test_chat_rolls_back_on_failure(setup):
    ws, run = setup
    with pytest.raises(AgentError):
        chat(FakeClient([reply(stop="refusal")]), ws, run, "سؤال")
    assert run.chat_messages == []
```

- [ ] **الخطوة 2: التشغيل**

```bash
project/bin/python -m pytest tests/test_analyst.py -q
```

المتوقع: `9 passed` (الكود كُتب في المهمة 4؛ إن فشل اختبار فأصلح `chat` لا الاختبار).

- [ ] **الخطوة 3: Commit**

```bash
git add tests/test_analyst.py
git commit -m "Test read-only, append-only agent chat"
```

---

## المهمة 6: التقييم (`agent/evaluate.py`)

**الملفات:** إنشاء `agent/evaluate.py` و`tests/test_evaluate.py`

- [ ] **الخطوة 1: كتابة الاختبارات الفاشلة** في `tests/test_evaluate.py`

```python
from agent.evaluate import (hallucinated_ips, score_decisions, summarize, types_correct,
                            unsupported_numbers)

TRUTH = {"172.16.0.1": {"attack_ratio": 1.0, "family": "PortScan"},
         "192.168.10.5": {"attack_ratio": 0.0, "family": "BENIGN"},
         "192.168.10.8": {"attack_ratio": 0.2, "family": "PortScan"}}


def test_score_decisions():
    assert score_decisions(TRUTH, {"172.16.0.1", "192.168.10.8"}) == {
        "tp": 1, "fp": 1, "fn": 0, "benign_sources": 2}
    assert score_decisions(TRUTH, set()) == {"tp": 0, "fp": 0, "fn": 1, "benign_sources": 2}


def test_types_correct():
    assert types_correct(["PortScan", "DoS"], "PortScan")
    assert not types_correct(["DoS"], "PortScan")
    assert types_correct([], "BENIGN") and not types_correct(["DoS"], "BENIGN")


def test_hallucinated_ip_detected():
    report = {"findings": [{"source_ip": "10.9.9.9", "evidence": []}], "summary_owner": "172.16.0.1"}
    assert hallucinated_ips(report, '{"source_ip": "172.16.0.1"}') == ["10.9.9.9"]


def test_unsupported_numbers_accepts_rounding_percent_and_arabic_digits():
    tool_text = '{"flagged_flows": 301, "attack_ratio": 0.97, "mean_z": 12.86}'
    report = {"findings": [{"source_ip": "172.16.0.1", "evidence": [
        "٣٠١ اتصال", "نسبة 97%", "انحراف 12.9", "3 مصادر", "4500 حزمة"]}]}
    assert unsupported_numbers(report, tool_text) == [4500.0]


def test_summarize():
    rows = [{"agent": {"tp": 1, "fp": 0, "fn": 1, "benign_sources": 4, "types_ok": True}},
            {"agent": {"tp": 1, "fp": 1, "fn": 0, "benign_sources": 4, "types_ok": False}}]
    s = summarize(rows, "agent")
    assert (s["precision"], s["recall"], s["false_block_rate"], s["type_accuracy"]) == (0.667, 0.667, 0.125, 0.5)
    assert s["f1"] == 0.667
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_evaluate.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'agent.evaluate'`

- [ ] **الخطوة 3: كتابة `agent/evaluate.py`**

```python
"""
===================================================================
التقييم العلمي للمحلل الذكي — مقارنة الوكيل بالقواعد الثابتة
===================================================================
كل سيناريو يُشغَّل على نظامين بنفس البيانات:
  القواعد  decide_action على كل مصدر مشبوه (سلوك /api/respond)
  الوكيل   مقترحاته، بافتراض موافقة صاحب المنشأة عليها كلها
المصدر «مهاجم» إذا كانت نسبة اتصالاته الهجومية الحقيقية ≥ 50%.

الاستخدام (من مجلد المشروع، يستهلك رصيد API):
  python -m agent.evaluate --limit 6 --no-stability   تجربة لقياس الزمن والتكلفة
  python -m agent.evaluate                            60 سيناريو + الثبات
النتائج: eval_results/agent_eval.json و eval_results/agent_eval.md
===================================================================
"""

import argparse
import json
import re

import numpy as np
import pandas as pd

from agent.scenarios import evaluation_suite
from agent.store import ROOT, Run
from agent.tools import ENFORCING, Workspace, make_resources, rules_proposals

OUT_DIR = ROOT / "eval_results"
CACHE = ROOT / "dashboard_cache"
ATTACKER_RATIO = 0.5
STABILITY_N, STABILITY_REPEATS = 10, 3
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
NUM_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩٫٬", "0123456789.,")


# ===================================================================
# المقاييس
# ===================================================================
def score_decisions(truth, enforced):
    attackers = {ip for ip, t in truth.items() if t["attack_ratio"] >= ATTACKER_RATIO}
    benign = set(truth) - attackers
    return {"tp": len(enforced & attackers), "fp": len(enforced & benign),
            "fn": len(attackers - enforced), "benign_sources": len(benign)}


def types_correct(types, family):
    return family in types if family != "BENIGN" else len(types) == 0


def _numbers(text):
    text = IP_RE.sub(" ", text.translate(ARABIC_DIGITS))
    return [float(n.replace(",", "")) for n in NUM_RE.findall(text)]


def hallucinated_ips(report, tool_text):
    return sorted(set(IP_RE.findall(json.dumps(report, ensure_ascii=False))) - set(IP_RE.findall(tool_text)))


def unsupported_numbers(report, tool_text):
    """أرقام في الأدلة لا تظهر في نتائج الأدوات. فحص تقريبي: يقبل التقريب
    وتحويل النسبة إلى مئوية، ويتجاهل الأعداد ≤ 10 (عدّ مثل «3 مصادر»)."""
    known = _numbers(tool_text)
    out = []
    for finding in report.get("findings", []):
        for ev in finding.get("evidence", []):
            for n in _numbers(ev):
                if n <= 10:
                    continue
                if not any(abs(n - k) <= 0.01 * max(1, abs(k)) or abs(n - 100 * k) <= 0.5 for k in known):
                    out.append(n)
    return out


def _rate(a, b):
    return round(a / b, 3) if b else None


def summarize(rows, key):
    tp, fp, fn = (sum(r[key][k] for r in rows) for k in ("tp", "fp", "fn"))
    benign = sum(r[key]["benign_sources"] for r in rows)
    precision, recall = _rate(tp, tp + fp), _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "false_block_rate": _rate(fp, benign),
            "type_accuracy": _rate(sum(r[key]["types_ok"] for r in rows), len(rows)),
            "tp": tp, "fp": fp, "fn": fn}


# ===================================================================
# التشغيل
# ===================================================================
def evaluate_incident(client, res, inc, model):
    from agent.analyst import run_investigation
    ws = Workspace(inc, res)
    run = Run(inc, ws)
    run_investigation(client, ws, run, model=model)
    report = run.report or {}
    agent_enf = {p.source_ip for p in ws.proposals.values() if p.action in ENFORCING}
    tool_text = " ".join(json.dumps(e["result"], ensure_ascii=False, default=str)
                         for e in run.events if e["type"] == "step")
    ws_rules = Workspace(inc, res)
    rules_enf = {p.source_ip for p in rules_proposals(ws_rules) if p.action in ENFORCING}
    rules_types = {s["attack_type"] for s in ws_rules.sources.values()}
    return {
        "incident_id": inc.id, "kind": inc.kind, "family": inc.family, "status": run.status,
        "agent": {**score_decisions(inc.truth, agent_enf), "enforced": sorted(agent_enf),
                  "types_ok": run.status == "done" and types_correct(report.get("attack_types", []), inc.family)},
        "rules": {**score_decisions(inc.truth, rules_enf), "enforced": sorted(rules_enf),
                  "types_ok": types_correct(rules_types, inc.family)},
        "hallucinated_ips": hallucinated_ips(report, tool_text),
        "unsupported_numbers": unsupported_numbers(report, tool_text),
        "seconds": run.seconds, "usage": run.usage,
    }


def stability(client, res, incidents, model):
    from agent.analyst import run_investigation
    agree = []
    for inc in incidents[:STABILITY_N]:
        decisions = set()
        for _ in range(STABILITY_REPEATS):
            ws = Workspace(inc, res)
            run_investigation(client, ws, Run(inc, ws), model=model)
            decisions.add(frozenset(p.source_ip for p in ws.proposals.values() if p.action in ENFORCING))
        agree.append(len(decisions) == 1)
    return _rate(sum(agree), len(agree))


def load_eval_inputs():
    import joblib
    from explain_decision import compute_baseline_stats
    from train_attack_type_model import normalize_label
    from train_final_lstm import ensemble_predict, load_final_ensemble
    tm = joblib.load(ROOT / "attack_type_model.joblib")
    bs = pd.read_parquet(CACHE / "baseline_sample.parquet")
    benign = bs[bs["Label"].map(normalize_label) == "BENIGN"]
    models, meta = load_final_ensemble()
    res = make_resources(tm, compute_baseline_stats(benign, tm["feature_names"]), models, meta, ensemble_predict)
    return res, pd.read_parquet(CACHE / "act_sample.parquet"), pd.read_parquet(CACHE / "lstm_windows.parquet")


def to_markdown(s):
    a, r = s["agent"], s["rules"]

    def fmt(v):
        return "—" if v is None else f"{v:.1%}"

    lines = [f"# تقييم المحلل الذكي ({s['model']}، {s['incidents']} سيناريو)", "",
             "| المقياس | القواعد الثابتة | الوكيل |", "|---|---|---|"]
    for key, label in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"),
                       ("false_block_rate", "نسبة حظر المصادر السليمة"), ("type_accuracy", "صحة نوع الهجوم")]:
        lines.append(f"| {label} | {fmt(r[key])} | {fmt(a[key])} |")
    lines += ["",
              f"- تحقيقات فشلت وعُرض فيها بديل القواعد: {s['agent_failures']}",
              f"- تحقيقات فيها عنوان IP مختلق: {s['incidents_with_hallucinated_ip']}",
              f"- أرقام غير مسندة في الأدلة (تُراجع يدويًا): {s['unsupported_numbers_total']}",
              f"- متوسط الزمن: {s['mean_seconds']} ثانية · متوسط التوكنز لكل حادثة: "
              f"{s['mean_input_tokens']} إدخال، {s['mean_cache_read_tokens']} من الكاش، {s['mean_output_tokens']} إخراج",
              f"- ثبات القرار ({STABILITY_N} سيناريوهات × {STABILITY_REPEATS}): {fmt(s['stability'])}"]
    return "\n".join(lines) + "\n"


def main():
    import anthropic
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    from agent.analyst import MODEL

    ap = argparse.ArgumentParser(description="تقييم المحلل الذكي مقابل القواعد الثابتة")
    ap.add_argument("--limit", type=int, help="عدد السيناريوهات (للتجربة)")
    ap.add_argument("--no-stability", action="store_true", help="تخطي اختبار الثبات")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    res, act, windows = load_eval_inputs()
    suite = evaluation_suite(act, windows)
    order = np.random.default_rng(0).permutation(len(suite))     # خلط ثابت حتى تشمل --limit أنواعًا مختلفة
    incidents = [suite[i] for i in order][:args.limit or len(suite)]
    client = anthropic.Anthropic(timeout=60.0)

    rows = []
    for i, inc in enumerate(incidents, 1):
        rows.append(evaluate_incident(client, res, inc, args.model))
        print(f"[{i}/{len(incidents)}] {inc.id}: {rows[-1]['status']} — {rows[-1]['seconds']} ث")

    mean = lambda k: int(np.mean([r["usage"][k] for r in rows]))
    summary = {
        "model": args.model, "incidents": len(rows),
        "agent": summarize(rows, "agent"), "rules": summarize(rows, "rules"),
        "agent_failures": sum(r["status"] != "done" for r in rows),
        "incidents_with_hallucinated_ip": sum(bool(r["hallucinated_ips"]) for r in rows),
        "unsupported_numbers_total": sum(len(r["unsupported_numbers"]) for r in rows),
        "mean_seconds": round(float(np.mean([r["seconds"] for r in rows])), 1),
        "mean_input_tokens": mean("input_tokens"), "mean_cache_read_tokens": mean("cache_read_input_tokens"),
        "mean_output_tokens": mean("output_tokens"),
        "stability": None if args.no_stability else stability(client, res, incidents, args.model),
    }
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "agent_eval.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (OUT_DIR / "agent_eval.md").write_text(to_markdown(summary), encoding="utf-8")
    print(to_markdown(summary))


if __name__ == "__main__":
    main()
```

- [ ] **الخطوة 4: التأكد من النجاح**

```bash
project/bin/python -m pytest tests/test_evaluate.py -q
```

المتوقع: `5 passed`

- [ ] **الخطوة 5: تشغيل كل الاختبارات**

```bash
project/bin/python -m pytest tests -q
```

المتوقع: `30 passed`

- [ ] **الخطوة 6: Commit**

```bash
git add agent/evaluate.py tests/test_evaluate.py
git commit -m "Add agent evaluation against static rules"
```

---

## المهمة 7: نقاط الوصول في الخادم (`api_server.py`)

**الملفات:** تعديل `api_server.py`

- [ ] **الخطوة 1: تحديث قائمة النقاط في التوثيق أعلى الملف.** بعد السطر `  GET  /api/stream/flow       تدفق حي واحد (طبيعي أو هجوم محدّد)` أضف:

```
  GET  /api/agent/status      حالة المحلل الذكي (هل يوجد مفتاح API)
  POST /api/agent/investigate يبدأ تحقيقًا في حادثة محاكاة
  GET  /api/agent/stream/{id} خطوات التحقيق لحظيًا (Server-Sent Events)
  POST /api/agent/decide      موافقة/رفض صاحب المنشأة على مقترح
  POST /api/agent/chat        سؤال للمحلل عن الحادثة
```

- [ ] **الخطوة 2: الاستيرادات.** استبدل كتلة الاستيراد الحالية:

```python
import random
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
```

بـ:

```python
import json
import os
import random
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")       # مفتاح Claude للمحلل الذكي (اختياري)
```

- [ ] **الخطوة 3: إضافة النقاط** قبل التعليق `# خدمة الواجهة الساكنة (توضع لاحقًا بمجلد web/)` مباشرة:

```python
# ===================================================================
# المحلل الذكي (وكيل Claude) — انظر agent/ ومستند التصميم
# ===================================================================
AGENT = {"runs": {}, "current": None}


class DecideReq(BaseModel):
    incident_id: str
    proposal_id: int
    decision: str


class ChatReq(BaseModel):
    incident_id: str
    message: str


def _agent_enabled():
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def _agent_client():
    if "client" not in AGENT:
        import anthropic
        AGENT["client"] = anthropic.Anthropic(timeout=60.0)
    return AGENT["client"]


def _agent_resources():
    if "res" not in AGENT:
        from agent.tools import make_resources
        try:
            from train_final_lstm import ensemble_predict
        except Exception:
            ensemble_predict = None
        AGENT["res"] = make_resources(STATE["type_model"], STATE["expl_baseline"],
                                      STATE.get("lstm_models"), STATE.get("lstm_meta"), ensemble_predict)
    return AGENT["res"]


@app.get("/api/agent/status")
def agent_status():
    from agent.analyst import MODEL
    cur = AGENT["runs"].get(AGENT["current"])
    return {"enabled": _agent_enabled(), "model": MODEL,
            "running": bool(cur and cur.status == "running")}


@app.post("/api/agent/investigate")
def agent_investigate(family: str = "random"):
    """ينشئ حادثة محاكاة ويبدأ التحقيق في خيط خلفي. تحقيق واحد في كل مرة."""
    from agent.analyst import run_investigation
    from agent.scenarios import ATTACK_FAMILIES, build_incident
    from agent.store import Run
    from agent.tools import Workspace
    if not _agent_enabled():
        return {"error": "لا يوجد مفتاح ANTHROPIC_API_KEY في ملف .env"}
    cur = AGENT["runs"].get(AGENT["current"])
    if cur and cur.status == "running":
        return {"incident_id": cur.incident.id, "already_running": True}
    choices = ATTACK_FAMILIES + ["BENIGN"]
    if family == "random":
        family = random.choice(choices)
    if family not in choices:
        return {"error": f"نوع غير معروف: {family}"}
    inc = build_incident(STATE["act_sample"], STATE["lstm_windows"], family, seed=random.randrange(10**6))
    ws = Workspace(inc, _agent_resources())
    run = Run(inc, ws)
    AGENT["runs"][inc.id] = run
    AGENT["current"] = inc.id
    threading.Thread(target=run_investigation, args=(_agent_client(), ws, run), daemon=True).start()
    return {"incident_id": inc.id}


@app.get("/api/agent/stream/{incident_id}")
def agent_stream(incident_id: str):
    """خطوات التحقيق كـ Server-Sent Events: step / report / agent_error / done."""
    run = AGENT["runs"].get(incident_id)
    if run is None:
        return {"error": "حادثة غير معروفة"}

    def events():
        sent = 0
        while True:
            batch = run.wait_events(sent, timeout=15)
            if not batch:
                yield ": keep-alive\n\n"
                continue
            for ev in batch:
                yield f"event: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
                if ev["type"] == "done":
                    return
            sent += len(batch)

    return StreamingResponse(events(), media_type="text/event-stream")


@app.post("/api/agent/decide")
def agent_decide(req: DecideReq):
    from agent.tools import ToolError, decide
    run = AGENT["runs"].get(req.incident_id)
    if run is None or req.decision not in ("approve", "reject"):
        return {"error": "طلب غير صالح"}
    try:
        out = decide(run.ws, req.proposal_id, req.decision)
    except ToolError as e:
        return {"error": str(e)}
    run.save()
    return out


@app.post("/api/agent/chat")
def agent_chat(req: ChatReq):
    import anthropic
    from agent.analyst import AgentError, chat
    run = AGENT["runs"].get(req.incident_id)
    if run is None:
        return {"error": "حادثة غير معروفة"}
    if run.status == "running":
        return {"error": "المحلل ما زال يحقق، انتظر التقرير"}
    try:
        out = chat(_agent_client(), run.ws, run, req.message)
    except AgentError as e:
        return {"error": str(e)}
    except anthropic.APIError:
        return {"error": "تعذّر الوصول إلى خدمة Claude"}
    run.save()
    return out
```

- [ ] **الخطوة 4: التحقق بدون مفتاح.** شغّل الخادم على منفذ تجربة (8000 و8001 و8002 قد تكون مشغولة على هذا الجهاز):

```bash
env -u ANTHROPIC_API_KEY project/bin/uvicorn api_server:app --port 8003
```

وفي طرفية أخرى (إن وُجد ملف `.env` بمفتاح، انقله مؤقتًا قبل هذه الخطوة):

```bash
curl -s localhost:8003/api/agent/status
curl -s -X POST "localhost:8003/api/agent/investigate?family=PortScan"
```

المتوقع: `{"enabled":false,"model":"claude-opus-5-5","running":false}` ثم `{"error":"لا يوجد مفتاح ANTHROPIC_API_KEY في ملف .env"}`. والصفحات الحالية تعمل كما هي.

- [ ] **الخطوة 5: التحقق بمفتاح حقيقي** (يستهلك رصيدًا بسيطًا). أنشئ `.env` من `.env.example` وضع المفتاح، وأعد تشغيل الخادم، ثم:

```bash
ID=$(curl -s -X POST "localhost:8003/api/agent/investigate?family=PortScan" | project/bin/python -c "import sys,json;print(json.load(sys.stdin)['incident_id'])")
curl -sN "localhost:8003/api/agent/stream/$ID"
```

المتوقع: أحداث `step` متتالية بجمل عربية، ثم `report` فيه `"attack_types": ["PortScan"]` ومقترح `block_ip` على `172.16.0.1`، ثم `done` بـ `"status": "done"`. وملف جديد في `agent_runs/`.

- [ ] **الخطوة 6: Commit**

```bash
git add api_server.py
git commit -m "Expose AI analyst endpoints with SSE investigation stream"
```

---

## المهمة 8: صفحة «المحلل الذكي» في الواجهة

**الملفات:** تعديل `web/index.html` و`web/style.css` و`web/app.js`

- [ ] **الخطوة 1: زر القائمة الجانبية.** في `web/index.html` بعد زر `data-page="overview"` (وقبل زر `data-page="detect"`) أضف:

```html
    <button data-page="analyst">
      <svg viewBox="0 0 24 24"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M9 12h.01M15 12h.01M9 16h6"/></svg>
      <span>المحلل الذكي</span>
    </button>
```

- [ ] **الخطوة 2: قسم الصفحة.** بعد إغلاق `</section>` الخاص بـ `p-overview` أضف:

```html
  <!-- ---------- المحلل الذكي ---------- -->
  <section class="page" id="p-analyst">
    <div class="note" id="agentSetup" hidden>
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>
      <span>المحلل الذكي يحتاج مفتاح Claude API: انسخ <span class="mono">.env.example</span> إلى <span class="mono">.env</span> وضع المفتاح، ثم أعد تشغيل الخادم.</span>
    </div>
    <div class="action-bar">
      <p>اختر هجومًا لمحاكاته وشاهد الوكيل يحقق خطوة بخطوة. النموذج: <span class="mono" id="agentModel">—</span></p>
      <select id="agentFamily" class="select" aria-label="نوع الهجوم"></select>
      <button class="btn-primary" id="agentStart">حاكِ هجومًا</button>
    </div>
    <div class="agent-grid">
      <div>
        <div class="card">
          <div class="card-title">خطوات التحقيق</div>
          <ol class="timeline" id="agentTimeline"><li class="tl-empty">لم يبدأ أي تحقيق بعد.</li></ol>
          <div class="sec-q" id="agentTruth" style="margin:10px 0 0"></div>
        </div>
        <div id="agentReport" style="margin-top:14px"></div>
      </div>
      <aside class="card chat">
        <div class="card-title">اسأل المحلل</div>
        <div class="chips">
          <button class="chip-btn" data-ask>هل شبكتي آمنة الحين؟</button>
          <button class="chip-btn" data-ask>ليش اقترحت الحظر؟</button>
          <button class="chip-btn" data-ask>وش المفروض أسوي؟</button>
        </div>
        <div class="chat-log" id="chatLog"></div>
        <form class="chat-form" id="chatForm">
          <input id="chatInput" placeholder="اكتب سؤالك…" autocomplete="off" aria-label="سؤالك">
          <button class="btn-primary" type="submit">أرسل</button>
        </form>
      </aside>
    </div>
  </section>
```

- [ ] **الخطوة 3: الأنماط.** في `web/style.css` أضف قبل قسم `الاستجابة لأحجام الشاشات`:

```css
/* ===================================================================
   المحلل الذكي
   =================================================================== */
[hidden]{display:none!important}
.select{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:11px;
  padding:9px 12px;font:inherit;font-size:.88rem}
.agent-grid{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:14px;align-items:start}
.timeline{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
.tl-step{border-inline-start:3px solid var(--accent);padding:8px 12px;background:var(--bg-2);
  border-radius:8px;font-size:.86rem;animation:rise .3s ease}
.tl-step.err{border-color:var(--danger)}
.tl-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.tl-step details{margin-top:6px}
.tl-step summary{cursor:pointer;color:var(--ink-3);font-size:.76rem}
.tl-step pre{margin:6px 0 0;max-height:220px;overflow:auto;font-size:.74rem;white-space:pre-wrap;text-align:left}
.tl-empty{color:var(--ink-3);font-size:.86rem}
.report-summary{font-size:.95rem;margin:14px 0}
.finding{padding:10px 0;border-top:1px solid var(--line-soft);font-size:.86rem}
.finding ul{margin:6px 0 0;padding-inline-start:18px;color:var(--ink-2)}
.proposal{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:10px 0;
  border-bottom:1px solid var(--line-soft);font-size:.86rem}
.proposal:last-child{border:none}
.p-actions{display:flex;gap:6px;flex:none}
.chat{position:sticky;top:96px;display:flex;flex-direction:column;gap:10px;max-height:calc(100vh - 120px)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip-btn{border:1px solid var(--line);background:var(--bg-2);color:var(--ink-2);border-radius:20px;
  padding:5px 11px;font-size:.78rem;cursor:pointer}
.chip-btn:hover{border-color:var(--accent);color:var(--accent)}
.chat-log{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:8px;min-height:120px}
.bubble{padding:9px 12px;border-radius:12px;font-size:.85rem;max-width:92%;white-space:pre-wrap}
.bubble.user{align-self:flex-start;background:var(--accent-dim)}
.bubble.agent{align-self:flex-end;background:var(--bg-2);border:1px solid var(--line-soft)}
.chat-form{display:flex;gap:6px}
.chat-form input{flex:1;min-width:0;border:1px solid var(--line);background:var(--bg-2);color:var(--ink);
  border-radius:10px;padding:9px 11px;font:inherit;font-size:.86rem}
@media (max-width:1080px){
  .agent-grid{grid-template-columns:1fr}
  .chat{position:static;max-height:none}
}
```

- [ ] **الخطوة 4: عنوان الصفحة.** في `web/app.js` داخل كائن `PAGES` أضف بعد سطر `overview`:

```js
  analyst:  ["المحلل الذكي", "وكيل ذكاء اصطناعي يحقق في الحادثة ويقترح، والقرار لك"],
```

- [ ] **الخطوة 5: منطق الصفحة.** أضف إلى نهاية `web/app.js`:

```js
/* ---------- المحلل الذكي (وكيل Claude) ---------- */
const TOOL_AR = {
  incident_overview: "نظرة عامة", suspicious_sources: "المصادر المشبوهة", explain_source: "تفسير السلوك",
  forecast_next_minute: "التنبؤ", check_policy: "فحص السياسة", propose_action: "اقتراح إجراء",
};
const REPORT_SEV = {
  critical: ["حرج", "critical"], high: ["مرتفع", "high"], medium: ["متوسط", "medium"],
  low: ["منخفض", "info"], none: ["لا خطر", "safe"],
};
const STATUS_AR = {
  pending: "بانتظار قرارك", applied: "طُبّق", rejected: "رُفض", refused: "مرفوض من الحاجز",
  covered: "مغطّى بقاعدة سابقة", no_enforcement: "مراقبة فقط",
};
let agentIncident = null, agentStream = null;

$("#agentFamily").innerHTML = '<option value="random">عشوائي</option>' +
  Object.entries(FAMILY).filter(([k]) => k !== "BENIGN")
    .map(([k, f]) => `<option value="${esc(k)}">${f.ar}</option>`).join("") +
  '<option value="BENIGN">ترافيك طبيعي فقط</option>';

async function initAgent() {
  try {
    const s = await api("/api/agent/status");
    $("#agentSetup").hidden = s.enabled;
    $("#agentStart").disabled = !s.enabled;
    $("#agentModel").textContent = s.model;
  } catch (e) {}
}
initAgent();

function addStep(s) {
  const li = document.createElement("li");
  li.className = "tl-step" + (s.is_error ? " err" : "");
  li.innerHTML = `<div class="tl-head"><span class="badge info">${TOOL_AR[s.tool] || esc(s.tool)}</span>
      <span>${esc(s.summary)}</span></div>
    <details><summary>التفاصيل</summary><pre class="mono">${esc(JSON.stringify(s.result, null, 2))}</pre></details>`;
  $("#agentTimeline").appendChild(li);
}

function proposalsHtml(ps) {
  if (!ps.length) return '<p class="sec-q">لا توجد إجراءات مقترحة.</p>';
  return ps.map((p) => {
    const a = ACTION_AR[p.action] || [p.action, "info"];
    return `<div class="proposal" data-id="${p.id}">
      <div><span class="mono">${esc(p.source_ip)}</span> · <span class="badge ${a[1]}">${a[0]}</span>
        ${p.duration_min ? ` · ${p.duration_min} د` : ""}
        <div class="sec-q" style="margin:4px 0 0">${esc((p.reasons || []).join("، "))}</div></div>
      <div class="p-actions">${p.status === "pending"
        ? '<button class="btn-primary" data-decide="approve">وافق</button><button class="btn-ghost" data-decide="reject">ارفض</button>'
        : `<span class="badge info">${STATUS_AR[p.status] || esc(p.status)}</span>`}</div></div>`;
  }).join("");
}

function renderReport(d) {
  const r = d.report, sev = REPORT_SEV[r.severity] || REPORT_SEV.medium;
  $("#agentReport").innerHTML = `
    <div class="card">
      <div class="inc-head"><h3>تقرير المحلل</h3><span class="badge ${sev[1]}">الخطورة: ${sev[0]}</span></div>
      <p class="report-summary">${esc(r.summary_owner)}</p>
      ${r.findings.map((f) => `<div class="finding"><b class="mono">${esc(f.source_ip)}</b> — ${esc(f.assessment)}
        <ul>${f.evidence.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`).join("")}
      <div class="kv"><span>ما يجب مراقبته</span><span>${esc(r.watch_next)}</span></div>
      <div class="kv"><span>ثقة المحلل</span><span class="mono">${pct(r.confidence, 0)}</span></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-title">الإجراءات المقترحة — القرار لك</div>${proposalsHtml(d.proposals)}</div>`;
}

function renderAgentError(d) {
  $("#agentReport").innerHTML = errorHtml("توقّف المحلل: " + esc(d.message), "عرضنا مقترحات القواعد الثابتة بدلًا منه.") +
    `<div class="card" style="margin-top:14px"><div class="card-title">مقترحات القواعد الثابتة</div>${proposalsHtml(d.proposals)}</div>`;
}

$("#agentStart").addEventListener("click", async () => {
  const btn = $("#agentStart");
  btn.disabled = true;
  $("#agentTimeline").innerHTML = "";
  $("#agentTruth").textContent = "";
  $("#chatLog").innerHTML = "";
  $("#agentReport").innerHTML = loadingHtml("المحلل يحقق في الحادثة…");
  let r;
  try { r = await post("/api/agent/investigate?family=" + encodeURIComponent($("#agentFamily").value)); }
  catch (e) { $("#agentReport").innerHTML = OFFLINE; btn.disabled = false; return; }
  if (r.error) { $("#agentReport").innerHTML = errorHtml("تعذّر بدء التحقيق", esc(r.error)); btn.disabled = false; return; }

  agentIncident = r.incident_id;
  if (agentStream) agentStream.close();
  agentStream = new EventSource(API + "/api/agent/stream/" + encodeURIComponent(r.incident_id));
  agentStream.addEventListener("step", (e) => addStep(JSON.parse(e.data)));
  agentStream.addEventListener("report", (e) => renderReport(JSON.parse(e.data)));
  agentStream.addEventListener("agent_error", (e) => renderAgentError(JSON.parse(e.data)));
  agentStream.addEventListener("done", (e) => {
    const d = JSON.parse(e.data);
    agentStream.close();
    btn.disabled = false;
    btn.textContent = "حاكِ هجومًا آخر";
    const truth = d.truth_family === "BENIGN" ? "ترافيك طبيعي فقط" : famInfo(d.truth_family).ar;
    $("#agentTruth").innerHTML = `السيناريو الحقيقي: <b>${esc(truth)}</b> · استغرق ${d.seconds} ثانية`;
  });
});

$("#agentReport").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-decide]");
  if (!b) return;
  const row = b.closest(".proposal");
  row.querySelectorAll("button").forEach((x) => (x.disabled = true));
  try {
    const r = await api("/api/agent/decide", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: agentIncident, proposal_id: Number(row.dataset.id), decision: b.dataset.decide }),
    });
    row.querySelector(".p-actions").innerHTML =
      `<span class="badge info">${esc(STATUS_AR[r.status] || r.status || r.error)}</span>`;
    if (r.note) toast(r.note);
  } catch (err) {
    toast("تعذّر الاتصال بالخادم");
    row.querySelectorAll("button").forEach((x) => (x.disabled = false));
  }
});

function addBubble(role, html) {
  const d = document.createElement("div");
  d.className = "bubble " + role;
  d.innerHTML = html;
  $("#chatLog").appendChild(d);
  d.scrollIntoView({ block: "nearest" });
  return d;
}
async function sendChat(text) {
  if (!agentIncident) { toast("ابدأ تحقيقًا أولًا"); return; }
  addBubble("user", esc(text));
  const pending = addBubble("agent", '<span class="loading"></span>');
  try {
    const r = await api("/api/agent/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: agentIncident, message: text }),
    });
    pending.innerHTML = r.error
      ? `<span style="color:var(--danger)">${esc(r.error)}</span>`
      : esc(r.reply) + (r.steps.length ? `<div class="sec-q" style="margin:6px 0 0">${r.steps.map(esc).join(" · ")}</div>` : "");
  } catch (e) {
    pending.innerHTML = '<span style="color:var(--danger)">تعذّر الاتصال بالخادم.</span>';
  }
}
$("#chatForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#chatInput").value.trim();
  if (!v) return;
  $("#chatInput").value = "";
  sendChat(v);
});
$$("[data-ask]").forEach((b) => b.addEventListener("click", () => sendChat(b.textContent)));
```

- [ ] **الخطوة 6: التحقق في المتصفح** (الخادم على 8003 بمفتاح حقيقي، وتحديث الصفحة بـ Cmd+Shift+R):
  - بلا مفتاح: الصفحة تعرض ملاحظة الإعداد وزر البدء معطّل، وبقية الصفحات تعمل.
  - بمفتاح: «فحص المنافذ» ← الخطوات تظهر واحدة تلو الأخرى ← التقرير ← «وافق» على الحظر يغيّر الحالة إلى «طُبّق».
  - «ترافيك طبيعي فقط» ← تقرير بخطورة منخفضة بلا حظر.
  - سؤال «ليش اقترحت الحظر؟» يرجع إجابة عربية قصيرة.
  - شاشة الجوال (375px) والوضعان الداكن والفاتح، وبلا أخطاء في الـ console.

- [ ] **الخطوة 7: Commit**

```bash
git add web/index.html web/style.css web/app.js
git commit -m "Add AI analyst page with live timeline, approvals, and chat"
```

---

## المهمة 9: التوثيق

**الملفات:** تعديل `README.md`

- [ ] **الخطوة 1:** في قسم «المميزات» أضف بندًا:

```markdown
- **المحلل الذكي:** وكيل Claude يحقق في الحادثة بطبقات النظام كأدوات، يكتب تقريرًا عربيًا لصاحب المنشأة، ويقترح إجراءات تنتظر موافقته، ويجيب على أسئلته. مقيَّم علميًا مقابل القواعد الثابتة على 60 سيناريو.
```

- [ ] **الخطوة 2:** في سطر `pip install` تحت «التشغيل» أضف `anthropic python-dotenv pytest` إلى نهاية الحزم.

- [ ] **الخطوة 3:** أضف قسمًا قبل «ملاحظة عن البيانات والنماذج»:

```markdown
## المحلل الذكي (اختياري)

    cp .env.example .env          # ثم ضع ANTHROPIC_API_KEY
    python -m pytest tests -q     # الاختبارات لا تستدعي Claude ولا تستهلك رصيدًا
    python -m agent.evaluate --limit 6 --no-stability   # تجربة تقييم صغيرة (تستهلك رصيدًا)

بدون مفتاح، صفحة «المحلل الذكي» تعرض تعليمات الإعداد وبقية النظام يعمل كالمعتاد. سجل كل تحقيق يُحفظ في `agent_runs/`.
```

- [ ] **الخطوة 4: Commit**

```bash
git add README.md
git commit -m "Document AI analyst setup, tests, and evaluation"
```

---

## المهمة 10: تشغيل التقييم (يستهلك رصيد API — بموافقة صاحب المشروع)

- [ ] **الخطوة 1: تجربة صغيرة لقياس الزمن والتكلفة**

```bash
project/bin/python -m agent.evaluate --limit 6 --no-stability
```

المتوقع: 6 أسطر تقدم ثم جدول. سجّل متوسط الزمن والتوكنز من آخر سطرين، واضربها في عدد التشغيلات الكامل (60 سيناريو + 30 للثبات = 90 تحقيقًا) بأسعار النموذج لتقدير التكلفة.

- [ ] **الخطوة 2: مراجعة يدوية قبل الصرف.** افتح 2-3 ملفات من `agent_runs/` وتأكد أن التقارير منطقية، وأن قسم «أرقام غير مسندة» في `eval_results/agent_eval.json` ليس أخطاء في الفحص نفسه.

- [ ] **الخطوة 3: التقييم الكامل** بعد موافقة صاحب المشروع على التكلفة المقدّرة:

```bash
project/bin/python -m agent.evaluate
```

- [ ] **الخطوة 4: توثيق النتائج.** انسخ جدول `eval_results/agent_eval.md` إلى قسم «التقييم» في README كما هو، بما فيه أي مقياس لم يتفوق فيه الوكيل، مع القيود المعلنة في مستند التصميم (القسم 8).

- [ ] **الخطوة 5: Commit**

```bash
git add README.md
git commit -m "Report AI analyst evaluation results"
```

---

## ما بعد الخطة (خارج النطاق)

- تحسين رسالة النظام بناءً على أخطاء التقييم ثم إعادة القياس (الأسبوع 6 في مستند التصميم).
- الوكيل على «شبكتي الحية» بعد ضبط صلاحية sudo على جهاز العرض.
- التقييم البشري الاختياري للتقارير (3-5 أشخاص غير تقنيين).
