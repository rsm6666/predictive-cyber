# خطة تنفيذ: نواة المنصة متعددة المنشآت (الجزء 1)

> **لمن ينفّذ:** نفّذ المهام بالترتيب، وخطوة خطوة، وعلّم `- [ ]` عند الإنجاز. لا تنتقل لمهمة قبل نجاح اختباراتها.

- **الهدف:** تسجيل المنشآت بمفتاحين منفصلي الصلاحية، وعزل بيانات كل منشأة في مجلدها، ونقل «المحلل الذكي» ليعمل داخل سياق المنشأة، مع صفحات «منشأتي» و«الإعدادات».
- **مستند التصميم:** [2026-10-26-multi-tenant-core-design.md](../specs/2026-10-26-multi-tenant-core-design.md)
- **البنية:** حزمة `tenancy/` جديدة: `registry.py` (سجل المنشآت والمفاتيح) ← `store.py` (مجلد معزول لكل منشأة) ← `auth.py` (المفتاح ← المنشأة، رموز البث، حد التسجيل) ← `api.py` (موجّه `/api/v1`). `api_server.py` يركّب الموجّه ويحذف نقاط `/api/agent/*` القديمة. الواجهة تضيف الدخول والصفحتين.
- **التقنيات:** Python 3.11، FastAPI، SQLite (`sqlite3` المدمجة)، pytest مع `fastapi.testclient`، JavaScript بلا مكتبات.
- **الفرع:** `platform-core`

## قرارات ثابتة

- **اسم الحزمة `tenancy`** لا `platform` (اسم وحدة في مكتبة بايثون القياسية).
- **الاختبارات لا تستورد `api_server`**: تبني تطبيق FastAPI صغيرًا يركّب الموجّه مع `Platform` مؤقت (مجلدات `tmp_path`، `DemoClient`، تنبؤ ثابت)، فلا تحمّل TensorFlow ولا تحتاج مفتاح Claude.
- **تخزين سجلات الحوادث:** `tenant.db` يحفظ الإعدادات، وسجلات التحقيقات (المقترحات والقرارات والمحادثة) تبقى ملفات JSON في `data/tenants/<id>/agent_runs/` كما يكتبها `Run.save` الحالي. (تعديل صغير على المستند، يُطبَّق في المهمة 6.)
- **ترتيب الاستيراد في `api_server.py`:** `tenancy.api` يستورد `agent.analyst` الذي يقرأ `ANTHROPIC_MODEL` عند الاستيراد، لذا يُستورد **بعد** `load_dotenv`.

## خريطة الملفات

| الملف | جديد/تعديل | المسؤولية |
|---|---|---|
| `tenancy/__init__.py` | جديد | فارغ |
| `tenancy/registry.py` | جديد | `Tenant` و`Registry`: إنشاء، تحليل مفتاح، تدوير. بصمات فقط |
| `tenancy/store.py` | جديد | `TenantStore`: مجلد المنشأة بعد التحقق من المعرّف، والإعدادات |
| `tenancy/auth.py` | جديد | `dashboard_tenant` و`StreamTokens` و`RateLimiter` |
| `tenancy/api.py` | جديد | `Platform` والموجّه `/api/v1` |
| `tests/test_tenancy.py` | جديد | اختبارات الوحدات (السجل، المجلدات، الرموز، الحد) |
| `tests/test_tenancy_api.py` | جديد | اختبارات العزل عبر الـ API |
| `api_server.py` | تعديل | تركيب الموجّه، بناء `Platform` عند الإقلاع، حذف `/api/agent/*` |
| `web/index.html` و`style.css` و`app.js` | تعديل | الدخول، المفاتيح، «منشأتي»، «الإعدادات»، المحلل على `/api/v1` |
| `README.md` ومستند التصميم | تعديل | التوثيق |

---

## المهمة 1: سجل المنشآت والمفاتيح (`tenancy/registry.py`)

**الملفات:** إنشاء `tenancy/__init__.py` (فارغ) و`tenancy/registry.py` و`tests/test_tenancy.py`

- [ ] **الخطوة 1: كتابة الاختبارات الفاشلة** في `tests/test_tenancy.py`

```python
import pytest

from tenancy.registry import DASHBOARD, INGEST, TENANT_ID_RE, Registry


@pytest.fixture
def reg(tmp_path):
    return Registry(tmp_path / "registry.db")


def test_create_returns_prefixed_keys_and_valid_id(reg):
    tenant, keys = reg.create("  مقهى الريف  ")
    assert TENANT_ID_RE.fullmatch(tenant.id) and tenant.name == "مقهى الريف"
    assert keys["ingest_key"].startswith("pc_ing_") and keys["dashboard_key"].startswith("pc_dash_")


def test_resolve_identifies_tenant_and_kind(reg):
    tenant, keys = reg.create("أ")
    assert reg.resolve(keys["dashboard_key"]) == (tenant, DASHBOARD)
    assert reg.resolve(keys["ingest_key"]) == (tenant, INGEST)
    for bad in ("", "random", "pc_dash_wrong", keys["dashboard_key"] + "x"):
        assert reg.resolve(bad) is None


def test_only_hashes_are_stored(tmp_path):
    path = tmp_path / "registry.db"
    _, keys = Registry(path).create("أ")
    raw = path.read_bytes()
    assert keys["ingest_key"].encode() not in raw and keys["dashboard_key"].encode() not in raw


def test_rotate_invalidates_old_keys(reg):
    tenant, old = reg.create("أ")
    new = reg.rotate(tenant.id)
    assert reg.resolve(old["dashboard_key"]) is None and reg.resolve(old["ingest_key"]) is None
    assert reg.resolve(new["dashboard_key"]) == (tenant, DASHBOARD)


def test_name_is_validated(reg):
    for bad in ("   ", "x" * 81):
        with pytest.raises(ValueError):
            reg.create(bad)
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_tenancy.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'tenancy'`

- [ ] **الخطوة 3: إنشاء `tenancy/__init__.py` فارغًا، وكتابة `tenancy/registry.py`**

```python
"""
===================================================================
سجل المنشآت — المعرّف والاسم وبصمات (sha256) المفتاحين، لا مفاتيح خام
===================================================================
المفتاح = بادئة تحدد صلاحيته + 32 بايت عشوائية، ويُعرض مرة واحدة:
  pc_ing_   مفتاح الاستقبال: إرسال البيانات فقط
  pc_dash_  مفتاح اللوحة: القراءة والموافقة والإعدادات
sha256 كافٍ هنا لأن المفتاح عشوائي عالي الإنتروبيا (ليس كلمة مرور).
===================================================================
"""

import hashlib
import hmac
import re
import secrets
import sqlite3
import string
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

TENANT_ID_RE = re.compile(r"t_[a-z0-9]{12}")
INGEST, DASHBOARD = "ingest", "dashboard"
PREFIX = {INGEST: "pc_ing_", DASHBOARD: "pc_dash_"}
_COLUMN = {INGEST: "ingest_key_hash", DASHBOARD: "dashboard_key_hash"}
MAX_NAME = 80


@dataclass(frozen=True)
class Tenant:
    id: str
    name: str
    created_at: float


def _hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


def _new_keys():
    return {f"{kind}_key": PREFIX[kind] + secrets.token_urlsafe(32) for kind in (INGEST, DASHBOARD)}


class Registry:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL,
                ingest_key_hash TEXT NOT NULL UNIQUE, dashboard_key_hash TEXT NOT NULL UNIQUE)""")

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path)
        try:
            with con:
                yield con
        finally:
            con.close()

    def create(self, name):
        name = name.strip()
        if not 1 <= len(name) <= MAX_NAME:
            raise ValueError(f"اسم المنشأة مطلوب (حتى {MAX_NAME} حرفًا)")
        alphabet = string.ascii_lowercase + string.digits
        tenant = Tenant("t_" + "".join(secrets.choice(alphabet) for _ in range(12)), name, time.time())
        keys = _new_keys()
        with self._db() as db:
            db.execute("INSERT INTO tenants VALUES (?, ?, ?, ?, ?)",
                       (tenant.id, tenant.name, tenant.created_at,
                        _hash(keys["ingest_key"]), _hash(keys["dashboard_key"])))
        return tenant, keys

    def rotate(self, tenant_id):
        keys = _new_keys()
        with self._db() as db:
            db.execute("UPDATE tenants SET ingest_key_hash = ?, dashboard_key_hash = ? WHERE id = ?",
                       (_hash(keys["ingest_key"]), _hash(keys["dashboard_key"]), tenant_id))
        return keys

    def resolve(self, key):
        """المفتاح ← (المنشأة، نوع المفتاح)، أو None."""
        kind = next((k for k, prefix in PREFIX.items() if key.startswith(prefix)), None)
        if kind is None:
            return None
        digest = _hash(key)
        column = _COLUMN[kind]
        with self._db() as db:
            row = db.execute(f"SELECT id, name, created_at, {column} FROM tenants WHERE {column} = ?",
                             (digest,)).fetchone()
        if row is None or not hmac.compare_digest(row[3], digest):
            return None
        return Tenant(*row[:3]), kind
```

- [ ] **الخطوة 4: التأكد من النجاح**

```bash
project/bin/python -m pytest tests/test_tenancy.py -q
```

المتوقع: `5 passed`

- [ ] **الخطوة 5: Commit**

```bash
git add tenancy/__init__.py tenancy/registry.py tests/test_tenancy.py
git commit -m "Add tenant registry with hashed, scoped API keys"
```

---

## المهمة 2: المجلدات المعزولة والمصادقة (`tenancy/store.py` و`tenancy/auth.py`)

**الملفات:** إنشاء `tenancy/store.py` و`tenancy/auth.py`، تعديل `tests/test_tenancy.py`

- [ ] **الخطوة 1: إضافة الاختبارات الفاشلة** إلى نهاية `tests/test_tenancy.py`، مع تحديث سطر الاستيراد أعلى الملف:

```python
from sandbox_firewall import DEFAULT_ALLOWLIST
from tenancy.auth import RateLimiter, StreamTokens
from tenancy.registry import DASHBOARD, INGEST, TENANT_ID_RE, Registry
from tenancy.store import TenantStore
```

```python
def test_store_rejects_bad_tenant_ids(tmp_path):
    store = TenantStore(tmp_path)
    for bad in ("../x", "t_ABCDEFGHIJKL", "t_short", "t_abcdefghijkl/../x", ""):
        with pytest.raises(ValueError):
            store.dir(bad)


def test_settings_default_and_roundtrip(tmp_path):
    store, tid = TenantStore(tmp_path), "t_abcdefghijkl"
    assert store.settings(tid) == {"webhook_url": None, "allowlist": list(DEFAULT_ALLOWLIST)}
    store.save_settings(tid, {"webhook_url": "https://x.test/hook", "allowlist": ["10.0.0.1"]})
    assert store.settings(tid) == {"webhook_url": "https://x.test/hook", "allowlist": ["10.0.0.1"]}
    assert (tmp_path / tid / "tenant.db").exists()


def test_stream_token_is_single_use_scoped_and_expiring():
    now = [0.0]
    tokens = StreamTokens(clock=lambda: now[0])
    t = tokens.issue("t_a", "inc1")
    assert tokens.consume(t, "inc2") is None              # حادثة أخرى، والرمز يُحرق
    t = tokens.issue("t_a", "inc1")
    assert tokens.consume(t, "inc1") == "t_a"
    assert tokens.consume(t, "inc1") is None              # مرة واحدة فقط
    t = tokens.issue("t_a", "inc1")
    now[0] = StreamTokens.TTL + 1
    assert tokens.consume(t, "inc1") is None              # منتهٍ


def test_rate_limiter_window():
    now = [0.0]
    limiter = RateLimiter(limit=2, window=10, clock=lambda: now[0])
    assert limiter.allow("ip") and limiter.allow("ip") and not limiter.allow("ip")
    assert limiter.allow("other")
    now[0] = 11
    assert limiter.allow("ip")
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_tenancy.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'tenancy.auth'`

- [ ] **الخطوة 3: كتابة `tenancy/store.py`**

```python
"""
مجلد معزول لكل منشأة: data/tenants/<tenant_id>/ فيه tenant.db (الإعدادات)
و agent_runs/ (سجلات التحقيقات). المعرّف يُتحقق منه بنمط صارم قبل بناء
أي مسار، فلا يمكن الخروج من مجلد المنشآت بـ ../
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from sandbox_firewall import DEFAULT_ALLOWLIST

from tenancy.registry import TENANT_ID_RE


class TenantStore:
    def __init__(self, root):
        self.root = Path(root)

    def dir(self, tenant_id):
        if not TENANT_ID_RE.fullmatch(tenant_id):
            raise ValueError("معرّف منشأة غير صالح")
        path = self.root / tenant_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def runs_dir(self, tenant_id):
        return self.dir(tenant_id) / "agent_runs"

    @contextmanager
    def _db(self, tenant_id):
        con = sqlite3.connect(self.dir(tenant_id) / "tenant.db")
        try:
            with con:
                con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                yield con
        finally:
            con.close()

    def settings(self, tenant_id):
        out = {"webhook_url": None, "allowlist": list(DEFAULT_ALLOWLIST)}
        with self._db(tenant_id) as db:
            out.update({k: json.loads(v) for k, v in db.execute("SELECT key, value FROM settings")})
        return out

    def save_settings(self, tenant_id, settings):
        with self._db(tenant_id) as db:
            db.executemany("INSERT OR REPLACE INTO settings VALUES (?, ?)",
                           [(k, json.dumps(v, ensure_ascii=False)) for k, v in settings.items()])
```

- [ ] **الخطوة 4: كتابة `tenancy/auth.py`**

```python
"""
مصادقة المنصة:
  dashboard_tenant  اعتمادية FastAPI: مفتاح اللوحة في الترويسة ← المنشأة
  StreamTokens      رمز بث لمرة واحدة (EventSource لا يرسل ترويسات)
  RateLimiter       حد بسيط في الذاكرة للتسجيل المفتوح
"""

import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from tenancy.registry import DASHBOARD


def _bearer(request):
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def dashboard_tenant(request: Request):
    """المنشأة تُستنتج من المفتاح فقط؛ لا يُقبل المفتاح ولا معرّف المنشأة من الرابط."""
    found = request.app.state.platform.registry.resolve(_bearer(request))
    if found is None:
        raise HTTPException(401, "مفتاح غير صالح")
    tenant, kind = found
    if kind != DASHBOARD:
        raise HTTPException(403, "هذا المفتاح لا يملك صلاحية اللوحة")
    return tenant


class StreamTokens:
    """رمز لمرة واحدة، مرتبط بمنشأة وحادثة، صالح TTL ثانية."""
    TTL = 60

    def __init__(self, clock=time.monotonic):
        self._clock, self._tokens, self._lock = clock, {}, threading.Lock()

    def issue(self, tenant_id, incident_id):
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._tokens[token] = (tenant_id, incident_id, self._clock() + self.TTL)
        return token

    def consume(self, token, incident_id):
        """يرجع معرّف المنشأة أو None. الرمز يُحرق في كل الأحوال."""
        with self._lock:
            entry = self._tokens.pop(token, None)
        if entry is None or entry[1] != incident_id or self._clock() > entry[2]:
            return None
        return entry[0]


class RateLimiter:
    def __init__(self, limit=10, window=3600, clock=time.monotonic):
        self.limit, self.window, self._clock = limit, window, clock
        self._hits, self._lock = defaultdict(deque), threading.Lock()

    def allow(self, key):
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True
```

- [ ] **الخطوة 5: التأكد من النجاح**

```bash
project/bin/python -m pytest tests/test_tenancy.py -q
```

المتوقع: `9 passed`

- [ ] **الخطوة 6: Commit**

```bash
git add tenancy/store.py tenancy/auth.py tests/test_tenancy.py
git commit -m "Add isolated tenant storage, stream tokens, and signup limiter"
```

---

## المهمة 3: موجّه المنصة `/api/v1` (`tenancy/api.py`)

**الملفات:** إنشاء `tenancy/api.py` و`tests/test_tenancy_api.py`

- [ ] **الخطوة 1: كتابة الاختبارات الفاشلة** في `tests/test_tenancy_api.py`

```python
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent.demo import DemoClient
from agent.tools import ENFORCING
from tenancy.api import Platform, router
from tenancy.auth import RateLimiter
from tenancy.registry import Registry
from tenancy.store import TenantStore


@pytest.fixture
def platform(tmp_path, resources, data):
    act, windows = data
    return Platform(registry=Registry(tmp_path / "registry.db"), store=TenantStore(tmp_path / "tenants"),
                    resources=lambda: resources, act_sample=act, windows=windows,
                    client=lambda: DemoClient(), live=lambda: False)


@pytest.fixture
def api(platform):
    app = FastAPI()
    app.include_router(router)
    app.state.platform = platform
    return TestClient(app)


def auth(key):
    return {"Authorization": f"Bearer {key}"}


def signup(api, name="منشأة"):
    r = api.post("/api/v1/tenants", json={"name": name})
    assert r.status_code == 201
    return r.json()


def investigate(api, platform, tenant, family="PortScan"):
    r = api.post("/api/v1/agent/investigate", params={"family": family}, headers=auth(tenant["dashboard_key"]))
    iid = r.json()["incident_id"]
    run = platform.runs[(tenant["tenant_id"], iid)]
    for _ in range(200):
        if run.status != "running":
            break
        time.sleep(0.05)
    return iid, run


def test_dashboard_endpoints_require_dashboard_key(api):
    t = signup(api)
    assert api.get("/api/v1/me").status_code == 401
    assert api.get("/api/v1/me", headers=auth("pc_dash_nope")).status_code == 401
    assert api.get("/api/v1/me", headers=auth(t["ingest_key"])).status_code == 403
    me = api.get("/api/v1/me", headers=auth(t["dashboard_key"])).json()
    assert me["tenant_id"] == t["tenant_id"] and me["settings"]["webhook_url"] is None


def test_rotated_keys_replace_old_ones(api):
    t = signup(api)
    new = api.post("/api/v1/keys/rotate", headers=auth(t["dashboard_key"])).json()
    assert api.get("/api/v1/me", headers=auth(t["dashboard_key"])).status_code == 401
    assert api.get("/api/v1/me", headers=auth(new["dashboard_key"])).status_code == 200


def test_signup_validation_and_rate_limit(api, platform):
    assert api.post("/api/v1/tenants", json={"name": "  "}).status_code == 422
    platform.signups = RateLimiter(limit=1)
    signup(api)
    assert api.post("/api/v1/tenants", json={"name": "ب"}).status_code == 429


def test_settings_are_validated_and_saved(api):
    h = auth(signup(api)["dashboard_key"])
    assert api.put("/api/v1/settings", json={"webhook_url": "ftp://x"}, headers=h).status_code == 422
    assert api.put("/api/v1/settings", json={"allowlist": ["999.1.1.1"]}, headers=h).status_code == 422
    body = {"webhook_url": "https://hooks.example.test/sec", "allowlist": [" 10.0.0.5 ", ""]}
    assert api.put("/api/v1/settings", json=body, headers=h).status_code == 200
    assert api.get("/api/v1/me", headers=h).json()["settings"] == {
        "webhook_url": "https://hooks.example.test/sec", "allowlist": ["10.0.0.5"]}


def test_other_tenant_cannot_touch_incident(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    iid, run = investigate(api, platform, a)
    pid = next(iter(run.ws.proposals))
    decide = {"incident_id": iid, "proposal_id": pid, "decision": "approve"}
    hb = auth(b["dashboard_key"])
    assert api.post("/api/v1/agent/decide", json=decide, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/stream-token", json={"incident_id": iid}, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/chat", json={"incident_id": iid, "message": "هل آمن؟"}, headers=hb).status_code == 404
    assert api.post("/api/v1/agent/decide", json=decide, headers=auth(a["dashboard_key"])).json()["status"] == "applied"


def test_tenant_files_stay_in_tenant_folder(api, platform, tmp_path):
    a, b = signup(api, "أ"), signup(api, "ب")
    iid, _ = investigate(api, platform, a)
    assert (tmp_path / "tenants" / a["tenant_id"] / "agent_runs" / f"{iid}.json").exists()
    assert not list((tmp_path / "tenants" / b["tenant_id"]).rglob("*.json"))


def test_allowlist_is_per_tenant(api, platform):
    a, b = signup(api, "أ"), signup(api, "ب")
    api.put("/api/v1/settings", json={"allowlist": ["172.16.0.1"]}, headers=auth(a["dashboard_key"]))
    _, run_a = investigate(api, platform, a)
    _, run_b = investigate(api, platform, b)

    def enforced(run):
        return {p.source_ip for p in run.ws.proposals.values() if p.action in ENFORCING}

    assert "172.16.0.1" not in enforced(run_a)
    assert "172.16.0.1" in enforced(run_b)


def test_stream_token_works_once(api, platform):
    t = signup(api)
    h = auth(t["dashboard_key"])
    iid, _ = investigate(api, platform, t)
    token = api.post("/api/v1/agent/stream-token", json={"incident_id": iid}, headers=h).json()["token"]
    with api.stream("GET", f"/api/v1/agent/stream/{iid}", params={"token": token}) as s:
        events = [line[7:] for line in s.iter_lines() if line.startswith("event: ")]
    assert events[-1] == "done"
    assert api.get(f"/api/v1/agent/stream/{iid}", params={"token": token}).status_code == 403
```

- [ ] **الخطوة 2: التأكد من الفشل**

```bash
project/bin/python -m pytest tests/test_tenancy_api.py -q
```

المتوقع: `ModuleNotFoundError: No module named 'tenancy.api'`

- [ ] **الخطوة 3: كتابة `tenancy/api.py`**

```python
"""
===================================================================
نقاط وصول المنصة (/api/v1) — كل شيء داخل سياق المنشأة
===================================================================
المنشأة تُستنتج من المفتاح فقط (auth.dashboard_tenant)، ولا تأخذ أي نقطة
معرّف منشأة من الرابط أو الجسم. التحقيقات مفهرسة بـ (المنشأة، الحادثة)،
وحادثة منشأة أخرى ترجع 404 حتى لا يُكشف وجودها. أدوات الوكيل تُبنى فوق
بيانات المنشأة، وجدارها المحاكى يأخذ قائمة السماح من إعداداتها.
===================================================================
"""

import ipaddress
import json
import random
import threading
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import anthropic
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sandbox_firewall import SimulatedFirewall

from agent.analyst import MODEL, AgentError, chat, run_investigation
from agent.scenarios import ATTACK_FAMILIES, build_incident
from agent.store import Run
from agent.tools import ToolError, Workspace, decide
from tenancy.auth import RateLimiter, StreamTokens, dashboard_tenant
from tenancy.registry import Registry
from tenancy.store import TenantStore


@dataclass
class Platform:
    registry: Registry
    store: TenantStore
    resources: Callable          # () -> agent.tools.Resources
    act_sample: pd.DataFrame
    windows: pd.DataFrame
    client: Callable             # () -> عميل Claude أو DemoClient
    live: Callable               # () -> هل يوجد مفتاح Claude
    tokens: StreamTokens = field(default_factory=StreamTokens)
    signups: RateLimiter = field(default_factory=RateLimiter)
    runs: dict = field(default_factory=dict)        # (tenant_id, incident_id) -> Run
    current: dict = field(default_factory=dict)     # tenant_id -> incident_id


class SignupReq(BaseModel):
    name: str


class SettingsReq(BaseModel):
    webhook_url: str | None = None
    allowlist: list[str] = []


class IncidentReq(BaseModel):
    incident_id: str


class DecideReq(IncidentReq):
    proposal_id: int
    decision: str


class ChatReq(IncidentReq):
    message: str


router = APIRouter(prefix="/api/v1")


def _platform(request: Request) -> Platform:
    return request.app.state.platform


def _run(p, tenant, incident_id):
    run = p.runs.get((tenant.id, incident_id))
    if run is None:
        raise HTTPException(404, "حادثة غير موجودة")
    return run


# ===================================================================
# المنشأة
# ===================================================================
@router.post("/tenants", status_code=201)
def signup(req: SignupReq, request: Request):
    p = _platform(request)
    if not p.signups.allow(request.client.host if request.client else "unknown"):
        raise HTTPException(429, "محاولات تسجيل كثيرة، حاول بعد ساعة")
    try:
        tenant, keys = p.registry.create(req.name)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    p.store.dir(tenant.id)
    return {"tenant_id": tenant.id, "name": tenant.name, **keys}


@router.get("/me")
def me(request: Request, tenant=Depends(dashboard_tenant)):
    return {"tenant_id": tenant.id, "name": tenant.name, "created_at": tenant.created_at,
            "settings": _platform(request).store.settings(tenant.id)}


@router.put("/settings")
def update_settings(req: SettingsReq, request: Request, tenant=Depends(dashboard_tenant)):
    url = (req.webhook_url or "").strip() or None
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise HTTPException(422, "رابط الـ Webhook يجب أن يبدأ بـ http:// أو https://")
    allowlist = []
    for ip in (s.strip() for s in req.allowlist):
        if not ip:
            continue
        try:
            allowlist.append(str(ipaddress.ip_address(ip)))
        except ValueError:
            raise HTTPException(422, f"عنوان IP غير صالح: {ip}") from None
    settings = {"webhook_url": url, "allowlist": allowlist}
    _platform(request).store.save_settings(tenant.id, settings)
    return settings


@router.post("/keys/rotate")
def rotate_keys(request: Request, tenant=Depends(dashboard_tenant)):
    return _platform(request).registry.rotate(tenant.id)


# ===================================================================
# المحلل الذكي داخل سياق المنشأة
# ===================================================================
@router.get("/agent/status")
def agent_status(request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    cur = p.runs.get((tenant.id, p.current.get(tenant.id)))
    return {"mode": "live" if p.live() else "demo", "model": MODEL,
            "running": bool(cur and cur.status == "running")}


@router.post("/agent/investigate")
def agent_investigate(request: Request, family: str = "random", tenant=Depends(dashboard_tenant)):
    """حادثة محاكاة في سياق المنشأة. تحقيق واحد في كل مرة لكل منشأة."""
    p = _platform(request)
    cur = p.runs.get((tenant.id, p.current.get(tenant.id)))
    if cur and cur.status == "running":
        return {"incident_id": cur.incident.id, "already_running": True}
    choices = ATTACK_FAMILIES + ["BENIGN"]
    if family == "random":
        family = random.choice(choices)
    if family not in choices:
        raise HTTPException(422, f"نوع غير معروف: {family}")
    inc = build_incident(p.act_sample, p.windows, family, seed=random.randrange(10**6))
    firewall = SimulatedFirewall(allowlist=p.store.settings(tenant.id)["allowlist"])
    ws = Workspace(inc, p.resources(), firewall=firewall)
    run = Run(inc, ws, save_dir=p.store.runs_dir(tenant.id))
    p.runs[(tenant.id, inc.id)] = run
    p.current[tenant.id] = inc.id
    threading.Thread(target=run_investigation, args=(p.client(), ws, run), daemon=True).start()
    return {"incident_id": inc.id}


@router.post("/agent/stream-token")
def agent_stream_token(req: IncidentReq, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    _run(p, tenant, req.incident_id)
    return {"token": p.tokens.issue(tenant.id, req.incident_id)}


@router.get("/agent/stream/{incident_id}")
def agent_stream(incident_id: str, token: str, request: Request):
    """خطوات التحقيق كـ Server-Sent Events. المصادقة برمز البث لا بمفتاح اللوحة."""
    p = _platform(request)
    tenant_id = p.tokens.consume(token, incident_id)
    if tenant_id is None:
        raise HTTPException(403, "رمز البث غير صالح أو منتهٍ")
    run = p.runs.get((tenant_id, incident_id))
    if run is None:
        raise HTTPException(404, "حادثة غير موجودة")

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


@router.post("/agent/decide")
def agent_decide(req: DecideReq, request: Request, tenant=Depends(dashboard_tenant)):
    run = _run(_platform(request), tenant, req.incident_id)
    if req.decision not in ("approve", "reject"):
        raise HTTPException(422, "القرار يجب أن يكون approve أو reject")
    try:
        out = decide(run.ws, req.proposal_id, req.decision)
    except ToolError as e:
        return {"error": str(e)}
    run.save()
    return out


@router.post("/agent/chat")
def agent_chat(req: ChatReq, request: Request, tenant=Depends(dashboard_tenant)):
    p = _platform(request)
    run = _run(p, tenant, req.incident_id)
    if run.status == "running":
        return {"error": "المحلل ما زال يحقق، انتظر التقرير"}
    try:
        out = chat(p.client(), run.ws, run, req.message)
    except AgentError as e:
        return {"error": str(e)}
    except anthropic.APIError:
        return {"error": "تعذّر الوصول إلى خدمة Claude"}
    run.save()
    return out
```

- [ ] **الخطوة 4: التأكد من النجاح، ثم تشغيل كل الاختبارات**

```bash
project/bin/python -m pytest tests/test_tenancy_api.py -q
project/bin/python -m pytest tests -q
```

المتوقع: `8 passed` ثم `56 passed` (39 سابقة + 9 + 8).

- [ ] **الخطوة 5: Commit**

```bash
git add tenancy/api.py tests/test_tenancy_api.py
git commit -m "Add tenant-scoped /api/v1 router with isolation tests"
```

---

## المهمة 4: ربط الخادم (`api_server.py`)

**الملفات:** تعديل `api_server.py`

- [ ] **الخطوة 1: التوثيق أعلى الملف.** استبدل أسطر `/api/agent/*` الخمسة:

```
  GET  /api/agent/status      حالة المحلل الذكي (هل يوجد مفتاح API)
  POST /api/agent/investigate يبدأ تحقيقًا في حادثة محاكاة
  GET  /api/agent/stream/{id} خطوات التحقيق لحظيًا (Server-Sent Events)
  POST /api/agent/decide      موافقة/رفض صاحب المنشأة على مقترح
  POST /api/agent/chat        سؤال للمحلل عن الحادثة
```

بـ:

```
  /api/v1/...                 المنصة متعددة المنشآت والمحلل الذكي (tenancy/api.py)
```

- [ ] **الخطوة 2: الاستيرادات.** احذف `import json` و`import threading` و`from fastapi.responses import StreamingResponse` (انتقل استخدامها إلى `tenancy/api.py`). ثم استبدل:

```python
HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")       # مفتاح Claude للمحلل الذكي (اختياري)
CACHE = HERE / "dashboard_cache"
```

بـ:

```python
HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")       # مفتاح Claude للمحلل الذكي (اختياري)
# بعد load_dotenv: agent.analyst يقرأ ANTHROPIC_MODEL عند الاستيراد
from tenancy.api import Platform, router as platform_router  # noqa: E402

CACHE = HERE / "dashboard_cache"
DATA = HERE / "data"             # سجل المنشآت ومجلداتها المعزولة (مستثنى من git)
```

- [ ] **الخطوة 3: بناء المنصة عند الإقلاع.** في `lifespan` استبدل:

```python
    print("جاهز. الخادم يعمل.")
```

بـ:

```python
    # المنصة: سجل المنشآت ومجلداتها المعزولة + المحلل الذكي
    from tenancy.registry import Registry
    from tenancy.store import TenantStore
    app.state.platform = Platform(
        registry=Registry(DATA / "registry.db"), store=TenantStore(DATA / "tenants"),
        resources=_agent_resources, act_sample=STATE["act_sample"], windows=STATE["lstm_windows"],
        client=_agent_client, live=_agent_live)

    print("جاهز. الخادم يعمل.")
```

- [ ] **الخطوة 4: استبدال قسم المحلل القديم.** احذف كل ما بين `# المحلل الذكي (وكيل Claude) — انظر agent/ ومستند التصميم` وبين `# خدمة الواجهة الساكنة`: القاموس `AGENT`، والصنفين `DecideReq` و`ChatReq`، والدوال الثلاث، ونقاط `/api/agent/*` الخمس. وضع مكانه:

```python
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


```

- [ ] **الخطوة 5: التحقق اليدوي** (منفذ تجربة غير مستخدم):

```bash
project/bin/uvicorn api_server:app --port 8005
```

وفي طرفية أخرى:

```bash
curl -s -X POST localhost:8005/api/v1/tenants -H 'content-type: application/json' -d '{"name":"تجربة"}'
curl -s -o /dev/null -w "%{http_code}\n" localhost:8005/api/agent/status
curl -s -o /dev/null -w "%{http_code}\n" localhost:8005/api/v1/me
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:8005/api/detect
```

المتوقع: JSON فيه `tenant_id` و`ingest_key` و`dashboard_key`، ثم `404` (النقطة القديمة حُذفت)، ثم `401`، ثم `200` (نقاط CICIDS العامة كما هي). ومجلد `data/tenants/<tenant_id>/` موجود.

- [ ] **الخطوة 6: Commit**

```bash
git add api_server.py
git commit -m "Mount tenant platform router and drop unscoped agent endpoints"
```

---

## المهمة 5: الواجهة

**الملفات:** تعديل `web/index.html` و`web/style.css` و`web/app.js`

- [ ] **الخطوة 1: القائمة الجانبية.** في `web/index.html` استبدل محتوى `<nav class="nav" aria-label="الأقسام">` كاملًا (الأزرار الخمسة) بـ:

```html
    <div class="nav-group">منشأتي</div>
    <button data-page="tenant">
      <svg viewBox="0 0 24 24"><path d="M3 21h18M5 21V8l7-5 7 5v13"/><path d="M9 21v-6h6v6"/></svg>
      <span>منشأتي</span>
    </button>
    <button data-page="analyst">
      <svg viewBox="0 0 24 24"><rect x="4" y="7" width="16" height="12" rx="3"/><path d="M12 3v4M9 12h.01M15 12h.01M9 16h6"/></svg>
      <span>المحلل الذكي</span>
    </button>
    <button data-page="settings">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z"/></svg>
      <span>الإعدادات</span>
    </button>
    <div class="nav-group">عرض بيانات CICIDS</div>
    <button data-page="overview" class="on">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>
      <span>نظرة عامة</span>
    </button>
    <button data-page="detect">
      <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/><path d="M8 11h6"/></svg>
      <span>الكشف اللحظي</span>
    </button>
    <button data-page="forecast">
      <svg viewBox="0 0 24 24"><path d="M3 17l5-5 4 3 8-8"/><path d="M15 7h5v5"/></svg>
      <span>التنبؤ</span>
    </button>
    <button data-page="respond">
      <svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z"/><path d="M9 9l6 6M15 9l-6 6"/></svg>
      <span>الاستجابة</span>
    </button>
```

- [ ] **الخطوة 2: صندوق المنشأة.** داخل `<div class="side-foot">` أضف قبل `<div class="sys" ...>`:

```html
    <div class="tenant-box" id="tenantBox" hidden>
      <span id="tenantName"></span>
      <button class="btn-ghost" data-logout>خروج</button>
    </div>
```

- [ ] **الخطوة 3: الصفحات الثلاث الجديدة وحوار المفاتيح.** قبل التعليق `<!-- ---------- المحلل الذكي ---------- -->` أضف:

```html
  <!-- ---------- دخول المنشأة ---------- -->
  <section class="page" id="p-login">
    <div class="login-grid">
      <form class="card" id="signupForm">
        <div class="card-title">سجّل منشأتك</div>
        <p class="sec-q">تحصل على مفتاحين: مفتاح استقبال لأنظمتك، ومفتاح لوحة للدخول والموافقة.</p>
        <input class="field" id="signupName" required maxlength="80" placeholder="اسم المنشأة" autocomplete="organization">
        <button class="btn-primary" type="submit">تسجيل</button>
      </form>
      <form class="card" id="loginForm">
        <div class="card-title">دخول</div>
        <p class="sec-q">ادخل بمفتاح اللوحة الذي حصلت عليه عند التسجيل.</p>
        <input class="field mono" id="loginKey" required placeholder="pc_dash_…" autocomplete="off" dir="ltr">
        <button class="btn-primary" type="submit">دخول</button>
      </form>
    </div>
  </section>

  <!-- ---------- منشأتي ---------- -->
  <section class="page" id="p-tenant">
    <div class="card">
      <div class="card-head"><div><b>بيانات المنشأة</b></div><button class="btn-ghost" data-logout>خروج</button></div>
      <div id="tenantInfo" style="margin-top:10px"></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-title">المصادر المتصلة</div>
      <div class="empty-state">
        <b>لا توجد مصادر متصلة بعد</b>
        <span>ربط السجلات والخوادم والمواقع يأتي في الأجزاء القادمة. استقبال السجلات قيد التطوير، وسيكون الطلب بهذا الشكل (<span class="mono">INGEST_KEY</span> = مفتاح الاستقبال):</span>
      </div>
      <pre class="code mono" id="ingestExample"></pre>
    </div>
  </section>

  <!-- ---------- الإعدادات ---------- -->
  <section class="page" id="p-settings">
    <form class="card" id="settingsForm">
      <div class="card-title">التنبيهات</div>
      <label class="field-label" for="webhookUrl">رابط Webhook لاستقبال التنبيهات (يُفعَّل لاحقًا)</label>
      <input class="field" id="webhookUrl" type="url" placeholder="https://example.com/hooks/security" dir="ltr">
      <div class="card-title" style="margin-top:16px">قائمة السماح</div>
      <label class="field-label" for="allowlist">عناوين IP لا تُحظر أبدًا، عنوان في كل سطر</label>
      <textarea class="field mono" id="allowlist" rows="4" dir="ltr"></textarea>
      <button class="btn-primary" type="submit">حفظ الإعدادات</button>
    </form>
    <div class="card" style="margin-top:14px">
      <div class="card-head">
        <div><b>تدوير المفاتيح</b><span>يولّد مفتاحين جديدين ويُبطل الحاليين فورًا. حدّث أنظمتك بالمفتاح الجديد.</span></div>
        <button class="btn-ghost" id="rotateBtn">تدوير المفاتيح</button>
      </div>
    </div>
  </section>
```

وقبل `<div class="toast" id="toast"></div>` أضف:

```html
<dialog class="card keys-dialog" id="keysDialog">
  <div class="card-title">مفاتيح منشأتك</div>
  <div class="error-state"><b>احفظ المفتاحين الآن.</b> لن يُعرضا مرة أخرى.</div>
  <div class="key-row">
    <span>مفتاح الاستقبال (لأنظمتك، إرسال فقط)</span>
    <code class="mono" id="ingestKey"></code>
    <button class="btn-ghost" data-copy="ingestKey">نسخ</button>
  </div>
  <div class="key-row">
    <span>مفتاح اللوحة (للدخول والموافقة)</span>
    <code class="mono" id="dashKey"></code>
    <button class="btn-ghost" data-copy="dashKey">نسخ</button>
  </div>
  <button class="btn-primary" id="keysDone">حفظتهما، متابعة</button>
</dialog>
```

- [ ] **الخطوة 4: الأنماط.** في `web/style.css` أضف قبل قسم `الاستجابة لأحجام الشاشات`:

```css
/* ===================================================================
   المنصة: الدخول، المنشأة، الإعدادات
   =================================================================== */
.nav-group{font-size:.72rem;color:var(--ink-3);font-weight:600;padding:12px 12px 4px}
.tenant-box{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 12px;
  margin-bottom:8px;border:1px solid var(--line);border-radius:10px;background:var(--panel);font-size:.84rem;font-weight:600}
.tenant-box .btn-ghost,.card-head .btn-ghost{padding:5px 12px;font-size:.78rem}
.login-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.login-grid form{display:flex;flex-direction:column;gap:10px}
.field{width:100%;border:1px solid var(--line);background:var(--bg-2);color:var(--ink);border-radius:10px;
  padding:10px 12px;font:inherit;font-size:.88rem}
textarea.field{resize:vertical}
.field-label{display:block;font-size:.8rem;color:var(--ink-2);margin:6px 0}
#settingsForm .btn-primary{margin-top:14px}
.code{margin:12px 0 0;padding:12px 14px;background:var(--bg-2);border:1px solid var(--line-soft);border-radius:10px;
  font-size:.78rem;white-space:pre-wrap;word-break:break-all;text-align:left}
.keys-dialog{width:min(560px,calc(100vw - 32px));color:var(--ink);display:none;flex-direction:column;gap:12px}
.keys-dialog[open]{display:flex}
.keys-dialog::backdrop{background:rgba(0,0,0,.6)}
.key-row{display:grid;grid-template-columns:1fr auto;gap:6px 10px;align-items:center;font-size:.82rem}
.key-row span{grid-column:1/-1;color:var(--ink-2)}
.key-row code{padding:8px 10px;background:var(--bg-2);border-radius:8px;font-size:.76rem;word-break:break-all}
```

وفي كتلة `@media (max-width:860px)` أضف بعد سطر `.nav button{...}`:

```css
  .nav{overflow-x:auto}
  .nav button{flex:0 0 76px}
  .nav-group{display:none}
  .login-grid{grid-template-columns:1fr}
```

- [ ] **الخطوة 5: جلسة المنشأة في `web/app.js`.** بعد السطر `const OFFLINE = ...` أضف:

```js

/* ---------- جلسة المنشأة (مفتاح اللوحة في sessionStorage، يُرسل في الترويسة فقط) ---------- */
const DASH_KEY = "pc_dashboard_key";
const TENANT_PAGES = new Set(["tenant", "analyst", "settings"]);
let afterLoginPage = "tenant";
function dashKey() {
  try { return sessionStorage.getItem(DASH_KEY); } catch (e) { return null; }
}
function setDashKey(k) {
  try { k ? sessionStorage.setItem(DASH_KEY, k) : sessionStorage.removeItem(DASH_KEY); } catch (e) {}
}
async function tenantApi(path, method = "GET", body) {
  const headers = { Authorization: "Bearer " + (dashKey() || "") };
  if (body) headers["Content-Type"] = "application/json";
  const r = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { logout(); throw new Error("مفتاح غير صالح أو منتهٍ، ادخل من جديد"); }
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "طلب غير صالح");
  return data;
}
```

- [ ] **الخطوة 6: الصفحات والبوابة.** في كائن `PAGES` أضف بعد سطر `analyst`:

```js
  tenant:   ["منشأتي", "بيانات منشأتك والمصادر المتصلة"],
  settings: ["الإعدادات", "التنبيهات وقائمة السماح ومفاتيح الوصول"],
  login:    ["دخول المنشأة", "سجّل منشأتك أو ادخل بمفتاح اللوحة"],
```

وفي `setPage` استبدل السطر الأول:

```js
  if (!PAGES[p]) p = "overview";
```

بـ:

```js
  if (!PAGES[p]) p = "overview";
  if (TENANT_PAGES.has(p) && !dashKey()) { afterLoginPage = p; p = "login"; }
```

- [ ] **الخطوة 7: المحلل على `/api/v1`.** في قسم المحلل الذكي:

(أ) في `initAgent` استبدل `const s = await api("/api/agent/status");` بـ `const s = await tenantApi("/api/v1/agent/status");`، واحذف السطر `initAgent();` الذي يليها (يُستدعى بعد الدخول).

(ب) في مستمع `#agentStart` استبدل:

```js
  let r;
  try { r = await post("/api/agent/investigate?family=" + encodeURIComponent($("#agentFamily").value)); }
  catch (e) { $("#agentReport").innerHTML = OFFLINE; btn.disabled = false; return; }
  if (r.error) { $("#agentReport").innerHTML = errorHtml("تعذّر بدء التحقيق", esc(r.error)); btn.disabled = false; return; }

  agentIncident = r.incident_id;
  if (agentStream) agentStream.close();
  agentStream = new EventSource(API + "/api/agent/stream/" + encodeURIComponent(r.incident_id));
```

بـ:

```js
  let r, token;
  try {
    r = await tenantApi("/api/v1/agent/investigate?family=" + encodeURIComponent($("#agentFamily").value), "POST");
    ({ token } = await tenantApi("/api/v1/agent/stream-token", "POST", { incident_id: r.incident_id }));
  } catch (e) {
    $("#agentReport").innerHTML = errorHtml("تعذّر بدء التحقيق", esc(e.message));
    btn.disabled = false;
    return;
  }

  agentIncident = r.incident_id;
  if (agentStream) agentStream.close();
  agentStream = new EventSource(API + "/api/v1/agent/stream/" + encodeURIComponent(r.incident_id) +
    "?token=" + encodeURIComponent(token));
```

(ج) في مستمع `#agentReport` استبدل:

```js
    const r = await api("/api/agent/decide", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: agentIncident, proposal_id: Number(row.dataset.id), decision: b.dataset.decide }),
    });
```

بـ:

```js
    const r = await tenantApi("/api/v1/agent/decide", "POST",
      { incident_id: agentIncident, proposal_id: Number(row.dataset.id), decision: b.dataset.decide });
```

وفي نفس المستمع استبدل `toast("تعذّر الاتصال بالخادم");` بـ `toast(err.message);`.

(د) في `sendChat` استبدل:

```js
    const r = await api("/api/agent/chat", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ incident_id: agentIncident, message: text }),
    });
```

بـ:

```js
    const r = await tenantApi("/api/v1/agent/chat", "POST", { incident_id: agentIncident, message: text });
```

وفي `catch` الخاصة بها استبدل `'<span style="color:var(--danger)">تعذّر الاتصال بالخادم.</span>'` بـ `` `<span style="color:var(--danger)">${esc(e.message)}</span>` ``.

- [ ] **الخطوة 8: منطق المنشأة.** أضف إلى نهاية `web/app.js`:

```js

/* ---------- المنشأة: التسجيل، الدخول، الإعدادات ---------- */
function showKeys(keys) {
  $("#ingestKey").textContent = keys.ingest_key;
  $("#dashKey").textContent = keys.dashboard_key;
  $("#keysDialog").showModal();
}
$$("[data-copy]").forEach((b) => b.addEventListener("click", () => {
  navigator.clipboard.writeText($("#" + b.dataset.copy).textContent)
    .then(() => toast("نُسخ المفتاح"), () => toast("انسخ المفتاح يدويًا"));
}));
$("#keysDone").addEventListener("click", () => { $("#keysDialog").close(); loadTenant(); });

$("#signupForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await fetch(API + "/api/v1/tenants", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: $("#signupName").value }),
    });
    const d = await r.json();
    if (!r.ok) { toast(typeof d.detail === "string" ? d.detail : "تعذّر التسجيل"); return; }
    setDashKey(d.dashboard_key);
    $("#signupName").value = "";
    showKeys(d);
  } catch (err) {
    toast("تعذّر الاتصال بالخادم");
  }
});

$("#loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  setDashKey($("#loginKey").value.trim());
  $("#loginKey").value = "";
  loadTenant();
});

async function loadTenant() {
  let me;
  try { me = await tenantApi("/api/v1/me"); }
  catch (e) { toast(e.message); return; }
  $("#tenantName").textContent = me.name;
  $("#tenantBox").hidden = false;
  $("#tenantInfo").innerHTML = `
    <div class="kv"><span>الاسم</span><span>${esc(me.name)}</span></div>
    <div class="kv"><span>المعرّف</span><span class="mono">${esc(me.tenant_id)}</span></div>
    <div class="kv"><span>تاريخ التسجيل</span><span>${new Date(me.created_at * 1000).toLocaleDateString("ar")}</span></div>`;
  $("#ingestExample").textContent =
    `curl -X POST ${location.origin}/api/v1/ingest/logs \\\n  -H "Authorization: Bearer $INGEST_KEY" \\\n  --data-binary @access.log`;
  $("#webhookUrl").value = me.settings.webhook_url || "";
  $("#allowlist").value = me.settings.allowlist.join("\n");
  initAgent();
  if (document.body.dataset.page === "login") setPage(afterLoginPage);
}

function logout() {
  setDashKey(null);
  $("#tenantBox").hidden = true;
  if (TENANT_PAGES.has(document.body.dataset.page)) setPage(document.body.dataset.page);   // يعيد لشاشة الدخول
}
$$("[data-logout]").forEach((b) => b.addEventListener("click", logout));

$("#settingsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await tenantApi("/api/v1/settings", "PUT", {
      webhook_url: $("#webhookUrl").value.trim() || null,
      allowlist: $("#allowlist").value.split("\n").map((s) => s.trim()).filter(Boolean),
    });
    toast("حُفظت الإعدادات");
  } catch (err) {
    toast(err.message);
  }
});

$("#rotateBtn").addEventListener("click", async () => {
  if (!confirm("سيتوقف المفتاحان الحاليان فورًا. متابعة؟")) return;
  try {
    const keys = await tenantApi("/api/v1/keys/rotate", "POST");
    setDashKey(keys.dashboard_key);
    showKeys(keys);
  } catch (err) {
    toast(err.message);
  }
});

if (dashKey()) loadTenant();
```

- [ ] **الخطوة 9: فحص صياغة JavaScript**

```bash
node --check web/app.js && echo ok
```

- [ ] **الخطوة 10: التحقق في المتصفح** (الخادم على 8005 من المهمة 4، وتحديث بـ Cmd+Shift+R):
  - صفحات CICIDS تعمل بلا دخول كما كانت.
  - «منشأتي» بلا دخول ← شاشة الدخول. التسجيل ← حوار المفتاحين (النسخ يعمل) ← «متابعة» ← صفحة «منشأتي» بالاسم والمعرّف.
  - «المحلل الذكي»: تحقيق «فحص المنافذ» في وضع العرض حتى النهاية، والموافقة والمحادثة تعمل.
  - «الإعدادات»: حفظ `172.16.0.1` في قائمة السماح ← تحقيق جديد بلا مقترح حظر عليه. رابط `ftp://x` يُرفض برسالة عربية.
  - «تدوير المفاتيح» ← حوار بمفتاحين جديدين، والمفتاح القديم لا يعمل عند الدخول به.
  - تبويب خاص جديد (sessionStorage فارغ) بمفتاح منشأة ثانية: لا يرى شيئًا من الأولى.
  - «خروج» ← شاشة الدخول. والجوال 375px بلا تمرير أفقي، والوضعان الداكن والفاتح، بلا أخطاء في الـ console.

- [ ] **الخطوة 11: Commit**

```bash
git add web/index.html web/style.css web/app.js
git commit -m "Add tenant login, keys dialog, business and settings pages"
```

---

## المهمة 6: التوثيق

**الملفات:** تعديل `README.md` و`docs/superpowers/specs/2026-10-26-multi-tenant-core-design.md`

- [ ] **الخطوة 1:** في README، في قسم «المميزات» أضف:

```markdown
- **منصة متعددة المنشآت:** كل منشأة تسجّل وتحصل على مفتاح استقبال (إرسال فقط) ومفتاح لوحة، وبياناتها في مجلد معزول، ووكيلها لا يرى إلا بياناتها ولا ينفّذ شيئًا دون موافقتها.
```

- [ ] **الخطوة 2:** في README أضف قسمًا قبل «المحلل الذكي (اختياري)»:

```markdown
## المنصة

افتح الواجهة ← «منشأتي» ← «سجّل منشأتك». يظهر المفتاحان مرة واحدة فقط، فاحفظهما. بيانات المنشآت في `data/` (مستثنى من git): `registry.db` يحوي بصمات المفاتيح لا المفاتيح نفسها، ولكل منشأة مجلد `data/tenants/<المعرّف>/`.
```

- [ ] **الخطوة 3:** في مستند التصميم، القسم 3، استبدل سطر `tenant.db`:

```markdown
- `data/tenants/<tenant_id>/tenant.db` — ملف مستقل لكل منشأة: الإعدادات (`webhook_url`، `allowlist`)، وسجل الحوادث والمقترحات والقرارات.
```

بـ:

```markdown
- `data/tenants/<tenant_id>/tenant.db` — ملف مستقل لكل منشأة: الإعدادات (`webhook_url`، `allowlist`). سجلات الحوادث (المقترحات والقرارات والمحادثة) ملفات JSON في `agent_runs/` بجانبه.
```

- [ ] **الخطوة 4: تشغيل كل الاختبارات ثم Commit**

```bash
project/bin/python -m pytest tests -q
git add README.md docs/superpowers/specs/2026-10-26-multi-tenant-core-design.md
git commit -m "Document the multi-tenant platform"
```

المتوقع: `56 passed`
