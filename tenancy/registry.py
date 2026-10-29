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

    def get(self, tenant_id):
        with self._db() as db:
            row = db.execute("SELECT id, name, created_at FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
        return Tenant(*row) if row else None

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
