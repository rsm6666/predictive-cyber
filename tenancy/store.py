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

    def logs(self, tenant_id):
        from ingest.store import LogStore
        return LogStore(self.dir(tenant_id) / "tenant.db")

    def net(self, tenant_id):
        from netdetect.store import NetStore
        return NetStore(self.dir(tenant_id) / "tenant.db")

    def anomaly_path(self, tenant_id):
        return self.dir(tenant_id) / "anomaly.joblib"

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
