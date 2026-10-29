"""
مواقع منشأة واحدة ونتائج فحصها، في tenant.db الخاص بها (العزل كما في الجزء 1).
الفحوص يُحتفظ بها 7 أيام، والملاحظات تُفتح وتُحل بمقارنة كل فحص عميق بالذي قبله.
"""

import json
import sqlite3
from contextlib import contextmanager

KEEP_SECONDS = 7 * 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE,
    token TEXT NOT NULL, verified_at REAL, verify_method TEXT, created_at REAL NOT NULL,
    last_avail_at REAL, last_deep_at REAL, last_manual_at REAL,
    down_streak INTEGER NOT NULL DEFAULT 0, slow_streak INTEGER NOT NULL DEFAULT 0, incident_id TEXT);
CREATE TABLE IF NOT EXISTS checks (site_id INTEGER, ts REAL, kind TEXT, ok INTEGER, status INTEGER,
    ms INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS checks_site_ts ON checks(site_id, ts);
CREATE TABLE IF NOT EXISTS findings (site_id INTEGER, key TEXT, severity TEXT, deduction INTEGER,
    finding TEXT, first_seen REAL, last_seen REAL, resolved_at REAL, incident_id TEXT);
"""


class SiteStore:
    def __init__(self, path):
        self.path = path
        with self._db() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    # ---------------- المواقع ----------------
    def add(self, url, token, now):
        with self._db() as db:
            return db.execute("INSERT INTO sites (url, token, created_at) VALUES (?, ?, ?)",
                              (url, token, now)).lastrowid

    def all(self):
        with self._db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM sites ORDER BY id")]

    def get(self, site_id):
        with self._db() as db:
            row = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        return dict(row) if row else None

    def update(self, site_id, **fields):
        with self._db() as db:
            db.execute(f"UPDATE sites SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                       (*fields.values(), site_id))

    def delete(self, site_id):
        with self._db() as db:
            for table, col in (("sites", "id"), ("checks", "site_id"), ("findings", "site_id")):
                db.execute(f"DELETE FROM {table} WHERE {col} = ?", (site_id,))

    # ---------------- الفحوص ----------------
    def add_check(self, site_id, ts, kind, ok, status, ms, detail):
        with self._db() as db:
            db.execute("INSERT INTO checks VALUES (?, ?, ?, ?, ?, ?, ?)", (site_id, ts, kind, int(ok), status, ms, detail))
            db.execute("DELETE FROM checks WHERE ts < ?", (ts - KEEP_SECONDS,))

    def last_check(self, site_id, kind="avail"):
        with self._db() as db:
            row = db.execute("SELECT * FROM checks WHERE site_id = ? AND kind = ? ORDER BY ts DESC LIMIT 1",
                             (site_id, kind)).fetchone()
        return dict(row) if row else None

    def uptime(self, site_id, since):
        """نسبة فحوص التوفر الناجحة منذ since، أو None بلا فحوص."""
        with self._db() as db:
            ok, total = db.execute("SELECT SUM(ok), COUNT(*) FROM checks WHERE site_id = ? AND kind = 'avail' AND ts >= ?",
                                   (site_id, since)).fetchone()
        return round(100 * ok / total, 1) if total else None

    # ---------------- الملاحظات ----------------
    def open_findings(self, site_id):
        with self._db() as db:
            rows = db.execute("SELECT * FROM findings WHERE site_id = ? AND resolved_at IS NULL ORDER BY deduction DESC, key",
                              (site_id,)).fetchall()
        return [{**json.loads(r["finding"]), "first_seen": r["first_seen"], "incident_id": r["incident_id"]} for r in rows]

    def sync_findings(self, site_id, findings, now):
        """يحدّث الملاحظات المفتوحة بنتيجة فحص عميق. ← (الجديدة، المحلولة بحوادثها)."""
        current = {f["key"]: f for f in findings}
        with self._db() as db:
            open_rows = {r["key"]: dict(r) for r in db.execute(
                "SELECT key, incident_id FROM findings WHERE site_id = ? AND resolved_at IS NULL", (site_id,))}
            new = [f for k, f in current.items() if k not in open_rows]
            resolved = [r for k, r in open_rows.items() if k not in current]
            for f in new:
                db.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                           (site_id, f["key"], f["severity"], f["deduction"], json.dumps(f, ensure_ascii=False), now, now))
            for k in current.keys() & open_rows.keys():
                db.execute("UPDATE findings SET last_seen = ?, finding = ? WHERE site_id = ? AND key = ? AND resolved_at IS NULL",
                           (now, json.dumps(current[k], ensure_ascii=False), site_id, k))
            for r in resolved:
                db.execute("UPDATE findings SET resolved_at = ? WHERE site_id = ? AND key = ? AND resolved_at IS NULL",
                           (now, site_id, r["key"]))
        return new, resolved

    def set_finding_incident(self, site_id, key, incident_id):
        with self._db() as db:
            db.execute("UPDATE findings SET incident_id = ? WHERE site_id = ? AND key = ? AND resolved_at IS NULL",
                       (incident_id, site_id, key))
