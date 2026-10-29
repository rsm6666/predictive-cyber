"""
الصندوق الصادر لمنشأة واحدة (جدول deliveries في tenant.db): كل رسالة لكل
قناة تُسجَّل أولًا ثم يرسلها المرسِل الخلفي، مع إعادة المحاولة عند الفشل.
5 محاولات إجمالًا، والانتظار بينها 5 ثوانٍ ثم 30 ثم دقيقتان ثم 10 دقائق.
"""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

BACKOFF = (5, 30, 120, 600)
MAX_ATTEMPTS = len(BACKOFF) + 1
MAX_RESPONSE = 500


class Outbox:
    def __init__(self, path):
        self.path = Path(path)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, event TEXT, channel TEXT,
                payload TEXT, status TEXT, attempts INTEGER, next_at REAL, last_error TEXT, response TEXT,
                created_at REAL)""")
            db.execute("CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(status, next_at)")

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    def enqueue(self, event, channel, payload, now):
        delivery_id = uuid.uuid4().hex
        with self._db() as db:
            db.execute("INSERT INTO deliveries VALUES (?, ?, ?, ?, 'pending', 0, ?, '', '', ?)",
                       (delivery_id, event, channel, json.dumps(payload, ensure_ascii=False), now, now))
        return delivery_id

    def due(self, now):
        with self._db() as db:
            rows = db.execute("""SELECT * FROM deliveries WHERE status = 'pending' AND next_at <= ?
                                 ORDER BY created_at""", (now,)).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]

    def delivered(self, delivery_id, response):
        with self._db() as db:
            db.execute("""UPDATE deliveries SET status = 'delivered', attempts = attempts + 1, response = ?
                          WHERE id = ?""", (str(response)[:MAX_RESPONSE], delivery_id))

    def attempt_failed(self, delivery_id, error, now):
        with self._db() as db:
            attempts = db.execute("SELECT attempts FROM deliveries WHERE id = ?", (delivery_id,)).fetchone()[0] + 1
            status = "failed" if attempts >= MAX_ATTEMPTS else "pending"
            next_at = now + BACKOFF[attempts - 1] if status == "pending" else now
            db.execute("""UPDATE deliveries SET status = ?, attempts = ?, next_at = ?, last_error = ?
                          WHERE id = ?""", (status, attempts, next_at, str(error)[:MAX_RESPONSE], delivery_id))
        return status

    def recent(self, limit=20):
        with self._db() as db:
            rows = db.execute("""SELECT id, event, channel, status, attempts, last_error, response, created_at
                                 FROM deliveries ORDER BY created_at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def pending_count(self):
        with self._db() as db:
            return db.execute("SELECT COUNT(*) FROM deliveries WHERE status = 'pending'").fetchone()[0]
