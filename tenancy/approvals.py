"""
رموز روابط الموافقة: رمز لكل مقترح تنفيذي معلّق، صالح ساعة، ولمرة واحدة.
تُخزَّن بصماتها في registry.db على مستوى المنصة، لأن الرمز نفسه هو ما يحدد
المنشأة (الرابط يُفتح بلا دخول).
"""

import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class ApprovalTokens:
    TTL = 3600

    def __init__(self, path, clock=time.time):
        self.path, self.clock = Path(path), clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS approval_tokens (token_hash TEXT PRIMARY KEY, tenant_id TEXT,
                incident_id TEXT, proposal_id INTEGER, expires_at REAL, used_at REAL)""")

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path)
        try:
            with con:
                yield con
        finally:
            con.close()

    def issue(self, tenant_id, incident_id, proposal_id):
        token = secrets.token_urlsafe(32)
        with self._db() as db:
            db.execute("INSERT INTO approval_tokens VALUES (?, ?, ?, ?, ?, NULL)",
                       (_hash(token), tenant_id, incident_id, proposal_id, self.clock() + self.TTL))
        return token

    def _row(self, db, token):
        row = db.execute("""SELECT tenant_id, incident_id, proposal_id FROM approval_tokens
                            WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?""",
                         (_hash(token), self.clock())).fetchone()
        return {"tenant_id": row[0], "incident_id": row[1], "proposal_id": row[2]} if row else None

    def peek(self, token):
        """يعرض صاحب الرمز دون استهلاكه (صفحة التأكيد)."""
        with self._db() as db:
            return self._row(db, token)

    def consume(self, token):
        """يستهلك الرمز ذريًا: ينجح مرة واحدة فقط."""
        with self._db() as db:
            row = self._row(db, token)
            if row is None:
                return None
            cur = db.execute("UPDATE approval_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
                             (self.clock(), _hash(token)))
            return row if cur.rowcount == 1 else None
