"""
تخزين سجلات منشأة واحدة في tenant.db الخاص بها (العزل كما في الجزء 1):
الأحداث، التنبيهات، الحوادث، وحالة نموذج الشذوذ.

الدمج والتجميع بأوقات الأحداث لا بالساعة، فيعمل التاريخ المُعاد كالبث:
  - نفس (النوع، العنوان) خلال 15 دقيقة ← يُدمج في التنبيه القائم
  - تنبيه خلال 30 دقيقة من آخر تحديث لحادثة سجلات غير مغلقة ← يُلحق بها
حوادث المراقبة الخارجية (kind = 'monitor') تُفتح منفردة ولا يُلحق بها تنبيه سجلات.
التنبيهات الشبكية من وكيل الخادم (kind = 'network') تُدمج وتُجمّع بنفس القواعد داخل نوعها فقط.
الحملة (kind = 'campaign') حادثة بلا تنبيهات، وأعضاؤها يشيرون إليها بعمود campaign،
وأسباب الربط في campaign_links (الجزء 6).
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

MERGE_SECONDS = 15 * 60
GROUP_SECONDS = 30 * 60
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
WEB_COLS = ("ts", "ip", "method", "path", "status", "bytes", "referer", "ua")
FW_COLS = ("ts", "action", "src", "dst", "proto", "dport")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS web_events (ts REAL, ip TEXT, method TEXT, path TEXT, status INTEGER,
    bytes INTEGER, referer TEXT, ua TEXT);
CREATE INDEX IF NOT EXISTS web_ts ON web_events(ts);
CREATE INDEX IF NOT EXISTS web_ip_ts ON web_events(ip, ts);
CREATE TABLE IF NOT EXISTS fw_events (ts REAL, action TEXT, src TEXT, dst TEXT, proto TEXT, dport INTEGER);
CREATE INDEX IF NOT EXISTS fw_ts ON fw_events(ts);
CREATE INDEX IF NOT EXISTS fw_src_ts ON fw_events(src, ts);
CREATE TABLE IF NOT EXISTS incidents (n INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, opened_at REAL,
    updated_at REAL, severity TEXT, kind TEXT NOT NULL DEFAULT 'log');
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, incident INTEGER, type TEXT,
    source TEXT, ip TEXT, first_ts REAL, last_ts REAL, count INTEGER, severity TEXT, evidence TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS anomaly_state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS campaign_links (campaign TEXT, a TEXT, b TEXT, rule TEXT, ip TEXT, reason TEXT,
    downloaded INTEGER, at REAL, UNIQUE (campaign, a, b, rule, ip));
"""


def _incident_id(n):
    return f"log-{n}"


def _incident_n(incident_id):
    if not str(incident_id).startswith("log-") or not incident_id[4:].isdigit():
        return None
    return int(incident_id[4:])


class LogStore:
    def __init__(self, path):
        self.path = Path(path)
        with self._db() as db:
            db.executescript(_SCHEMA)
            cols = {r["name"] for r in db.execute("PRAGMA table_info(incidents)")}
            if "kind" not in cols:          # قاعدة أقدم
                db.execute("ALTER TABLE incidents ADD COLUMN kind TEXT NOT NULL DEFAULT 'log'")
            if "campaign" not in cols:
                db.execute("ALTER TABLE incidents ADD COLUMN campaign TEXT")

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    # ---------------- الأحداث ----------------
    def insert_web(self, events):
        with self._db() as db:
            db.executemany(f"INSERT INTO web_events VALUES ({','.join('?' * len(WEB_COLS))})",
                           [tuple(e[c] for c in WEB_COLS) for e in events])
        return len(events)

    def insert_fw(self, events):
        with self._db() as db:
            db.executemany(f"INSERT INTO fw_events VALUES ({','.join('?' * len(FW_COLS))})",
                           [tuple(e[c] for c in FW_COLS) for e in events])
        return len(events)

    def prune(self, now, keep_seconds=7 * 86400, max_rows=500_000):
        with self._db() as db:
            for table in ("web_events", "fw_events"):
                db.execute(f"DELETE FROM {table} WHERE ts < ?", (now - keep_seconds,))
                db.execute(f"""DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table}
                               ORDER BY ts DESC LIMIT -1 OFFSET ?)""", (max_rows,))

    def _between(self, table, ip_col, start, end, ip):
        sql = f"SELECT * FROM {table} WHERE ts >= ? AND ts <= ?"
        args = [start, end]
        if ip is not None:
            sql += f" AND {ip_col} = ?"
            args.append(ip)
        with self._db() as db:
            return [dict(r) for r in db.execute(sql + " ORDER BY ts", args)]

    def web_between(self, start, end, ip=None):
        return self._between("web_events", "ip", start, end, ip)

    def fw_between(self, start, end, ip=None):
        return self._between("fw_events", "src", start, end, ip)

    def source_stats(self):
        out = {}
        with self._db() as db:
            for name, table in (("web", "web_events"), ("firewall", "fw_events")):
                row = db.execute(f"SELECT COUNT(*), MAX(ts) FROM {table}").fetchone()
                out[name] = {"events": row[0], "last_ts": row[1]}
        return out

    # ---------------- التنبيهات والحوادث ----------------
    def add_alert(self, a, kind="log"):
        """يدمج أو يضيف تنبيهًا ويلحقه بحادثة من نفس النوع. ← (alert_id، incident_id، هل فُتحت حادثة جديدة)."""
        with self._db() as db:
            prev = db.execute("""SELECT id, incident, count, first_ts, last_ts FROM alerts
                                 WHERE type = ? AND ip = ? AND last_ts >= ? ORDER BY last_ts DESC LIMIT 1""",
                              (a["type"], a["ip"], a["first_ts"] - MERGE_SECONDS)).fetchone()
            if prev is not None:
                same_bucket = a["first_ts"] <= prev["last_ts"]
                count = max(prev["count"], a["count"]) if same_bucket else prev["count"] + a["count"]
                db.execute("UPDATE alerts SET count = ?, last_ts = ? WHERE id = ?",
                           (count, max(prev["last_ts"], a["last_ts"]), prev["id"]))
                self._touch(db, prev["incident"], a)
                return prev["id"], _incident_id(prev["incident"]), False

            inc = db.execute("""SELECT n FROM incidents WHERE status != 'closed' AND kind = ? AND updated_at >= ?
                                ORDER BY updated_at DESC LIMIT 1""", (kind, a["first_ts"] - GROUP_SECONDS)).fetchone()
            new = inc is None
            if new:
                n = db.execute("INSERT INTO incidents (status, opened_at, updated_at, severity, kind) VALUES (?, ?, ?, ?, ?)",
                               ("open", a["first_ts"], a["last_ts"], a["severity"], kind)).lastrowid
            else:
                n = inc["n"]
                self._touch(db, n, a)
            return self._insert_alert(db, n, a), _incident_id(n), new

    def open_incident(self, a, kind="monitor"):
        """حادثة جديدة منفردة بتنبيه واحد (للمراقبة الخارجية). ← incident_id"""
        with self._db() as db:
            n = db.execute("INSERT INTO incidents (status, opened_at, updated_at, severity, kind) VALUES (?, ?, ?, ?, ?)",
                           ("open", a["first_ts"], a["last_ts"], a["severity"], kind)).lastrowid
            self._insert_alert(db, n, a)
        return _incident_id(n)

    @staticmethod
    def _insert_alert(db, n, a):
        return db.execute(
            """INSERT INTO alerts (incident, type, source, ip, first_ts, last_ts, count, severity, evidence, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (n, a["type"], a["source"], a["ip"], a["first_ts"], a["last_ts"], a["count"], a["severity"],
             json.dumps(a["evidence"], ensure_ascii=False), json.dumps(a["details"], ensure_ascii=False))).lastrowid

    @staticmethod
    def _touch(db, n, a):
        row = db.execute("SELECT updated_at, severity FROM incidents WHERE n = ?", (n,)).fetchone()
        severity = max(row["severity"], a["severity"], key=SEVERITY_RANK.get)
        db.execute("UPDATE incidents SET updated_at = ?, severity = ? WHERE n = ?",
                   (max(row["updated_at"], a["last_ts"]), severity, n))

    def alerts(self, incident_id):
        n = _incident_n(incident_id)
        with self._db() as db:
            rows = db.execute("SELECT * FROM alerts WHERE incident = ? ORDER BY first_ts", (n,)).fetchall()
        return [{**dict(r), "incident": incident_id, "evidence": json.loads(r["evidence"]),
                 "details": json.loads(r["details"])} for r in rows]

    def _incident_row(self, r):
        return {"id": _incident_id(r["n"]), "status": r["status"], "opened_at": r["opened_at"],
                "updated_at": r["updated_at"], "severity": r["severity"], "kind": r["kind"],
                "campaign": r["campaign"]}

    def incidents(self, limit=50):
        with self._db() as db:
            rows = db.execute("SELECT * FROM incidents ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
        return [self._incident_row(r) for r in rows]

    def incident(self, incident_id):
        n = _incident_n(incident_id)
        with self._db() as db:
            row = db.execute("SELECT * FROM incidents WHERE n = ?", (n,)).fetchone()
        return self._incident_row(row) if row else None

    def set_incident_status(self, incident_id, status):
        with self._db() as db:
            db.execute("UPDATE incidents SET status = ? WHERE n = ?", (status, _incident_n(incident_id)))

    # ---------------- الحملات (الجزء 6) ----------------
    def new_campaign(self, ts, severity):
        with self._db() as db:
            n = db.execute("INSERT INTO incidents (status, opened_at, updated_at, severity, kind) VALUES (?, ?, ?, ?, ?)",
                           ("open", ts, ts, severity, "campaign")).lastrowid
        return _incident_id(n)

    def set_campaign(self, incident_id, campaign_id):
        with self._db() as db:
            db.execute("UPDATE incidents SET campaign = ? WHERE n = ?", (campaign_id, _incident_n(incident_id)))

    def campaign_members(self, campaign_id):
        with self._db() as db:
            rows = db.execute("SELECT * FROM incidents WHERE campaign = ? ORDER BY opened_at, n",
                              (campaign_id,)).fetchall()
        return [self._incident_row(r) for r in rows]

    def add_link(self, campaign, a, b, rule, ip, reason, downloaded, at):
        """← هل أُضيف سبب جديد (الربط المكرر يُتجاهل)."""
        with self._db() as db:
            cur = db.execute("INSERT OR IGNORE INTO campaign_links VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (campaign, a, b, rule, ip, reason, int(downloaded), at))
        return cur.rowcount == 1

    def links(self, campaign_id):
        with self._db() as db:
            rows = db.execute("SELECT * FROM campaign_links WHERE campaign = ? ORDER BY at", (campaign_id,)).fetchall()
        return [{**dict(r), "downloaded": bool(r["downloaded"])} for r in rows]

    def move_campaign(self, src, dst):
        with self._db() as db:
            db.execute("UPDATE incidents SET campaign = ? WHERE campaign = ?", (dst, src))
            db.execute("UPDATE OR IGNORE campaign_links SET campaign = ? WHERE campaign = ?", (dst, src))
            db.execute("DELETE FROM campaign_links WHERE campaign = ?", (src,))

    def update_incident(self, incident_id, **fields):
        """severity و updated_at و status فقط."""
        assert set(fields) <= {"severity", "updated_at", "status"}
        with self._db() as db:
            db.execute(f"UPDATE incidents SET {', '.join(f'{k} = ?' for k in fields)} WHERE n = ?",
                       (*fields.values(), _incident_n(incident_id)))

    def incidents_with_ip(self, ip, start, end):
        """حوادث السجلات والشبكة التي فيها تنبيه بهذا العنوان، وتتقاطع فترتها مع [start، end]."""
        with self._db() as db:
            rows = db.execute("""SELECT DISTINCT i.n FROM incidents i JOIN alerts a ON a.incident = i.n
                                 WHERE a.ip = ? AND i.kind IN ('log', 'network')
                                   AND i.opened_at <= ? AND i.updated_at >= ? ORDER BY i.n""",
                              (ip, end, start)).fetchall()
        return [_incident_id(r["n"]) for r in rows]

    def path_requests(self, path, start, end, ip=None):
        """طلبات الويب لمسار بعينه (مع سلسلة استعلام أو بدونها)."""
        sql = "SELECT * FROM web_events WHERE ts >= ? AND ts <= ? AND (path = ? OR substr(path, 1, ?) = ?)"
        args = [start, end, path, len(path) + 1, path + "?"]
        if ip is not None:
            sql += " AND ip = ?"
            args.append(ip)
        with self._db() as db:
            return [dict(r) for r in db.execute(sql + " ORDER BY ts", args)]

    def rule_alert_spans(self):
        with self._db() as db:
            rows = db.execute("SELECT ip, first_ts, last_ts FROM alerts WHERE type != 'anomaly' AND source = 'web'")
            return [(r["ip"], r["first_ts"], r["last_ts"]) for r in rows]

    # ---------------- حالة نموذج الشذوذ ----------------
    def state_get(self, key, default=None):
        with self._db() as db:
            row = db.execute("SELECT value FROM anomaly_state WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def state_set(self, key, value):
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO anomaly_state VALUES (?, ?)", (key, json.dumps(value)))
