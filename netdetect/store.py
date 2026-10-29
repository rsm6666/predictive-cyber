"""
تدفقات وكيل الخادم لمنشأة واحدة في tenant.db الخاص بها (العزل كما في الجزء 1):
net_flows (الخصائص الـ77 كنص JSON) و net_windows (ملخص كل نافذة بخصائص LSTM).
النافذة المعادة (نفس البداية) تُتجاهل، فإعادة الإرسال من مخزن الوكيل آمنة.
"""

import json
import sqlite3
from contextlib import contextmanager

import pandas as pd

from sensor.flows import FEATURES

KEEP_SECONDS = 7 * 86400
MAX_FLOWS = 500_000
OFFLINE_AFTER = 3 * 60
WINDOW_COLS = ("total_flows", "unique_dst_ports", "unique_src_ips", "avg_flow_duration", "avg_packet_size",
               "total_fwd_packets", "total_bwd_packets")

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS net_flows (ts REAL, src TEXT, dst TEXT, dport INTEGER, proto INTEGER, f TEXT);
CREATE INDEX IF NOT EXISTS net_flows_ts ON net_flows(ts);
CREATE TABLE IF NOT EXISTS net_windows (start REAL PRIMARY KEY, end REAL, received_at REAL, host TEXT,
    flows INTEGER, truncated INTEGER, {", ".join(f"{c} REAL" for c in WINDOW_COLS)});
"""


def window_summary(flows):
    """نفس تعريف نوافذ تدريب LSTM (live_monitor.window_features)."""
    if not flows:
        return dict.fromkeys(WINDOW_COLS, 0.0)
    col = {name: FEATURES.index(name) for name in
           ("Flow Duration", "Average Packet Size", "Total Fwd Packets", "Total Backward Packets")}
    n = len(flows)
    return {"total_flows": float(n), "unique_dst_ports": float(len({f["dport"] for f in flows})),
            "unique_src_ips": float(len({f["src"] for f in flows})),
            "avg_flow_duration": sum(f["f"][col["Flow Duration"]] for f in flows) / n,
            "avg_packet_size": sum(f["f"][col["Average Packet Size"]] for f in flows) / n,
            "total_fwd_packets": float(sum(f["f"][col["Total Fwd Packets"]] for f in flows)),
            "total_bwd_packets": float(sum(f["f"][col["Total Backward Packets"]] for f in flows))}


class NetStore:
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

    def add_window(self, batch, received_at):
        """← هل النافذة جديدة (False = إعادة إرسال لنافذة مخزّنة)."""
        flows = batch["flows"]
        summary = window_summary(flows)
        with self._db() as db:
            cur = db.execute(f"INSERT OR IGNORE INTO net_windows VALUES ({','.join('?' * (6 + len(WINDOW_COLS)))})",
                             (batch["window_start"], batch["window_end"], received_at, batch["agent"]["host"],
                              len(flows), int(batch["truncated"]), *summary.values()))
            if cur.rowcount == 0:
                return False
            db.executemany("INSERT INTO net_flows VALUES (?, ?, ?, ?, ?, ?)",
                           [(f["start"], f["src"], f["dst"], f["dport"], f["proto"], json.dumps(f["f"]))
                            for f in flows])
        return True

    def prune(self, now):
        with self._db() as db:
            db.execute("DELETE FROM net_flows WHERE ts < ?", (now - KEEP_SECONDS,))
            db.execute("DELETE FROM net_windows WHERE start < ?", (now - KEEP_SECONDS,))
            db.execute("""DELETE FROM net_flows WHERE rowid IN (SELECT rowid FROM net_flows
                          ORDER BY ts DESC LIMIT -1 OFFSET ?)""", (MAX_FLOWS,))

    def flows_between(self, start, end):
        """جدول التدفقات بالخصائص وبالأعمدة التي يقرأها الكاشف السلوكي وأدوات المحلل."""
        with self._db() as db:
            rows = db.execute("SELECT * FROM net_flows WHERE ts >= ? AND ts < ? ORDER BY ts", (start, end)).fetchall()
        df = pd.DataFrame([json.loads(r["f"]) for r in rows], columns=FEATURES)
        df["source_ip"] = df["_src"] = [r["src"] for r in rows]
        df["destination_ip"] = df["_dst"] = [r["dst"] for r in rows]
        df["destination_port"] = df["_dport"] = [r["dport"] for r in rows]
        df["_proto"] = [r["proto"] for r in rows]
        df["ts"] = [r["ts"] for r in rows]
        return df

    def windows(self, until, limit=10):
        """آخر limit نوافذ حتى until (شاملة)، من الأقدم للأحدث."""
        with self._db() as db:
            rows = db.execute("SELECT * FROM net_windows WHERE start <= ? ORDER BY start DESC LIMIT ?",
                              (until, limit)).fetchall()
        return pd.DataFrame([dict(r) for r in reversed(rows)],
                            columns=["start", "end", "received_at", "host", "flows", "truncated", *WINDOW_COLS])

    def status(self, now):
        with self._db() as db:
            last = db.execute("SELECT * FROM net_windows ORDER BY received_at DESC LIMIT 1").fetchone()
            count = db.execute("SELECT COUNT(*) FROM net_windows").fetchone()[0]
            truncated = db.execute("SELECT COUNT(*) FROM net_windows WHERE truncated = 1 AND received_at >= ?",
                                   (now - 3600,)).fetchone()[0]
        if last is None:
            return {"state": "never", "windows": 0}
        return {"state": "connected" if now - last["received_at"] <= OFFLINE_AFTER else "offline",
                "host": last["host"], "windows": count, "last_window": last["start"],
                "received_at": last["received_at"], "flows_per_minute": last["flows"], "truncated_last_hour": truncated}
