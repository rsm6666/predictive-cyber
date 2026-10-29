"""
حالة تحقيق واحد: أحداث الخط الزمني (step/report/agent_error/done)،
الاستهلاك، والحفظ في agent_runs/ كسجل تدقيق. آمنة بين الخيوط: خيط
التحقيق يكتب الأحداث، وطلب SSE ينتظرها بـ wait_events.
"""

import json
import threading
import time
from dataclasses import asdict
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
        self.settled = threading.Event()    # كل ما بعد التحقيق انتهى (حالة الحادثة، التقرير، التالي في الطابور)

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
