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
