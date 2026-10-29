"""
فك ضغط دفعة الوكيل بحد، والتحقق منها حقلًا حقلًا. الحقول غير المعروفة تُحذف،
والدفعة التي فيها قيمة واحدة غير صالحة تُرفض كاملة بسبب واضح.
"""

import ipaddress
import json
import math
import zlib

from sensor.agent import MAX_FLOWS
from sensor.flows import FEATURES

MAX_COMPRESSED = 5 * 1024 * 1024
MAX_RAW = 20 * 1024 * 1024
MAX_AGE = 7 * 86400
MAX_FUTURE = 300
MAX_WINDOW = 300


class BatchError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def decompress(body, encoding):
    if (encoding or "").lower() != "gzip":
        if len(body) > MAX_RAW:
            raise BatchError(413, "الدفعة أكبر من 20MB")
        return body
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = d.decompress(body, MAX_RAW + 1)
    except zlib.error:
        raise BatchError(422, "ضغط gzip غير صالح") from None
    if len(raw) > MAX_RAW or d.unconsumed_tail:
        raise BatchError(413, "الدفعة بعد فك الضغط أكبر من 20MB")
    return raw


def _num(v, what, low=None):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        raise BatchError(422, f"{what}: رقم غير صالح")
    if low is not None and v < low:
        raise BatchError(422, f"{what}: قيمة أصغر من المسموح")
    return float(v)


def _int(v, what, high):
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= high:
        raise BatchError(422, f"{what}: عدد صحيح بين 0 و{high}")
    return v


def _ip(v, what):
    try:
        return str(ipaddress.ip_address(v))
    except (ValueError, TypeError):
        raise BatchError(422, f"{what}: عنوان IP غير صالح") from None


def validate(raw, now):
    try:
        b = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise BatchError(422, "JSON غير صالح") from None
    if not isinstance(b, dict) or not isinstance(b.get("flows"), list):
        raise BatchError(422, "الدفعة يجب أن تحوي flows")
    start, end = _num(b.get("window_start"), "window_start"), _num(b.get("window_end"), "window_end")
    if not 0 < end - start <= MAX_WINDOW:
        raise BatchError(422, "مدة النافذة غير منطقية")
    if start < now - MAX_AGE or end > now + MAX_FUTURE:
        raise BatchError(422, "وقت النافذة خارج المسموح (أقدم من 7 أيام أو في المستقبل)")
    if len(b["flows"]) > MAX_FLOWS:
        raise BatchError(422, f"أكثر من {MAX_FLOWS} تدفق في النافذة")
    agent = b.get("agent") if isinstance(b.get("agent"), dict) else {}
    flows = []
    for i, f in enumerate(b["flows"]):
        if not isinstance(f, dict) or not isinstance(f.get("f"), list) or len(f["f"]) != len(FEATURES):
            raise BatchError(422, f"التدفق {i}: يجب أن يحوي {len(FEATURES)} خاصية")
        flows.append({
            "src": _ip(f.get("src"), f"التدفق {i}"), "dst": _ip(f.get("dst"), f"التدفق {i}"),
            "sport": _int(f.get("sport", 0), f"التدفق {i} sport", 65535),
            "dport": _int(f.get("dport"), f"التدفق {i} dport", 65535),
            "proto": _int(f.get("proto"), f"التدفق {i} proto", 255),
            "start": _num(f.get("start"), f"التدفق {i} start"), "end": _num(f.get("end"), f"التدفق {i} end"),
            "f": [_num(v, f"التدفق {i} {FEATURES[j]}", low=-1) for j, v in enumerate(f["f"])],   # Init_Win قد تكون -1
        })
    return {"agent": {"host": str(agent.get("host") or "server")[:100], "version": str(agent.get("version") or "")[:20]},
            "window_start": start, "window_end": end, "truncated": bool(b.get("truncated")), "flows": flows}
