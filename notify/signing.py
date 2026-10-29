"""
توقيع رسائل الـ Webhook: HMAC-SHA256 على "<الطابع الزمني>.<الجسم>".
الطابع الزمني داخل التوقيع يمنع إعادة إرسال رسالة قديمة بتوقيعها الصحيح.
"""

import hashlib
import hmac

MAX_AGE = 300       # رسالة أقدم من 5 دقائق تُرفض
MAX_FUTURE = 60     # تسامح مع فرق الساعات بين الخادمين


def sign(secret, timestamp, body):
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify(secret, timestamp, body, signature, now, max_age=MAX_AGE, max_future=MAX_FUTURE):
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if now - ts > max_age or ts - now > max_future:
        return False
    return hmac.compare_digest(sign(secret, ts, body), signature or "")
