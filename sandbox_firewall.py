"""
===================================================================
جدار ناري محاكى (Sandbox) + سياسة القرار + حواجز الأمان
===================================================================
هذي هي طبقة "Act" بحلقة الـ Agent:
    Observe -> Predict (نوع الهجوم) -> Decide (سياسة + حواجز) -> Act (محاكى)

مهم: كل شي هنا محاكاة بالذاكرة. ما يمس أي جدار ناري أو شبكة حقيقية.

حواجز الأمان (Guardrails) — هي الجزء الأهم بتبرير تصميم الـ Human-in-the-loop:
  1) أدلة كافية: عدد تدفقات كافٍ، ثقة عالية، ونسبة هجوم عالية من تدفقات المصدر.
     لو ناقصة، الإجراء يتحول لمراقبة فقط (ما نحظر على دليل ضعيف).
  2) قائمة محمية (Allowlist): عناوين بنية تحتية ما تُحظر أبدًا.
  3) سقف للقواعد النشطة: حتى ما يتحول الـ Agent لمصدر ضرر لو غلط.
  4) كل إجراء تنفيذي يحتاج موافقة بشرية (أو موافقة آلية صريحة داخل الـ Sandbox).
  5) كل قاعدة لها مدة (TTL) وكل قرار يُسجَّل.
===================================================================
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime

import numpy as np

# نوع الهجوم -> (الإجراء, المدة بالدقائق)
POLICY = {
    "PortScan": ("block_ip", 15),
    "Brute Force (FTP/SSH)": ("block_ip", 60),
    "DoS": ("block_ip", 30),
    "DDoS": ("rate_limit_target", 30),     # مصادر كثيرة: نقيّد الهدف مو المصدر
    "Web Attack": ("block_ip", 30),
    "Botnet": ("quarantine_host", 120),    # الجهاز المصاب يُعزل (للتحقيق البشري)
}

MIN_FLOWS = 20            # أقل عدد تدفقات هجوم من المصدر لاعتبار الدليل كافيًا
MIN_CONFIDENCE = 0.80     # أقل متوسط ثقة
MIN_ATTACK_RATIO = 0.50   # أقل نسبة تدفقات مصنّفة هجومًا من كل تدفقات المصدر
# درس مستفاد موثّق: جرّبنا خفض عتبة Botnet إلى 0.25 (بحجة أن الجهاز
# المصاب يخلط ترافيكه الطبيعي بترافيك خادم التحكم)، فعزل أجهزة ثلثا
# ترافيكها طبيعي ورفع الأضرار الجانبية (Collateral) إلى 42%. لذلك
# كل إجراء يقطع *كل* ترافيك الكيان (العزل أو الحظر الكامل) يتطلب أدلة
# أعلى، لا أقل. العزل هو الأصرم فله أعلى عتبة.
MIN_ATTACK_RATIO_BY_TYPE = {"Botnet": 0.80}
# إجراءات تقطع كل ترافيك الكيان؛ نطبّق عليها حدًا أدنى صارمًا للأضرار الجانبية
FULL_CUTOFF_ACTIONS = ("quarantine_host", "block_ip")
MAX_ACTIVE_RULES = 10     # سقف القواعد النشطة
RATE_LIMIT_DROP = 0.70    # نسبة التدفقات اللي تُسقط عند تقييد معدل الهدف (محاكاة)
# أمثلة لعناوين بنية تحتية لا تُحظر؛ عدّلها لتناسب شبكتك
DEFAULT_ALLOWLIST = ("192.168.10.3",)


@dataclass
class Proposal:
    id: int
    source_ip: str
    attack_type: str
    action: str                 # block_ip | rate_limit_target | quarantine_host | monitor | none
    duration_min: int
    n_flows: int
    attack_ratio: float
    mean_confidence: float
    target: str = ""            # "ip:port" لقاعدة تقييد المعدل
    reasons: list = field(default_factory=list)
    status: str = "pending"     # pending | applied | rejected | refused | no_enforcement
    rationale: str = ""         # شرح نصي اختياري (من Ollama)


def decide_action(stats, proposal_id, allowlist=DEFAULT_ALLOWLIST):
    """يحوّل إحصاءات مصدر واحد إلى مقترح إجراء، مع تطبيق حواجز الدليل والقائمة المحمية."""
    attack_type = stats["attack_type"]
    action, duration = POLICY.get(attack_type, ("monitor", 0))
    reasons = []

    if stats["source_ip"] in allowlist:
        action, duration = "none", 0
        reasons.append("المصدر ضمن القائمة المحمية (Allowlist)")
    else:
        if stats["n_flows"] < MIN_FLOWS:
            reasons.append(f"عدد التدفقات {stats['n_flows']} أقل من {MIN_FLOWS}")
        if stats["mean_confidence"] < MIN_CONFIDENCE:
            reasons.append(f"متوسط الثقة {stats['mean_confidence']:.2f} أقل من {MIN_CONFIDENCE}")
        min_ratio = MIN_ATTACK_RATIO_BY_TYPE.get(attack_type, MIN_ATTACK_RATIO)
        if stats["attack_ratio"] < min_ratio:
            reasons.append(f"نسبة التدفقات الهجومية {stats['attack_ratio']:.2f} أقل من {min_ratio}")
        # حاجز الأضرار الجانبية: أي إجراء يقطع كل ترافيك الكيان يتطلب أن
        # يكون أغلب ترافيكه هجوميًا فعلًا (وإلا نقطع مستخدمين أبرياء).
        if action in FULL_CUTOFF_ACTIONS and stats["attack_ratio"] < MIN_ATTACK_RATIO:
            reasons.append(
                f"إجراء قطع كامل ({action}) يتطلب نسبة هجوم ≥ {MIN_ATTACK_RATIO}، "
                f"والنسبة {stats['attack_ratio']:.2f} تعني تضرر ترافيك طبيعي كثير")
        if action == "rate_limit_target" and not stats.get("top_target"):
            reasons.append("لا يوجد هدف محدد لتقييد المعدل")
        if reasons:   # الدليل ناقص: مراقبة فقط
            action, duration = "monitor", 0

    return Proposal(
        id=proposal_id, source_ip=stats["source_ip"], attack_type=attack_type,
        action=action, duration_min=duration, n_flows=stats["n_flows"],
        attack_ratio=stats["attack_ratio"], mean_confidence=stats["mean_confidence"],
        target=stats.get("top_target", ""), reasons=reasons,
    )


class SimulatedFirewall:
    def __init__(self, allowlist=DEFAULT_ALLOWLIST, max_rules=MAX_ACTIVE_RULES):
        self.allowlist = set(allowlist)
        self.max_rules = max_rules
        self.rules = []
        self.log = []

    def _log(self, p, approver, note):
        self.log.append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "proposal_id": p.id, "source_ip": p.source_ip,
            "attack_type": p.attack_type, "action": p.action,
            "duration_min": p.duration_min, "status": p.status,
            "approver": approver, "note": note,
        })

    def apply(self, p, approver):
        if p.action in ("monitor", "none"):
            p.status = "no_enforcement"
            self._log(p, approver, "مراقبة فقط: " + "؛ ".join(p.reasons))
            return False
        if p.source_ip in self.allowlist:
            p.status = "refused"
            self._log(p, approver, "مرفوض: المصدر محمي")
            return False
        if len(self.rules) >= self.max_rules:
            p.status = "refused"
            self._log(p, approver, f"مرفوض: بلغ سقف القواعد النشطة ({self.max_rules})")
            return False
        self.rules.append({
            "proposal_id": p.id, "action": p.action, "source_ip": p.source_ip,
            "target": p.target, "ttl_min": p.duration_min,
        })
        p.status = "applied"
        self._log(p, approver, "طُبّقت القاعدة بالجدار المحاكى")
        return True

    def is_covered(self, p):
        """هل المصدر محظور/معزول أصلًا بقاعدة مطبّقة (فالمقترح مكرر)؟"""
        return any(
            r["source_ip"] == p.source_ip and r["action"] in ("block_ip", "quarantine_host")
            for r in self.rules
        )

    def mark_covered(self, p):
        p.status = "covered"
        self._log(p, "system", "مغطّى بقاعدة سابقة على نفس المصدر")

    def reject(self, p, approver):
        p.status = "rejected"
        self._log(p, approver, "رفض بشري")

    def would_drop_mask(self, flows, rng):
        """أي من التدفقات كانت ستُسقط لو القواعد الحالية مفعّلة (محاكاة)."""
        mask = np.zeros(len(flows), dtype=bool)
        src, dst = flows["source_ip"], flows["destination_ip"]
        for rule in self.rules:
            if rule["action"] == "block_ip":
                mask |= (src == rule["source_ip"]).to_numpy()
            elif rule["action"] == "quarantine_host":
                mask |= ((src == rule["source_ip"]) | (dst == rule["source_ip"])).to_numpy()
            elif rule["action"] == "rate_limit_target":
                tip, tport = rule["target"].rsplit(":", 1)
                hit = ((dst == tip) &
                       (flows["destination_port"].astype(str) == tport)).to_numpy()
                mask |= hit & (rng.random(len(flows)) < RATE_LIMIT_DROP)
        return mask

    def save_log(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"rules": self.rules, "log": self.log}, f,
                      ensure_ascii=False, indent=2)


def proposal_to_dict(p):
    return asdict(p)
