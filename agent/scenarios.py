"""
===================================================================
سيناريوهات المحلل الذكي — حوادث من بيانات CICIDS بحقيقة معروفة
===================================================================
الحادثة = نافذة مراقبة (~1500 اتصال): ترافيك طبيعي + هجوم من نوع واحد
(أو بلا هجوم). لكل حادثة جزآن:
  observed / windows  ما تراه أدوات الوكيل (حُذفت منها أعمدة الحقيقة)
  truth               نوع كل مصدر ونسبة اتصالاته الهجومية — للتقييم فقط
سياق التنبؤ (10 نوافذ زمنية) مطابق لنوع السيناريو، لكنه ليس من نفس
الاتصالات زمنيًا؛ هذا قيد معلن في مستند التصميم.
===================================================================
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

ATTACK_FAMILIES = ["PortScan", "DoS", "DDoS", "Brute Force (FTP/SSH)", "Web Attack", "Botnet"]
TRUTH_COLS = ["family", "attack_label", "Label"]
WINDOW_TRUTH_COLS = ["attack_flows", "attack_next_window"]
N_BENIGN = 1200
N_ATTACK = 300
N_ATTACK_LOW = 20       # حالة صعبة: هجوم بحجم صغير
SEQ_LEN = 10


@dataclass
class Incident:
    id: str
    kind: str               # attack | attack_low | benign
    family: str             # النوع الحقيقي، أو BENIGN
    observed: pd.DataFrame
    windows: pd.DataFrame
    truth: dict             # source_ip -> {"attack_ratio": float, "family": str}


def _source_truth(flows):
    is_attack = flows["family"] != "BENIGN"
    ratio = is_attack.groupby(flows["source_ip"]).mean()
    fam = flows[is_attack].groupby("source_ip")["family"].agg(lambda s: s.value_counts().index[0])
    return {ip: {"attack_ratio": round(float(r), 3), "family": fam.get(ip, "BENIGN")}
            for ip, r in ratio.items()}


def _pick_windows(windows, attack_next, rng):
    ends = np.arange(SEQ_LEN, len(windows))
    last = ends - 1
    target = windows["attack_next_window"].values[last]
    if attack_next:
        ok = target == 1
    else:
        ok = (target == 0) & (windows["attack_flows"].values[last] == 0)
    end = int(rng.choice(ends[ok]))
    return windows.iloc[end - SEQ_LEN:end].drop(columns=WINDOW_TRUTH_COLS)


def build_incident(act_sample, windows, family, seed, low_volume=False):
    rng = np.random.default_rng(seed)
    parts = [act_sample[act_sample["family"] == "BENIGN"].sample(N_BENIGN, random_state=seed)]
    if family != "BENIGN":
        pool = act_sample[act_sample["family"] == family]
        n = N_ATTACK_LOW if low_volume else N_ATTACK
        parts.append(pool.sample(min(n, len(pool)), random_state=seed))
    flows = pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)
    kind = "benign" if family == "BENIGN" else ("attack_low" if low_volume else "attack")
    return Incident(
        id=f"{kind}-{family.split()[0].lower()}-{seed}",
        kind=kind,
        family=family,
        observed=flows.drop(columns=[c for c in TRUTH_COLS if c in flows.columns]),
        windows=_pick_windows(windows, family != "BENIGN", rng),
        truth=_source_truth(flows),
    )


def evaluation_suite(act_sample, windows, seed=2026):
    """60 سيناريو ثابتًا: لكل نوع 6 عادية + 2 منخفضة الحجم، ثم 12 طبيعيًا."""
    incidents, s = [], seed
    for fam in ATTACK_FAMILIES:
        for i in range(8):
            incidents.append(build_incident(act_sample, windows, fam, s, low_volume=i >= 6))
            s += 1
    for _ in range(12):
        incidents.append(build_incident(act_sample, windows, "BENIGN", s))
        s += 1
    return incidents
