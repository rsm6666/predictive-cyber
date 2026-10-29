"""
مساحة عمل المحلل لحادثة شبكية حقيقية: نفس أدوات CICIDS (agent/tools.py)
على تدفقات المنشأة من وكيل الخادم بدل بيانات المحاكاة.

الملاحظ = تدفقات نوافذ الحادثة بحد 2000؛ تدفقات عناوين التنبيهات كاملة،
والباقي عيّنة من الطبيعي. نوافذ التنبؤ = آخر 10 نوافذ حتى الحادثة.
لا «حقيقة» معروفة في الواقع، فـ truth فارغ.
"""

from dataclasses import dataclass, field

import pandas as pd
from sandbox_firewall import SimulatedFirewall

from agent.tools import ENFORCING, Workspace

MAX_OBSERVED = 2000


@dataclass
class NetIncident:
    id: str
    observed: pd.DataFrame
    windows: pd.DataFrame
    kind: str = "network"
    family: str | None = None
    truth: dict = field(default_factory=dict)


class NetWorkspace(Workspace):
    def __init__(self, log_store, net_store, incident_id, res, allowlist):
        alerts = log_store.alerts(incident_id)
        start, end = min(a["first_ts"] for a in alerts), max(a["last_ts"] for a in alerts)
        flows = net_store.flows_between(start, end)
        flagged = flows["source_ip"].isin({a["ip"] for a in alerts})
        keep, rest = flows[flagged], flows[~flagged]
        room = max(MAX_OBSERVED - len(keep), 0)
        observed = pd.concat([keep, rest.sample(min(room, len(rest)), random_state=0)]).reset_index(drop=True)
        incident = NetIncident(incident_id, observed, net_store.windows(until=end - 1))
        super().__init__(incident, res, firewall=SimulatedFirewall(allowlist=allowlist))
        self.store = log_store

    def sync_incident_status(self):
        pending = any(p.status == "pending" and p.action in ENFORCING for p in self.proposals.values())
        self.store.set_incident_status(self.incident.id, "investigating" if pending else "closed")
