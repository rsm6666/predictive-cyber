"""
===================================================================
الحزم ← تدفقات ثنائية الاتجاه ← الخصائص الـ77 التي دُرّب عليها النموذج
===================================================================
التعريف الوحيد للخصائص في المشروع: الوكيل على خادم المنشأة يستخدمه،
و live_capture.py غلاف فوقه. numpy فقط (بلا pandas) ليبقى التثبيت خفيفًا.

البادئ (العميل) = مُرسِل أول حزمة في التدفق، والاتجاه الأمامي منه.

تصحيحان عن live_capture القديم ليطابق CICFlowMeter (ثبتا من بيانات التدريب):
  - أطوال الترويسة = ترويسة TCP/UDP فقط (20/32…) لا IP معها
  - act_data_pkt_fwd = حزم أمامية تحمل بيانات فعلًا (لا كل الحزم)

صدق علمي: Bulk وActive/Idle تتطلب منطق CICFlowMeter الكامل، فتبقى صفرًا.
===================================================================
"""

from dataclasses import dataclass

import numpy as np

# الأعمدة الـ77 بالترتيب الذي يتوقّعه النموذج
FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
TCP, UDP, ICMP = 6, 17, 1
FLAGS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08, "ack": 0x10, "urg": 0x20, "ece": 0x40, "cwe": 0x80}


@dataclass
class Packet:
    """ما يلزم من الحزمة فقط؛ لا يُحتفظ بأي محتوى."""
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    size: int            # طول الإطار كما التُقط
    payload: int         # بايتات البيانات فوق TCP/UDP
    header: int          # ترويسة TCP/UDP (صفر لغيرهما)
    flags: int = 0
    window: int = -1


def from_scapy(p):
    from scapy.layers.inet import IP, TCP as STCP, UDP as SUDP
    if not p.haslayer(IP):
        return None
    ip = p[IP]
    sport = dport = flags = header = 0
    window = -1
    payload = len(ip.payload)
    if p.haslayer(STCP):
        l4 = p[STCP]
        sport, dport, flags, window = int(l4.sport), int(l4.dport), int(l4.flags), int(l4.window)
        header = int(l4.dataofs or 5) * 4
        payload = len(l4.payload)
    elif p.haslayer(SUDP):
        l4 = p[SUDP]
        sport, dport, header, payload = int(l4.sport), int(l4.dport), 8, len(l4.payload)
    return Packet(float(p.time), ip.src, ip.dst, sport, dport, int(ip.proto), len(p), payload, header, flags, window)


class _Flow:
    def __init__(self, p):
        self.src, self.dst, self.sport, self.dport, self.proto = p.src, p.dst, p.sport, p.dport, p.proto
        self.fwd, self.bwd, self.ftime, self.btime = [], [], [], []
        self.t0 = self.t1 = p.ts
        self.counts = dict.fromkeys(FLAGS, 0)
        self.fwd_psh = self.bwd_psh = self.fwd_urg = self.bwd_urg = 0
        self.fwd_hdr = self.bwd_hdr = self.act_data = self.min_seg = 0
        self.win_f = self.win_b = -1

    def add(self, p):
        fwd = p.src == self.src and p.sport == self.sport
        self.t0, self.t1 = min(self.t0, p.ts), max(self.t1, p.ts)
        if fwd:
            self.fwd.append(p.size); self.ftime.append(p.ts); self.fwd_hdr += p.header
            if p.payload > 0:
                self.act_data += 1
            if self.min_seg == 0 or 0 < p.header < self.min_seg:
                self.min_seg = p.header
        else:
            self.bwd.append(p.size); self.btime.append(p.ts); self.bwd_hdr += p.header
        if self.proto == TCP:
            for name, bit in FLAGS.items():
                if p.flags & bit:
                    self.counts[name] += 1
            if p.flags & FLAGS["psh"]:
                if fwd: self.fwd_psh += 1
                else: self.bwd_psh += 1
            if p.flags & FLAGS["urg"]:
                if fwd: self.fwd_urg += 1
                else: self.bwd_urg += 1
            if fwd and self.win_f == -1:
                self.win_f = p.window
            if not fwd and self.win_b == -1:
                self.win_b = p.window

    def row(self):
        fwd, bwd, allpk = self.fwd, self.bwd, self.fwd + self.bwd
        dur = self.t1 - self.t0
        dur_s = dur if dur > 0 else 1e-6
        n_f, n_b, n_all = len(fwd), len(bwd), len(allpk)
        fmax, fmin, fmean, fstd = _stats(fwd)
        bmax, bmin, bmean, bstd = _stats(bwd)
        pmax, pmin, pmean, pstd = _stats(allpk)
        f_iat, b_iat, a_iat = _iat(self.ftime), _iat(self.btime), _iat(self.ftime + self.btime)
        fi_max, fi_min, fi_mean, fi_std = _stats(f_iat)
        bi_max, bi_min, bi_mean, bi_std = _stats(b_iat)
        ai_max, ai_min, ai_mean, ai_std = _stats(a_iat)
        c = self.counts
        v = dict.fromkeys(FEATURES, 0.0)
        v.update({
            "Flow Duration": dur * 1e6,   # بالميكروثانية (مثل الداتاسيت)
            "Total Fwd Packets": n_f, "Total Backward Packets": n_b,
            "Total Length of Fwd Packets": sum(fwd), "Total Length of Bwd Packets": sum(bwd),
            "Fwd Packet Length Max": fmax, "Fwd Packet Length Min": fmin,
            "Fwd Packet Length Mean": fmean, "Fwd Packet Length Std": fstd,
            "Bwd Packet Length Max": bmax, "Bwd Packet Length Min": bmin,
            "Bwd Packet Length Mean": bmean, "Bwd Packet Length Std": bstd,
            "Flow Bytes/s": sum(allpk) / dur_s, "Flow Packets/s": n_all / dur_s,
            "Flow IAT Mean": ai_mean, "Flow IAT Std": ai_std, "Flow IAT Max": ai_max, "Flow IAT Min": ai_min,
            "Fwd IAT Total": sum(f_iat), "Fwd IAT Mean": fi_mean, "Fwd IAT Std": fi_std,
            "Fwd IAT Max": fi_max, "Fwd IAT Min": fi_min,
            "Bwd IAT Total": sum(b_iat), "Bwd IAT Mean": bi_mean, "Bwd IAT Std": bi_std,
            "Bwd IAT Max": bi_max, "Bwd IAT Min": bi_min,
            "Fwd PSH Flags": self.fwd_psh, "Bwd PSH Flags": self.bwd_psh,
            "Fwd URG Flags": self.fwd_urg, "Bwd URG Flags": self.bwd_urg,
            "Fwd Header Length": self.fwd_hdr, "Bwd Header Length": self.bwd_hdr,
            "Fwd Header Length.1": self.fwd_hdr,
            "Fwd Packets/s": n_f / dur_s, "Bwd Packets/s": n_b / dur_s,
            "Min Packet Length": pmin, "Max Packet Length": pmax,
            "Packet Length Mean": pmean, "Packet Length Std": pstd, "Packet Length Variance": pstd ** 2,
            "FIN Flag Count": c["fin"], "SYN Flag Count": c["syn"], "RST Flag Count": c["rst"],
            "PSH Flag Count": c["psh"], "ACK Flag Count": c["ack"], "URG Flag Count": c["urg"],
            "CWE Flag Count": c["cwe"], "ECE Flag Count": c["ece"],
            "Down/Up Ratio": (n_b / n_f) if n_f else 0.0,
            "Average Packet Size": (sum(allpk) / n_all) if n_all else 0.0,
            "Avg Fwd Segment Size": fmean, "Avg Bwd Segment Size": bmean,
            "Subflow Fwd Packets": n_f, "Subflow Fwd Bytes": sum(fwd),
            "Subflow Bwd Packets": n_b, "Subflow Bwd Bytes": sum(bwd),
            "Init_Win_bytes_forward": self.win_f, "Init_Win_bytes_backward": self.win_b,
            "act_data_pkt_fwd": self.act_data, "min_seg_size_forward": self.min_seg,
        })
        return {"src": self.src, "dst": self.dst, "sport": self.sport, "dport": self.dport, "proto": self.proto,
                "start": self.t0, "end": self.t1, "f": [float(v[name]) for name in FEATURES]}


class FlowTable:
    """جدول تدفقات نافذة واحدة: الحزم تُضاف تباعًا، والصفوف تُقرأ عند إغلاق النافذة."""

    def __init__(self):
        self.flows = {}

    def __len__(self):
        return len(self.flows)

    def add(self, p):
        if p is None:
            return
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (a, b, p.proto) if a <= b else (b, a, p.proto)   # الاتجاهان في تدفق واحد
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = _Flow(p)
        flow.add(p)

    def rows(self):
        return [f.row() for f in self.flows.values()]


def _stats(vals):
    """(max, min, mean, std) بأمان لقائمة قد تكون فارغة."""
    if not vals:
        return 0.0, 0.0, 0.0, 0.0
    a = np.asarray(vals, dtype=float)
    return float(a.max()), float(a.min()), float(a.mean()), float(a.std())


def _iat(times):
    if len(times) < 2:
        return []
    t = sorted(times)
    return [t[i + 1] - t[i] for i in range(len(t) - 1)]
