"""
محللات السجلات: سطر نصي ← حدث (dict) أو None إن تعذّر التحليل.
  parse_web       صيغة Nginx/Apache Combined (والصيغة Common بلا محيل ووكيل)
  parse_firewall  سطر kernel من iptables/UFW (syslog بلا سنة، فتُمرَّر السنة)
الأوقات ثوانٍ UTC، والعناوين يُتحقق منها بـ ipaddress.
"""

import ipaddress
import re
from datetime import datetime, timezone

MAX_PATH = 2048

_WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?')
_SYSLOG_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) ")
_UFW_RE = re.compile(r"\[UFW (BLOCK|ALLOW|AUDIT)\]")
_FIELD_RE = {k: re.compile(rf"\b{k}=(\S+)") for k in ("SRC", "DST", "PROTO", "DPT")}


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_web(line):
    m = _WEB_RE.match(line.strip())
    if not m or not (ip := _ip(m["ip"])):
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    return {"ts": ts, "ip": ip, "method": m["method"], "path": m["path"][:MAX_PATH],
            "status": int(m["status"]), "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
            "referer": m["referer"] or "", "ua": m["ua"] or ""}


def parse_firewall(line, year):
    m = _SYSLOG_RE.match(line)
    fields = {k: (f.search(line) or [None, None])[1] for k, f in _FIELD_RE.items()}
    if not m or not fields["SRC"] or not fields["DST"]:
        return None
    src, dst = _ip(fields["SRC"]), _ip(fields["DST"])
    if not src or not dst:
        return None
    try:
        ts = datetime.strptime(f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    ufw = _UFW_RE.search(line)
    return {"ts": ts.replace(tzinfo=timezone.utc).timestamp(), "action": ufw[1] if ufw else "BLOCK",
            "src": src, "dst": dst, "proto": fields["PROTO"] or "",
            "dport": int(fields["DPT"]) if fields["DPT"] and fields["DPT"].isdigit() else None}
