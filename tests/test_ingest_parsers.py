from ingest.parsers import parse_firewall, parse_web

COMBINED = '203.0.113.7 - - [26/Oct/2026:13:55:36 +0000] "POST /login?next=/cart HTTP/1.1" 401 532 "https://shop.test/" "curl/8.4"'


def test_combined_line():
    e = parse_web(COMBINED)
    assert e == {"ts": 1793022936.0, "ip": "203.0.113.7", "method": "POST", "path": "/login?next=/cart",
                 "status": 401, "bytes": 532, "referer": "https://shop.test/", "ua": "curl/8.4"}


def test_common_line_and_dash_bytes():
    e = parse_web('198.51.100.2 - frank [26/Oct/2026:13:55:36 +0000] "GET / HTTP/1.0" 304 -')
    assert e["bytes"] == 0 and e["referer"] == "" and e["ua"] == "" and e["status"] == 304


def test_timezone_is_converted_to_utc():
    assert parse_web(COMBINED.replace("13:55:36 +0000", "16:55:36 +0300"))["ts"] == 1793022936.0


def test_bad_web_lines():
    assert parse_web("garbage") is None
    assert parse_web(COMBINED.replace("203.0.113.7", "999.1.1.1")) is None
    assert parse_web("") is None


def test_long_path_is_truncated():
    e = parse_web(COMBINED.replace("/login?next=/cart", "/" + "a" * 5000))
    assert len(e["path"]) == 2048


UFW = ("Oct 26 13:55:36 shop kernel: [123.456] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=192.0.2.9 "
       "DST=10.0.0.5 LEN=60 TOS=0x00 PROTO=TCP SPT=51515 DPT=22 WINDOW=1024 SYN URGP=0")


def test_ufw_block():
    assert parse_firewall(UFW, 2026) == {"ts": 1793022936.0, "action": "BLOCK", "src": "192.0.2.9",
                                         "dst": "10.0.0.5", "proto": "TCP", "dport": 22}


def test_icmp_without_port_and_iptables_drop():
    line = "Oct  6 01:02:03 fw kernel: IPTABLES-DROP: IN=eth0 SRC=192.0.2.10 DST=10.0.0.5 PROTO=ICMP TYPE=8"
    e = parse_firewall(line, 2026)
    assert e["dport"] is None and e["action"] == "BLOCK" and e["proto"] == "ICMP"


def test_ufw_allow_and_non_firewall_line():
    assert parse_firewall(UFW.replace("UFW BLOCK", "UFW ALLOW"), 2026)["action"] == "ALLOW"
    assert parse_firewall("Oct 26 13:55:36 shop sshd[1]: Accepted publickey", 2026) is None
    assert parse_firewall(COMBINED, 2026) is None
