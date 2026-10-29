from ingest.rules import (BRUTE_MIN, FLOOD_PER_MINUTE, FW_FLOOD_MIN, FW_PORTS_MIN, SCAN_404_MIN,
                          firewall_rules, web_rules)

T0 = 1_800_000_000.0     # بداية دلو 5 دقائق


def web(i, ip="203.0.113.7", path="/", status=200, method="GET", step=1.0):
    return {"ts": T0 + i * step, "ip": ip, "method": method, "path": path, "status": status,
            "bytes": 10, "referer": "", "ua": "ua"}


def fw(i, src="192.0.2.9", port=22, action="BLOCK", step=1.0):
    return {"ts": T0 + i * step, "action": action, "src": src, "dst": "10.0.0.5", "proto": "TCP", "dport": port}


def types(alerts):
    return sorted(a["type"] for a in alerts)


def test_brute_force_threshold():
    login = [web(i, path="/wp-login.php", status=401, method="POST") for i in range(BRUTE_MIN)]
    assert types(web_rules(login)) == ["brute_force"]
    assert web_rules(login[:-1]) == []
    assert web_rules([web(i, path="/products", status=401) for i in range(BRUTE_MIN)]) == []


def test_path_scan_by_404s_and_sensitive_paths():
    scan = [web(i, path=f"/p{i}", status=404) for i in range(SCAN_404_MIN)]
    assert types(web_rules(scan)) == ["path_scan"]
    assert web_rules(scan[:-1]) == []
    sensitive = [web(0, path="/.env", status=404), web(1, path="/.git/config", status=404),
                 web(2, path="/phpmyadmin/", status=404)]
    alerts = web_rules(sensitive)
    assert types(alerts) == ["path_scan"] and "/.env" in alerts[0]["details"]["sensitive"]
    assert web_rules(sensitive[:2]) == []


def test_flood_per_minute():
    flood = [web(i, step=60 / FLOOD_PER_MINUTE) for i in range(FLOOD_PER_MINUTE)]
    assert types(web_rules(flood)) == ["flood"]
    assert web_rules(flood[:-1]) == []


def test_injection_patterns_and_false_positive():
    assert types(web_rules([web(0, path="/products?id=1%27%20UNION%20SELECT%20password%20FROM%20users")])) == ["injection"]
    assert types(web_rules([web(0, path="/search?q=%253Cscript%253Ealert(1)%253C/script%253E")])) == ["injection"]
    assert types(web_rules([web(0, path="/download?f=../../etc/passwd")])) == ["injection"]
    assert web_rules([web(0, path="/blog/how-to-select-a-laptop")]) == []


def test_counts_are_per_source_and_evidence_capped():
    mixed = [web(i, ip=f"198.51.100.{i % 2}", path="/login", status=401, method="POST") for i in range(BRUTE_MIN * 2 - 2)]
    assert web_rules(mixed) == []
    login = [web(i, path="/login", status=401, method="POST") for i in range(BRUTE_MIN + 10)]
    alert = web_rules(login)[0]
    assert alert["count"] == BRUTE_MIN + 10 and len(alert["evidence"]) == 5 and alert["severity"] == "high"


def test_firewall_port_scan_and_flood():
    scan = [fw(i, port=1000 + i) for i in range(FW_PORTS_MIN)]
    assert types(firewall_rules(scan)) == ["fw_port_scan"]
    assert firewall_rules(scan[:-1]) == []
    flood = [fw(i, step=0.5) for i in range(FW_FLOOD_MIN)]
    assert types(firewall_rules(flood)) == ["fw_flood"]
    assert firewall_rules([fw(i, step=0.5, action="ALLOW") for i in range(FW_FLOOD_MIN)]) == []
