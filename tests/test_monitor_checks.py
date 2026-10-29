from sites import SECURE_HEADERS, LocalSite, page

from monitor.checks import availability, exposed_files, header_findings, score
from monitor.fetch import Response, fetch, is_private_host

PUBLIC = [(2, 1, 6, "", ("93.184.215.14", 0))]
LOOPBACK = [(2, 1, 6, "", ("127.0.0.1", 0))]


def keys(findings):
    return sorted(f["key"] for f in findings)


def test_site_without_headers():
    with LocalSite({"/": page([("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/8.1"),
                              ("Set-Cookie", "sid=abc")])}) as s:
        r = fetch(s.url + "/")
        found = header_findings(r, https=False)
    assert keys(found) == ["cookies", "csp", "nosniff", "permissions", "powered_by", "referrer", "server_version", "xfo"]
    assert score(found) == (40, "F")
    f = next(x for x in found if x["key"] == "csp")
    assert "Content-Security-Policy" in f["fix"]["nginx"] and f["title"] and f["risk"]


def test_secure_site_scores_a_and_hsts_only_matters_on_https():
    with LocalSite({"/": page(SECURE_HEADERS)}) as s:
        r = fetch(s.url + "/")
    assert header_findings(r, https=True) == [] and score([]) == (100, "A")
    no_hsts = [h for h in SECURE_HEADERS if h[0] != "Strict-Transport-Security"]
    with LocalSite({"/": page(no_hsts)}) as s:
        r = fetch(s.url + "/")
    assert header_findings(r, https=False) == [] and keys(header_findings(r, https=True)) == ["hsts"]


def test_frame_ancestors_counts_as_frame_protection_and_plain_server_is_fine():
    headers = [h for h in SECURE_HEADERS if h[0] not in ("X-Frame-Options", "Content-Security-Policy")]
    with LocalSite({"/": page(headers + [("Content-Security-Policy", "frame-ancestors 'self'")])}) as s:
        assert header_findings(fetch(s.url + "/"), https=True) == []


def test_spa_returning_200_everywhere_has_no_false_exposures():
    with LocalSite(fallback=page()) as s:
        assert exposed_files(lambda u: fetch(u), s.url) == []


def test_real_env_and_git_head_are_critical():
    routes = {"/.env": (200, [("Content-Type", "text/plain")], b"APP_KEY=secret\nDB_PASSWORD=hunter2\n"),
              "/.git/HEAD": (200, [("Content-Type", "text/plain")], b"ref: refs/heads/main\n")}
    with LocalSite(routes, fallback=page()) as s:
        found = exposed_files(lambda u: fetch(u), s.url)
    assert keys(found) == ["exposed:/.env", "exposed:/.git/HEAD"]
    assert all(f["severity"] == "critical" and f["deduction"] == 40 for f in found)


def test_backup_file_must_differ_from_baseline():
    routes = {"/backup.zip": (200, [("Content-Type", "application/zip")], b"PK\x03\x04data")}
    with LocalSite(routes) as s:
        assert keys(exposed_files(lambda u: fetch(u), s.url)) == ["exposed:/backup.zip"]


def test_availability_down_slow_and_ok():
    with LocalSite({"/": page()}) as s:
        assert availability(fetch(s.url + "/"))["ok"] is True
        s.down = True
        assert availability(fetch(s.url + "/"))["ok"] is False
    assert availability(fetch("http://127.0.0.1:1/", timeout=2))["ok"] is False   # لا شيء يستمع
    assert availability(Response(200, ms=3500))["slow"] is True


def test_private_targets_and_redirects():
    assert is_private_host("127.0.0.1") and not is_private_host("example.com", resolver=lambda h, p: PUBLIC)
    with LocalSite({"/": (302, [("Location", "http://127.0.0.1:1/x")], b"")}) as s:
        port = int(s.url.rsplit(":", 1)[1])   # المحلل الوهمي يجعل موقع الاختبار «عامًا» ووجهة التحويل داخلية
        r = fetch(s.url + "/", allow_private=False, resolver=lambda h, p: PUBLIC if p == port else LOOPBACK)
    assert r.error and "داخلي" in r.error
    assert "داخلي" in fetch("http://127.0.0.1:9/", allow_private=False).error
