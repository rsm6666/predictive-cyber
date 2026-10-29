import pytest
from test_campaign_linker import ATTACKER, exposed
from test_ingest_store import T0, alert, web

from agent.analyst import run_investigation
from agent.demo import DemoClient
from agent.log_tools import LogWorkspace
from agent.store import Run
from agent.tools import decide
from campaign.linker import link
from campaign.workspace import CampaignWorkspace, campaign_view
from ingest.store import LogStore


class Scenario:
    """ملف مكشوف ← فحص مسارات حمّل الملف ← تخمين بعد ساعتين؛ كل حادثة سجلات حقق فيها متخصص."""

    def __init__(self, tmp_path):
        self.store, self.dir, self.runs = LogStore(tmp_path / "tenant.db"), tmp_path / "runs", {}
        self.monitor = exposed(self.store, at=T0 - 600)
        self.store.insert_web([web(T0 + i, ip=ATTACKER, path=p, status=s)
                               for i, (p, s) in enumerate([("/.git/config", 404), ("/.env", 200), ("/admin", 404)])])
        self.scan = self.store.add_alert(alert(type_="path_scan", ip=ATTACKER, first=T0, severity="medium"))[1]
        self.brute = self.store.add_alert(alert(type_="brute_force", ip=ATTACKER, first=T0 + 7200))[1]
        for inc in (self.scan, self.brute):
            self.specialist(inc)
            self.cid = link(self.store, inc).campaign

    def specialist(self, incident_id):
        ws = LogWorkspace(self.store, incident_id, allowlist=[])
        run = Run(ws.incident, ws, save_dir=self.dir)
        run_investigation(DemoClient(), ws, run)
        ws.sync_incident_status()
        self.runs[incident_id] = run
        return run

    def ws(self, previous=None, allowlist=(), live=True):
        return CampaignWorkspace(self.store, self.cid, (self.runs.get if live else lambda _: None), self.dir,
                                 allowlist=allowlist, previous=previous)


@pytest.fixture
def s(tmp_path):
    return Scenario(tmp_path)


def test_view_orders_stages_and_shows_download(s):
    v = campaign_view(s.store, s.cid)
    assert {m["incident_id"] for m in v["members"]} == {s.monitor, s.scan, s.brute}
    assert v["attackers"] == [ATTACKER] and v["severity"] == "critical"
    assert [x["stage"] for x in v["stages"]] == ["weakness", "recon", "exploit", "access"]
    assert "/.env" in v["stages"][2]["description"]
    assert {l["rule"] for l in v["links"]} == {"same_ip", "exposed_file"}


def test_specialist_report_live_saved_and_monitor(s):
    ws = s.ws()
    live = ws.specialist_report(s.scan)
    assert live["kind"] == "log" and live["report"]["summary_owner"] and live["proposals"][0]["action"] == "block_ip"
    assert s.ws(live=False).specialist_report(s.scan)["report"] == live["report"]       # بعد إعادة التشغيل
    mon = ws.specialist_report(s.monitor)
    assert mon["kind"] == "monitor" and mon["path"] == "/.env"
    with pytest.raises(Exception, match="ليست من أعضاء"):
        ws.specialist_report("log-99")


def test_attacker_profile_spans_members(s):
    p = s.ws().attacker_profile(ATTACKER)
    assert p["linking_ip"] and {a["incident_id"] for a in p["alerts"]} == {s.scan, s.brute}
    assert p["exposed_files"][0]["downloaded"]
    assert [d["status"] for d in p["decisions"]] == ["pending", "pending"]


def test_policy_takes_strongest_member_policy(s):
    pol = s.ws().check_policy(ATTACKER)
    assert pol["max_action"] == "block_ip" and pol["duration_min"] == 60 and pol["enforced_in"] == []
    assert s.ws(live=False).check_policy(ATTACKER)["max_action"] == "block_ip"       # من المقترحات المحفوظة
    assert s.ws(allowlist=[ATTACKER]).ips == []


def test_proposal_merges_specialists_and_cannot_exceed_policy(s):
    ws = s.ws()
    assert not ws.propose_action(ATTACKER, "quarantine_host", "أشد")["accepted"]
    r = ws.propose_action(ATTACKER, "block_ip", "حملة")
    assert r["accepted"] and ws.proposals[r["proposal_id"]].duration_min == 60
    for inc in (s.scan, s.brute):
        old = s.runs[inc].ws.proposals[1]
        assert old.status == "merged" and s.cid in old.rationale
        assert decide(s.runs[inc].ws, 1, "approve")["status"] == "merged"           # رابطها القديم لا يعمل
    assert not ws.propose_action(ATTACKER, "block_ip", "مكرر")["accepted"]


def test_no_duplicate_when_already_enforced(s):
    decide(s.runs[s.scan].ws, 1, "approve")
    ws = s.ws()
    assert ws.check_policy(ATTACKER)["enforced_in"] == [s.scan]
    r = ws.propose_action(ATTACKER, "block_ip", "حملة")
    assert not r["accepted"] and s.scan in r["reason"]


def test_saved_campaign_block_survives_restart(s):
    ws = s.ws()
    pid = ws.propose_action(ATTACKER, "block_ip", "حملة")["proposal_id"]
    decide(ws, pid, "approve")
    Run(ws.incident, ws, save_dir=s.dir).save()
    fresh = s.ws(live=False)                    # بعد إعادة تشغيل الخادم: لا Run حي ولا previous
    assert fresh.check_policy(ATTACKER)["enforced_in"] == [s.cid]
    assert not fresh.propose_action(ATTACKER, "block_ip", "مكرر")["accepted"]


def test_rules_fallback_one_proposal_per_attacker(s):
    ws = s.ws()
    [p] = ws.rules_proposals()
    assert (p.source_ip, p.action, p.status) == (ATTACKER, "block_ip", "pending")
    assert s.runs[s.brute].ws.proposals[1].status == "merged" and ws.rules_proposals() == []


def test_closing_campaign_closes_log_members_not_monitor(s):
    ws = s.ws()
    pid = ws.propose_action(ATTACKER, "block_ip", "حملة")["proposal_id"]
    ws.sync_incident_status()
    assert s.store.incident(s.cid)["status"] == "investigating"
    decide(ws, pid, "approve")
    ws.sync_incident_status()
    status = {i: s.store.incident(i)["status"] for i in (s.cid, s.scan, s.brute, s.monitor)}
    assert status == {s.cid: "closed", s.scan: "closed", s.brute: "closed", s.monitor: "open"}


def test_rerun_keeps_proposal_numbers(s):
    first = s.ws()
    first.propose_action(ATTACKER, "block_ip", "حملة")
    second = s.ws(previous=first)
    assert second.proposals[1].status == "superseded"
    assert second.propose_action(ATTACKER, "block_ip", "حملة")["proposal_id"] == 2


def test_demo_coordinator_writes_campaign_report(s):
    ws = s.ws()
    run = Run(ws.incident, ws, save_dir=s.dir)
    run_investigation(DemoClient(), ws, run)
    assert run.status == "done" and run.report["severity"] == "critical"
    assert [x["stage"] for x in run.report["stages"]] == ["weakness", "recon", "exploit", "access"]
    assert "حُمّل ملف حساس" in run.report["summary_owner"] and "كلمات المرور" in run.report["watch_next"]
    [p] = ws.proposals.values()
    assert (p.source_ip, p.action, p.status) == (ATTACKER, "block_ip", "pending")
    assert run.report["proposal_ids"] == [p.id]
    assert (s.dir / f"{s.cid}.json").exists()
