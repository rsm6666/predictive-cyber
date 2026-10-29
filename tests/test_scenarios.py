import pandas as pd

from agent.scenarios import (N_ATTACK, N_ATTACK_LOW, N_BENIGN, SEQ_LEN, TRUTH_COLS,
                             WINDOW_TRUTH_COLS, build_incident, evaluation_suite)


def test_same_seed_same_incident(data):
    a = build_incident(*data, "DoS", seed=5)
    b = build_incident(*data, "DoS", seed=5)
    assert a.id == b.id and a.truth == b.truth
    pd.testing.assert_frame_equal(a.observed, b.observed)
    pd.testing.assert_frame_equal(a.windows, b.windows)


def test_observed_and_windows_hide_truth(portscan):
    assert not set(TRUTH_COLS) & set(portscan.observed.columns)
    assert not set(WINDOW_TRUTH_COLS) & set(portscan.windows.columns)
    assert len(portscan.windows) == SEQ_LEN


def test_attack_incident_truth(portscan):
    attackers = {ip: t for ip, t in portscan.truth.items() if t["attack_ratio"] >= 0.5}
    assert attackers and all(t["family"] == "PortScan" for t in attackers.values())
    assert len(portscan.observed) == N_BENIGN + N_ATTACK
    assert portscan.kind == "attack"


def test_benign_incident_has_no_attackers(data):
    inc = build_incident(*data, "BENIGN", seed=3)
    assert inc.kind == "benign"
    assert all(t["attack_ratio"] == 0 for t in inc.truth.values())


def test_low_volume_incident(data):
    inc = build_incident(*data, "DDoS", seed=2, low_volume=True)
    assert inc.kind == "attack_low" and len(inc.observed) == N_BENIGN + N_ATTACK_LOW


def test_evaluation_suite_composition(data):
    suite = evaluation_suite(*data)
    kinds = [i.kind for i in suite]
    assert len(suite) == 60 and len({i.id for i in suite}) == 60
    assert kinds.count("attack") == 36 and kinds.count("attack_low") == 12
    assert kinds.count("benign") == 12
