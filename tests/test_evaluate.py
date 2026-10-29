from agent.evaluate import (hallucinated_ips, score_decisions, summarize, types_correct,
                            unsupported_numbers)

TRUTH = {"172.16.0.1": {"attack_ratio": 1.0, "family": "PortScan"},
         "192.168.10.5": {"attack_ratio": 0.0, "family": "BENIGN"},
         "192.168.10.8": {"attack_ratio": 0.2, "family": "PortScan"}}


def test_score_decisions():
    assert score_decisions(TRUTH, {"172.16.0.1", "192.168.10.8"}) == {
        "tp": 1, "fp": 1, "fn": 0, "benign_sources": 2}
    assert score_decisions(TRUTH, set()) == {"tp": 0, "fp": 0, "fn": 1, "benign_sources": 2}


def test_types_correct():
    assert types_correct(["PortScan", "DoS"], "PortScan")
    assert not types_correct(["DoS"], "PortScan")
    assert types_correct([], "BENIGN") and not types_correct(["DoS"], "BENIGN")


def test_hallucinated_ip_detected():
    report = {"findings": [{"source_ip": "10.9.9.9", "evidence": []}], "summary_owner": "172.16.0.1"}
    assert hallucinated_ips(report, '{"source_ip": "172.16.0.1"}') == ["10.9.9.9"]


def test_unsupported_numbers_accepts_rounding_percent_and_arabic_digits():
    tool_text = '{"flagged_flows": 301, "attack_ratio": 0.97, "mean_z": 12.86}'
    report = {"findings": [{"source_ip": "172.16.0.1", "evidence": [
        "٣٠١ اتصال", "نسبة 97%", "انحراف 12.9", "3 مصادر", "4500 حزمة"]}]}
    assert unsupported_numbers(report, tool_text) == [4500.0]


def test_summarize():
    rows = [{"agent": {"tp": 1, "fp": 0, "fn": 1, "benign_sources": 4, "types_ok": True}},
            {"agent": {"tp": 1, "fp": 1, "fn": 0, "benign_sources": 4, "types_ok": False}}]
    s = summarize(rows, "agent")
    assert (s["precision"], s["recall"], s["false_block_rate"], s["type_accuracy"]) == (0.667, 0.667, 0.125, 0.5)
    assert s["f1"] == 0.667
