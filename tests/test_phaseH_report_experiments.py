"""A/B report variants on an identical already collected graph; synthetic data."""
from copy import deepcopy

import pytest

from bluesec1_agent.decision_guard import detect_attack_signals, decisive_signals
from bluesec1_agent.report_experiments import apply_report_experiment
from bluesec1_agent.response_mapper import ObservedGraph

TR = "tr"; H = "local"; CH = "child"; F = "file"; ARCH = "archive"
SVC = "service"; USER = "user"; PEER = "peer"; PEER2 = "peer2"; CONN = "conn"

def node(nid, kind, host_id=None, **props):
    return {"id": nid, "type": kind, "properties": props, "host_id": host_id}

def edge(nid, kind, source, target):
    return {"id": nid, "type": kind, "source_id": source, "target_id": target}

def graph():
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [
        node(TR, "windows_process", H, pid=11, image_path=r"C:\Windows\launcher-9.exe",
             parent_image=r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\SYSTEM",
             cmdline=r"C:\Windows\launcher-9.exe -service"),
        node(H, "host", ip="10.1.1.2", hostname="LOCAL"),
    ]}})
    g.absorb([
        node(CH, "windows_process", H, parent_pid=11, pid=12, image_path=r"C:\Temp\child.exe"),
        node(F, "windows_file", path=r"C:\Temp\child.exe", is_executable=True),
        node(ARCH, "archive_file", path=r"C:\Temp\payload.7z"),
        node(SVC, "windows_service", binary_path=r"C:\Windows\launcher-9.exe -service", service_name="PSEXESVC"),
        node(USER, "windows_user", username="alice", group_memberships=["Domain Users"]),
        node(PEER, "host", ip="198.51.100.203", role="external", hostname="ext"),
        node(PEER2, "host", ip="203.0.113.4", role="external", hostname="ext2"),
        node("unrelated", "host", ip="192.0.2.77", role="external"),
        node(CONN, "network_connection", src_ip="10.1.1.2", dst_ip="198.51.100.203", dst_port=443),
        node("conn2", "network_connection", dst_ip="203.0.113.4", dst_port=8443),
        edge("sp", "win_process_create", TR, CH),
        edge("wf1", "wrote_file", TR, F),
        edge("wf2", "wrote_file", CH, ARCH),
        edge("sv", "started_service", TR, SVC),
        edge("net", "connected_to", TR, CONN),
        edge("net2", "connected_to", CH, "conn2"),
        edge("group", "added_to_group", TR, USER),
    ])
    return g


def malicious():
    return {"verdict": "malicious", "reasoning": "The model's original rationale",
            "ir_artifacts": [{"entity_id": H, "kind": "host_to_isolate"},
                             {"entity_id": CONN, "kind": "network_block"}]}


def benign():
    return {"verdict": "benign", "reasoning": "A benign narrative",
            "legitimacy_evidence": [{"anchor": "relation", "relation_id": "sp",
                                      "property_fields": ["source_id", "target_id"]},
                                     {"anchor": "entity", "entity_id": TR,
                                      "property_fields": ["cmdline"]}]}


def test_control_is_identical_and_pure():
    g = graph(); orig = malicious(); snapshot = deepcopy(orig)
    assert apply_report_experiment(orig, g, "control") == orig
    assert orig == snapshot


def test_arm_a_adds_observed_written_executable_archive_and_matched_service_only():
    g = graph(); original = malicious()
    result = apply_report_experiment(original, g, "malicious_files")
    actions = {(x["entity_id"], x["kind"]) for x in result["ir_artifacts"]}
    assert (F, "file_to_delete") in actions
    assert (ARCH, "file_to_delete") in actions
    assert (SVC, "persistence_to_remove") in actions
    assert (H, "host_to_isolate") in actions
    assert (CONN, "network_block") in actions
    assert result["verdict"] == original["verdict"]
    assert result["reasoning"] == original["reasoning"]
    assert original == malicious()


def test_arm_a_requires_actual_write_and_matching_service_binary():
    g = graph()
    g.relations.pop("wf2")
    g.entities[SVC]["properties"]["binary_path"] = r"C:\Windows\unrelated.exe"
    items = apply_report_experiment(malicious(), g, "malicious_files")["ir_artifacts"]
    assert {x["entity_id"] for x in items} == {H, CONN, F}


def test_arm_b_targets_only_distinct_observed_external_hosts():
    g = graph()
    sub = apply_report_experiment(malicious(), g, "malicious_block")
    block = [x for x in sub["ir_artifacts"] if x["kind"] == "network_block"]
    assert {x["entity_id"] for x in block} == {PEER, PEER2}
    assert len(block) == 2
    assert "unrelated" not in {x["entity_id"] for x in block}
    assert sub["reasoning"] == malicious()["reasoning"]
    assert sub["verdict"] == "malicious"


def test_arm_b_does_not_fabricate_hosts_for_only_connection_data():
    g = graph()
    g.entities.pop(PEER)
    g.entities.pop(PEER2)
    assert not [a for a in apply_report_experiment(malicious(), g, "malicious_block")["ir_artifacts"]
                if a["kind"] == "network_block"]


def test_arm_c_only_relevant_real_entities_no_trigger_or_relations():
    g = graph(); original = benign()
    result = apply_report_experiment(original, g, "benign_entities", benign_limit=3)
    evidence = result["legitimacy_evidence"]
    assert evidence
    assert len(evidence) <= 3
    assert USER in {e["entity_id"] for e in evidence}
    assert all(e["anchor"] == "entity" for e in evidence)
    assert all(e["entity_id"] != TR for e in evidence)
    assert all("source_id" not in e["property_fields"] for e in evidence)
    assert result["reasoning"] == original["reasoning"]


def test_arm_d_changes_only_reasoning_and_is_deterministic():
    g = graph(); original = malicious()
    one = apply_report_experiment(original, g, "fact_reasoning")
    two = apply_report_experiment(original, g, "fact_reasoning")
    assert one == two
    assert one["ir_artifacts"] == original["ir_artifacts"]
    assert one["verdict"] == original["verdict"]
    assert one["reasoning"] != original["reasoning"]
    assert "launcher-9.exe" in one["reasoning"]
    assert "Written files:" in one["reasoning"]


def test_each_arm_affects_only_its_one_field():
    g = graph()
    for arm, sub, field in [
        ("malicious_files", malicious(), "ir_artifacts"),
        ("malicious_block", malicious(), "ir_artifacts"),
        ("benign_entities", benign(), "legitimacy_evidence"),
        ("fact_reasoning", benign(), "reasoning"),
    ]:
        final = apply_report_experiment(sub, g, arm)
        changed = {k for k in sub if sub[k] != final[k]}
        assert changed == {field}


def test_successful_invalid_domain_is_decisive_but_other_reserved_domains_are_not():
    nodes = {"c1": node("c1", "network_connection", fqdn="vendor.invalid",
                        dst_ip="198.51.100.100", query_status="SUCCESS")}
    signals = detect_attack_signals(nodes, {})
    assert signals
    assert decisive_signals(signals)
    for suffix in (".example", ".test", ".localhost"):
        nodes["c1"]["properties"]["fqdn"] = "vendor" + suffix
        weak = detect_attack_signals(nodes, {})
        assert weak and not decisive_signals(weak)


def test_reject_unknown_mode():
    with pytest.raises(ValueError):
        apply_report_experiment(malicious(), graph(), "bad_mode")
