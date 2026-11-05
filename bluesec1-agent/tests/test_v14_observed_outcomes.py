"""Verdict-independent semantic outcome tests: no task IDs or labels."""
from bluesec1_agent.agent import InvestigationMemory
from bluesec1_agent.investigation_director import InvestigationDirector


def _auth_graph(*, failed=True, linked=True):
    m = InvestigationMemory()
    m.focus_ids = {"server-process"}
    m.absorb({"id": "server-process", "type": "windows_process", "properties": {
        "cmdline": "System", "user": "SYSTEM"}})
    m.absorb({"id": "destination-host", "type": "host", "properties": {
        "hostname": "SERVER", "ip": "10.2.0.15"}})
    if linked:
        m.absorb({"id": "host-edge", "type": "hosts", "source_id": "destination-host",
                  "target_id": "server-process"})
    for i in range(4):
        user_id = "user-" + str(i % 2)
        m.absorb({"id": user_id, "type": "windows_user", "properties": {
            "username": "operator" + str(i % 2)}})
        m.absorb({"id": f"login-{i}", "type": "logged_on_to", "source_id": user_id,
                  "target_id": "destination-host", "logon_properties": {
                      "source_ip": "10.2.4.23", "auth_failed": failed,
                      "protocol": "NTLM" if i % 2 else "RDP"}})
    return m


def test_authentication_attempts_separate_failure_from_success():
    d = InvestigationDirector()
    m = _auth_graph()
    report = d.observable_outcomes(m)
    assert "FAILED=4" in report and "SUCCEEDED=0" in report
    assert "attempt" in report.lower() and "NOT a completed login" in report
    assert "operator0" in report and "operator1" in report
    assert "NTLM" in report and "RDP" in report
    assert "benign" not in report.lower() and "malicious" not in report.lower()
    benign = {"verdict": "benign", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "server-process", "property_fields": ["cmdline"]}]}
    assert any("failed logins" in s for s in d.benign_evidence_gaps(m, benign))


def test_authentication_success_not_called_failed_or_intrusion():
    d = InvestigationDirector()
    m = _auth_graph(failed=False)
    report = d.observable_outcomes(m)
    assert "FAILED=0" in report and "SUCCEEDED=4" in report
    assert d.benign_evidence_gaps(m, {"verdict": "benign"}) == []


def test_unrelated_failed_auth_does_not_trigger_benign_challenge():
    d = InvestigationDirector()
    m = _auth_graph(linked=False)
    assert d.benign_evidence_gaps(m, {"verdict": "benign"}) == []


def test_inbound_direction_is_not_initiating_system_process():
    d = InvestigationDirector()
    m = InvestigationMemory()
    m.focus_ids = {"hostprocess"}
    m.absorb({"id": "hostprocess", "type": "windows_process", "properties": {"cmdline": "System"}})
    m.absorb({"id": "flow", "type": "network_connection", "properties": {
        "src_ip": "10.12.5.19", "dst_ip": "10.12.5.20", "dst_port": 445, "direction": "inbound"}})
    m.absorb({"id": "edge", "type": "accepted_connection_from", "source_id": "hostprocess",
              "target_id": "flow"})
    txt = d.observable_outcomes(m)
    assert "REMOTE PEER 10.12.5.19 -> RECEIVING HOST 10.12.5.20:445" in txt
    assert "not network initiator" in d.action_ledger(m)


def test_directory_mutation_is_neither_automatic_attack_nor_authorized():
    d = InvestigationDirector()
    m = InvestigationMemory()
    m.focus_ids = {"console"}
    m.absorb({"id": "console", "type": "windows_process", "properties": {
        "cmdline": "management-console.exe", "user": "DOMAIN\\admin"}})
    m.absorb({"id": "user", "type": "windows_user", "properties": {"username": "newhire"}})
    m.absorb({"id": "mutation", "type": "added_to_group", "source_id": "console",
              "target_id": "user"})
    txt = d.observable_outcomes(m)
    assert "PRIVILEGE / DIRECTORY CHANGE" in txt
    assert "missing approval log" in txt
    assert "compromise" in txt
    assert "malicious" not in txt.lower()
