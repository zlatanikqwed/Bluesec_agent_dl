"""v17 SOC engine: causal correlation, not hardcoded labels."""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.security_engine import SecurityEngine


def engine():
    return SecurityEngine(InvestigationDirector())


def memory():
    m = InvestigationMemory()
    m.absorb({"id": "powershell", "type": "windows_process", "properties": {
        "cmdline": "powershell.exe -NoProfile -EncodedCommand AAA",
        "user": "LAB\\svc_updater", "signed": True},
        "relation_ids": {"outgoing": ["written", "network"], "incoming": ["spawn"]}})
    m.focus_ids = {"powershell"}
    m.trigger_ids = {"powershell"}
    m.absorb({"id": "written", "type": "wrote_file",
              "source_id": "powershell", "target_id": "payload"})
    m.absorb({"id": "network", "type": "connected_to",
              "source_id": "powershell", "target_id": "connection"})
    m.absorb({"id": "connection", "type": "network_connection", "properties": {
        "dst_ip": "192.168.4.12", "dst_port": 5985, "src_ip": "192.168.4.2"}})
    m.fetched_ids.update({"powershell", "written", "network", "connection"})
    return m


def test_security_engine_correlates_state_change_and_network_same_process():
    m = memory()
    results = engine().hypotheses(m)
    assert any(f.technique == "change_and_network" for f in results)
    assert any(f.technique == "encoded_execution" for f in results)
    assert not any(f.technique == "credential_access" for f in results)


def test_security_engine_follow_observed_effect_target_not_guess_ids():
    m = memory()
    lead = engine().next_lead(m, {"get_entity", "get_relation"})
    assert lead[0] == "get_entity"
    assert lead[1]["entity_id"] == "payload"
    assert lead[1]["entity_id"] in m.known_ids


def test_security_engine_cites_process_not_enough_to_explain_impact():
    m = memory()
    sub = {"verdict": "benign", "reasoning": "Trusted signed updater", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "powershell", "property_fields": ["signed"]}]}
    assert any("UNCITED" in q for q in engine().review_questions(m, sub))


def test_security_engine_ignore_isolated_search_hit_and_false_positive():
    m = memory()
    m.absorb({"id": "separate", "type": "windows_process", "properties": {
        "cmdline": "mimikatz.exe sekurlsa::logonpasswords"}})
    assert not any(f.technique == "credential_access" for f in engine().hypotheses(m))
    assert not engine().review_questions(m, {"verdict": "malicious"})


def test_security_engine_credential_dumping_is_high_priority_but_not_forced_verdict():
    m = memory()
    m.absorb({"id": "powershell", "type": "windows_process", "properties": {
        "cmdline": "rundll32.exe comsvcs.dll, MiniDump 1234 C:\\temp\\lsass.dmp full"}})
    hits = engine().hypotheses(m)
    assert any(f.technique == "credential_access" and f.weight >= 7 for f in hits)
    assert not any("verdict" in f.__dict__ for f in hits)


def test_security_engine_does_not_assume_signed_means_authorized():
    m = memory()
    m.absorb({"id": "payload", "type": "windows_file", "properties": {
        "path": "C:\\Temp\\payload.exe", "signed": True}})
    m.fetched_ids.add("payload")
    findings = engine().hypotheses(m)
    assert any(f.level == "impact" and f.technique == "state_change" for f in findings)
    assert "NOT automatic attack verdicts" in engine().dossier(m)


def test_security_mode_is_explicit_and_opt_in():
    assert not SimpleSGRAgent(None).security_mode
    assert SimpleSGRAgent(None, v16_mode=True, security_mode=True).security_mode


def test_written_binary_executed_then_writes_document_is_correlated():
    m = InvestigationMemory()
    m.focus_ids = {"starter"}
    m.absorb({"id": "starter", "type": "windows_process", "properties": {
        "cmdline": "powershell.exe -s"}})
    m.absorb({"id": "drop", "type": "windows_file", "properties": {
        "path": "C:\\ProgramData\\cache\\client-238.exe"}})
    m.absorb({"id": "child", "type": "windows_process", "properties": {
        "image_path": "C:\\ProgramData\\cache\\client-238.exe"}})
    m.absorb({"id": "report", "type": "windows_file", "properties": {"path": "D:\\Shares\\report.txt"}})
    for rid, kind, src, dest in (("write", "wrote_file", "starter", "drop"),
                                  ("create", "win_process_create", "starter", "child"),
                                  ("output", "wrote_file", "child", "report")):
        m.absorb({"id": rid, "type": kind, "source_id": src, "target_id": dest})
    assert any(f.technique == "write_execute_chain" and len(f.relation_ids) == 3
               for f in engine().hypotheses(m))


def test_nonstandard_winrm_port_matched_to_observed_network_flow():
    m = InvestigationMemory()
    m.focus_ids = {"remote"}
    m.absorb({"id": "remote", "type": "windows_process", "properties": {
        "cmdline": 'powershell.exe -Command "New-PSSession -ComputerName 10.1.2.3 -Port 62001"'}})
    m.absorb({"id": "flow", "type": "network_connection", "properties": {
        "dst_ip": "10.1.2.3", "dst_port": 62001}})
    m.absorb({"id": "connect", "type": "connected_to", "source_id": "remote", "target_id": "flow"})
    assert any(f.technique == "nonstandard_remote_session"
               for f in engine().hypotheses(m))


def test_cross_identity_smb_requires_real_remote_relation_for_impact():
    m = InvestigationMemory()
    m.focus_ids = {"net"}
    m.absorb({"id": "net", "type": "windows_process", "properties": {
        "cmdline": "net use \\\\server\\share /user:EXAMPLE\\otheradmin secret",
        "user": "LAB\\service"}})
    m.absorb({"id": "conn", "type": "network_connection", "properties": {"dst_port": 445}})
    m.absorb({"id": "r", "type": "connected_to", "source_id": "net", "target_id": "conn"})
    assert any(f.technique == "cross_identity_smb" and f.level == "impact"
               for f in engine().hypotheses(m))


def test_v17_full_agent_loop_still_uses_real_remote_tools():
    import asyncio
    from test_v16_loop import FakeSession, FakeLLM
    session = FakeSession()
    agent = SimpleSGRAgent(FakeLLM(), max_steps=12, trajectory_dir=None,
                           review_enabled=True, gpt_oss_mode=True, v16_mode=True,
                           security_mode=True)
    result = asyncio.run(agent._investigate(session, []))
    assert result.completion_reason == "terminated"
    assert [t for t, _ in session.calls] == [
        "get_entity", "get_relation", "get_entity", "finish_investigation"]


def test_restarted_same_service_is_positive_normal_context_not_proof():
    m = InvestigationMemory()
    m.focus_ids = {"service"}
    m.absorb({"id": "service", "type": "windows_service", "properties": {"service_name": "MSSQL"}})
    m.absorb({"id": "stop", "type": "stopped_service", "source_id": "admin", "target_id": "service"})
    m.absorb({"id": "start", "type": "started_service", "source_id": "admin", "target_id": "service"})
    context = engine().benign_correlations(m)
    assert context and "same service object" in context[0]
    assert "verify operator authority" in context[0]


def test_security_architecture_works_without_old_v16_flag():
    import asyncio
    from test_v16_loop import FakeSession, FakeLLM
    session = FakeSession()
    agent = SimpleSGRAgent(FakeLLM(), max_steps=12, trajectory_dir=None,
                           review_enabled=True, gpt_oss_mode=True, v16_mode=False,
                           security_mode=True)
    transcript=[]
    result = asyncio.run(agent._investigate(session, transcript))
    assert result.completion_reason == "terminated"
    assert sum('v17_security_gate' in str(msg) for msg in transcript) >= 1
    assert sum('blind_review' in str(msg) for msg in transcript) == 1
