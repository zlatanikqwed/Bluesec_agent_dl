"""Offline v16 tests: facts, not scenario-specific labels."""

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.evidence_workbench import EvidenceWorkbench
from bluesec1_agent.investigation_director import InvestigationDirector


def graph():
    m = InvestigationMemory()
    m.focus_ids = {"proc"}
    m.absorb({"id": "proc", "type": "windows_process", "properties": {
        "cmdline": "powershell.exe -File inventory.ps1", "signed": True,
        "user": "LAB\\inventory_svc"}, "relation_ids": {"outgoing": ["r-write", "r-host"]}})
    m.absorb({"id": "file", "type": "windows_file", "properties": {
        "path": "C:\\Shares\\stage.dat"}})
    m.absorb({"id": "r-write", "type": "wrote_file", "source_id": "proc", "target_id": "file"})
    m.absorb({"id": "host", "type": "host", "properties": {"hostname": "LAB01"}})
    m.absorb({"id": "r-host", "type": "hosts", "source_id": "host", "target_id": "proc"})
    m.absorb({"id": "other", "type": "windows_process", "properties": {
        "cmdline": "unrelated.exe"}})
    m.absorb({"id": "other-file", "type": "windows_file", "properties": {"path": "Z:/x"}})
    m.absorb({"id": "r-unrelated", "type": "wrote_file", "source_id": "other", "target_id": "other-file"})
    m.fetched_ids.update({"proc", "r-write"})
    m.calls_made.append("get_entity(proc)")
    return m


def wb():
    return EvidenceWorkbench(InvestigationDirector())


def test_only_linked_events_are_counted_and_not_host_edges():
    effects = wb().effects(graph())
    assert [x.relation_id for x in effects] == ["r-write"]
    assert effects[0].target_label.startswith("path=C:")


def test_next_lead_prioritizes_target_of_confirmed_effect():
    tool, args, reason = wb().next_lead(graph(), {"get_relation", "get_entity"})
    assert tool == "get_entity"
    assert args["entity_id"] == "file"
    assert "wrote_file" in reason


def test_unopened_effect_is_unknown_not_proof_of_malicious():
    m = graph()
    eff = wb().effects(m)[0]
    assert not eff.target_opened
    assert "NOT OPENED" in eff.statement()
    assert "malicious" not in eff.statement()


def test_only_signed_actor_citation_does_not_cover_file_write():
    sub = {"verdict": "benign", "reasoning": "Signed legitimate user", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "proc", "property_fields": ["cmdline", "signed", "user"]}
    ]}
    assert len(wb().uncovered(graph(), sub)) == 1


def test_relation_citation_covers_action_but_not_proof_of_authorization():
    m = graph()
    sub = {"verdict": "benign", "reasoning": "Authorized maintenance", "legitimacy_evidence": [
        {"anchor": "relation", "relation_id": "r-write", "property_fields": ["source_id", "target_id"]}
    ]}
    assert not wb().uncovered(m, sub)
    assert "citation is NOT authorization" in wb().final_claim_check(m, sub)


def test_target_path_citation_covers_action_but_actor_user_does_not():
    m = graph()
    sub = {"verdict": "benign", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "file", "property_fields": ["path"]}
    ]}
    assert not wb().uncovered(m, sub)


def test_unrelated_search_hit_does_not_create_causal_effect():
    m = graph()
    m.fetched_ids.add("file")
    assert "r-unrelated" not in wb().digest(m)


def test_no_more_leads_when_no_unopened_verified_ids():
    m = graph()
    m.fetched_ids.update({"file", "r-write", "proc", "r-host", "r-unrelated", "other", "other-file"})
    assert wb().next_lead(m, {"get_entity", "get_relation"}) is None


def test_malicious_submissions_have_no_forced_benign_gaps():
    assert wb().uncovered(graph(), {"verdict": "malicious"}) == []


def test_arbitration_packet_contains_both_hypotheses_and_real_event():
    m = graph()
    packet = wb().dossier_messages(m, {"verdict": "malicious"}, {"verdict": "benign"})
    assert "--wrote_file-->" in packet[1]["content"]
    assert "H_attack" in packet[1]["content"]
    assert "H_normal" in packet[1]["content"]
    assert "ANALYSIS A" in packet[1]["content"]


def test_explicit_v16_toggle_is_noninvasive_for_legacy_model():
    agent = SimpleSGRAgent(llm=None)
    assert not agent.v16_mode
    v16 = SimpleSGRAgent(llm=None, gpt_oss_mode=True, v16_mode=True)
    assert v16.v16_mode
    assert v16.workbench is not None


def test_blind_review_ledger_does_not_leak_original_verdict():
    m = graph()
    docket = wb().digest(m)
    assert "arbitrary first investigator says attack" not in docket
    assert "EVENT r-write" in docket
