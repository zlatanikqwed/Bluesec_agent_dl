"""Model-agnostic local checks for v15.1's GPT-OSS premature finish guard."""

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.models import NextStep


class NoNetworkLLM:
    model = "openai/gpt-oss-20b"


def investigation_memory():
    m = InvestigationMemory()
    m.absorb({"id": "trigger", "type": "windows_process", "properties": {
        "cmdline": "powershell -File script.ps1"}})
    m.focus_ids = {"trigger"}
    m.trigger_ids = set(m.known_ids)
    # A real get_entity introduces a relation ID, not an imaginary one.
    m.absorb({"id": "trigger", "type": "windows_process", "properties": {
        "cmdline": "powershell -File script.ps1"},
        "relation_ids": {"outgoing": ["write-edge"]}})
    m.fetched_ids.add("trigger")
    m.calls_made.append("get_entity(trigger)")
    return m


def test_premature_benign_is_redirected_to_known_relation():
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    m = investigation_memory()
    reroute = agent._redirect_premature_finish("benign", m, {"get_relation", "get_entity"})
    assert reroute is not None
    tool, args, reason = reroute
    assert tool == "get_relation"
    assert args["relation_id"] == "write-edge"
    assert "only 1 calls" in reason


def test_forwarding_an_early_finish_is_locally_rolled_back():
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    original = NextStep.model_validate({
        "current_state": "Signed PowerShell implies safe.",
        "plan_remaining_steps_brief": ["Finish"],
        "task_completed": True,
        "function": {"tool": "finish_investigation", "submission": {
            "verdict": "benign", "reasoning": "Only trusted binary name observed.",
            "legitimacy_evidence": [{"anchor": "entity", "entity_id": "trigger",
                                     "property_fields": ["cmdline"]}],
        }},
    })
    action = agent._redirect_premature_finish("benign", investigation_memory(),
                                              {"get_relation", "get_entity"})
    assert action
    redirected = agent._replace_finish_with_lookup(original, *action)
    assert redirected.function.tool == "get_relation"
    assert redirected.task_completed is False
    assert redirected.function.relation_id == "write-edge"


def test_no_fabricated_calls_when_frontier_exhausted():
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    m = investigation_memory()
    m.fetched_ids.add("write-edge")
    assert agent._redirect_premature_finish("benign", m, {"get_relation", "get_entity"}) is None


def test_after_causal_coverage_finish_allowed():
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    m = investigation_memory()
    m.absorb({"id": "report", "type": "windows_file", "properties": {"path": "C:/report.txt"}})
    m.absorb({"id": "write-edge", "type": "wrote_file",
              "source_id": "trigger", "target_id": "report"})
    m.fetched_ids.update({"write-edge", "report"})
    m.calls_made.extend(f"get_entity({i})" for i in range(8))
    assert agent._redirect_premature_finish("benign", m, {"get_relation", "get_entity"}) is None


def test_unknown_reference_never_reaches_server_after_rejections_exhausted():
    # Repaired deterministically instead of rejected: a temperature-0 LLM repeats
    # the same finish, so rejection looped to the step limit (aborted task, Q=0).
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    m = investigation_memory()
    finish = {"submission": {"verdict": "benign", "reasoning": "ordinary task",
            "legitimacy_evidence": [{"anchor": "entity", "entity_id": "fabricated-id",
                                    "property_fields": ["cmdline"]}]}}
    agent._local_check("finish_investigation", finish,
                       {"finish_investigation"}, m, finish_rejections=999)
    assert finish["submission"]["legitimacy_evidence"] == []


def test_invalid_cited_field_never_reaches_server_after_rejections_exhausted():
    agent = SimpleSGRAgent(NoNetworkLLM(), gpt_oss_mode=True)
    m = investigation_memory()
    finish = {"submission": {"verdict": "benign", "reasoning": "ordinary task",
            "legitimacy_evidence": [{"anchor": "entity", "entity_id": "trigger",
                                    "property_fields": ["invented_field"]}]}}
    agent._local_check("finish_investigation", finish,
                       {"finish_investigation"}, m, finish_rejections=999)
    assert all("invented_field" not in e["property_fields"]
               for e in finish["submission"]["legitimacy_evidence"])


def test_original_v15_mode_still_disabled_by_default():
    agent = SimpleSGRAgent(NoNetworkLLM())
    assert not agent.gpt_oss_mode
    assert agent.max_finish_rejections == 1
