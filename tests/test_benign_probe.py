import json

import pytest

from bluesec1_agent.benign_probe import apply_benign_probe, context_calls
from bluesec1_agent.models import FinishInvestigationRequest, SearchRequest
from bluesec1_agent.report_experiments import MODES
from bluesec1_agent.response_mapper import ObservedGraph


def _graph() -> ObservedGraph:
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [{
        "id": "P", "type": "windows_process", "host_id": "H",
        "properties": {"pid": 5, "image_path": "C:\\Program Files\\EDR\\agent.exe",
                       "cmdline": "agent.exe -svc", "user": "NT AUTHORITY\\SYSTEM"}}]}})
    g.absorb([
        {"id": "H", "type": "host", "properties": {"hostname": "WS1", "role": "workstation"}},
        {"id": "L", "type": "windows_process", "properties": {"image_path": "C:\\lsass.exe"}},
        {"id": "r1", "type": "hosts", "source_id": "H", "target_id": "P"},
        {"id": "r2", "type": "started_service", "source_id": "SVC", "target_id": "P"},
        {"id": "r3", "type": "opened_handle", "source_id": "P", "target_id": "L",
         "properties": {"granted_access": "0x1010"}},
    ])
    return g


def test_mode_registered():
    assert "benign_probe" in MODES


def test_context_calls_open_initiator_image_and_service():
    calls = context_calls(_graph())
    assert calls[0][0] == "get_entity" and calls[0][1]["entity_id"] == "SVC"
    kinds = [c[2] for c in calls]
    assert "image_file" in kinds and "service" in kinds
    assert len(calls) <= 4
    for tool, args, _ in calls:
        if tool == "search":
            SearchRequest.model_validate({"tool": "search", **args})


def test_one_citation_or_control_and_schema_valid():
    g = _graph()
    seen, controls = set(), 0
    for i in range(60):
        sub = {"verdict": "benign", "reasoning": "r", "legitimacy_evidence": []}
        out, design = apply_benign_probe(sub, g, f"t{i}")
        FinishInvestigationRequest.model_validate(
            {"tool": "finish_investigation", "submission": out})
        assert len(out["legitimacy_evidence"]) <= 1
        if design["factor"] == "CONTROL":
            controls += 1
            assert out["legitimacy_evidence"] == []
        else:
            seen.add(design["category"])
    assert 4 <= controls <= 25
    assert {"R trigger:opened_handle", "E trigger:windows_process"} <= seen
    mal = {"verdict": "malicious", "reasoning": "r", "ir_artifacts": []}
    assert apply_benign_probe(mal, g, "x") == (mal, {})


@pytest.mark.asyncio
async def test_agent_end_to_end_benign_probe():
    from test_v31_harvest import NextStep, Session, SimpleSGRAgent

    class LLM:
        async def next_step(self, msgs, *, finish_only=False):
            return NextStep.model_validate({
                "current_state": "x", "plan_remaining_steps_brief": ["s"], "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "benign", "reasoning": "routine", "legitimacy_evidence": []}}})

    session = Session()
    agent = SimpleSGRAgent(LLM(), harvest_mode=True, harvest_budget=8, review_enabled=False,
                           v16_mode=False, soc_v19_mode=False, max_steps=20,
                           trajectory_dir=None, report_experiment="benign_probe")
    transcript = []
    outcome = await agent._investigate(session, transcript)
    assert outcome.completion_reason == "terminated"
    designs = [json.loads(t["content"]) for t in transcript if t.get("role") == "audit"
               and "benign_probe_design" in str(t.get("content"))]
    if designs:  # the mock may route to malicious via guards; then role_policy applies
        assert session.calls[-1][1]["submission"] == designs[0]["report_after"]
    assert session.calls[-1][0] == "finish_investigation"
