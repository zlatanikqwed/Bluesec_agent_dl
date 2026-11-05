"""Regression: a relation id in ir_artifacts used to loop until the step limit (Q=0)."""
import pytest
from test_v31_harvest import NextStep, Session, SimpleSGRAgent

REL = "88888888-8888-4888-8888-888888888888"  # logged_on_to relation returned by the mock


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["inbound_guard", "control"])
async def test_relation_id_artifact_is_repaired_not_looped(mode):
    class LLM:
        def __init__(self):
            self.calls = 0

        async def next_step(self, msgs, *, finish_only=False):
            self.calls += 1
            return NextStep.model_validate({
                "current_state": "same answer every time (temperature 0)",
                "plan_remaining_steps_brief": ["Submit"], "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "payload",
                    "ir_artifacts": [{"entity_id": REL, "kind": "network_block"}]}}})

    session, llm = Session(), LLM()
    agent = SimpleSGRAgent(llm, harvest_mode=True, harvest_budget=8, review_enabled=False,
                           v16_mode=False, soc_v19_mode=False, max_steps=26,
                           trajectory_dir=None, report_experiment=mode)
    outcome = await agent._investigate(session, [])
    assert outcome.completion_reason == "terminated"
    assert session.calls[-1][0] == "finish_investigation"
    ids = [a["entity_id"] for a in session.calls[-1][1]["submission"]["ir_artifacts"]]
    assert REL not in ids
    assert llm.calls < 6


def test_actions_on_already_deleted_files_are_dropped():
    from bluesec1_agent.report_experiments import drop_deleted_file_artifacts
    from bluesec1_agent.response_mapper import ObservedGraph

    g = ObservedGraph()
    g.absorb([{"id": "F1", "type": "windows_file", "properties": {"path": "C:\\Temp\\a.exe"}},
              {"id": "F2", "type": "archive_file", "properties": {"path": "C:\\Temp\\b.zip"}},
              {"id": "H", "type": "host", "properties": {"hostname": "WS1"}},
              {"id": "r1", "type": "deleted_file", "source_id": "P", "target_id": "F1"},
              {"id": "r2", "type": "wrote_file", "source_id": "P", "target_id": "F2"}])
    sub = {"verdict": "malicious", "reasoning": "x", "ir_artifacts": [
        {"entity_id": "H", "kind": "host_to_isolate"},
        {"entity_id": "F1", "kind": "file_to_delete"},
        {"entity_id": "F1", "kind": "cleanup_to_verify"},
        {"entity_id": "F2", "kind": "file_to_delete"}]}
    out, dropped = drop_deleted_file_artifacts(sub, g)
    assert dropped == ["F1", "F1"]
    assert [a["entity_id"] for a in out["ir_artifacts"]] == ["H", "F2"]
    benign = {"verdict": "benign", "reasoning": "x", "legitimacy_evidence": []}
    assert drop_deleted_file_artifacts(benign, g) == (benign, [])
