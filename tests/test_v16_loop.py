"""A fully offline three-tool case through the REAL investigation loop."""
import asyncio
import json

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import NextStep
from bluesec1_client import PublicTask, TaskResult, ToolCallResult


def finish() -> NextStep:
    return NextStep.model_validate({
        "current_state": "Test both explanations against confirmed file write.",
        "plan_remaining_steps_brief": ["Submit verified evidence"],
        "task_completed": True,
        "function": {"tool": "finish_investigation", "submission": {
            "verdict": "benign", "reasoning": "Inventory script wrote an observed report.",
            "legitimacy_evidence": [{
                "anchor": "relation", "relation_id": "write-edge",
                "property_fields": ["source_id", "target_id", "type"],
            }],
        }},
    })


class FakeLLM:
    async def next_step(self, messages, *, finish_only=False):
        if finish_only:
            assert any("VERIFIED" in str(x) for x in messages)
            return finish()
        if not getattr(self, "started", False):
            self.started = True
            return NextStep.model_validate({
                "current_state": "First inspect original process",
                "plan_remaining_steps_brief": ["Get process"],
                "task_completed": False,
                "function": {"tool": "get_entity", "entity_id": "proc",
                             "reasoning": "Inspect original process"},
            })
        return finish()


class FakeSession:
    task_id = "v16-synthetic"

    def __init__(self):
        self.task = PublicTask(task_id=self.task_id, observation={
            "alert_text": {
                "alert_description": "Started service script",
                "trigger_entities": [{"id": "proc", "type": "windows_process",
                    "properties": {"cmdline": "powershell -File inventory.ps1"}}],
            },
            "available_tools": json.dumps([
                {"name": name, "arguments": [arg]}
                for name, arg in (("get_entity", "entity_id"),
                                  ("get_relation", "relation_id"),
                                  ("finish_investigation", "submission"))
            ]),
        })
        self.calls = []

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        if name == "get_entity" and args.get("entity_id") == "proc":
            observed = {"id": "proc", "type": "windows_process", "properties": {
                "cmdline": "powershell -File inventory.ps1"},
                "relation_ids": {"outgoing": ["write-edge"]}}
        elif name == "get_relation" and args.get("relation_id") == "write-edge":
            observed = {"id": "write-edge", "type": "wrote_file",
                "source_id": "proc", "target_id": "report"}
        elif name == "get_entity" and args.get("entity_id") == "report":
            observed = {"id": "report", "type": "windows_file",
                        "properties": {"path": "C:/reports/inventory.csv"}}
        elif name == "finish_investigation":
            return ToolCallResult(task_id=self.task_id, tool_name=name,
                terminated=True, task_result=TaskResult(task_id=self.task_id,
                                                         completion_reason="terminated"))
        else:
            raise AssertionError((name, args))
        return ToolCallResult(task_id=self.task_id, tool_name=name,
            observation={"last_tool_result": json.dumps(observed)},
            info={"tool_status": "ok"})


def test_v16_redirects_two_early_finishes_then_runs_blind_audit():
    session = FakeSession()
    agent = SimpleSGRAgent(FakeLLM(), max_steps=12, trajectory_dir=None,
                           review_enabled=True, gpt_oss_mode=True, v16_mode=True)
    transcript = []
    result = asyncio.run(agent._investigate(session, transcript))
    assert result.completion_reason == "terminated"
    assert [name for name, _ in session.calls] == [
        "get_entity", "get_relation", "get_entity", "finish_investigation"
    ]
    assert sum("v16_evidence_gate" in str(m) for m in transcript) >= 2
    assert sum("blind_review" in str(m) for m in transcript) == 1
    last = session.calls[-1][1]["submission"]
    assert last["verdict"] == "benign"
    assert all(e.get("relation_id") != "fabricated" for e in last["legitimacy_evidence"])
