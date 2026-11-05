"""Mock runtime regression for search-first harvesting without grader signals."""
import json
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester, _public
from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import NextStep
from bluesec1_client import PublicTask, TaskResult, ToolCallResult

HOST = "11111111-1111-4111-8111-111111111111"
TRIGGER = "22222222-2222-4222-8222-222222222222"
CHILD = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
USER = "55555555-5555-4555-8555-555555555555"
FILE = "66666666-6666-4666-8666-666666666666"
PEER = "77777777-7777-4777-8777-777777777777"
LOGON = "0xa1982"
SID = "S-1-5-21-100-100-100-1001"


def entity(nid, typ, **p):
    return {"id": nid, "type": typ, "host_id": HOST if typ == "windows_process" else None,
            "properties": p}


ALERT = {
    "trigger_entities": [
        entity(HOST, "host", ip="10.10.0.8", hostname="SRC"),
        entity(TRIGGER, "windows_process", pid=120, parent_pid=4,
               image_path=r"C:\Windows\System32\powershell.exe", user="CORP\\Analyst",
               user_sid=SID, logon_id=LOGON, start_time="2026-10-01T10:00:00Z",
               cmdline=r"powershell.exe C:\ProgramData\payload.ps1"),
    ],
    "trigger_relations": [],
    "alert_description": "Process started with a script argument",
}


class Session:
    def __init__(self):
        self.calls = []
        self.task_id = "case-test"
        self.task = PublicTask(task_id=self.task_id, observation={
            "alert_text": ALERT,
            "available_tools": json.dumps([{"name": t, "parameters": {}} for t in
                                           ("search", "get_entity", "get_relation", "finish_investigation")]),
        })

    async def call_tool(self, tool, args):
        self.calls.append((tool, args))
        raw = {}
        if tool == "search":
            typ = args.get("scope", {}).get("type")
            if typ == "windows_process" and args.get("query") == LOGON:
                raw = {"results": [
                    entity(CHILD, "windows_process", pid=450, parent_pid=120, user="CORP\\Analyst",
                           logon_id=LOGON, user_sid=SID, image_path=r"C:\ProgramData\payload.exe",
                           start_time="2026-10-01T10:01:00Z", cmdline=r"C:\ProgramData\payload.exe"),
                    entity(OTHER, "windows_process", pid=999, parent_pid=87,
                           logon_id=LOGON, start_time="2026-10-01T10:01:00Z", cmdline="explorer.exe"),
                ]}
            elif typ == "logged_on_to":
                raw = {"results": [{"id": "88888888-8888-4888-8888-888888888888",
                        "type": "logged_on_to", "source_id": USER, "target_id": HOST,
                        "properties": {"source_ip": "192.0.2.66"}}]}
            elif typ == "windows_user":
                raw = {"results": [entity(USER, "windows_user", sid=SID, username="Analyst",
                                              group_memberships=["Domain Users"])]}
            elif typ == "host":
                raw = {"results": [entity(PEER, "host", ip="192.0.2.66")]}
            elif typ == "windows_file":
                raw = {"results": [entity(FILE, "windows_file", path=r"C:\ProgramData\payload.exe",
                                              is_executable=True)]}
            elif typ == "wrote_file":
                raw = {"results": [{"id": "99999999-9999-4999-8999-999999999999",
                        "type": "wrote_file", "source_id": TRIGGER, "target_id": FILE}]}
        elif tool == "get_entity":
            raw = {**ALERT["trigger_entities"][1],
                   "relation_ids": {"incoming": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
                                    "outgoing": ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]}}
        terminal = tool == "finish_investigation"
        return ToolCallResult(task_id=self.task_id, tool_name=tool, terminated=terminal,
                              info={"tool_result": raw, "tool_status": "ok",
                                    "ground_truth_only": "dangerous", "reward": 100000},
                              reward=100000,
                              task_result=TaskResult(task_id=self.task_id, completion_reason="terminated")
                              if terminal else None)


@pytest.mark.asyncio
async def test_harvest_discovers_session_descendants_actor_peer_and_files():
    session = Session()
    values = []
    harvest = await EvidenceHarvester(budget=9).collect(
        session, {"alert_text": ALERT}, {"search", "get_entity", "get_relation"},
        lambda name, args, result: values.append((name, args)))
    assert harvest.completed
    assert 7 <= harvest.calls <= 9
    assert len([c for c in session.calls if c[0] == "get_relation"]) == 0
    assert any(c[1].get("scope", {}).get("type") == "windows_user" for c in session.calls)
    assert any(c[1].get("scope", {}).get("type") == "host" for c in session.calls)
    assert any(c[1].get("scope", {}).get("type") == "windows_file" for c in session.calls)
    assert CHILD in harvest.digest
    assert OTHER not in harvest.digest  # same-logon bystanders aren't causal descendants
    assert "ground_truth_only" not in harvest.digest
    assert "reward" not in harvest.digest
    assert len(harvest.digest) <= 4800


def test_grade_metadata_is_stripped():
    assert _public({"results": [{"type": "host", "log_sources": ["ground_truth_only"],
                                 "properties": {"ip": "10.2.3.4"}}],
                    "runtime_reward": 42}) == {"results": [{"type": "host",
                                                               "properties": {"ip": "10.2.3.4"}}]}


@pytest.mark.asyncio
async def test_original_decision_pipeline_still_submits_after_harvest():
    class LLM:
        def __init__(self): self.calls = []
        async def next_step(self, msgs, *, finish_only=False):
            self.calls.append((msgs, finish_only))
            return NextStep.model_validate({
                "current_state": "Observed an unauthorized payload execution chain.",
                "plan_remaining_steps_brief": ["Submit a verified verdict"],
                "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "Observed payload and session context.",
                    "ir_artifacts": [{"entity_id": HOST, "kind": "host_to_isolate"}]}}
            })
    session = Session()
    llm = LLM()
    agent = SimpleSGRAgent(llm, harvest_mode=True, harvest_budget=8,
                           review_enabled=False, v16_mode=False, soc_v19_mode=False,
                           max_steps=12, trajectory_dir=None)
    transcript = []
    outcome = await agent._investigate(session, transcript)
    assert outcome.completion_reason == "terminated"
    assert len(llm.calls) >= 1
    assert llm.calls[0][1] is True  # unchanged v31 finish-only schema
    assert session.calls[-1][0] == "finish_investigation"
    assert len(session.calls) <= 10
    assert not any(call[0] == "get_relation" for call in session.calls)
    assert any("V31" not in str(t.get("content", "")) for t in transcript)

@pytest.mark.asyncio
async def test_default_v24_and_v25_do_not_blow_platform_budget():
    class LLM:
        def __init__(self): self.requests=[]
        async def next_step(self, msgs, *, finish_only=False):
            self.requests.append((msgs, finish_only))
            return NextStep.model_validate({
                "current_state": "Malicious payload chain grounded in observed facts.",
                "plan_remaining_steps_brief": ["Submit exact incident report"],
                "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "Observed script payload under actor session.",
                    "ir_artifacts": [{"entity_id": HOST, "kind": "host_to_isolate"}]}}
            })
    session=Session();llm=LLM()
    agent=SimpleSGRAgent(llm, soc_v24_mode=True, v25_response_mode=True,
                         v25_scope_calls=3, v25_benign_calls=3,
                         harvest_mode=True, harvest_budget=8,
                         review_enabled=True, max_steps=28, trajectory_dir=None)
    output=await agent._investigate(session, [])
    assert output.completion_reason == "terminated"
    assert len(session.calls) <= 10  # 8 harvest + at most 1 scope + report
    assert llm.requests
    assert llm.requests[0][1] is True  # v31 original, NOT v32's judge_case
    assert len(str(llm.requests[0][0])) <= 22000  # rough provider 8k safety ceiling
