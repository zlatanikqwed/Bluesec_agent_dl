"""Offline tests for the v32 public-evidence-only investigation path."""
import asyncio
import json

from bluesec1_agent.harvest_v32 import (
    HarvestJudgeReport, _malicious_actions, _legitimate_evidence, _search,
)
from bluesec1_agent.models import NextStep
from bluesec1_agent.response_mapper import ObservedGraph
from bluesec1_client import PublicTask, ToolCallResult, TaskResult


HOST = "host-test-1"
TRIGGER = "trigger-proc-1"
USER = "actor-user-1"
FILE = "payload-file-1"
OTHER = "unrelated-file-1"


def public_alert():
    return {"trigger_entities": [
        {"id": HOST, "type": "host", "properties": {"ip": "10.1.1.5", "hostname": "OPS"}},
        {"id": TRIGGER, "type": "windows_process", "host_id": HOST,
         "properties": {"pid": 512, "logon_id": "0x15fabc", "user_sid": "S-1-5-21-12345",
                        "user": "OPS\\alice", "cmdline": "powershell.exe -nop",
                        "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "start_time": "2024-06-12T08:17:08+00:00"}},
    ], "trigger_relations": []}


def fake_graph():
    g = ObservedGraph()
    g.absorb_alert({"alert_text": public_alert()})
    g.absorb({"id": USER, "type": "windows_user", "properties": {
        "user_sid": "S-1-5-21-12345", "username": "alice", "group_memberships": ["Ops"]}})
    g.absorb({"id": FILE, "type": "windows_file", "properties": {
        "path": "C:\\Windows\\Temp\\a.exe", "is_executable": True}})
    g.absorb({"id": OTHER, "type": "windows_file", "properties": {
        "path": "C:\\Windows\\Temp\\unrelated.exe", "is_executable": True}})
    g.absorb({"id": "write-rel-1", "type": "wrote_file", "source_id": TRIGGER, "target_id": FILE})
    return g


def test_search_contract():
    tool, args = _search("0x15fabc", "Observe same logon session", "windows_process",
                         window={"from": "2024-06-12T08:17:00+00:00",
                                 "to": "2024-06-12T09:17:00+00:00"})
    assert tool == "search"
    assert args["scope"] == {"kind": "entity", "type": "windows_process"}
    assert args["time_window"]["from"].startswith("2024-06-12")


def test_malicious_precision():
    found = _malicious_actions(fake_graph(), TRIGGER, [])
    assert {tuple(x.values()) for x in found} == {
        (HOST, "host_to_isolate"), (USER, "identity_to_rotate"), (FILE, "file_to_delete")}
    assert not any(a["kind"].endswith("_observed") for a in found)


def test_benign_excludes_trigger():
    found = _legitimate_evidence(fake_graph(), TRIGGER, [
        {"anchor": "entity", "entity_id": TRIGGER, "property_fields": ["user"]},
        {"anchor": "entity", "entity_id": USER, "property_fields": ["group_memberships"]},
    ])
    assert all(f["entity_id"] != TRIGGER for f in found)
    assert found[0]["property_fields"] == ["group_memberships", "username"]


class FakeJudge:
    def __init__(self, verdict):
        self.verdict = verdict
        self.calls = 0

    async def next_step(self, messages, *, finish_only=False):
        self.calls += 1
        assert finish_only
        payload = ({"verdict": "malicious", "ir_artifacts": [{"entity_id": FILE, "kind": "file_to_delete"}],
                    "reasoning": "Payload written by trigger"} if self.verdict == "malicious" else
                   {"verdict": "benign", "legitimacy_evidence": [{"anchor": "entity", "entity_id": USER,
                    "property_fields": ["group_memberships"]}], "reasoning": "Approved admin operation"})
        return NextStep.model_validate({"current_state": "public evidence", "plan_remaining_steps_brief": ["finish"],
                                       "task_completed": True, "function": {"tool": "finish_investigation", "submission": payload}})


class FakeSession:
    def __init__(self):
        self.task = PublicTask(task_id="t", observation={"alert_text": public_alert()})
        self.calls = []

    async def call_tool(self, tool, args):
        self.calls.append((tool, args))
        result = {}
        if tool == "search" and args.get("scope", {}).get("type") == "windows_user":
            result = {"results": [{"id": USER, "type": "windows_user",
                                   "properties": {"user_sid": "S-1-5-21-12345", "username": "alice",
                                                  "group_memberships": ["Ops"]}}]}
        if tool == "search" and args.get("scope", {}).get("type") == "wrote_file":
            result = {"results": [
                {"id": "write-rel-1", "type": "wrote_file", "source_id": TRIGGER, "target_id": FILE},
                {"id": FILE, "type": "windows_file", "properties": {"path": "C:\\Windows\\Temp\\a.exe", "is_executable": True}},
            ]}
        term = tool == "finish_investigation"
        return ToolCallResult(task_id="t", tool_name=tool, terminated=term,
                              reward=999999.0, # MUST NOT affect any decision!
                              info={"tool_status": "ok", "tool_result": result,
                                    "runtime_reward": 99999, "log_sources": "ground_truth_only"},
                              task_result=TaskResult(task_id="t", completion_reason="terminated") if term else None)


def test_v32_end_to_end_without_reward_leak():
    session, judge = FakeSession(), FakeJudge("malicious")
    transcript = []
    final = asyncio.run(HarvestJudgeReport(judge, budget=7, votes=3).investigate(
        session, transcript, tool_specs=[{"name": "search"}, {"name": "get_entity"},
                                        {"name": "finish_investigation"}] ))
    assert final.completion_reason == "terminated"
    assert judge.calls == 3
    assert len(session.calls) <= 8  # 7 harvest + 1 finish
    assert session.calls[-1][0] == "finish_investigation"
    artifacts = session.calls[-1][1]["submission"]["ir_artifacts"]
    assert any(x["entity_id"] == HOST and x["kind"] == "host_to_isolate" for x in artifacts)
    assert any(x["entity_id"] == USER and x["kind"] == "identity_to_rotate" for x in artifacts)
    assert not any(x["kind"].endswith("_observed") for x in artifacts)
    assert "runtime_reward" not in str(transcript)
    assert "ground_truth_only" not in str(transcript)
