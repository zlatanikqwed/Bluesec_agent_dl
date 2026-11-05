"""New public-evidence behavior for v31+Harvest. Synthetic graph only."""
import base64
import json

import pytest

from bluesec1_agent.decision_guard import detect_attack_signals, decisive_signals
from bluesec1_agent.response_mapper import ObservedGraph, merge_benign, merge_submission
from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_client import ToolCallResult

HOST = "11111111-1111-4111-8111-111111111111"
P = "22222222-2222-4222-8222-222222222222"
C = "33333333-3333-4333-8333-333333333333"
FILE = "44444444-4444-4444-8444-444444444444"
USER = "55555555-5555-4555-8555-555555555555"
PEER = "66666666-6666-4666-8666-666666666666"
CONN = "77777777-7777-4777-8777-777777777777"

def entity(nid, typ, **props):
    return {"id": nid, "type": typ, "properties": props}


def graph():
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [
        entity(HOST, "host", hostname="MAIN", ip="10.1.1.1"),
        {**entity(P, "windows_process", pid=100, logon_id="0xa1234",
                  user_sid="S-1-5-21-1000", user="OPS\\john",
                  image_path=r"C:\Windows\System32\powershell.exe"), "host_id": HOST}]}})
    g.absorb([
        {**entity(C, "windows_process", pid=200, parent_pid=100,
                  start_time="2026-10-01T12:03", image_path=r"C:\Users\Public\payload.exe",
                  user="OPS\\john", user_sid="S-1-5-21-1000"), "host_id": HOST},
        entity(USER, "windows_user", sid="S-1-5-21-1000", username="john",
               group_memberships=["Domain Users"]),
        entity(FILE, "windows_file", path=r"C:\Users\Public\payload.exe", is_executable=True),
        entity(PEER, "host", ip="10.1.1.9", hostname="PEER", role="workstation"),
        entity(CONN, "network_connection", src_ip="10.1.1.1", dst_ip="10.1.1.9"),
        {"id": "rconn", "type": "connected_to", "source_id": P, "target_id": CONN},
        entity("svc", "windows_service", binary_path=r"C:\Program Files\Vendor\app.exe"),
        {"id": "rfile", "type": "wrote_file", "source_id": P, "target_id": FILE},
        {"id": "rspawn", "type": "win_process_create", "source_id": P, "target_id": C},
    ])
    return g


def test_structural_write_then_execute_veto_requires_both_halves():
    g = graph()
    signals = decisive_signals(detect_attack_signals(g.entities, {
        k: (v["type"], v["source_id"], v["target_id"]) for k, v in g.relations.items()}))
    assert any("wrote and executed" in a.name for a in signals)
    edges = {"rfile": ("wrote_file", P, FILE)}
    assert not any("wrote and executed" in a.name for a in
                   detect_attack_signals({k: v for k, v in g.entities.items() if k != C}, edges))


def test_system_binary_and_hidden_parent_and_reserved_dns():
    encoded = base64.b64encode('IEX (New-Object Net.WebClient)'.encode('utf-16-le')).decode()
    nodes = {
        "parent": entity("parent", "windows_process", pid=1,
                         image_path=r"C:\Windows\System32\powershell.exe",
                         cmdline=f"powershell -WindowStyle Hidden -EncodedCommand {encoded}",
                         cmdline_decoded="IEX (New-Object Net.WebClient)"),
        "child": entity("child", "windows_process", parent_pid=1,
                        image_path=r"C:\ProgramData\odd.exe", user="SYSTEM"),
        "net": entity("net", "network_connection", fqdn="c2.invalid", query_status="SUCCESS",
                      dst_ip="192.0.2.20"),
    }
    for n in nodes.values():
        n["host_id"] = HOST
    named = {s.name for s in decisive_signals(detect_attack_signals(nodes, {}))}
    assert "child launched by hidden encoded PowerShell parent" in named
    assert "SYSTEM launched executable from writable non-system location" in named
    assert "successful resolution of a .invalid DNS domain" in named
    nodes["net"]["properties"]["fqdn"] = "telemetry.eset.example"
    assert "reserved-domain DNS resolution (context only)" in {s.name for s in detect_attack_signals(nodes, {})}
    assert "successful resolution of a .invalid DNS domain" not in {
        s.name for s in decisive_signals(detect_attack_signals(nodes, {}))}


def test_merged_report_has_actions_only_and_exact_written_payload():
    g = graph()
    original = {"verdict": "malicious", "reasoning": "observed executable execution",
                "ir_artifacts": [
                    {"entity_id": P, "kind": "process_observed"},
                    {"entity_id": FILE, "kind": "file_observed"},
                    {"entity_id": CONN, "kind": "network_block"}]}
    merged = merge_submission(original, g)
    items = {(a["entity_id"], a["kind"]) for a in merged["ir_artifacts"]}
    assert (HOST, "host_to_isolate") in items
    assert (USER, "identity_to_rotate") in items
    assert (FILE, "file_to_delete") in items
    assert not any(kind.endswith("_observed") for _, kind in items)
    assert (CONN, "network_block") not in items


def test_benign_cites_peer_user_service_not_trigger_or_relation():
    g = graph()
    sub = {"verdict": "benign", "reasoning": "ordinary maintenance", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": P, "property_fields": ["cmdline"]},
        {"anchor": "relation", "relation_id": "rspawn", "property_fields": ["source_id", "target_id"]}]}
    evid = merge_benign(sub, g)["legitimacy_evidence"]
    # Phase F: an opened file actually written by the chain outranks an
    # unrelated service when only three citations are allowed.
    assert {x["entity_id"] for x in evid} == {PEER, USER, FILE}
    assert {"hostname", "role"} == set(evid[0]["property_fields"])
    assert not any("source_id" in x["property_fields"] for x in evid)


@pytest.mark.asyncio
async def test_harvest_unscoped_uuid_and_no_get_entity_trigger():
    g = graph()
    class Session:
        def __init__(self): self.calls = []
        async def call_tool(self, tool, args):
            self.calls.append((tool, args))
            raw = {"results": []}
            if tool == "search" and args["query"] == P and not args.get("scope"):
                raw = {"relations": list(g.relations.values())}
            elif tool == "search" and (args.get("scope") or {}).get("type") == "windows_process":
                raw = {"entities": [g.entities[C]]}
            elif tool == "search" and (args.get("scope") or {}).get("type") == "windows_user":
                raw = {"entities": [g.entities[USER]]}
            elif tool == "get_entity" and args.get("entity_id") == FILE:
                raw = g.entities[FILE]
            return ToolCallResult(task_id="example", tool_name=tool, info={"tool_result": raw,
                                  "tool_status": "ok"})
    session = Session()
    alert = {"trigger_entities": [g.entities[P], g.entities[HOST]], "trigger_relations": []}
    out = await EvidenceHarvester(budget=8).collect(
        session, {"alert_text": alert}, {"search", "get_entity", "get_relation"},
        lambda tool, args, response: None)
    assert out.completed
    assert session.calls[0][0] == "search"
    assert session.calls[0][1].get("scope") is None
    assert not any(t == "get_entity" and a.get("entity_id") == P for t, a in session.calls)
    assert out.discovered_relations >= 2
    assert out.calls <= 8


@pytest.mark.asyncio
async def test_system_logon_does_not_search_session_or_sid():
    g = graph()
    alert = {"trigger_entities": [
        {**g.entities[P], "properties": {**g.props(P), "logon_id": "0x3e7",
                                               "user_sid": "S-1-5-18", "user": "SYSTEM"}},
        g.entities[HOST]]}
    class Session:
        def __init__(self): self.calls=[]
        async def call_tool(self, tool, args):
            self.calls.append((tool, args))
            return ToolCallResult(task_id="sys", tool_name=tool,
                                  info={"tool_result": {"results": []}, "tool_status": "ok"})
    sess = Session()
    await EvidenceHarvester(budget=8).collect(
        sess, {"alert_text": alert}, {"search", "get_entity"}, lambda *args: None)
    assert not any(a.get("query") in ("0x3e7", "S-1-5-18") for _, a in sess.calls)

@pytest.mark.asyncio
async def test_agent_vetoes_benign_using_only_harvested_search_graph():
    """No extra model calls or scoring fields: structural proof reaches final guard."""
    from bluesec1_agent.agent import SimpleSGRAgent
    from bluesec1_agent.models import NextStep
    from bluesec1_client import PublicTask, TaskResult

    g = graph()
    trig = {**g.entities[P], "properties": {
        **g.props(P), "logon_id": "0xa1234", "start_time": "2026-10-01T12:00:00Z"}}
    alert = {"trigger_entities": [trig, g.entities[HOST]], "trigger_relations": []}
    class Session:
        def __init__(self):
            self.calls = []
            self.task_id = "case-hardened"
            self.task = PublicTask(task_id=self.task_id, observation={
                "alert_text": alert,
                "available_tools": json.dumps([{"name": t, "parameters": {}} for t in
                                               ("search", "get_entity", "finish_investigation")])})
        async def call_tool(self, tool, args):
            self.calls.append((tool, args))
            data = {"results": []}
            if tool == "search":
                typ = (args.get("scope") or {}).get("type")
                if args.get("query") == P and not typ:
                    data = {"relations": list(g.relations.values())}
                elif typ == "windows_process":
                    data = {"results": [g.entities[C]]}
                elif typ == "windows_user":
                    data = {"results": [g.entities[USER]]}
                elif typ == "host":
                    data = {"results": [g.entities[PEER]]}
                elif typ == "windows_file":
                    data = {"results": [g.entities[FILE]]}
            elif tool == "get_entity" and args.get("entity_id") == FILE:
                data = g.entities[FILE]
            if tool == "finish_investigation":
                self.submission = args["submission"]
                return ToolCallResult(task_id=self.task_id, tool_name=tool, terminated=True,
                                      info={"tool_result": {}},
                                      task_result=TaskResult(task_id=self.task_id,
                                                             completion_reason="terminated"))
            return ToolCallResult(task_id=self.task_id, tool_name=tool,
                                  info={"tool_result": data, "tool_status": "ok"})
    class LLM:
        async def next_step(self, *_args, **_kwargs):
            return NextStep.model_validate({
                "current_state": "Routine maintenance", "plan_remaining_steps_brief": ["submit"],
                "task_completed": True, "function": {"tool": "finish_investigation",
                    "submission": {"verdict": "benign", "reasoning": "Signed PowerShell",
                                   "legitimacy_evidence": [{"anchor": "entity",
                                       "entity_id": P, "property_fields": ["image_path"]}]}}})
    session = Session()
    agent = SimpleSGRAgent(LLM(), harvest_mode=True, harvest_budget=8, max_steps=12,
                           review_enabled=False, v16_mode=False, soc_v18_mode=False,
                           soc_v19_mode=False, soc_v21_mode=False, soc_v23_mode=False,
                           soc_v24_mode=False, v25_response_mode=False, trajectory_dir=None)
    await agent._investigate(session, [])
    assert session.submission["verdict"] == "malicious"
    final = {(a["entity_id"], a["kind"]) for a in session.submission["ir_artifacts"]}
    assert (HOST, "host_to_isolate") in final
    assert (FILE, "file_to_delete") in final
    assert (USER, "identity_to_rotate") in final
    assert not any(kind.endswith("_observed") for _, kind in final)
