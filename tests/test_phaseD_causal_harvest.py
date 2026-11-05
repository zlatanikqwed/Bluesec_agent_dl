"""Phase D: reward-independent, causal discovery before session/network sweeps."""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.response_mapper import ObservedGraph

P = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
C1 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
C2 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
C3 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
F1 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
F2 = "ffffffff-ffff-4fff-8fff-ffffffffffff"
H = "11111111-1111-4111-8111-111111111111"
U = "22222222-2222-4222-8222-222222222222"
NET = "33333333-3333-4333-8333-333333333333"
PEER = "44444444-4444-4444-8444-444444444444"
SVC = "55555555-5555-4555-8555-555555555555"
GRP = "66666666-6666-4666-8666-666666666666"
ARC = "77777777-7777-4777-8777-777777777777"
HANDLE = "88888888-8888-4888-8888-888888888888"
LOGON = "0xabcd91"
SID = "S-1-5-21-1000-1000-1000-1001"


def node(nid, kind, **props):
    return {"id": nid, "type": kind, "properties": props,
            "host_id": H if kind == "windows_process" else None}


def edge(nid, kind, src, dst):
    return {"id": nid, "type": kind, "source_id": src, "target_id": dst}


ALERT = {"trigger_entities": [
    node(H, "host", hostname="START", ip="10.0.0.10"),
    node(P, "windows_process", pid=100, logon_id=LOGON, user_sid=SID,
         start_time="2026-10-20T10:00:00Z",
         image_path=r"C:\Windows\System32\powershell.exe")], "trigger_relations": []}


class FakeSession:
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.calls = []

    async def call_tool(self, tool, args):
        self.calls.append((tool, args))
        raw = self.dispatcher(tool, args)
        return SimpleNamespace(info={"tool_result": raw}, observation={},
                               task_result=None, reward=5.0)


async def harvest(session, budget=8, alert=ALERT):
    evidence = []
    result = await EvidenceHarvester(budget=budget).collect(
        session, {"alert_text": alert}, {"search", "get_entity", "get_relation"},
        lambda t, args, response: evidence.append((t, args, response.info.get("tool_result"))))
    graph = ObservedGraph()
    graph.absorb_alert({"alert_text": alert})
    for _, _, raw in evidence:
        graph.absorb(raw)
    return result, graph


@pytest.mark.asyncio
async def test_spawn_edges_open_three_children_without_session_scan():
    children = [node(C1, "windows_process", pid=101, parent_pid=100,
                     logon_id=LOGON, image_path=r"C:\Windows\System32\cmd.exe"),
                node(C2, "windows_process", pid=102, parent_pid=100,
                     logon_id=LOGON, image_path=r"C:\Windows\System32\cmd.exe"),
                node(C3, "windows_process", pid=103, parent_pid=100,
                     logon_id=LOGON, image_path=r"C:\Windows\System32\cmd.exe")]
    rels = [edge(f"child-{idx}", "win_process_create", P, child["id"])
            for idx, child in enumerate(children)]
    def dispatcher(tool, args):
        if tool == "search" and args.get("query") == P and "scope" not in args:
            return {"relations": rels}
        if tool == "get_entity":
            return next((c for c in children if c["id"] == args["entity_id"]), {})
        return {"results": []}
    s = FakeSession(dispatcher)
    result, graph = await harvest(s)
    child_opens = [args["entity_id"] for t, args in s.calls
                   if t == "get_entity" and args["entity_id"] in {C1, C2, C3}]
    assert set(child_opens) == {C1, C2, C3}
    assert not any(a.get("scope", {}).get("type") == "windows_process"
                   for t, a in s.calls if t == "search")
    assert set(child_opens).issubset(graph.entities)
    assert result.calls <= 8


@pytest.mark.asyncio
async def test_no_spawn_uses_12_hour_session_window_then_opens_descendant():
    child = node(C1, "windows_process", pid=101, parent_pid=100, logon_id=LOGON,
                 image_path=r"C:\Windows\System32\cmd.exe")
    def dispatcher(tool, args):
        if tool == "search" and args.get("scope", {}).get("type") == "windows_process":
            return {"results": [child]}
        if tool == "get_entity" and args["entity_id"] == C1:
            return child
        return {"results": []}
    session = FakeSession(dispatcher)
    result, graph = await harvest(session)
    scans = [a for t, a in session.calls if t == "search" and
             a.get("scope", {}).get("type") == "windows_process"]
    assert len(scans) == 1
    window = scans[0]["time_window"]
    assert (datetime.fromisoformat(window["to"]) -
            datetime.fromisoformat(window["from"])).total_seconds() == 12 * 3600
    assert any(t == "get_entity" and a.get("entity_id") == C1
               for t, a in session.calls)
    assert result.calls <= 8


@pytest.mark.asyncio
async def test_child_image_probed_then_written_payload_opened():
    child = node(C1, "windows_process", pid=101, parent_pid=100, logon_id=LOGON,
                 image_path=r"C:\Users\Public\droplet.exe", cmdline="droplet.exe")
    f = node(F1, "windows_file", path=r"C:\Users\Public\second.exe")
    def dispatcher(tool, args):
        if tool == "search" and args.get("query") == P and not args.get("scope"):
            return {"relations": [edge("r-spawn", "win_process_create", P, C1)]}
        if tool == "get_entity" and args["entity_id"] == C1:
            return child
        if tool == "search" and args.get("query") == C1 and not args.get("scope"):
            return {"relations": [edge("r-write", "wrote_file", C1, F1)]}
        if tool == "get_entity" and args["entity_id"] == F1:
            return f
        return {"results": []}
    s = FakeSession(dispatcher)
    out, graph = await harvest(s, budget=8)
    assert any(t == "search" and a["query"] == C1 and not a.get("scope")
               for t, a in s.calls if t == "search")
    assert F1 in graph.entities
    assert any(t == "get_entity" and a.get("entity_id") == F1 for t, a in s.calls)
    assert out.calls <= 8


@pytest.mark.asyncio
async def test_effect_targets_prioritized_and_network_is_one_call():
    f1 = node(F1, "windows_file", path=r"C:\Temp\drop.exe")
    f2 = node(F2, "windows_file", path=r"C:\Temp\drop2.exe")
    r = [edge("r-a", "wrote_file", P, F1),
         edge("r-b", "wrote_file", P, F2),
         edge("r-c", "added_to_group", P, GRP),
         edge("r-d", "started_service", P, SVC),
         edge("r-e", "opened_handle", P, HANDLE),
         edge("r-f", "deleted_file", P, ARC),
         edge("r-g", "connected_to", P, NET),
         edge("r-h", "connected_to", P, "other-connection")]
    nodes = {F1: f1, F2: f2, GRP: node(GRP, "ad_object", name="Administrators"),
             SVC: node(SVC, "windows_service", name="Updater"),
             HANDLE: node(HANDLE, "windows_process", image_path="lsass.exe"),
             ARC: node(ARC, "archive_file", path=r"C:\Temp\secret.zip"),
             NET: node(NET, "network_connection", dst_ip="10.0.0.20"),
             PEER: node(PEER, "host", ip="10.0.0.20", hostname="PEER")}
    def dispatcher(tool, args):
        if tool == "search" and args.get("query") == P and not args.get("scope"):
            return {"relations": r}
        if tool == "get_entity":
            return nodes.get(args["entity_id"], {})
        if tool == "search" and args.get("scope", {}).get("type") == "host":
            return {"results": [nodes[PEER]]}
        return {"results": []}
    s = FakeSession(dispatcher)
    out, graph = await harvest(s, budget=10)
    calls = [a.get("entity_id") for t, a in s.calls if t == "get_entity"]
    assert F1 in calls and F2 in calls and GRP in calls and SVC in calls
    assert HANDLE in calls and ARC in calls
    assert calls.count(NET) <= 1 and "other-connection" not in calls
    assert out.calls <= 10


@pytest.mark.asyncio
async def test_system_skips_sid_and_session_but_opens_observed_children():
    alert = {"trigger_entities": [ALERT["trigger_entities"][0],
        node(P, "windows_process", pid=100, logon_id="0x3e7", user_sid="S-1-5-18",
             image_path=r"C:\Windows\System32\services.exe")],
        "trigger_relations": []}
    child = node(C1, "windows_process", pid=101, parent_pid=100, logon_id="0x3e7",
                 image_path=r"C:\ProgramData\p.exe")
    def dispatcher(tool, args):
        if tool == "search" and args.get("query") == P and not args.get("scope"):
            return {"relations": [edge("r-child", "win_process_create", P, C1)]}
        if tool == "get_entity" and args["entity_id"] == C1:
            return child
        return {"results": []}
    sess = FakeSession(dispatcher)
    out, _ = await harvest(sess, budget=8, alert=alert)
    assert any(t == "get_entity" and a.get("entity_id") == C1 for t, a in sess.calls)
    assert all(a.get("query") not in {"0x3e7", "S-1-5-18"} for _, a in sess.calls)
    assert out.calls <= 8

@pytest.mark.asyncio
async def test_typed_outgoing_relation_ids_resolve_without_untyped_edge_sweep():
    trigger = {**ALERT["trigger_entities"][1],
               "relation_ids": {"out:win_process_create": ["spawn-ref"],
                                "out:wrote_file": ["write-ref"],
                                "outgoing": ["untyped-noise-1", "untyped-noise-2"]}}
    alert = {"trigger_entities": [ALERT["trigger_entities"][0], trigger],
             "trigger_relations": []}
    child = node(C1, "windows_process", pid=101, parent_pid=100, logon_id=LOGON,
                 image_path=r"C:\Windows\System32\cmd.exe")
    file = node(F1, "windows_file", path=r"C:\Temp\probe.exe")
    def dispatcher(tool, args):
        if tool == "get_relation":
            if args["relation_id"] == "spawn-ref":
                return edge("spawn-ref", "win_process_create", P, C1)
            if args["relation_id"] == "write-ref":
                return edge("write-ref", "wrote_file", P, F1)
        if tool == "get_entity":
            return {C1: child, F1: file}.get(args["entity_id"], {})
        return {"results": []}
    session = FakeSession(dispatcher)
    out, graph = await harvest(session, budget=8, alert=alert)
    assert C1 in graph.entities and F1 in graph.entities
    assert not any(t == "get_relation" and a["relation_id"].startswith("untyped")
                   for t, a in session.calls)
    assert out.calls <= 8
