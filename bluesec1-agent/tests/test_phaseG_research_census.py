"""Phase G: exact service-origin evidence + opt-in reward-blind graph census."""
import json
from types import SimpleNamespace
import pytest

from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.research_harvest_v31 import ResearchHarvester
from bluesec1_agent.response_mapper import ObservedGraph

H = "11111111-1111-4111-8111-111111111111"
P = "22222222-2222-4222-8222-222222222222"
PAR = "33333333-3333-4333-8333-333333333333"
C = "44444444-4444-4444-8444-444444444444"
G = "55555555-5555-4555-8555-555555555555"
F = "66666666-6666-4666-8666-666666666666"
NET = "77777777-7777-4777-8777-777777777777"
PEER = "88888888-8888-4888-8888-888888888888"
SVC = "99999999-9999-4999-8999-999999999999"
BAD = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

def n(nid, typ, **props):
    return {"id": nid, "type": typ, "host_id": H if typ == "windows_process" else None,
            "properties": props}

def r(rid, typ, src, dst):
    return {"id": rid, "type": typ, "source_id": src, "target_id": dst}

HOST = n(H, "host", ip="10.0.0.10", hostname="CASE")
TRIGGER = n(P, "windows_process", pid=80, parent_pid=10, parent_image=r"C:\Windows\System32\services.exe",
            image_path=r"C:\Windows\launcher-83133.exe", user="SYSTEM", logon_id="0x3e7")
ALERT = {"trigger_entities": [HOST, TRIGGER], "trigger_relations": []}

class Session:
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.calls = []
    async def call_tool(self, tool, args):
        self.calls.append((tool, args))
        return SimpleNamespace(info={"tool_result": self.dispatcher(tool, args)},
                               observation={}, task_result=None)

@pytest.mark.asyncio
async def test_service_parent_search_matches_exact_binary_and_skips_unrelated_service():
    good = n(SVC, "windows_service", service_name="PSEXESVC",
             binary_path=r"C:\Windows\launcher-83133.exe -service")
    bad = n(BAD, "windows_service", service_name="Other",
            binary_path=r"C:\Windows\elsewhere.exe -service")
    def dispatcher(tool, a):
        if tool == "search" and a.get("scope", {}).get("type") == "windows_service":
            return {"entities": [bad, good]}
        return {"results": []}
    got = []
    sess = Session(dispatcher)
    out = await EvidenceHarvester(budget=8).collect(
        sess, {"alert_text": ALERT}, {"search", "get_entity", "get_relation"},
        lambda tool, args, response: got.append(response.info["tool_result"]))
    g = ObservedGraph()
    for x in got:
        g.absorb(x)
    assert SVC in g.entities
    assert BAD not in g.entities
    assert any(t == "search" and a.get("scope", {}).get("type") == "windows_service"
               and a["query"] == "launcher-83133.exe" for t, a in sess.calls)
    assert out.calls <= 8

@pytest.mark.asyncio
async def test_no_service_lookup_for_unrelated_parent():
    alert = {"trigger_entities": [HOST, {**TRIGGER, "properties": {
        **TRIGGER["properties"], "parent_image": r"C:\Windows\System32\cmd.exe"}}],
             "trigger_relations": []}
    sess = Session(lambda t, a: {"results": []})
    await EvidenceHarvester(budget=8).collect(
        sess, {"alert_text": alert}, {"search", "get_entity"}, lambda *x: None)
    assert not any(a.get("scope", {}).get("type") == "windows_service"
                   for t, a in sess.calls if t == "search")

@pytest.mark.asyncio
async def test_research_opens_parent_children_second_level_effects_and_peers():
    parent = n(PAR, "windows_process", pid=10, image_path=r"C:\Windows\System32\services.exe")
    child = n(C, "windows_process", pid=81, parent_pid=80,
              image_path=r"C:\Users\Public\loader.exe", logon_id="0x3e7")
    grandchild = n(G, "windows_process", pid=82, parent_pid=81,
                   image_path=r"C:\Users\Public\stage2.exe", logon_id="0x3e7")
    archive = n(F, "windows_file", path=r"C:\Users\Public\drop.exe")
    conn = n(NET, "network_connection", src_ip="10.0.0.10", dst_ip="198.51.100.203", dst_port=443)
    peer = n(PEER, "host", ip="198.51.100.203", role="external")
    relations = [r("spawn0", "win_process_create", PAR, P),
                 r("spawn1", "win_process_create", P, C),
                 r("connection", "connected_to", P, NET)]
    def dispatcher(tool, a):
        if tool == "search":
            scope = a.get("scope", {}).get("type")
            if a["query"] == P and scope is None:
                return {"relations": relations}
            if a["query"] == C and scope is None:
                return {"relations": [r("spawn2", "win_process_create", C, G),
                                      r("write", "wrote_file", C, F)]}
            if scope == "host" and a["query"] == "198.51.100.203":
                return {"entities": [peer]}
            if scope == "windows_service":
                return {"entities": [n(SVC, "windows_service", binary_path=r"C:\Windows\launcher-83133.exe -service")]}
            return {"results": []}
        if tool == "get_entity":
            return {PAR: parent, C: child, G: grandchild, F: archive, NET: conn}.get(a["entity_id"], {})
        return {"results": []}
    sess = Session(dispatcher)
    received = []
    result = await ResearchHarvester(budget=20).collect(
        sess, {"alert_text": ALERT}, {"search", "get_entity", "get_relation"},
        lambda t, a, resp: received.append((t, a, resp.info["tool_result"])))
    assert result.completed and result.calls <= 20
    calls = [(t, a.get("entity_id"), a.get("query")) for t, a in sess.calls]
    assert ("get_entity", PAR, None) in calls
    assert ("get_entity", C, None) in calls
    assert any(t == "search" and q == C for t, _, q in calls)
    assert any(t == "get_entity" and eid == NET for t, eid, _ in calls)
    assert any(t == "get_entity" and eid == F for t, eid, _ in calls)
    assert any(t == "get_entity" and eid == G for t, eid, _ in calls)
    assert any(t == "search" and q == "198.51.100.203" for t, _, q in calls)
    assert any("research_" in str(a.get("reasoning")) for t, a in sess.calls)

@pytest.mark.asyncio
async def test_research_never_reads_runtime_reward():
    class ProtectedResponse:
        info = {"tool_result": {"results": []}}
        observation = {}
        task_result = None
        @property
        def reward(self):
            raise AssertionError("Research policy must not read evaluator reward")
    class ProtectedSession:
        def __init__(self): self.calls=[]
        async def call_tool(self, t, a):
            self.calls.append((t,a))
            return ProtectedResponse()
    s = ProtectedSession()
    res = await ResearchHarvester(budget=8).collect(
        s, {"alert_text": ALERT}, {"search", "get_entity", "get_relation"},
        lambda *args: None)
    assert 1 <= res.calls <= 8

@pytest.mark.asyncio
async def test_cli_rejects_non_practice_research_before_network(monkeypatch):
    from types import SimpleNamespace
    from bluesec1_agent import cli
    monkeypatch.setattr(cli, "_load_settings", lambda: SimpleNamespace(
        agent_harvest_research=True, scenario_runtime_arena="final"))
    with pytest.raises(SystemExit, match="Practice-only"):
        await cli.run(SimpleNamespace(arena=None))


def test_normal_and_research_budget_settings_are_separate():
    from bluesec1_agent.agent import SimpleSGRAgent
    agent = SimpleSGRAgent(SimpleNamespace(), harvest_budget=8,
                           harvest_research=False, harvest_research_budget=20)
    assert agent.harvest_budget == 8
    assert agent.harvest_research_budget == 20
    assert agent.harvest_research is False
