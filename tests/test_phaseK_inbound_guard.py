"""Phase K: real public logon_properties, causal external peer, response actions."""
import json
from types import SimpleNamespace

import pytest

from bluesec1_agent.inbound_evidence import logon_details, confirmed_remote_login
from bluesec1_agent.external_peer_guard import external_peer_signals
from bluesec1_agent.harvest_v31 import EvidenceHarvester
from bluesec1_agent.report_experiments import (
    _observed_inbound_source_ips, apply_report_experiment, report_probe_diagnostics,
)
from bluesec1_agent.response_mapper import ObservedGraph
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent

H = "11111111-1111-4111-8111-111111111111"
P = "22222222-2222-4222-8222-222222222222"
C = "33333333-3333-4333-8333-333333333333"
U = "44444444-4444-4444-8444-444444444444"
E = "55555555-5555-4555-8555-555555555555"
N = "66666666-6666-4666-8666-666666666666"
L = "77777777-7777-4777-8777-777777777777"
SESSION = "0x7a338"
SID = "S-1-5-21-99-1000"


def entity(nid, typ, **p):
    return {"id": nid, "type": typ, "properties": p}


def trigger(image=r"C:\Windows\System32\powershell.exe"):
    return {**entity(P, "windows_process", pid=10, logon_id=SESSION, user_sid=SID,
                     user="CORP\\user", image_path=image, cmdline="powershell.exe -NoLogo"),
            "host_id": H}


def graph(external=True, ip="203.0.113.240", case="powershell"):
    g = ObservedGraph()
    proc = trigger(image=("System" if case == "system" else
                          r"C:\Program Files\Kaspersky\avp.exe" if case == "av" else
                          r"C:\Windows\System32\cmd.exe" if case == "cmd" else
                          r"C:\Windows\System32\powershell.exe"))
    g.absorb_alert({"alert_text": {"trigger_entities": [
        {**entity(H, "host", ip="10.0.0.2", hostname="MAIN"), "host_id": None}, proc]}})
    g.absorb(entity(U, "windows_user", sid=SID, username="user"))
    g.absorb(entity(E, "host", ip=ip, hostname="PEER", role="external" if external else "workstation"))
    return g


def login(ip="203.0.113.240", **extra):
    return {"id": L, "type": "logged_on_to", "source_id": U, "target_id": H,
            "logon_properties": {"source_ip": ip, "logon_id": SESSION,
                                 "logon_type": 3, **extra}}


def benign():
    return {"verdict": "benign", "reasoning": "routine activity", "legitimacy_evidence": []}


def malicious():
    return {"verdict": "malicious", "reasoning": "verified network contact", "ir_artifacts": []}


def test_nested_and_top_level_login_attributes_and_failed_login():
    log = login()
    assert logon_details(log)["source_ip"] == "203.0.113.240"
    assert confirmed_remote_login(log)
    assert not confirmed_remote_login(login(success=False))
    assert not confirmed_remote_login(login(logon_type=2))
    assert confirmed_remote_login({**log, "logon_properties": {},
                                  "properties": {"logon_properties": log["logon_properties"]}})


@pytest.mark.parametrize("ip, expected", [("10.99.138.195", "host_to_isolate"),
                                         ("203.0.113.240", "network_block")])
def test_inbound_source_report_and_diagnostics(ip, expected):
    g = graph(ip=ip)
    g.absorb(login(ip))
    ext, internal = _observed_inbound_source_ips(g)
    assert ip in (internal if expected == "host_to_isolate" else ext)
    diagnosis = report_probe_diagnostics(g)
    assert ip in diagnosis[("confirmed_internal_source_ips" if expected == "host_to_isolate"
                            else "external_inbound_source_ips")]
    result = apply_report_experiment(malicious(), g, "inbound_guard")
    assert {"entity_id": E, "kind": expected} in result["ir_artifacts"]
    assert result["verdict"] == "malicious"
    assert apply_report_experiment(malicious(), g, "baseline_archives")["ir_artifacts"] == []


def test_failed_and_unrelated_logins_do_not_infer_host_is_compromised():
    g = graph(ip="10.99.138.195")
    g.absorb(login("10.99.138.195", success=False))
    assert not _observed_inbound_source_ips(g)[1]
    assert apply_report_experiment(malicious(), g, "inbound_guard")["ir_artifacts"] == []
    g.relations.clear()
    unrelated = login("10.99.138.195")
    unrelated["logon_properties"]["logon_id"] = "0xdifferent"
    g.absorb(unrelated)
    assert not _observed_inbound_source_ips(g)[1]


def test_external_guard_requires_causal_contact_and_matching_role():
    g = graph()
    # An external host somewhere on the same machine is not enough.
    assert not external_peer_signals(g)
    g.absorb(entity(N, "network_connection", dst_ip="203.0.113.240"))
    assert not external_peer_signals(g)
    g.absorb({"id": "connected", "type": "connected_to", "source_id": P, "target_id": N})
    assert len(external_peer_signals(g)) == 1
    g.entities[E]["properties"]["role"] = "workstation"
    assert not external_peer_signals(g)
    g.entities[E]["properties"]["role"] = "external"
    g.entities[P]["properties"]["image_path"] = "System"
    assert not external_peer_signals(g)
    g.entities[P]["properties"]["image_path"] = r"C:\Program Files\ESET\ekrn.exe"
    assert not external_peer_signals(g)


def test_cmd_child_powershell_can_trigger_external_guard():
    g = graph(case="cmd")
    g.absorb({**entity(C, "windows_process", image_path=r"C:\Windows\System32\powershell.exe",
                       pid=11, parent_pid=10, start_time="2026-10-01T12:00Z"), "host_id": H})
    g.absorb({"id": "spawn", "type": "win_process_create", "source_id": P, "target_id": C})
    g.absorb(entity(N, "network_connection", dst_ip="203.0.113.240"))
    g.absorb({"id": "connected", "type": "connected_to", "source_id": C, "target_id": N})
    assert external_peer_signals(g)


def test_causal_login_external_host_can_trigger_guard_without_connection():
    g = graph()
    g.absorb(login())
    assert external_peer_signals(g)
    g.relations[L]["logon_properties"]["logon_id"] = "0xunrelated"
    assert not external_peer_signals(g)


def test_final_guard_only_changes_opt_in_mode():
    g = graph()
    g.absorb(entity(N, "network_connection", dst_ip="203.0.113.240"))
    g.absorb({"id": "connected", "type": "connected_to", "source_id": P, "target_id": N})
    mem = InvestigationMemory()
    mem.absorb(list(g.entities.values()) + list(g.relations.values()))
    mem.focus_ids = {P}
    args = {"submission": benign()}
    original, _ = SimpleSGRAgent._reconcile_final(args, mem)
    assert original["submission"]["verdict"] == "benign"
    changed, note = SimpleSGRAgent._reconcile_final(args, mem, external_graph=g)
    assert changed["submission"]["verdict"] == "malicious" and note
    assert changed["submission"].get("ir_artifacts")


@pytest.mark.asyncio
async def test_harvest_searches_confirmed_source_host_inside_eight_calls():
    g = graph()
    child = {**entity(C, "windows_process", image_path=r"C:\Windows\System32\hostname.exe",
                      pid=11, parent_pid=10, logon_id=SESSION), "host_id": H}
    class Session:
        def __init__(self): self.calls = []
        async def call_tool(self, tool, args):
            self.calls.append((tool, args))
            scope = (args.get("scope") or {}).get("type")
            result = {"results": []}
            if tool == "search":
                if args["query"] == P and not scope:
                    result = {"relations": [{"id": "spawn", "type": "win_process_create",
                                              "source_id": P, "target_id": C}]}
                elif scope == "logged_on_to":
                    result = {"relations": [login()]}
                elif scope == "host" and args["query"] == "203.0.113.240":
                    result = {"entities": [g.entities[E]]}
                elif scope == "windows_user":
                    result = {"entities": [g.entities[U]]}
            elif tool == "get_entity" and args["entity_id"] == C:
                result = {"entity": child}
            return SimpleNamespace(info={"tool_result": result}, observation=None, task_result=None)
    session = Session()
    observed = ObservedGraph()
    observed.absorb_alert({"alert_text": {"trigger_entities": [g.entities[P],g.entities[H]]}})
    harvest = await EvidenceHarvester(budget=8, inbound_probe=True, service_probe=True).collect(
        session, {"alert_text": {"trigger_entities": [g.entities[P],g.entities[H]]}},
        {"search", "get_entity"},
        lambda tool, args, response: observed.absorb(response.info.get("tool_result")))
    assert harvest.calls <= 8
    lookups = [(i, args) for i, (tool, args) in enumerate(session.calls)
               if tool == "search" and (args.get("scope") or {}).get("type") == "host"]
    assert any(args["query"] == "203.0.113.240" for _,args in lookups)
    assert report_probe_diagnostics(observed)["external_inbound_source_ips"] == ["203.0.113.240"]
