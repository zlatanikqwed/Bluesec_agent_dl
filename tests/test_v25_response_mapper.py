import importlib.util
import pathlib
import sys

_path = pathlib.Path(__file__).parents[1] / "src" / "bluesec1_agent" / "response_mapper.py"
_spec = importlib.util.spec_from_file_location("response_mapper_t", _path)
rm = importlib.util.module_from_spec(_spec)
sys.modules["response_mapper_t"] = rm
_spec.loader.exec_module(rm)


def _graph() -> "rm.ObservedGraph":
    g = rm.ObservedGraph()
    host = {"id": "H", "type": "host", "properties": {"hostname": "REPO57", "ip": "10.0.0.5"}}
    src = {"id": "H2", "type": "host", "properties": {"hostname": "LAP01", "ip": "10.0.0.9"}}
    ps = {"id": "P", "type": "windows_process", "host_id": "H",
          "properties": {"pid": 3160, "user": "TERRA\\svc_powerbi", "start_time": "2026-04-15T21:38",
                         "image_path": "C:\\Windows\\System32\\powershell.exe", "cmdline": "powershell"}}
    child = {"id": "C", "type": "windows_process", "host_id": "H",
             "properties": {"pid": 2044, "parent_pid": 3160, "user": "TERRA\\svc_powerbi",
                            "start_time": "2026-04-15T22:42",
                            "image_path": "C:\\Windows\\Temp\\datacache\\monitor-8.exe"}}
    exe = {"id": "F", "type": "windows_file", "host_id": "H",
           "properties": {"path": "C:\\Windows\\Temp\\datacache\\monitor-8.exe", "is_executable": True}}
    c2 = {"id": "N", "type": "network_connection", "host_id": "H",
          "properties": {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.7", "dst_port": 443}}
    inbound = {"id": "N2", "type": "network_connection", "host_id": "H",
               "properties": {"src_ip": "10.0.0.9", "dst_ip": "10.0.0.5", "dst_port": 5985}}
    svc = {"id": "S", "type": "windows_service", "host_id": "H",
           "properties": {"binary_path": "C:\\Windows\\Temp\\datacache\\monitor-8.exe"}}
    g.absorb_alert({"alert_text": {"trigger_entities": [host, ps]}})
    g.absorb([src, child, exe, c2, inbound, svc])
    g.absorb([
        {"id": "r1", "type": "runs_process", "source_id": "U", "target_id": "P"},
        {"id": "r2", "type": "wrote_file", "source_id": "P", "target_id": "F"},
        {"id": "r3", "type": "connected_to", "source_id": "C", "target_id": "N"},
        {"id": "r4", "type": "accepted_connection_from", "source_id": "P", "target_id": "N2"},
    ])
    return g


def test_maps_response_kinds_from_observed_graph() -> None:
    got = {(a["entity_id"], a["kind"]) for a in rm.map_response(_graph(), ["P"], max_tier=2)}
    assert ("H", "host_to_isolate") in got
    assert ("U", "identity_to_rotate") in got          # user id implied by runs_process
    assert ("F", "file_to_delete") in got
    assert ("C", "process_observed") in got           # descendant found via parent_pid
    assert ("N", "network_block") not in got          # external IP alone is not verified C2
    assert ("S", "persistence_to_remove") in got      # service points at the payload
    assert ("H2", "host_to_isolate") not in got       # remote source is not proven compromised


def test_tier_one_is_stricter_and_ids_are_never_invented() -> None:
    g = _graph()
    tier1 = {(a["entity_id"], a["kind"]) for a in rm.map_response(g, ["P"], max_tier=1)}
    assert ("H2", "host_to_isolate") not in tier1
    known = set(g.entities) | {"U"}
    assert all(nid in known for nid, _ in tier1)


def test_merge_upgrades_observed_kind_and_keeps_benign_untouched() -> None:
    g = _graph()
    sub = {"verdict": "malicious", "reasoning": "x",
           "ir_artifacts": [{"entity_id": "F", "kind": "file_observed"},
                            {"entity_id": "P", "kind": "process_observed"}]}
    merged = rm.merge_submission(sub, g)
    kinds = {a["entity_id"]: a["kind"] for a in merged["ir_artifacts"]}
    assert kinds["F"] == "file_to_delete" and kinds["H"] == "host_to_isolate"
    benign = {"verdict": "benign", "reasoning": "x", "legitimacy_evidence": []}
    assert rm.merge_submission(benign, g) is benign


def test_builtin_accounts_are_not_rotated() -> None:
    g = rm.ObservedGraph()
    g.absorb([
        {"id": "P", "type": "windows_process", "host_id": "H",
         "properties": {"user": "NT AUTHORITY\\SYSTEM", "pid": 1}},
        {"id": "H", "type": "host", "properties": {"ip": "10.1.1.1"}},
        {"id": "r", "type": "runs_process", "source_id": "U", "target_id": "P"},
    ])
    kinds = {a["kind"] for a in rm.map_response(g, ["P"])}
    assert "identity_to_rotate" not in kinds


class _Issue:
    def __init__(self, code, ids=()):
        self.code, self.entity_ids = code, tuple(ids)


def test_arbiter_flips_only_on_hard_codes() -> None:
    g = _graph()
    benign = {"verdict": "benign", "reasoning": "routine", "legitimacy_evidence": []}
    assert rm.benign_to_malicious(benign, [_Issue("absence_claim_contradicted_by_actions")],
                                  {"unaccounted_cross_identity_share"}, g) is None
    flipped = rm.benign_to_malicious(benign, [_Issue("unaccounted_cross_identity_share", ["P"])],
                                     {"unaccounted_cross_identity_share"}, g)
    assert flipped["verdict"] == "malicious"
    assert {"entity_id": "H", "kind": "host_to_isolate"} in flipped["ir_artifacts"]
    assert all(not x["kind"].endswith("_observed") for x in flipped["ir_artifacts"])
    assert rm.benign_to_malicious(benign, [_Issue("x", ["P"])], set(), g) is None


def test_benign_anchor_cites_authorizing_task() -> None:
    g = rm.ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [
        {"id": "P", "type": "windows_process", "properties": {"user": "ORBIT\\svc_inventory"},
         "relation_ids": {"incoming": ["r1"]}}]}})
    assert rm.benign_anchor_pivots(g, ["P"], set())[0] == (
        "get_relation", {"relation_id": "r1"}, "find authorizing object")
    g.absorb({"id": "r1", "type": "ran_scheduled_task", "source_id": "T", "target_id": "P"})
    assert rm.benign_anchor_pivots(g, ["P"], set())[0][:2] == ("get_entity", {"entity_id": "T"})
    g.absorb({"id": "T", "type": "scheduled_task", "properties": {
        "task_name": "\\IT-Asset-Discovery", "run_as_account": "ORBIT\\svc_inventory", "sha256": "x"}})
    sub = rm.merge_benign({"verdict": "benign", "reasoning": "r", "legitimacy_evidence": []}, g)
    first = sub["legitimacy_evidence"][0]
    assert first["entity_id"] == "T" and "sha256" not in first["property_fields"]
