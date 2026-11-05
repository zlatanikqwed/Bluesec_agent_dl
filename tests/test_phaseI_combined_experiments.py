"""Phase I: one validated combined report and three independent follow-up arms."""
from copy import deepcopy

import pytest

from bluesec1_agent.decision_guard import detect_attack_signals, decisive_signals
from bluesec1_agent.harvest_v31 import EvidenceHarvester, _services_for_image
from bluesec1_agent.report_experiments import apply_report_experiment
from bluesec1_agent.response_mapper import ObservedGraph
from bluesec1_client import ToolCallResult

TR, H, CHILD, EXE, ARCH, SERVICE, SCRIPT, SRC, NET = (
    "trigger-001", "local-host", "child", "exe", "arch", "svc", "script", "src", "conn"
)


def node(nid, typ, host_id=None, **props):
    return {"id": nid, "type": typ, "host_id": host_id, "properties": props}


def relation(nid, typ, src, dst, **props):
    return {"id": nid, "type": typ, "source_id": src, "target_id": dst, "properties": props}


def observed():
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [
        node(TR, "windows_process", H, pid=20, logon_id="0xaa01", user="ACME\\svc",
             image_path=r"C:\Windows\launcher-123.exe",
             cmdline=r"C:\Windows\launcher-123.exe -service",
             parent_image=r"C:\Windows\System32\services.exe"),
        node(H, "host", ip="10.1.1.10", hostname="MAIN")
    ]}})
    g.absorb([
        node(CHILD, "windows_process", H, parent_pid=20, pid=22,
             image_path=r"C:\Temp\child.exe"),
        node(EXE, "windows_file", path=r"C:\Temp\payload.exe"),
        node(ARCH, "archive_file", path=r"C:\Temp\package.zip"),
        node(SERVICE, "windows_service", binary_path=r"C:\Windows\launcher-123.exe -service"),
        node(SCRIPT, "powershell_script", script_text="Get-Process"),
        node(SRC, "host", ip="10.1.1.5", role="workstation"),
        node("peer", "host", ip="198.51.100.203", role="external"),
        node(NET, "network_connection", src_ip="10.1.1.10", dst_ip="198.51.100.203", dst_port=443),
        relation("childedge", "win_process_create", TR, CHILD),
        relation("writtenexe", "wrote_file", CHILD, EXE),
        relation("writtenarch", "wrote_file", TR, ARCH),
        relation("remote", "connected_to", TR, NET),
        relation("login", "logged_on_to", TR, H, logon_id="0xaa01", source_ip="10.1.1.5", status="SUCCESS"),
    ])
    return g


def malicious():
    return {"verdict": "malicious", "reasoning": "Model unchanged",
            "ir_artifacts": [{"entity_id": H, "kind": "host_to_isolate"}]}


def benign():
    return {"verdict": "benign", "reasoning": "Model unchanged",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": SCRIPT, "property_fields": ["script_text"]},
                {"anchor": "entity", "entity_id": "src", "property_fields": ["role"]},
            ]}


def changes(initial, final):
    return {k for k in initial if initial[k] != final[k]}


def test_combined_only_exe_and_external_host_and_no_archives_or_services():
    graph = observed(); initial = malicious(); frozen = deepcopy(initial)
    final = apply_report_experiment(initial, graph, "combined")
    acts = {(x["entity_id"], x["kind"]) for x in final["ir_artifacts"]}
    assert (EXE, "file_to_delete") in acts
    assert ("peer", "network_block") in acts
    assert (ARCH, "file_to_delete") not in acts
    assert (SERVICE, "persistence_to_remove") not in acts
    assert changes(initial, final) == {"ir_artifacts"}
    assert initial == frozen


def test_combined_benign_omits_only_scripts():
    initial = benign(); final = apply_report_experiment(initial, observed(), "combined")
    assert final["legitimacy_evidence"] == initial["legitimacy_evidence"][1:]
    assert changes(initial, final) == {"legitimacy_evidence"}


def test_archive_arm_adds_only_writes_by_chain():
    g = observed(); base = apply_report_experiment(malicious(), g, "combined")
    arm = apply_report_experiment(malicious(), g, "archive_files")
    assert changes(base, arm) == {"ir_artifacts"}
    assert {i["entity_id"] for i in arm["ir_artifacts"]} - {
        i["entity_id"] for i in base["ir_artifacts"]} == {ARCH}
    g.relations.pop("writtenarch")
    arm2 = apply_report_experiment(malicious(), g, "archive_files")
    assert ARCH not in {i["entity_id"] for i in arm2["ir_artifacts"]}


def test_service_arm_adds_matched_opened_service():
    g = observed(); arm = apply_report_experiment(malicious(), g, "service_persistence")
    assert (SERVICE, "persistence_to_remove") in {
        (a["entity_id"], a["kind"]) for a in arm["ir_artifacts"]}
    g.entities[SERVICE]["properties"]["binary_path"] = r"C:\Windows\other.exe"
    arm = apply_report_experiment(malicious(), g, "service_persistence")
    assert not any(a["entity_id"] == SERVICE for a in arm["ir_artifacts"])


def test_internal_source_arm_only_verified_authenticated_source():
    g = observed(); base = apply_report_experiment(malicious(), g, "combined")
    arm = apply_report_experiment(malicious(), g, "internal_source")
    assert SRC in {a["entity_id"] for a in arm["ir_artifacts"] if a["kind"] == "host_to_isolate"}
    assert SRC not in {a["entity_id"] for a in base["ir_artifacts"] if a["kind"] == "host_to_isolate"}
    # logged_on_to may have only a remote logon type, not a status field.
    g.relations["login"]["properties"].pop("status")
    g.relations["login"]["properties"]["logon_type"] = 3
    remote = apply_report_experiment(malicious(), g, "internal_source")
    assert SRC in {a["entity_id"] for a in remote["ir_artifacts"]}
    g.relations["login"]["properties"]["status"] = "FAILED"
    arm = apply_report_experiment(malicious(), g, "internal_source")
    assert SRC not in {a["entity_id"] for a in arm["ir_artifacts"]}


def test_reserved_domain_veto_is_invalid_only():
    for fqdn, hard in [("abc.invalid", True), ("telemetry.eset.example", False),
                       ("vendor.test", False), ("internal.localhost", False)]:
        c = node("con", "network_connection", fqdn=fqdn,
                 dst_ip="198.51.100.101", query_status="SUCCESS")
        assert bool(decisive_signals(detect_attack_signals({"con": c}, {}))) == hard
    assert not decisive_signals(detect_attack_signals({"con": node(
        "con", "network_connection", fqdn="abc.invalid", query_status="FAILURE",
        dst_ip="198.51.100.101")}, {}))


def test_service_lookup_filters_unrelated_binaries():
    raw = {"entities": [
        node(SERVICE, "windows_service", binary_path=r"C:\Windows\launcher-123.exe -service"),
        node("bad", "windows_service", binary_path=r"C:\Windows\other.exe"),
    ]}
    found = _services_for_image(raw, r"C:\Windows\launcher-123.exe")
    assert [n["id"] for n in found["entities"]] == [SERVICE]


@pytest.mark.asyncio
async def test_service_probe_shared_across_all_phase_i_modes():
    tr = observed()
    alert = {"trigger_entities": [tr.entities[TR], tr.entities[H]]}
    for service_probe in (False, True):
        class S:
            def __init__(self): self.calls = []
            async def call_tool(self, tool, args):
                self.calls.append((tool, args))
                raw = {"results": []}
                if tool == "search" and (args.get("scope") or {}).get("type") == "windows_service":
                    raw = {"entities": [tr.entities[SERVICE]]}
                return ToolCallResult(task_id="x", tool_name=tool,
                                      info={"tool_result": raw, "tool_status": "ok"})
        sess = S()
        result = await EvidenceHarvester(budget=8, service_probe=service_probe).collect(
            sess, {"alert_text": alert}, {"search", "get_entity", "get_relation"},
            lambda _t, _a, _r: None)
        found = [a for name, a in sess.calls if name == "search" and
                 (a.get("scope") or {}).get("type") == "windows_service"]
        assert bool(found) == service_probe
        assert result.calls <= 8


def test_quoted_service_binary_and_original_connection_fallback():
    g = observed()
    g.entities[SERVICE]["properties"]["binary_path"] = '"C:\\Windows\\launcher-123.exe" -service'
    assert SERVICE in {a["entity_id"] for a in apply_report_experiment(
        malicious(), g, "service_persistence")["ir_artifacts"]}
    assert [x["id"] for x in _services_for_image({"entities": [g.entities[SERVICE]]},
            r"C:\Windows\launcher-123.exe")["entities"]] == [SERVICE]
    # A network_connection already eligible for block must not be lost if the
    # host search did not resolve a suitable host entity.
    g.entities.pop("peer")
    base = malicious()
    base["ir_artifacts"].append({"entity_id": NET, "kind": "network_block"})
    result = apply_report_experiment(base, g, "combined")
    assert {"entity_id": NET, "kind": "network_block"} in result["ir_artifacts"]
