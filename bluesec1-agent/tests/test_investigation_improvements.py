"""Regression tests for investigation mistakes observed in trajectory logs."""

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent


def test_meta_text_is_not_graph_evidence() -> None:
    memory = InvestigationMemory()
    memory.absorb({"tool_name": "search", "message": "vssadmin delete shadows"})
    assert not memory.red_flags
    memory.absorb({
        "id": "proc", "type": "windows_process",
        "properties": {"cmdline": "vssadmin delete shadows /all"},
    })
    assert "ransomware: shadow-copy deletion" in memory.strongly_suspicious()


def test_system32_powershell_not_misclassified_as_system_process() -> None:
    memory = InvestigationMemory()
    memory.absorb({
        "id": "conn", "type": "network_connection",
        "properties": {
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "dst_ip": "8.8.8.8", "dst_port": 443,
        },
    })
    assert not any("should never reach external" in k for k in memory.red_flags)


def test_double_extension_document_is_a_lead_not_a_proof() -> None:
    memory = InvestigationMemory()
    memory.absorb({
        "id": "file", "type": "windows_file",
        "properties": {"path": r"D:\Forms\agreement.docx.lockdata"},
    })
    assert any("appended extension" in label for label in memory.red_flags)
    assert not memory.strongly_suspicious()


def test_duplicate_lookup_recovers_unopened_edge() -> None:
    memory = InvestigationMemory()
    memory.absorb({
        "id": "proc", "type": "windows_process",
        "relation_ids": {"outgoing": ["edge"]},
    })
    memory.cache[InvestigationMemory.cache_key("get_entity", {"entity_id": "proc"})] = {}
    tool, args, note = SimpleSGRAgent._recover_duplicate(
        "get_entity", {"entity_id": "proc", "reasoning": "repeat"},
        memory, {"get_entity", "get_relation"},
    )
    assert tool == "get_relation"
    assert args["relation_id"] == "edge"
    assert note


def test_benign_citation_keeps_only_real_properties() -> None:
    memory = InvestigationMemory()
    memory.absorb({
        "id": "process", "type": "windows_process",
        "properties": {"cmdline": "signedtool.exe"},
    })
    memory.fetched_ids.update({"r1", "r2", "r3"})
    agent = SimpleSGRAgent(llm=None)
    finish = {"submission": {
        "verdict": "benign", "legitimacy_evidence": [
            {"anchor": "entity", "entity_id": "process",
             "property_fields": ["signer", "cmdline"]}
        ],
    }}
    agent._local_check("finish_investigation", finish, {"finish_investigation"}, memory, 0)
    assert finish["submission"]["legitimacy_evidence"][0]["property_fields"] == ["cmdline"]


def test_concise_tool_catalog_reduces_prompt_without_losing_tool_names():
    from bluesec1_agent.agent import concise_tool_catalog
    specs = [
        {"name": "get_entity", "parameters": {"description": "a" * 30000}},
        {"name": "finish_investigation", "parameters": {"description": "z" * 10000}},
    ]
    summary = concise_tool_catalog(specs)
    assert [s["name"] for s in summary] == ["get_entity", "finish_investigation"]
    assert summary[0]["arguments"] == ["entity_id", "reasoning"]
    assert len(str(summary)) < 1000


def test_wrong_remediation_type_replaced_with_compatible_observation():
    from bluesec1_agent.agent import validate_artifact_types
    memory = InvestigationMemory()
    memory.absorb({"id": "u1", "type": "ad_object", "properties": {"name": "Administrators"}})
    sub, corrected = validate_artifact_types({"verdict": "malicious", "ir_artifacts": [
        {"entity_id": "u1", "kind": "persistence_to_remove"},
    ]}, memory)
    assert corrected == 1
    assert sub["ir_artifacts"] == [{"entity_id": "u1", "kind": "identity_observed"}]
