"""Verify nested event fields and causal references, not benchmark case answers."""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent


def connected_memory():
    mem = InvestigationMemory()
    mem.absorb({"id": "host", "type": "host", "properties": {"hostname": "target"}})
    mem.absorb({"id": "parent", "type": "windows_process", "properties": {
        "cmdline": "winlogon.exe", "signed": True}})
    mem.absorb({"id": "child", "type": "windows_process", "properties": {
        "cmdline": "userinit.exe", "signed": True}})
    mem.absorb({"id": "user", "type": "windows_user", "properties": {
        "username": "analyst", "group_memberships": ["Administrators"]}})
    mem.absorb({"id": "rhost", "type": "hosts", "source_id": "host", "target_id": "child"})
    mem.absorb({"id": "rcreate", "type": "win_process_create",
                "source_id": "parent", "target_id": "child"})
    mem.absorb({"id": "rlogin", "type": "logged_on_to", "source_id": "user",
                "target_id": "host", "logon_properties": {
                    "logon_type": 10, "source_ip": "10.8.1.1", "auth_failed": False,
                    "protocol": "RDP"}})
    mem.focus_ids = {"child"}
    mem.trigger_ids = {"host", "child"}
    return mem


def test_validation_preserves_real_nested_authentication_properties():
    obj = {"logon_properties": {"logon_type": 10, "auth_failed": False}}
    valid = SimpleSGRAgent._grounded_property_fields(obj, [
        "logon_properties.logon_type", "logon_properties.auth_failed",
        "logon_properties.no_such_field", "logon_properties.__class__", "no_field",
    ])
    assert valid == ["logon_properties.logon_type", "logon_properties.auth_failed"]


def test_benign_merges_nested_relations_from_independent_reviewer():
    mem = connected_memory()
    agent = SimpleSGRAgent(llm=None)
    inv = {"verdict": "benign", "reasoning": "Examined interactive logon", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "child", "property_fields": ["cmdline"]},
        {"anchor": "relation", "relation_id": "rlogin", "property_fields": ["type"]},
    ]}
    rev = {"verdict": "benign", "legitimacy_evidence": [
        {"anchor": "relation", "relation_id": "rlogin", "property_fields": [
            "logon_properties.logon_type", "logon_properties.auth_failed"]},
    ]}
    result = agent._merge_agreed_evidence(inv, rev, mem)
    assert inv["legitimacy_evidence"][1]["property_fields"] == ["type"]
    assert result["legitimacy_evidence"][1]["property_fields"] == [
        "type", "logon_properties.logon_type", "logon_properties.auth_failed"]


def test_final_benign_references_actual_causal_event_and_preserves_verdict():
    mem = connected_memory()
    # Ensure user endpoint is directly cited so the login can be added.
    response = {"submission": {"verdict": "benign", "reasoning": "Interactive logon",
        "legitimacy_evidence": [
            {"anchor": "entity", "entity_id": "child", "property_fields": ["cmdline"]},
            {"anchor": "entity", "entity_id": "user", "property_fields": ["username"]},
        ]}}
    new, note = SimpleSGRAgent._reconcile_final(response, mem)
    assert new["submission"]["verdict"] == "benign"
    rows = new["submission"]["legitimacy_evidence"]
    login = next(row for row in rows if row.get("relation_id") == "rlogin")
    assert "logon_properties.source_ip" in login["property_fields"]
    assert "logon_properties.auth_failed" in login["property_fields"]
    assert note


def test_unlinked_background_event_is_never_inserted_as_support():
    mem = connected_memory()
    mem.absorb({"id": "otherproc", "type": "windows_process", "properties": {"cmdline": "x"}})
    mem.absorb({"id": "rbackground", "type": "logged_on_to", "source_id": "otherproc",
                "target_id": "otherhost", "logon_properties": {"auth_failed": True}})
    r = SimpleSGRAgent._reconcile_final({"submission": {"verdict": "benign",
        "reasoning": "Standard launch", "legitimacy_evidence": [
            {"anchor": "entity", "entity_id": "child", "property_fields": ["cmdline"]}]}}, mem)[0]
    assert "rbackground" not in [v.get("relation_id") for v in r["submission"]["legitimacy_evidence"]]


def test_dotted_nonexistent_property_is_removed_not_hallucinated():
    mem = connected_memory()
    response = {"submission": {"verdict": "benign", "reasoning": "Logon occurred",
        "legitimacy_evidence": [
            {"anchor": "relation", "relation_id": "rlogin", "property_fields": [
                "logon_properties.logon_type", "logon_properties.imaginary_field"]}]}}
    new, _ = SimpleSGRAgent._reconcile_final(response, mem)
    fields = new["submission"]["legitimacy_evidence"][0]["property_fields"]
    assert fields == ["logon_properties.logon_type"]


def test_no_event_fabrication_when_only_signed_binaries_are_observed():
    mem = InvestigationMemory()
    mem.absorb({"id": "p", "type": "windows_process", "properties": {"signed": True}})
    mem.focus_ids = {"p"}
    assert SimpleSGRAgent._observed_benign_event_citations(mem, []) == []
