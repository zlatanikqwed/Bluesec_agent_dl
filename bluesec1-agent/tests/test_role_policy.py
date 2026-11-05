from bluesec1_agent.models import FinishInvestigationRequest
from bluesec1_agent.report_experiments import MODES, apply_role_policy
from bluesec1_agent.response_mapper import ObservedGraph


def _graph() -> ObservedGraph:
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [{
        "id": "P", "type": "windows_process", "host_id": "H",
        "properties": {"pid": 1, "image_path": "C:\\x\\powershell.exe", "cmdline": "ps"}}]}})
    g.absorb([
        {"id": "H", "type": "host", "properties": {"hostname": "WS1", "ip": "10.0.0.5", "role": "ws"}},
        {"id": "SRC", "type": "host", "properties": {"hostname": "ADM1", "ip": "10.0.0.9"}},
        {"id": "DC", "type": "host", "properties": {"hostname": "DC1", "ip": "10.0.0.1"}},
        {"id": "EXT", "type": "host", "properties": {"hostname": "CDN", "ip": "203.0.113.7",
                                                       "role": "external"}},
        {"id": "U", "type": "windows_user", "properties": {"username": "bob",
                                                             "group_memberships": ["Ops"]}},
        {"id": "S", "type": "powershell_script", "properties": {"path": "C:\\s.ps1",
                                                                  "script_text": "x"}},
        {"id": "D", "type": "windows_file", "properties": {"path": "C:\\Temp\\t.exe"}},
        {"id": "r1", "type": "hosts", "source_id": "H", "target_id": "P"},
        {"id": "r2", "type": "runs_process", "source_id": "U", "target_id": "P"},
        {"id": "r3", "type": "logged_on_to", "source_id": "U", "target_id": "H",
         "logon_properties": {"source_ip": "10.0.0.9", "logon_type": "network"}},
        {"id": "r4", "type": "executed_script", "source_id": "P", "target_id": "S"},
        {"id": "r5", "type": "deleted_file", "source_id": "P", "target_id": "D"},
        {"id": "r6", "type": "win_process_create", "source_id": "X", "target_id": "P"},
    ])
    return g


def test_mode_registered():
    assert "role_policy" in MODES


def test_malicious_rules_by_role():
    sub = {"verdict": "malicious", "reasoning": "r", "ir_artifacts": [
        {"entity_id": "H", "kind": "host_to_isolate"},
        {"entity_id": "U", "kind": "identity_to_rotate"},
        {"entity_id": "S", "kind": "file_observed"},
        {"entity_id": "D", "kind": "file_to_delete"}]}
    out = apply_role_policy(sub, _graph())
    got = {(a["entity_id"], a["kind"]) for a in out["ir_artifacts"]}
    assert got == {("H", "host_to_isolate"), ("U", "identity_to_rotate"),
                   ("SRC", "host_to_isolate"), ("EXT", "network_block")}
    assert ("DC", "host_to_isolate") not in got  # internal host without causal contact
    assert out["verdict"] == "malicious" and out["reasoning"] == "r"
    FinishInvestigationRequest.model_validate({"tool": "finish_investigation", "submission": out})


def test_benign_rules_by_role():
    sub = {"verdict": "benign", "reasoning": "r", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "H", "property_fields": ["hostname", "role"]},
        {"anchor": "entity", "entity_id": "P", "property_fields": ["cmdline"]},
        {"anchor": "relation", "relation_id": "r6", "property_fields": []},
        {"anchor": "entity", "entity_id": "S", "property_fields": ["path", "script_text"]},
        {"anchor": "entity", "entity_id": "U", "property_fields": ["username", "group_memberships"]},
    ]}
    out = apply_role_policy(sub, _graph())
    ev = out["legitimacy_evidence"]
    assert ev[0] == {"anchor": "entity", "entity_id": "U", "property_fields": ["group_memberships"]}
    assert {"anchor": "entity", "entity_id": "S", "property_fields": ["path"]} in ev
    assert all(e.get("entity_id") not in {"H", "P"} for e in ev)
    assert all(e.get("relation_id") != "r6" for e in ev)
    FinishInvestigationRequest.model_validate({"tool": "finish_investigation", "submission": out})


import pytest  # noqa: E402


@pytest.mark.asyncio
async def test_agent_end_to_end_role_policy():
    import json

    from test_v31_harvest import HOST, NextStep, Session, SimpleSGRAgent

    class LLM:
        async def next_step(self, msgs, *, finish_only=False):
            return NextStep.model_validate({
                "current_state": "x", "plan_remaining_steps_brief": ["s"], "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "r",
                    "ir_artifacts": [{"entity_id": HOST, "kind": "host_to_isolate"}]}}})

    session = Session()
    agent = SimpleSGRAgent(LLM(), harvest_mode=True, harvest_budget=8, review_enabled=False,
                           v16_mode=False, soc_v19_mode=False, max_steps=12,
                           trajectory_dir=None, report_experiment="role_policy")
    transcript = []
    outcome = await agent._investigate(session, transcript)
    assert outcome.completion_reason == "terminated"
    audits = [json.loads(t["content"]) for t in transcript if t.get("role") == "audit"
              and "role_policy_before" in str(t.get("content"))]
    assert len(audits) == 1
    assert session.calls[-1][1]["submission"] == audits[0]["report_after"]


def test_benign_v2_drops_hosts_files_and_generic_accounts():
    from bluesec1_agent.report_experiments import legitimising_groups

    assert legitimising_groups({"group_memberships": ["Administrators"]}) == []
    assert legitimising_groups({"group_memberships": None}) == []
    assert legitimising_groups({"group_memberships": "['Production-DBA', 'Remote Desktop Users']"}) \
        == ["Production-DBA"]
    g = _graph()
    g.absorb([{"id": "U", "type": "windows_user",
               "properties": {"username": "Administrator", "group_memberships": ["Administrators"]}},
              {"id": "F", "type": "windows_file", "properties": {"path": "C:\\x.html"}}])
    sub = {"verdict": "benign", "reasoning": "r", "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "SRC", "property_fields": ["hostname"]},
        {"anchor": "entity", "entity_id": "F", "property_fields": ["path"]},
        {"anchor": "entity", "entity_id": "U", "property_fields": ["group_memberships"]}]}
    assert apply_role_policy(sub, g)["legitimacy_evidence"] == []


def test_benign_probe2_keeps_base_and_adds_at_most_one():
    from bluesec1_agent.benign_probe import apply_benign_probe_extra

    g = _graph()
    base = apply_role_policy({"verdict": "benign", "reasoning": "r",
                              "legitimacy_evidence": []}, g)
    assert base["legitimacy_evidence"][0]["entity_id"] == "U"
    controls = 0
    for i in range(40):
        out, d = apply_benign_probe_extra(base, g, f"s{i}")
        FinishInvestigationRequest.model_validate(
            {"tool": "finish_investigation", "submission": out})
        assert out["legitimacy_evidence"][:1] == base["legitimacy_evidence"]
        assert len(out["legitimacy_evidence"]) <= len(base["legitimacy_evidence"]) + 1
        controls += d["factor"] == "CONTROL"
    assert 5 <= controls <= 22
