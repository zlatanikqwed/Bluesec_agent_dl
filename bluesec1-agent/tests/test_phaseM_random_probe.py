import pytest

from bluesec1_agent.models import FinishInvestigationRequest
from bluesec1_agent.probe_design import apply_random_probe, candidate_roles
from bluesec1_agent.report_experiments import MODES
from bluesec1_agent.response_mapper import ObservedGraph


def _graph() -> ObservedGraph:
    g = ObservedGraph()
    g.absorb_alert({"alert_text": {"trigger_entities": [{
        "id": "P", "type": "windows_process", "host_id": "H",
        "properties": {"pid": 10, "image_path": "C:\\Windows\\System32\\cmd.exe",
                       "cmdline": "cmd /c x", "user": "CORP\\alice"}}]}})
    g.absorb([
        {"id": "H", "type": "host", "properties": {"hostname": "WS1", "ip": "10.0.0.5",
                                                     "role": "workstation"}},
        {"id": "U", "type": "windows_user", "properties": {"username": "alice",
                                                             "group_memberships": ["Users"]}},
        {"id": "C", "type": "windows_process", "host_id": "H",
         "properties": {"pid": 11, "parent_pid": 10, "image_path": "C:\\Temp\\x.exe"}},
        {"id": "F1", "type": "windows_file", "properties": {"path": "C:\\Temp\\x.exe"}},
        {"id": "F2", "type": "windows_file", "properties": {"path": "\\\\NAS\\d\\plan.dwg"}},
        {"id": "F3", "type": "windows_file", "properties": {"path": "C:\\Temp\\tmp.txt"}},
        {"id": "E", "type": "host", "properties": {"hostname": "CDN", "ip": "203.0.113.9",
                                                     "role": "external"}},
        {"id": "r1", "type": "hosts", "source_id": "H", "target_id": "P"},
        {"id": "r2", "type": "runs_process", "source_id": "U", "target_id": "P"},
        {"id": "r3", "type": "win_process_create", "source_id": "P", "target_id": "C"},
        {"id": "r4", "type": "wrote_file", "source_id": "P", "target_id": "F1"},
        {"id": "r5", "type": "read_file", "source_id": "C", "target_id": "F2"},
        {"id": "r6", "type": "wrote_file", "source_id": "C", "target_id": "F2"},
        {"id": "r7", "type": "deleted_file", "source_id": "C", "target_id": "F3"},
        {"id": "r8", "type": "logged_on_to", "source_id": "U", "target_id": "H",
         "logon_properties": {"logon_type": "remote_interactive"}},
    ])
    return g


def test_mode_registered():
    assert "random_probe" in MODES


def test_roles_are_generic_graph_positions():
    roles = candidate_roles(_graph())
    assert roles["trigger_process"] == ["P"]
    assert roles["trigger_host"] == ["H"]
    assert roles["trigger_user"] == ["U"]
    assert roles["child_process"] == ["C"]
    assert roles["written_exec"] == ["F1"]
    assert roles["modified_file"] == ["F2"]
    assert roles["deleted_file"] == ["F3"]
    assert roles["external_host"] == ["E"]


def test_malicious_probe_is_deterministic_valid_and_keeps_verdict():
    sub = {"verdict": "malicious", "ir_artifacts": [], "reasoning": "r"}
    a, design_a = apply_random_probe(sub, _graph(), "task-1")
    b, design_b = apply_random_probe(sub, _graph(), "task-1")
    assert a == b and design_a == design_b
    assert a["verdict"] == "malicious" and a["reasoning"] == "r"
    included = [f for f in design_a["factors"] if f["included"]]
    assert len(a["ir_artifacts"]) == len(included)
    FinishInvestigationRequest.model_validate({"tool": "finish_investigation", "submission": a})
    # Different tasks explore different arms.
    designs = {tuple((f["entity_id"], f["kind"]) for f in
                     apply_random_probe(sub, _graph(), f"t{i}")[1]["factors"]) for i in range(20)}
    assert len(designs) > 5


def test_benign_probe_cites_only_present_fields():
    sub = {"verdict": "benign", "legitimacy_evidence": [], "reasoning": "r"}
    g = _graph()
    for i in range(10):
        result, design = apply_random_probe(sub, g, f"b{i}")
        FinishInvestigationRequest.model_validate(
            {"tool": "finish_investigation", "submission": result})
        for ev in result["legitimacy_evidence"]:
            if ev["anchor"] == "entity":
                props = g.props(ev["entity_id"])
                assert all(props.get(f) for f in ev["property_fields"])
            else:
                assert ev["relation_id"] in g.relations
        assert len(result["legitimacy_evidence"]) <= 6


@pytest.mark.asyncio
async def test_agent_end_to_end_logs_design_and_submits_probe():
    import json

    from test_v31_harvest import HOST, NextStep, Session, SimpleSGRAgent

    class LLM:
        async def next_step(self, msgs, *, finish_only=False):
            return NextStep.model_validate({
                "current_state": "Observed payload chain.",
                "plan_remaining_steps_brief": ["Submit"], "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "payload",
                    "ir_artifacts": [{"entity_id": HOST, "kind": "host_to_isolate"}]}}})

    session = Session()
    agent = SimpleSGRAgent(LLM(), harvest_mode=True, harvest_budget=8, review_enabled=False,
                           v16_mode=False, soc_v19_mode=False, max_steps=12,
                           trajectory_dir=None, report_experiment="random_probe")
    transcript = []
    outcome = await agent._investigate(session, transcript)
    assert outcome.completion_reason == "terminated"
    designs = [json.loads(t["content"]) for t in transcript if t.get("role") == "audit"
               and "probe_design" in str(t.get("content"))]
    assert len(designs) == 1
    submitted = session.calls[-1][1]["submission"]
    assert submitted["verdict"] == "malicious"
    assert submitted == designs[0]["report_after"]
    assert designs[0]["probe_design"]["factors"]


def test_explore_design_opens_only_unopened_chain_endpoints():
    from bluesec1_agent.probe_design import expand_design, explore_design

    g = _graph()
    g.absorb([{"id": "r9", "type": "wrote_file", "source_id": "C", "target_id": "UNSEEN1"},
              {"id": "r10", "type": "connected_to", "source_id": "P", "target_id": "UNSEEN2"},
              {"id": "r11", "type": "wrote_file", "source_id": "OTHER", "target_id": "UNSEEN3"}])
    seen_on = set()
    for i in range(30):
        plan = explore_design(g, f"s{i}")
        ids = {e for _, e in plan["calls"]}
        assert ids <= {"UNSEEN1", "UNSEEN2"}
        for c in plan["categories"]:
            assert c["opened"] == (len(c["entity_ids"]))
            if c["enabled"]:
                seen_on.add(c["category"])
    assert seen_on == {"written_file", "network"}
    # child C already has known effects -> nothing to expand
    assert expand_design(g, "x") == []


@pytest.mark.asyncio
async def test_agent_end_to_end_explore_probe_keeps_report():
    import json

    from test_v31_harvest import HOST, NextStep, Session, SimpleSGRAgent

    class LLM:
        async def next_step(self, msgs, *, finish_only=False):
            return NextStep.model_validate({
                "current_state": "Observed payload chain.",
                "plan_remaining_steps_brief": ["Submit"], "task_completed": True,
                "function": {"tool": "finish_investigation", "submission": {
                    "verdict": "malicious", "reasoning": "payload",
                    "ir_artifacts": [{"entity_id": HOST, "kind": "host_to_isolate"}]}}})

    session = Session()
    agent = SimpleSGRAgent(LLM(), harvest_mode=True, harvest_budget=8, review_enabled=False,
                           v16_mode=False, soc_v19_mode=False, max_steps=20,
                           trajectory_dir=None, report_experiment="explore_probe")
    transcript = []
    outcome = await agent._investigate(session, transcript)
    assert outcome.completion_reason == "terminated"
    plans = [json.loads(t["content"]) for t in transcript if t.get("role") == "audit"
             and "explore_design" in str(t.get("content"))]
    assert len(plans) == 1
    report = [json.loads(t["content"]) for t in transcript if t.get("role") == "audit"
              and '"report_after"' in str(t.get("content"))][-1]["report_after"]
    assert session.calls[-1][0] == "finish_investigation"
    assert session.calls[-1][1]["submission"] == report
