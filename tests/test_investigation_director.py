"""No answers or ids from training runs: new architecture tested by graph properties."""
from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.investigation_director import InvestigationDirector


def make_memory():
    memory = InvestigationMemory()
    memory.absorb({
        "id": "p-main", "type": "windows_process", "host_id": "h-main",
        "properties": {"cmdline": "worker.exe --run job"},
        "relation_ids": {"incoming": ["r-parent"], "outgoing": ["r-a", "r-b", "r-c", "r-d"]},
    })
    memory.absorb({
        "id": "h-main", "type": "host", "properties": {"hostname": "test-machine"},
        "relation_ids": {"outgoing": ["noise" + str(i) for i in range(80)]},
    })
    memory.focus_ids = {"p-main"}
    memory.trigger_ids = {"p-main", "h-main"}
    return memory


def test_question_director_does_not_traverse_hub_relations():
    memory = make_memory()
    ranked = InvestigationDirector().rank_frontier(memory)
    ids = [r.identifier for r in ranked]
    assert "r-parent" in ids
    assert any(i.startswith("r-") for i in ids)
    assert not any(i.startswith("noise") for i in ids)
    assert any("caused the alerted action" in r.question for r in ranked)


def test_tells_model_missing_evidence_is_unknown_not_benign():
    case = InvestigationDirector().situation(make_memory(), remaining_steps=12)
    assert "UNKNOWN" in case
    assert "H_attack" in case and "H_normal" in case
    assert "Unchecked dimensions:" in case
    assert "test-machine" not in case  # host is not incident behavioral evidence


def test_rankings_shift_toward_different_causal_branch_as_exploration_progresses():
    memory = make_memory()
    first = InvestigationDirector(per_owner_limit=2).rank_frontier(memory)
    assert first
    memory.fetched_ids.update(("r-parent", "r-a"))
    after = InvestigationDirector(per_owner_limit=2).rank_frontier(memory)
    assert not after  # no new observations: don't burn calls on 80 host-hub relations
    memory.absorb({"id": "f-1", "type": "windows_file", "properties": {"path": "C:/reports/latest.dat"},
                   "relation_ids": {"outgoing": ["r-f1"]}})
    later = InvestigationDirector(per_owner_limit=2).rank_frontier(memory)
    assert [c.identifier for c in later] == ["r-f1"]


def test_causal_trace_renders_confirmed_edge_and_effect_not_hypothesized_edge():
    memory = make_memory()
    memory.absorb({"id": "f-main", "type": "windows_file", "properties": {"path": "C:/app/log.txt"}})
    memory.absorb({"id": "r-a", "type": "wrote_file", "source_id": "p-main", "target_id": "f-main"})
    traced = InvestigationDirector().causal_trace(memory)
    assert "--wrote_file-->" in traced
    assert "p-main" in traced and "f-main" in traced
    assert "r-b" not in traced


def test_review_is_verdict_only_and_does_not_request_new_search():
    director = InvestigationDirector()
    challenge = director.challenge(make_memory(), {
        "verdict": "benign", "reasoning": "Signed by Microsoft", "legitimacy_evidence": []
    }, remaining_steps=9)
    assert "DISPROVE" in challenge and "authorized" in challenge
    assert "decision-only audit" in challenge
    assert "No more searches/tools" in challenge
    assert "Signed by Microsoft" in challenge


def test_graph_based_request_context_replaces_hardcoded_playbook():
    agent = SimpleSGRAgent(llm=None, review_enabled=True)
    memory = make_memory()
    context = agent._request_messages([], memory)[-1]["content"]
    assert "CASE DIRECTOR" in context
    assert "Highest-value" in context
    assert "PLAYBOOK" not in context
    assert agent.review_enabled


def test_two_hypotheses_do_not_assume_security_product_is_safe():
    memory = InvestigationMemory()
    memory.absorb({"id": "av1", "type": "windows_process", "properties": {
        "image_path": "C:/apps/vendor/antivirus.exe", "signed": True,
        "signer": "Vendor", "cmdline": "antivirus.exe /scan"
    }})
    memory.focus_ids = {"av1"}
    case = InvestigationDirector().situation(memory, remaining_steps=6)
    assert "H_attack" in case and "H_normal" in case
    assert "No signs of malicious activity" not in case


def test_separate_audit_changes_proposed_verdict_before_remote_submission(tmp_path):
    """Only the reviewed verdict reaches the runtime; Qwen review uses same tool schema."""
    import asyncio
    import json
    from types import SimpleNamespace
    from bluesec1_agent.models import NextStep
    from bluesec1_client import PublicTask, TaskResult, ToolCallResult

    class LLM:
        def __init__(self):
            self.steps = []
            self.requests = []

        async def next_step(self, messages, *, finish_only=False):
            self.requests.append((messages, finish_only))
            return self.steps.pop(0)

    class Session:
        task_id = "task-A"

        def __init__(self):
            self.calls = []
            self.task = PublicTask(task_id=self.task_id, observation={
                "alert_text": {"trigger_entities": [
                    {"id": f"process-{i}", "type": "windows_process", "properties": {
                        "cmdline": f"maintenance-tool --check {i}"
                    }} for i in range(5)
                ]},
                "available_tools": json.dumps([
                    {"name": "get_entity", "parameters": {"type": "object"}},
                    {"name": "finish_investigation", "parameters": {"type": "object"}},
                ]),
            })

        async def call_tool(self, name, arguments):
            self.calls.append((name, arguments))
            if name == "finish_investigation":
                return ToolCallResult(task_id=self.task_id, tool_name=name, terminated=True,
                    task_result=TaskResult(task_id=self.task_id, completion_reason="terminated"))
            identifier = arguments["entity_id"]
            return ToolCallResult(task_id=self.task_id, tool_name=name, info={"tool_status": "ok"},
                observation={"last_tool_result": json.dumps({
                    "id": identifier, "type": "windows_process", "properties": {
                        "cmdline": f"maintenance-tool --check {identifier}",
                    }, "relation_ids": {"outgoing": []}
                })})

    class Client:
        def __init__(self, session):
            self.run = SimpleNamespace(run_id="run-A")
            self.session = session

        async def start_task(self):
            session, self.session = self.session, None
            return session

    def step(tool, **arguments):
        return NextStep.model_validate({
            "current_state": f"Question to test using {tool}",
            "plan_remaining_steps_brief": ["Verify effects and compare hypotheses"],
            "task_completed": tool == "finish_investigation",
            "function": {"tool": tool, **arguments},
        })

    llm = LLM()
    llm.steps.extend(step("get_entity", entity_id=f"process-{i}", reasoning="test initiator")
                     for i in range(5))
    llm.steps.append(step("finish_investigation", submission={
        "verdict": "malicious", "ir_artifacts": [], "reasoning": "Possible misuse"}))
    llm.steps.append(step("finish_investigation", submission={
        "verdict": "benign", "reasoning": "Observed checks are routine and causally explained",
        "legitimacy_evidence": [{"anchor": "entity", "entity_id": "process-0",
                                 "property_fields": ["cmdline"]}],
    }))
    session = Session()
    agent = SimpleSGRAgent(llm, review_enabled=True, max_steps=12,
                           trajectory_dir=str(tmp_path), min_entities_before_benign=0)
    result = asyncio.run(agent.run(Client(session)))
    assert result.successful_tasks == 1
    submissions = [args["submission"] for name, args in session.calls if name == "finish_investigation"]
    assert len(submissions) == 1 and submissions[0]["verdict"] == "benign"
    assert any("INDEPENDENT VERDICT AUDIT" in str(request[-1]["content"])
               and finish_only for request, finish_only in llm.requests)
    audit_log = tmp_path / "run-A" / "task-A.json"
    saved = json.loads(audit_log.read_text())
    assert any(m.get("role") == "audit" for m in saved["messages"])


def test_confirmed_causal_endpoint_is_prioritized_as_entity_not_random_edge():
    m = make_memory()
    m.absorb({"id": "r-a", "type": "connected_to", "source_id": "p-main", "target_id": "target-new"})
    m.fetched_ids.update({"p-main", "r-a"})
    ranked = InvestigationDirector().rank_frontier(m)
    assert ranked[0].identifier == "target-new"
    assert ranked[0].tool == "get_entity"
    assert "endpoint" in ranked[0].description
    assert "get_entity(target-new)" in InvestigationDirector().situation(m, remaining_steps=10)


def test_duplicate_search_recovery_pivots_to_observed_endpoint():
    m = make_memory()
    m.absorb({"id": "r-a", "type": "connected_to", "source_id": "p-main", "target_id": "net-endpoint"})
    m.fetched_ids.update({"p-main", "r-a"})
    args = {"query": "server activity", "reasoning": "check"}
    m.cache[InvestigationMemory.cache_key("search", args)] = {"status": "ok"}
    tool, newargs, note = SimpleSGRAgent._recover_duplicate("search", args, m,
                                    {"search", "get_entity", "get_relation"})
    assert tool == "get_entity"
    assert newargs["entity_id"] == "net-endpoint"
    assert "Avoided repeated search" in note


def test_reviewed_evidence_prioritizes_actual_operations_over_reputation():
    m = make_memory()
    m.absorb({"id": "p-child", "type": "windows_process", "properties": {
        "cmdline": "powershell -command perform-action", "cmdline_decoded": "write data to target"
    }})
    m.absorb({"id": "r-a", "type": "created_process", "source_id": "p-main", "target_id": "p-child"})
    digest = InvestigationDirector().evidence_digest(m)
    assert "cmdline_decoded=write data to target" in digest
    assert "FOLLOW THE EFFECT" in InvestigationDirector().situation(m, remaining_steps=8)


def test_high_consequence_event_is_visible_even_when_discovered_late():
    memory = make_memory()
    for i in range(12):
        memory.absorb({"id": f"n{i}", "type": "windows_process", "properties": {
            "cmdline": f"process-{i}"}})
        memory.absorb({"id": f"early{i}", "type": "win_process_create",
                       "source_id": "p-main", "target_id": f"n{i}"})
    memory.absorb({"id": "impact-node", "type": "windows_file",
                   "properties": {"path": "C:/important/settings.json"}})
    memory.absorb({"id": "late-mutation", "type": "modified_file",
                   "source_id": "p-main", "target_id": "impact-node"})
    chain = InvestigationDirector().causal_trace(memory, limit=5)
    assert "--modified_file-->" in chain
    assert chain.index("--modified_file-->") < chain.index("--win_process_create-->")


def test_ad_subject_reached_through_observed_group_change_is_investigated():
    memory = make_memory()
    memory.absorb({"id": "membership-change", "type": "added_to_group",
                   "source_id": "p-main", "target_id": "target-user"})
    memory.absorb({"id": "target-user", "type": "windows_user",
                   "properties": {"username": "some-account", "ad_object_id": "target-ad-id"}})
    ranked = InvestigationDirector().rank_frontier(memory)
    candidates = {(c.tool, c.identifier) for c in ranked}
    assert ("get_ad_object_info", "target-ad-id") in candidates
    assert not any(c.identifier == "h-main" for c in ranked)


def test_host_ad_identifier_does_not_trigger_unrelated_directory_query():
    memory = make_memory()
    memory.absorb({"id": "other-host", "type": "host",
                   "properties": {"hostname": "unrelated", "ad_object_id": "unrelated-ad-id"}})
    ranked = InvestigationDirector().rank_frontier(memory)
    assert all(c.identifier != "unrelated-ad-id" for c in ranked)


def test_checkpoint_requires_behavior_and_considers_another_informative_call():
    director = InvestigationDirector()
    text = director.decision_checkpoint(make_memory(), steps_used=11, remaining_steps=17)
    assert "DECISION CHECKPOINT" in text
    assert "finish_investigation" in text
    assert "ONE missing discriminating fact" in text
    assert "signed" in text


def test_effect_endpoint_preferred_after_repetitive_relation_enumeration():
    memory = make_memory()
    for i in range(5):
        rid = f"r-sampled-{i}"
        memory.absorb({"id": "p-main", "type": "windows_process",
                       "properties": {"cmdline": "worker.exe"},
                       "relation_ids": {"outgoing": [rid]}})
        memory.fetched_ids.add(rid)
    memory.absorb({"id": "change", "type": "modified_file",
                   "source_id": "p-main", "target_id": "new-file"})
    memory.absorb({"id": "new-file", "type": "windows_file",
                   "properties": {"path": "C:/app/config.json"}})
    agent = SimpleSGRAgent(llm=None)
    tool, args, reason = agent._prefer_effect_endpoint(
        "get_relation", {"relation_id": "r-a", "reasoning": "enumerate"},
        memory, {"get_entity", "get_relation"})
    assert tool == "get_entity"
    assert args["entity_id"] == "new-file"
    assert "consequence" in reason


def test_effect_prioritizer_does_not_redirect_before_evidence_threshold():
    memory = make_memory()
    memory.absorb({"id": "change", "type": "modified_file",
                   "source_id": "p-main", "target_id": "new-file"})
    agent = SimpleSGRAgent(llm=None)
    tool, args, reason = agent._prefer_effect_endpoint(
        "get_relation", {"relation_id": "r-a", "reasoning": "check"},
        memory, {"get_entity", "get_relation"})
    assert tool == "get_relation" and reason is None


def test_v8_independent_audit_does_not_inherit_investigator_conversation():
    """A second opinion gets an observed graph, not a continuation of self-justification."""
    memory = make_memory()
    memory.absorb({"id": "p-child", "type": "windows_process",
                   "properties": {"cmdline": "worker --set-parameter alternate"}})
    memory.absorb({"id": "r-a", "type": "win_process_create",
                   "source_id": "p-main", "target_id": "p-child"})
    packet = InvestigationDirector().independent_review_messages(memory, {
        "verdict": "benign", "reasoning": "All processes are signed",
        "legitimacy_evidence": []}, remaining_steps=7)
    assert [m["role"] for m in packet] == ["system", "user"]
    assert "INDEPENDENT VERDICT AUDIT" in packet[1]["content"]
    assert "p-main --win_process_create--> p-child" in packet[1]["content"]
    assert "worker --set-parameter alternate" in packet[1]["content"]
    assert "INDEPENDENT SOC/DFIR" in packet[0]["content"]
    assert "All processes are signed" not in packet[1]["content"]


def test_v8_audit_preserves_configuration_effect_and_treats_identity_as_unproven():
    memory = make_memory()
    memory.absorb({"id": "cfg", "type": "registry_value",
                   "properties": {"path": "HKLM/Service/parameters"}})
    memory.absorb({"id": "r-a", "type": "set_registry_value",
                   "source_id": "p-main", "target_id": "cfg"})
    packet = InvestigationDirector().independent_review_messages(
        memory, {"verdict": "benign", "reasoning": "Executed by SYSTEM"}, remaining_steps=5)
    text = packet[1]["content"]
    assert "--set_registry_value-->" in text
    assert "HKLM/Service/parameters" in text
    assert "valid account" in packet[0]["content"]
    assert "Executed by SYSTEM" not in text  # blind review is not primed by proposal


def test_v8_review_exposes_context_for_potential_benign_forensic_operation():
    memory = make_memory()
    memory.absorb({"id": "file-a", "type": "windows_file", "properties": {
        "path": "C:/Temp/triage/memory.raw"}})
    memory.absorb({"id": "driver", "type": "windows_driver", "properties": {
        "path": "C:/Temp/triage/memory.sys"}})
    memory.absorb({"id": "r1", "type": "loaded_driver",
                   "source_id": "p-main", "target_id": "driver"})
    memory.absorb({"id": "r2", "type": "wrote_file",
                   "source_id": "p-main", "target_id": "file-a"})
    memory.absorb({"id": "r3", "type": "deleted_file",
                   "source_id": "p-main", "target_id": "driver"})
    ledger = InvestigationDirector().action_ledger(memory)
    assert all(f"--{event}-->" in ledger for event in (
        "loaded_driver", "wrote_file", "deleted_file"))
    packet = InvestigationDirector().independent_review_messages(
        memory, {"verdict": "malicious", "reasoning": "Temp driver deleted"}, remaining_steps=0)
    assert "memory dump" in packet[0]["content"]
    assert "Temp driver deleted" not in packet[1]["content"]
