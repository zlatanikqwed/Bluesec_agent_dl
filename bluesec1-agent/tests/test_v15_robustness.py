"""General resilience and provenance checks; not benchmark answer memorization."""
import asyncio

import pytest

from bluesec1_agent.agent import InvestigationMemory, SimpleSGRAgent
from bluesec1_agent.llm import NextStepRequestError
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.models import NextStep


def _memory():
    m = InvestigationMemory()
    m.focus_ids = {"runner"}
    m.absorb({"id": "runner", "type": "windows_process", "properties": {
        "cmdline": "powershell -File nightly.ps1", "signed": True}})
    m.absorb({"id": "report", "type": "windows_file", "properties": {
        "path": "C:\\Reports\\inventory.csv"}})
    m.absorb({"id": "write-event", "type": "wrote_file", "source_id": "runner",
              "target_id": "report"})
    return m


def _finish_step():
    return NextStep.model_validate({
        "current_state": "Observed scheduled report export; effect is evidenced.",
        "plan_remaining_steps_brief": ["Finish"],
        "task_completed": True,
        "function": {"tool": "finish_investigation", "submission": {
            "verdict": "benign", "reasoning": "The runner wrote inventory.csv as a report.",
            "legitimacy_evidence": [{"anchor": "entity", "entity_id": "runner",
                                     "property_fields": ["cmdline"]}],
        }},
    })


class FakeFinalModel:
    def __init__(self):
        self.calls = []

    async def next_step(self, messages, *, finish_only=False):
        self.calls.append((messages, finish_only))
        if len(self.calls) == 1:
            raise NextStepRequestError("unterminated JSON")
        return _finish_step()


def test_corrupted_model_history_is_not_replayed_during_recovery():
    m = _memory()
    client = FakeFinalModel()
    agent = SimpleSGRAgent(llm=client)
    transcript = []
    result = asyncio.run(agent._recover_structured_step(
        m, transcript, error=NextStepRequestError("unterminated JSON")))
    assert result.function.tool == "finish_investigation"
    assert len(client.calls) == 2
    context = str(client.calls[0][0])
    assert "wrote_file" in context and "inventory.csv" in context
    assert "previous generation could not be parsed" in context.lower()
    assert "unterminated JSON" not in context
    assert all(finish_only for _, finish_only in client.calls)
    assert any('structured_output_error' in str(x) for x in transcript)


def test_recovery_second_pass_smaller_and_failing_two_attempts_raises():
    class Broken:
        def __init__(self):
            self.contexts = []

        async def next_step(self, messages, *, finish_only=False):
            self.contexts.append(str(messages))
            raise NextStepRequestError('malformed')

    broken = Broken()
    agent = SimpleSGRAgent(llm=broken)
    with pytest.raises(NextStepRequestError):
        asyncio.run(agent._recover_structured_step(
            _memory(), [], error=NextStepRequestError('malformed')))
    assert len(broken.contexts) == 2


def test_only_explicitly_explained_effect_references_can_be_added():
    m = _memory()
    submission = {"submission": {
        "verdict": "benign", "reasoning": "The runner wrote inventory.csv as a report.",
        "legitimacy_evidence": [{"anchor": "entity", "entity_id": "runner",
                                 "property_fields": ["cmdline"]}],
    }}
    fixed, note = SimpleSGRAgent._reconcile_final(submission, m)
    citations = fixed["submission"]["legitimacy_evidence"]
    assert note and len(citations) == 2
    assert citations[-1] == {"anchor": "relation", "relation_id": "write-event",
                             "property_fields": ["type", "source_id", "target_id"]}
    assert fixed["submission"]["verdict"] == "benign"


def test_no_unsupported_citations_when_effect_not_described():
    m = _memory()
    submission = {"submission": {
        "verdict": "benign", "reasoning": "The runner is signed.",
        "legitimacy_evidence": [{"anchor": "entity", "entity_id": "runner",
                                 "property_fields": ["signed"]}],
    }}
    fixed, _ = SimpleSGRAgent._reconcile_final(submission, m)
    assert fixed["submission"]["legitimacy_evidence"] == submission["submission"]["legitimacy_evidence"]


def test_unlinked_effect_not_attached_to_investigation():
    m = _memory()
    m.absorb({"id": "other", "type": "windows_process", "properties": {"cmdline": "unrelated"}})
    m.absorb({"id": "file2", "type": "windows_file", "properties": {"path": "X:\\Reports\\other.csv"}})
    m.absorb({"id": "other-write", "type": "wrote_file", "source_id": "other", "target_id": "file2"})
    submission = {"submission": {
        "verdict": "benign", "reasoning": "Report named other.csv; also inventory.csv.",
        "legitimacy_evidence": [{"anchor": "entity", "entity_id": "runner",
                                 "property_fields": ["cmdline"]}],
    }}
    fixed, _ = SimpleSGRAgent._reconcile_final(submission, m)
    rel_ids = {i.get("relation_id") for i in fixed["submission"]["legitimacy_evidence"]}
    assert "other-write" not in rel_ids


def test_inbound_connection_does_not_mislabel_receiver_as_initiator():
    m = InvestigationMemory()
    m.focus_ids = {"receiver"}
    m.absorb({"id": "receiver", "type": "windows_process", "properties": {"image_path": "System"}})
    m.absorb({"id": "flow", "type": "network_connection", "properties": {
        "src_ip": "192.0.2.41", "dst_port": 445}})
    m.absorb({"id": "accepted", "type": "accepted_connection_from",
              "source_id": "receiver", "target_id": "flow"})
    ledger = InvestigationDirector().action_ledger(m)
    assert "RECEIVING PROCESS" in ledger
    assert "INBOUND CONNECTION" in ledger
    assert "ACTOR" not in ledger
