"""Regression: an 8192-token local judge must not retry an unchanged 8319-token prompt."""
import asyncio
from types import SimpleNamespace

import pytest

from bluesec1_agent.llm import (
    OpenAIStructuredStepClient,
    compact_overflow_messages,
    is_context_overflow,
)
from bluesec1_agent.models import GetEntityRequest, NextStep


class Engine400(Exception):
    status_code = 400


LIMIT_ERROR = Engine400(
    "Error code: 400 - {'error': 'Engine protocol predict request returned 400: "
    "{\"error\":{\"code\":400,\"message\":\"request (8319 tokens) exceeds the "
    "available context size (8192 tokens)\",\"type\":\"exceed_context_size_error\","
    "\"n_prompt_tokens\":8319,\"n_ctx\":8192}}'}"
)


class FakeCompletions:
    def __init__(self, failures=1):
        self.failures = failures
        self.requests = []

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        if len(self.requests) <= self.failures:
            raise LIMIT_ERROR
        valid = NextStep(current_state="Evidence verified", plan_remaining_steps_brief=["Confirm"],
                         task_completed=False, function=GetEntityRequest(
                             tool="get_entity", entity_id="id-1", reasoning="Test"))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=valid.model_dump_json(), refusal=None))],
            usage=SimpleNamespace(total_tokens=32))


def make_client(completions):
    return OpenAIStructuredStepClient(
        base_url="http://localhost", api_key="test", model="local-8192",
        timeout_seconds=3, max_completion_tokens=1024, max_retries=1,
        client=SimpleNamespace(chat=SimpleNamespace(completions=completions)),
    )


def test_engine_wrapped_overflow_does_not_sleep_or_repeat_unchanged(monkeypatch):
    import bluesec1_agent.llm as llm
    async def never_sleep(_):
        raise AssertionError("Context overflow must not use transient backoff")
    monkeypatch.setattr(llm.asyncio, "sleep", never_sleep)
    calls = FakeCompletions(1)
    assert is_context_overflow(LIMIT_ERROR)
    with pytest.raises(Engine400):
        asyncio.run(make_client(calls)._create_with_recovery(model="local-8192"))
    assert len(calls.requests) == 1


def test_compaction_on_overflow_preserves_system_alert_and_latest_evidence():
    completions = FakeCompletions(1)
    original = [
        {"role": "system", "content": "DO NOT ASSUME MISSING EVIDENCE"},
        {"role": "user", "content": '{"initial_observation":{"alert":"original trigger"},'
          '"available_tools":["get_entity","get_relation","search"],"step_budget":28}'},
        {"role": "user", "content": "CASE START: child_process id-1\\n" + "observations " * 2000
         + "\\nLATEST VERIFIED: wrote_file FILE-UUID and created_service SERVICE-UUID"},
    ]
    step = asyncio.run(make_client(completions).next_step(original, finish_only=True))
    assert step.function.tool == "get_entity"
    assert len(completions.requests) == 2
    first = completions.requests[0]["messages"]
    second = completions.requests[1]["messages"]
    assert second[0]["content"] == first[0]["content"]
    assert "original trigger" in second[1]["content"]
    assert "available_tools" not in second[1]["content"]
    assert "child_process id-1" in second[-1]["content"]
    assert "FILE-UUID" in second[-1]["content"]
    assert "SERVICE-UUID" in second[-1]["content"]
    assert len(str(second)) < len(str(first))
    assert "available_tools" in original[1]["content"]  # untouched
    assert original[-1]["content"].count("observations") == 2000


def test_minimal_request_compacts_last_user_without_truncating_system():
    request = [{"role": "system", "content": "IMPORTANT SYSTEM RULES"},
               {"role": "user", "content": "FIRST FACT" + "x" * 16000 + "LAST FACT"}]
    compacted, saved = compact_overflow_messages(request, 3500, finish_only=False)
    assert saved >= 3300
    assert compacted[0] == request[0]
    assert "FIRST FACT" in compacted[1]["content"]
    assert "LAST FACT" in compacted[1]["content"]
    assert request[1]["content"].count("x") == 16000


def test_persistent_context_error_fails_after_four_attempts_without_backoff(monkeypatch):
    import bluesec1_agent.llm as llm
    async def never_sleep(_):
        raise AssertionError("Context overflow is not transient")
    monkeypatch.setattr(llm.asyncio, "sleep", never_sleep)
    calls = FakeCompletions(20)
    with pytest.raises(Engine400):
        asyncio.run(make_client(calls).next_step([
            {"role": "system", "content": "RULES"},
            {"role": "user", "content": "fact " * 6000},
        ], finish_only=True))
    assert 1 <= len(calls.requests) <= 4
