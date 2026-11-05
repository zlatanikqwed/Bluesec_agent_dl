"""Regression coverage for V32 8192-token LLM context errors (offline)."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from bluesec1_agent.harvest_v32 import _bounded_digest, _context_overflow
from bluesec1_agent.llm import OpenAIStructuredStepClient, V32_JUDGE_RESPONSE_FORMAT


class Engine400(Exception):
    status_code = 400


class FakeCompletion:
    def __init__(self, error=None):
        self.requests = []
        self.error = error

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({
                "verdict": "benign", "reasoning": "Observed approved admin activity",
                "ir_artifacts": [], "legitimacy_evidence": [],
            })))],
            usage=SimpleNamespace(total_tokens=456),
        )


def fake_llm(completion):
    client = SimpleNamespace(chat=SimpleNamespace(completions=completion))
    return OpenAIStructuredStepClient(
        base_url="http://local", api_key="unused", model="gpt-oss-20b",
        timeout_seconds=1, max_completion_tokens=8192, max_retries=1, client=client,
    )


def test_compact_judge_no_full_step_schema():
    c = FakeCompletion()
    result = asyncio.run(fake_llm(c).judge_case([
        {"role": "system", "content": "Judge"},
        {"role": "user", "content": "Synthetic test"},
    ]))
    assert result["verdict"] == "benign"
    request = c.requests[0]
    assert request["response_format"] == V32_JUDGE_RESPONSE_FORMAT
    assert request["max_completion_tokens"] == 2400
    assert len(json.dumps(request["response_format"])) < 1600
    assert "STRUCTURED_OUTPUT_INSTRUCTION" not in str(request["messages"])


def test_context_400_fails_without_waiting(monkeypatch):
    async def bad_sleep(_):
        raise AssertionError("should not sleep/retry an oversized request")
    monkeypatch.setattr("bluesec1_agent.llm.asyncio.sleep", bad_sleep)
    exc = Engine400('Engine protocol predict request returned 400: '
                    '{"type":"exceed_context_size_error", "n_prompt_tokens":9660, "n_ctx":8192}')
    c = FakeCompletion(error=exc)
    with pytest.raises(Engine400):
        asyncio.run(fake_llm(c).judge_case([{"role": "user", "content": "huge"}]))
    assert len(c.requests) == 1
    assert _context_overflow(exc)


def test_digest_bounded_with_large_search_results():
    digest = {
        "trigger_id": "proc-123", "trigger_host_id": "host-1",
        "session_process_ids": [f"proc-{i}" for i in range(30)],
        "attack_signals": [{"name": "suspicious", "entity_id": "proc-123",
                            "evidence": "x"*1000} for _ in range(20)],
        "entities": [{"id": f"proc-{i}", "type": "windows_process",
                      "host_id": "host-1", "properties": {"image_path": "C:\\Temp\\evil.exe",
                      "cmdline": "z" * 3000, "script_text": "n" * 3000,
                      "logon_id": "0x01", "pid": str(i)}} for i in range(100)],
        "relations": [{"type": "wrote_file", "source_id": f"proc-{i}",
                       "target_id": f"file-{i}"} for i in range(100)],
    }
    result = _bounded_digest(digest)
    assert len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) <= 6800
    assert result["trigger_id"] == "proc-123"
    assert result["entities"]
    assert len(result["entities"]) < 100
    assert len(result["attack_signals"]) <= 6


def test_context_overflow_shrinks_digest_instead_of_repeating(monkeypatch):
    from bluesec1_agent.harvest_v32 import HarvestJudgeReport
    from bluesec1_client import PublicTask, ToolCallResult, TaskResult

    class TestJudge:
        def __init__(self):
            self.sizes = []

        async def judge_case(self, messages):
            evidence = json.loads(messages[-1]["content"])["evidence"]
            size = len(json.dumps(evidence, ensure_ascii=False, separators=(",", ":")))
            self.sizes.append(size)
            if size > 4400:
                raise Engine400('request exceeds the available context size (8192 tokens)')
            return {"verdict": "benign", "reasoning": "Routine process activity",
                    "ir_artifacts": [], "legitimacy_evidence": []}

    class TestSession:
        def __init__(self):
            self.task = PublicTask(task_id="t", observation={"alert_text": {
                "trigger_entities": [
                    {"id": "host-1", "type": "host", "properties": {"ip": "10.0.0.2"}},
                    {"id": "proc-1", "type": "windows_process", "host_id": "host-1",
                     "properties": {"logon_id": "0xabc123", "user_sid": "S-1-5-21-23445",
                                    "pid": 123, "image_path": "C:\\Windows\\System32\\cmd.exe"}},
                ], "trigger_relations": []}})
            self.calls = []

        async def call_tool(self, tool, args):
            self.calls.append(tool)
            if tool == "search":
                # Full session results can be verbose, independent of truth labels.
                result = {"results": [{"id": f"p-{i}", "type": "windows_process",
                        "host_id": "host-1", "properties": {"logon_id": "0xabc123",
                        "pid": 1000+i, "cmdline": "x" * 400}} for i in range(15)]}
            else:
                result = {}
            term = tool == "finish_investigation"
            return ToolCallResult(task_id="t", tool_name=tool, terminated=term,
                                  info={"tool_status": "ok", "tool_result": result},
                                  task_result=TaskResult(task_id="t", completion_reason="terminated")
                                  if term else None)

    judge = TestJudge()
    session = TestSession()
    finished = asyncio.run(HarvestJudgeReport(judge, budget=2, votes=2).investigate(
        session, [], tool_specs=[{"name": "search"}, {"name": "finish_investigation"}] ))
    assert finished.completion_reason == "terminated"
    assert len(judge.sizes) >= 3
    assert judge.sizes[0] > judge.sizes[1]
    assert session.calls[-1] == "finish_investigation"
