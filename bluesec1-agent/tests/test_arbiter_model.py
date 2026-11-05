"""Optional arbiter model: used only for disagreements, falls back to the main model."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import FinishInvestigationRequest


def _step(verdict: str):
    sub = ({"verdict": "benign", "reasoning": "r", "legitimacy_evidence": []}
           if verdict == "benign" else
           {"verdict": "malicious", "reasoning": "r", "ir_artifacts": []})
    return SimpleNamespace(function=FinishInvestigationRequest.model_validate(
        {"tool": "finish_investigation", "submission": sub}))


class FakeLLM:
    def __init__(self, verdict: str, model: str, fail: bool = False) -> None:
        self.verdict, self.model, self.fail, self.calls = verdict, model, fail, 0

    async def next_step(self, messages, finish_only=False):
        self.calls += 1
        if self.fail:
            raise RuntimeError("504 gateway timeout")
        return _step(self.verdict)


def _agent(main, arbiter, shadow=True):
    return SimpleSGRAgent(main, trajectory_dir=None, arbiter_llm=arbiter, arbiter_shadow=shadow)


def test_without_arbiter_main_model_decides():
    main = FakeLLM("benign", "small")
    transcript: list = []
    step = asyncio.run(_agent(main, None)._arbitrate([{"role": "user", "content": "x"}], transcript, "t"))
    assert step.function.submission.verdict == "benign"
    assert main.calls == 1 and transcript == []


def test_arbiter_decides_and_shadow_is_only_logged():
    main, big = FakeLLM("benign", "small"), FakeLLM("malicious", "big")
    transcript: list = []
    step = asyncio.run(_agent(main, big)._arbitrate([], transcript, "disagreement"))
    assert step.function.submission.verdict == "malicious"
    assert big.calls == 1 and main.calls == 1
    log = transcript[-1]["content"]
    assert '"source": "arbiter"' in log and '"shadow_main_verdict": "benign"' in log


def test_arbiter_failure_falls_back_to_main():
    main, big = FakeLLM("benign", "small"), FakeLLM("malicious", "big", fail=True)
    transcript: list = []
    step = asyncio.run(_agent(main, big)._arbitrate([], transcript, "consequence"))
    assert step.function.submission.verdict == "benign"
    assert '"source": "fallback_main"' in transcript[-1]["content"]


def test_response_mode_controls_response_format():
    from typing import Any, cast

    from openai import AsyncOpenAI

    from bluesec1_agent.llm import OpenAIStructuredStepClient
    from test_llm import FakeOpenAI, valid_process_step

    seen = {}
    for mode, expected in (("schema", "json_schema"), ("json_object", "json_object"), ("none", None)):
        fake = FakeOpenAI([valid_process_step().model_dump_json()])
        client = OpenAIStructuredStepClient(
            base_url="https://llm.example/v1", api_key="k", model="m", timeout_seconds=5,
            max_completion_tokens=100, max_retries=1, client=cast(AsyncOpenAI, fake),
            response_mode=mode)
        asyncio.run(client.next_step([{"role": "system", "content": "x"}]))
        rf: Any = fake.completions.requests[0].get("response_format")
        seen[mode] = rf.get("type") if rf else None
        assert seen[mode] == expected


def test_empty_content_uses_json_from_reasoning_field():
    from types import SimpleNamespace as NS

    from bluesec1_agent.llm import extract_raw_content

    msg = NS(content="", refusal=None, reasoning_content='{"verdict": "x"}')
    assert extract_raw_content(NS(choices=[NS(message=msg)])) == '{"verdict": "x"}'
    plain = NS(content="", refusal=None, reasoning_content="just thinking, no json")
    assert extract_raw_content(NS(choices=[NS(message=plain)])) == ""
