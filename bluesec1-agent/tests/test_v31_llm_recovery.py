import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import bluesec1_agent.llm as llm_mod  # noqa: E402
from bluesec1_agent.llm import OpenAIStructuredStepClient  # noqa: E402


class _EngineError(Exception):
    status_code = 400


class _Completions:
    def __init__(self, failures: int, exc: Exception) -> None:
        self.failures, self.exc, self.calls = failures, exc, 0

    async def create(self, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.exc
        return "ok"


def _client(completions):
    c = type("C", (), {})()
    c.chat = type("Chat", (), {"completions": completions})()
    return c


def _llm(completions):
    return OpenAIStructuredStepClient(base_url="x", api_key="k", model="m", timeout_seconds=1,
                                      max_completion_tokens=8, max_retries=1,
                                      client=_client(completions))


def test_engine_400_is_retried(monkeypatch) -> None:
    async def no_sleep(_):
        return None
    monkeypatch.setattr(llm_mod.asyncio, "sleep", no_sleep)
    comp = _Completions(2, _EngineError("Engine protocol predict request failed: fetch failed"))
    assert asyncio.run(_llm(comp)._create_with_recovery(model="m")) == "ok"
    assert comp.calls == 3


def test_real_bad_request_is_not_retried() -> None:
    comp = _Completions(1, _EngineError("invalid schema"))
    try:
        asyncio.run(_llm(comp)._create_with_recovery(model="m"))
    except _EngineError:
        pass
    assert comp.calls == 1
