"""Why does the arbiter model return empty content? Raw-request diagnostics.

Run: uv run --env-file .env python scripts/arbiter_diag.py
For four request variants prints time, finish_reason, length of the answer and
of the hidden reasoning, and token usage:
  A  json_schema + LLM_ARBITER_EXTRA_BODY (as the agent sends it now)
  B  json_schema + thinking switched off (chat_template_kwargs)
  C  json_object (no schema) + thinking off
  D  no response_format + thinking off
finish_reason=length with empty content = the model spent all tokens thinking.
"""

import asyncio
import json
import os
import time

from openai import AsyncOpenAI

from bluesec1_agent.agent import SYSTEM_PROMPT
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.models import FINISH_STEP_RESPONSE_FORMAT
from bluesec1_agent.settings import Settings

CASE = (
    "Two analysts disagree. Decide using only the facts and reply with the "
    "finish_investigation JSON. Facts: powershell.exe -NoP -W Hidden -Enc SQBFAFgA... "
    "started by winword.exe under keystone.local\\svc_bi on host APP97. "
    "Analyst: benign (signed Microsoft binary). Reviewer: malicious (hidden encoded "
    "PowerShell spawned by Word)."
)
NO_THINK = {"chat_template_kwargs": {"thinking": False, "enable_thinking": False}}


def _reasoning(message) -> str:
    for attr in ("reasoning_content", "reasoning"):
        value = getattr(message, attr, None)
        if value:
            return str(value)
    extra = getattr(message, "model_extra", None) or {}
    return str(extra.get("reasoning_content") or extra.get("reasoning") or "")


async def main() -> None:
    s = Settings()
    model = s.llm_arbiter_model.strip() or s.llm_default_model
    base = json.loads(s.llm_arbiter_extra_body.strip() or s.llm_extra_body.strip() or "{}")
    raw = AsyncOpenAI(
        base_url=s.llm_arbiter_base_url.strip() or s.llm_base_url,
        api_key=s.llm_arbiter_api_key.get_secret_value() or s.llm_api_key.get_secret_value(),
        timeout=s.llm_timeout_seconds,
        max_retries=0,
    )
    schema = OpenAIStructuredStepClient._prepare(FINISH_STEP_RESPONSE_FORMAT, True)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": CASE}]
    only = {v.strip().upper() for v in os.environ.get("ARBITER_DIAG_ONLY", "").split(",") if v.strip()}
    variants = [
        ("A schema + extra_body", {"response_format": schema}, base),
        ("B schema + no thinking", {"response_format": schema}, {**base, **NO_THINK}),
        ("C json_object + no thinking", {"response_format": {"type": "json_object"}}, {**base, **NO_THINK}),
        ("D plain + no thinking", {}, {**base, **NO_THINK}),
    ]
    print(f"model={model} max_tokens={s.llm_arbiter_max_completion_tokens}")
    for label, kwargs, body in variants:
        if only and label[0] not in only:
            continue
        t = time.perf_counter()
        try:
            r = await raw.chat.completions.create(
                model=model, messages=messages,
                max_tokens=s.llm_arbiter_max_completion_tokens,
                extra_body=body or None, **kwargs)
            ch = r.choices[0]
            content = ch.message.content or ""
            usage = getattr(r, "usage", None)
            print(f"[{label}] {time.perf_counter() - t:.0f}s finish={ch.finish_reason} "
                  f"content={len(content)} reasoning={len(_reasoning(ch.message))} "
                  f"tokens={getattr(usage, 'completion_tokens', '?')} -> {content[:160]!r}")
            if not content:
                print(f"    reasoning head: {_reasoning(ch.message)[:400]!r}")
        except Exception as exc:
            print(f"[{label}] {time.perf_counter() - t:.0f}s FAILED {type(exc).__name__}: {str(exc)[:200]}")
    await raw.close()


asyncio.run(main())
