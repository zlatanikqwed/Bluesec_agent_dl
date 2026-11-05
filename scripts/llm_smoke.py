"""Quick LLM diagnostics without the competition runtime.

Run: uv run --env-file .env python scripts/llm_smoke.py
[1] plain completion            – server alive, generation speed
[2] tiny JSON schema            – does the server enforce response_format at all
[3] agent step, schema with $defs (default)
[4] agent step, inlined schema  (LLM_INLINE_SCHEMA_REFS=true)
"""

import asyncio
import json
import time

from openai import AsyncOpenAI

from bluesec1_agent.agent import SYSTEM_PROMPT
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.models import tool_signatures
from bluesec1_agent.settings import Settings

ALERT = {
    "alert_text": "Process powershell.exe (PID: 3080) was started on host APP97",
    "trigger_entities": [
        {
            "id": "bfe64f2c-1e7c-54aa-90b5-7012018f03e1",
            "type": "host",
            "properties": {"hostname": "APP97", "platform": "windows"},
        },
        {
            "id": "83ddd3f2-ae87-52ee-b29a-4f999ce09039",
            "type": "windows_process",
            "properties": {
                "image_path": "C:\\Windows\\System32\\powershell.exe",
                "user": "keystone.local\\svc_bi",
                "parent_image": "explorer.exe",
            },
        },
    ],
}


async def main() -> None:
    s = Settings()
    key = s.llm_api_key.get_secret_value()
    raw = AsyncOpenAI(base_url=s.llm_base_url, api_key=key, timeout=s.llm_timeout_seconds)

    t = time.perf_counter()
    r = await raw.chat.completions.create(
        model=s.llm_default_model,
        max_tokens=64,
        messages=[{"role": "user", "content": "Reply with the single word OK. /no_think"}],
    )
    print(f"[1] plain: {time.perf_counter() - t:.1f}s -> {r.choices[0].message.content!r}")

    tiny = {
        "type": "json_schema",
        "json_schema": {
            "name": "tiny",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {"color": {"type": "string", "enum": ["purple"]}},
                "required": ["color"],
                "additionalProperties": False,
            },
        },
    }
    r = await raw.chat.completions.create(
        model=s.llm_default_model,
        max_tokens=64,
        response_format=tiny,
        messages=[{"role": "user", "content": "Name any color. /no_think"}],
    )
    out = r.choices[0].message.content or ""
    enforced = out.strip().startswith("{") and "purple" in out
    print(f"[2] tiny schema enforced: {enforced} -> {out[:80]!r}")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "instruction": "Investigate this alert.",
                    "initial_observation": ALERT,
                    "available_tools": tool_signatures(),
                }
            ),
        },
    ]
    for label, inline in (("[3] $defs schema", False), ("[4] inlined schema", True)):
        llm = OpenAIStructuredStepClient(
            base_url=s.llm_base_url,
            api_key=key,
            model=s.llm_default_model,
            timeout_seconds=s.llm_timeout_seconds,
            max_completion_tokens=s.llm_max_completion_tokens,
            max_retries=2,
            disable_thinking=s.llm_disable_thinking,
            inline_schema_refs=inline,
        )
        t = time.perf_counter()
        try:
            step = await llm.next_step(messages)
            result = step.function.model_dump(mode="json", by_alias=True)
        except Exception as exc:
            result = f"FAILED: {type(exc).__name__}"
        print(f"{label}: {time.perf_counter() - t:.1f}s -> {result}")
        await llm.aclose()
    await raw.close()


asyncio.run(main())
