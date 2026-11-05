"""Check the arbiter model before a run (no competition runtime involved).

Run: uv run --env-file .env python scripts/arbiter_smoke.py
Uses LLM_ARBITER_* settings (empty values fall back to LLM_*), sends one
finish-only request in the same format as a real arbitration and prints the
verdict, the time and the full submission.
"""

import asyncio
import json
import time

from bluesec1_agent.agent import SYSTEM_PROMPT
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.settings import Settings

CASE = {
    "alert_text": "Process powershell.exe (PID: 3080) was started on host APP97",
    "trigger_entities": [
        {"id": "83ddd3f2-ae87-52ee-b29a-4f999ce09039", "type": "windows_process",
         "properties": {"image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "cmdline": "powershell.exe -NoP -W Hidden -Enc SQBFAFgA...",
                        "user": "keystone.local\\svc_bi", "parent_image": "winword.exe"}},
    ],
    "analyst": {"verdict": "benign", "reasoning": "Signed Microsoft binary run by a service account."},
    "reviewer": {"verdict": "malicious", "reasoning": "Hidden encoded PowerShell spawned by Word."},
}


async def main() -> None:
    s = Settings()
    model = s.llm_arbiter_model.strip()
    if not model:
        raise SystemExit("LLM_ARBITER_MODEL is empty")
    body = s.llm_arbiter_extra_body.strip() or s.llm_extra_body.strip()
    llm = OpenAIStructuredStepClient(
        base_url=s.llm_arbiter_base_url.strip() or s.llm_base_url,
        api_key=s.llm_arbiter_api_key.get_secret_value() or s.llm_api_key.get_secret_value(),
        model=model,
        timeout_seconds=s.llm_timeout_seconds,
        max_completion_tokens=s.llm_arbiter_max_completion_tokens,
        max_retries=2,
        disable_thinking=s.llm_arbiter_disable_thinking,
        inline_schema_refs=s.llm_arbiter_inline_schema_refs,
        extra_body=json.loads(body) if body else None,
        http_retries=s.llm_http_retries,
        response_mode=s.llm_arbiter_response_mode,
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Two analysts disagree. Decide using only the facts.\n"
                                    + json.dumps(CASE, ensure_ascii=False)},
    ]
    t = time.perf_counter()
    try:
        step = await llm.next_step(messages, finish_only=True)
        sub = step.function.model_dump(mode="json", by_alias=True).get("submission", {})
        print(f"{model}: {time.perf_counter() - t:.1f}s -> verdict={sub.get('verdict')}")
        print(json.dumps(sub, ensure_ascii=False, indent=2)[:1500])
    except Exception as exc:
        print(f"{model}: FAILED after {time.perf_counter() - t:.1f}s: {type(exc).__name__}: {exc}")
    finally:
        await llm.aclose()


asyncio.run(main())
